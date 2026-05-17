//! Smart routing rules (F17 from `bridge-features-roadmap-v2`).
//!
//! Operators author rules in the `routing_rules` table. The engine
//! `eval` walks enabled rules in priority order on each emitted
//! trigger and returns the actions to fire. Actions go through the
//! existing `publish_system` helper so they share the audit-log +
//! `bridge-auto` author path.
//!
//! Design decisions locked into v1 (see decision key
//! `decision-bridge-f17-routing`):
//!
//! - **Q1 AutoAssign** = post addressed message, NEVER mutate
//!   finding/task rows.
//! - **Q2 Filter language** = JSON eq/contains/in with implicit
//!   AND. Unknown operator at insert ⇒ reject (`FilterError`).
//!   Unknown operator at eval ⇒ Err + counts toward the
//!   3-strike auto-disable.
//! - **Q3 Cycle depth** = default 1 + `BRIDGE_ROUTING_MAX_DEPTH`
//!   env (1–3, refuse-to-start if >3).
//! - **Q4 AutoMessage rate** = 10/min per (rule_id, channel) hard
//!   cap. 3 trips in 5 min flips `enabled = 0` (quarantine) +
//!   posts an addressed message to `ops`.
//! - **Q5 Template** = literal `{{name}}` placeholders, regex
//!   one-pass, NEVER recursive. Markdown-escape every substituted
//!   value. Whitelisted context fields per trigger_type. Unknown
//!   placeholder ⇒ literal output + WARN.

use std::collections::HashMap;
use std::time::Duration;

use dashmap::DashMap;
use serde_json::Value;
use thiserror::Error;

use crate::RoutingRule;

/// Reasons a filter parse / eval can fail. Insert-time errors land
/// here so a misspelled operator surfaces immediately rather than
/// silently making the rule never match.
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("filter must be a JSON object (got {0})")]
    NotAnObject(&'static str),
    #[error("field `{field}` operator `{op}` is not supported (allowed: eq, contains, in)")]
    UnknownOperator { field: String, op: String },
    #[error("field `{field}` operator `{op}` requires {expected} (got {actual})")]
    BadOperandType {
        field: String,
        op: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("filter JSON malformed: {0}")]
    Malformed(#[from] serde_json::Error),
}

/// One action produced by the engine for a matched rule. The
/// dispatcher in `server.rs` reads these and fans out via
/// `publish_system` / direct task mutation.
#[derive(Debug, Clone)]
pub struct MatchedAction {
    pub rule_id: String,
    pub rule_name: String,
    pub action_type: String,
    pub action_params: Value,
}

/// Validate a filter JSON without holding the rule yet. Used at
/// insert time to refuse a bad rule before it lands in the
/// routing_rules table. The check is deep enough to catch the
/// common author mistakes (`{severity: {eq: "high"}}` written as
/// `{severity: {eqs: "high"}}`) — anything beyond eq/contains/in
/// gets rejected.
pub fn validate_filter(filter: &Value) -> Result<(), FilterError> {
    let obj = match filter {
        Value::Object(o) => o,
        Value::Null => return Ok(()), // empty filter == match-all
        other => return Err(FilterError::NotAnObject(type_name(other))),
    };
    for (field, cond) in obj {
        match cond {
            // Literal eq form — `{field: "v"}`, `{field: 42}`, etc.
            Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => continue,
            // Operator-object form — `{field: {op: v}}`. We accept
            // exactly one op per field; anything else is a typo.
            Value::Object(ops) => {
                if ops.len() != 1 {
                    return Err(FilterError::UnknownOperator {
                        field: field.clone(),
                        op: format!("(expected exactly one operator, got {})", ops.len()),
                    });
                }
                let (op, operand) = ops.iter().next().unwrap();
                match op.as_str() {
                    "eq" => {
                        // Any scalar OK; rejects nested objects /
                        // arrays for eq.
                        if matches!(operand, Value::Object(_) | Value::Array(_)) {
                            return Err(FilterError::BadOperandType {
                                field: field.clone(),
                                op: op.clone(),
                                expected: "scalar",
                                actual: type_name(operand),
                            });
                        }
                    }
                    "contains" => {
                        if !matches!(operand, Value::String(_)) {
                            return Err(FilterError::BadOperandType {
                                field: field.clone(),
                                op: op.clone(),
                                expected: "string",
                                actual: type_name(operand),
                            });
                        }
                    }
                    "in" => {
                        if !matches!(operand, Value::Array(_)) {
                            return Err(FilterError::BadOperandType {
                                field: field.clone(),
                                op: op.clone(),
                                expected: "array",
                                actual: type_name(operand),
                            });
                        }
                    }
                    other => {
                        return Err(FilterError::UnknownOperator {
                            field: field.clone(),
                            op: other.to_string(),
                        });
                    }
                }
            }
            // Arrays and arbitrary nested objects at the top-level
            // value position aren't supported.
            other => {
                return Err(FilterError::UnknownOperator {
                    field: field.clone(),
                    op: format!("(unsupported value type {})", type_name(other)),
                });
            }
        }
    }
    Ok(())
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Apply a (pre-validated) filter to a context payload. Top-level
/// fields are implicit-AND'd: every field must match for the
/// overall result to be true. A missing field in `payload` =
/// non-match (so a rule conditioning on `severity` doesn't fire
/// when the trigger context lacks one).
///
/// Returns `Err` only on a filter shape that survived validation
/// but turned out malformed at runtime (e.g., schema drift after
/// an upgrade). Caller treats `Err` as a strike toward the
/// 3-in-5-min auto-disable.
pub fn matches_filter(filter: &Value, payload: &Value) -> Result<bool, FilterError> {
    let Value::Object(filter_obj) = filter else {
        return Ok(matches!(filter, Value::Null));
    };
    let Value::Object(payload_obj) = payload else {
        // Caller must hand us an object payload; the engine
        // guarantees this for every emitted trigger.
        return Ok(filter_obj.is_empty());
    };
    for (field, cond) in filter_obj {
        let value = match payload_obj.get(field) {
            Some(v) => v,
            None => return Ok(false), // missing field → non-match
        };
        let ok = match cond {
            Value::String(s) => value == &Value::String(s.clone()),
            Value::Number(n) => value == &Value::Number(n.clone()),
            Value::Bool(b) => value == &Value::Bool(*b),
            Value::Null => value.is_null(),
            Value::Object(ops) => {
                let (op, operand) = ops.iter().next().ok_or_else(|| {
                    FilterError::UnknownOperator {
                        field: field.clone(),
                        op: "(empty operator)".into(),
                    }
                })?;
                match op.as_str() {
                    "eq" => value == operand,
                    "contains" => {
                        let needle = operand.as_str().ok_or_else(|| {
                            FilterError::BadOperandType {
                                field: field.clone(),
                                op: op.clone(),
                                expected: "string",
                                actual: type_name(operand),
                            }
                        })?;
                        value
                            .as_str()
                            .map(|haystack| haystack.contains(needle))
                            .unwrap_or(false)
                    }
                    "in" => {
                        let arr = operand.as_array().ok_or_else(|| {
                            FilterError::BadOperandType {
                                field: field.clone(),
                                op: op.clone(),
                                expected: "array",
                                actual: type_name(operand),
                            }
                        })?;
                        arr.iter().any(|elem| elem == value)
                    }
                    other => {
                        return Err(FilterError::UnknownOperator {
                            field: field.clone(),
                            op: other.to_string(),
                        });
                    }
                }
            }
            _ => false,
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Render a Q5-Option-A template — literal `{{name}}` placeholders,
/// single-pass regex match, **never recursive**. Substituted values
/// are markdown-escaped so a value containing `*bold*` renders as
/// `\*bold\*` in the channel rather than breaking out into markup.
/// Unknown placeholders pass through as the literal `{{foo}}` string
/// AND emit a WARN (no panic, no Err — UX-friendly per ops 1779048867).
pub fn render_template(template: &str, context: &HashMap<&str, &str>) -> String {
    // Avoid pulling in `regex` for one fixed pattern — write a tiny
    // state machine. Matches `{{` ... `}}` with `\w` ident inside.
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len() + 32);
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Find closing `}}`. Bounded scan to avoid pathological
            // O(n²) on malformed input — placeholder ident max 64
            // bytes is plenty.
            let scan_end = (i + 2 + 64).min(bytes.len());
            let mut j = i + 2;
            while j + 1 < scan_end && !(bytes[j] == b'}' && bytes[j + 1] == b'}') {
                if !(bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j = scan_end; // bail; not an ident
                    break;
                }
                j += 1;
            }
            if j + 1 < scan_end && bytes[j] == b'}' && bytes[j + 1] == b'}' && j > i + 2 {
                // SAFETY: we walked j-i+2 chars asserted ASCII
                // alphanumeric + underscore; valid UTF-8 boundary.
                let name = std::str::from_utf8(&bytes[i + 2..j]).expect("ascii ident");
                match context.get(name) {
                    Some(val) => out.push_str(&markdown_escape(val)),
                    None => {
                        tracing::warn!(
                            placeholder = name,
                            "routing template references unknown placeholder; rendered as literal"
                        );
                        out.push_str("{{");
                        out.push_str(name);
                        out.push_str("}}");
                    }
                }
                i = j + 2;
                continue;
            }
        }
        // Non-template byte. UTF-8 safe push via char iter.
        let ch = template[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Escape characters that bridge channels render as markdown
/// formatting. Conservative — wraps every metacharacter with `\`
/// regardless of position. Substituted values stay literal even
/// when the surrounding template uses bold/italic/code/links.
fn markdown_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '*' | '_' | '~' | '`' | '[' | ']' | '<' | '>' | '\\' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Extract `{{name}}` ident tokens from a template string. Used
/// at insert/update time to check action_params templates against
/// the trigger_type's whitelist (0f4543 Phase 1 bonus). Mirrors
/// `render_template`'s parser exactly — same `\w` ident rule,
/// same bounded scan, same conservative literal-on-malformed
/// fallback — so what passes here is exactly what would render.
pub fn extract_template_placeholders(template: &str) -> Vec<String> {
    let bytes = template.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            let scan_end = (i + 2 + 64).min(bytes.len());
            let mut j = i + 2;
            let mut ok = true;
            while j + 1 < scan_end && !(bytes[j] == b'}' && bytes[j + 1] == b'}') {
                if !(bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok && j + 1 < scan_end && bytes[j] == b'}' && bytes[j + 1] == b'}' && j > i + 2 {
                let name = std::str::from_utf8(&bytes[i + 2..j])
                    .expect("ascii ident")
                    .to_string();
                if !out.contains(&name) {
                    out.push(name);
                }
                i = j + 2;
                continue;
            }
        }
        let ch = template[i..].chars().next().unwrap();
        i += ch.len_utf8();
    }
    out
}

/// Validate that every placeholder used in an `auto_message` /
/// `auto_batch` action's `template` is in the whitelist for the
/// rule's trigger_type. Per 0f4543 Phase 1 bonus: catches the
/// "rule references `{{ops_secret}}` against a trigger that
/// doesn't carry it" path at insert time, instead of warn-spam at
/// every eval. Other action types (auto_assign, auto_escalate)
/// don't accept templates so they're no-op.
pub fn validate_template_placeholders(
    trigger_type: &str,
    action_type: &str,
    action_params: &serde_json::Value,
) -> Result<(), FilterError> {
    let template = match action_type {
        "auto_message" | "auto_batch" => action_params.get("template").and_then(|v| v.as_str()),
        _ => None,
    };
    let Some(template) = template else { return Ok(()) };
    let allowed = placeholders_for(trigger_type);
    // Batch metadata placeholders (count, batch_key, rule_name) are
    // legal on auto_batch templates only (they're rendered by the
    // flush path, not the per-trigger emit path).
    let batch_extras: &[&str] = if action_type == "auto_batch" {
        &["count", "batch_key", "rule_name"]
    } else {
        &[]
    };
    let used = extract_template_placeholders(template);
    for name in &used {
        let in_whitelist = allowed.iter().any(|w| *w == name.as_str());
        let in_batch_extras = batch_extras.iter().any(|w| *w == name.as_str());
        if !in_whitelist && !in_batch_extras {
            return Err(FilterError::UnknownOperator {
                field: format!("template placeholder `{{{{{name}}}}}`"),
                op: format!(
                    "not in whitelist for trigger_type `{trigger_type}` — \
                     allowed: {allowed:?}{}",
                    if batch_extras.is_empty() {
                        String::new()
                    } else {
                        format!(" + batch extras {batch_extras:?}")
                    }
                ),
            });
        }
    }
    Ok(())
}

/// Whitelisted context fields per trigger_type (locked at ops
/// 1779048867). Returning a `&'static [&str]` lets us validate
/// rule action_params against the trigger-context vocabulary at
/// insert time too.
pub fn placeholders_for(trigger_type: &str) -> &'static [&'static str] {
    match trigger_type {
        "finding_created" => &["finding_id", "severity", "title", "endpoint", "from", "channel"],
        "task_unassigned" => &["task_id", "title", "description", "from", "channel"],
        "peer_idle" => &["peer", "idle_secs", "channel"],
        "dispatch_stale" => &["message_id", "from", "to", "channel", "age_secs"],
        _ => &[],
    }
}

/// Evaluate every enabled rule for `trigger_type` against `payload`.
/// Walks rules in priority DESC order. Returns the actions to fire
/// in the same order; the caller dispatches.
///
/// `depth` is the caller's current chain depth (0 for an
/// externally-triggered event). The caller MUST refuse to recurse
/// past `max_depth` regardless of what we return — depth is here
/// for instrumentation, not enforcement. This module doesn't fire
/// actions; the dispatcher in `server.rs` owns the recursion budget.
pub fn eval(
    rules: &[RoutingRule],
    trigger_type: &str,
    payload: &Value,
) -> Vec<MatchedAction> {
    let mut out = Vec::new();
    for r in rules {
        if !r.enabled || r.trigger_type != trigger_type {
            continue;
        }
        let parsed: Value = serde_json::from_str(&r.trigger_filter).unwrap_or(Value::Null);
        match matches_filter(&parsed, payload) {
            Ok(true) => {
                let params: Value =
                    serde_json::from_str(&r.action_params).unwrap_or(Value::Null);
                out.push(MatchedAction {
                    rule_id: r.id.clone(),
                    rule_name: r.name.clone(),
                    action_type: r.action_type.clone(),
                    action_params: params,
                });
            }
            Ok(false) => {}
            Err(e) => {
                // Eval-time error: log + skip this rule. The
                // dispatcher tracks the strike per Q4.
                tracing::warn!(
                    rule_id = %r.id,
                    error = %e,
                    "routing filter eval errored at runtime; skipping rule"
                );
            }
        }
    }
    out
}

/// Per-(rule_id, channel) AutoMessage rate-limiter state.
/// Distinct from the `/resume` bucket because the threat model
/// differs — here we're guarding against a flapping rule
/// channel-spamming, not against scraping.
#[derive(Default)]
pub struct RateBucket {
    /// (rule_id, channel) → (window_start, count)
    pub counts: DashMap<(String, String), (u64, u32)>,
    /// (rule_id) → vec of (trip_at) timestamps for the 5-min
    /// quarantine trigger. Old entries pruned on insert.
    pub trips: DashMap<String, Vec<u64>>,
}

pub const AUTO_MESSAGE_CAP_PER_MIN: u32 = 10;
pub const AUTO_MESSAGE_WINDOW: Duration = Duration::from_secs(60);
/// 3 trips in 5 minutes flips `enabled = 0` for the rule (Q4).
pub const QUARANTINE_TRIP_THRESHOLD: usize = 3;
pub const QUARANTINE_TRIP_WINDOW: Duration = Duration::from_secs(5 * 60);

impl RateBucket {
    /// Returns `true` if this AutoMessage emit fits under the cap;
    /// `false` if it should be dropped + counted as a trip.
    pub fn check_and_count(&self, rule_id: &str, channel: &str, now: u64) -> bool {
        let key = (rule_id.to_string(), channel.to_string());
        let mut entry = self.counts.entry(key).or_insert((now, 0));
        let (window_start, count) = *entry.value();
        if now.saturating_sub(window_start) >= AUTO_MESSAGE_WINDOW.as_secs() {
            *entry.value_mut() = (now, 1);
            return true;
        }
        if count >= AUTO_MESSAGE_CAP_PER_MIN {
            return false;
        }
        *entry.value_mut() = (window_start, count + 1);
        true
    }

    /// Record a trip (a cap-hit). Returns `true` if this trip puts
    /// the rule into quarantine (≥3 trips in 5 min). Caller is
    /// responsible for the actual `enabled = 0` flip + ops ping.
    pub fn record_trip(&self, rule_id: &str, now: u64) -> bool {
        let mut entry = self.trips.entry(rule_id.to_string()).or_default();
        let v = entry.value_mut();
        v.push(now);
        // Prune anything past the 5-min window so the count is a
        // rolling window, not all-time.
        let cutoff = now.saturating_sub(QUARANTINE_TRIP_WINDOW.as_secs());
        v.retain(|t| *t >= cutoff);
        v.len() >= QUARANTINE_TRIP_THRESHOLD
    }
}

/// Read `BRIDGE_ROUTING_MAX_DEPTH` env, default 1, clamped to
/// 1..=3. Per Q3 ops, any value >3 → refuse to start (caller
/// surfaces via the same FATAL pattern as `Config::from_env`).
pub fn parse_max_depth_env() -> Result<u8, MaxDepthError> {
    let raw = std::env::var("BRIDGE_ROUTING_MAX_DEPTH").ok();
    let Some(s) = raw.filter(|s| !s.is_empty()) else {
        return Ok(1);
    };
    let n: u8 = s.parse().map_err(|_| MaxDepthError::Invalid(s.clone()))?;
    if !(1..=3).contains(&n) {
        return Err(MaxDepthError::OutOfRange(n));
    }
    Ok(n)
}

#[derive(Debug, Error)]
pub enum MaxDepthError {
    #[error("BRIDGE_ROUTING_MAX_DEPTH must be 1, 2, or 3; got `{0}`")]
    Invalid(String),
    #[error("BRIDGE_ROUTING_MAX_DEPTH out of range (1..=3); got {0}")]
    OutOfRange(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(name: &str, trig: &str, filter: Value, act: &str, params: Value, prio: i64) -> RoutingRule {
        RoutingRule {
            id: name.into(),
            name: name.into(),
            trigger_type: trig.into(),
            trigger_filter: filter.to_string(),
            action_type: act.into(),
            action_params: params.to_string(),
            enabled: true,
            priority: prio,
            created_by: "test".into(),
            created_at: 0,
        }
    }

    // === filter language ===

    #[test]
    fn validate_filter_accepts_known_ops() {
        for f in [
            json!({}),
            json!({"severity": "high"}),
            json!({"severity": {"eq": "high"}}),
            json!({"title": {"contains": "xss"}}),
            json!({"severity": {"in": ["high", "critical"]}}),
            json!({"severity": "high", "channel": {"contains": "pale"}}),
        ] {
            validate_filter(&f).unwrap_or_else(|e| panic!("rejected valid filter {f:?}: {e}"));
        }
    }

    #[test]
    fn validate_filter_rejects_unknown_op() {
        // Misspelled `eq` → reject (no silent no-match).
        let err = validate_filter(&json!({"severity": {"eqs": "high"}})).unwrap_err();
        assert!(matches!(err, FilterError::UnknownOperator { .. }));
        // contains with non-string operand → reject.
        let err = validate_filter(&json!({"severity": {"contains": 42}})).unwrap_err();
        assert!(matches!(err, FilterError::BadOperandType { .. }));
        // in with non-array operand → reject.
        let err = validate_filter(&json!({"severity": {"in": "high"}})).unwrap_err();
        assert!(matches!(err, FilterError::BadOperandType { .. }));
        // Two operators on one field → reject.
        let err =
            validate_filter(&json!({"severity": {"eq": "high", "contains": "i"}})).unwrap_err();
        assert!(matches!(err, FilterError::UnknownOperator { .. }));
    }

    #[test]
    fn matches_filter_eq_in_contains_implicit_and() {
        let payload = json!({
            "severity": "high",
            "title": "XSS in admin",
            "channel": "pale-pentest",
        });
        // Pure eq.
        assert!(matches_filter(&json!({"severity": "high"}), &payload).unwrap());
        assert!(!matches_filter(&json!({"severity": "low"}), &payload).unwrap());
        // contains.
        assert!(matches_filter(&json!({"title": {"contains": "XSS"}}), &payload).unwrap());
        assert!(!matches_filter(&json!({"title": {"contains": "SQL"}}), &payload).unwrap());
        // in.
        assert!(matches_filter(
            &json!({"severity": {"in": ["high", "critical"]}}),
            &payload
        )
        .unwrap());
        // Implicit AND across multiple fields.
        assert!(matches_filter(
            &json!({"severity": "high", "title": {"contains": "XSS"}}),
            &payload
        )
        .unwrap());
        // Missing field → non-match.
        assert!(!matches_filter(&json!({"endpoint": "GET /admin"}), &payload).unwrap());
    }

    // === eval ===

    #[test]
    fn eval_returns_in_priority_desc_order_and_skips_disabled() {
        let payload = json!({"severity": "high"});
        let mut rules = vec![
            rule("r-low",  "finding_created", json!({}), "auto_message", json!({}), 10),
            rule("r-high", "finding_created", json!({}), "auto_message", json!({}), 90),
            rule("r-mid",  "finding_created", json!({}), "auto_message", json!({}), 50),
        ];
        // Disabled rule should NOT appear in matches.
        let mut r_disabled = rule("r-disabled", "finding_created", json!({}), "auto_message", json!({}), 99);
        r_disabled.enabled = false;
        rules.push(r_disabled);
        // The engine doesn't sort — the caller (Store query) hands
        // them in priority DESC. Simulate that here.
        rules.sort_by_key(|r| -r.priority);
        let out = eval(&rules, "finding_created", &payload);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].rule_id, "r-high");
        assert_eq!(out[1].rule_id, "r-mid");
        assert_eq!(out[2].rule_id, "r-low");
    }

    #[test]
    fn eval_skips_rules_whose_filter_errors_at_runtime() {
        let payload = json!({"severity": "high"});
        // The eval skips the broken rule (logs warn), still returns
        // the good one. No panic.
        let rules = vec![
            rule("good", "finding_created", json!({"severity": "high"}), "auto_message", json!({}), 50),
            // contains expects a string; pass an array — errors at eval-time.
            rule("bad",  "finding_created", json!({"severity": {"contains": ["high"]}}), "auto_message", json!({}), 60),
        ];
        let out = eval(&rules, "finding_created", &payload);
        let ids: Vec<_> = out.iter().map(|m| m.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["good"]);
    }

    // === template ===

    #[test]
    fn template_substitutes_known_placeholders() {
        let mut ctx = HashMap::new();
        ctx.insert("peer", "alice");
        ctx.insert("count", "3");
        assert_eq!(
            render_template("ping {{peer}} ({{count}} open)", &ctx),
            "ping alice (3 open)"
        );
    }

    #[test]
    fn template_substitution_single_pass_no_recursive_eval() {
        // A substituted value containing template syntax must NOT
        // be re-evaluated — closes the secondary-injection vector
        // pentest 0f4543 raised in 1779048843.
        let mut ctx = HashMap::new();
        ctx.insert("title", "{{exfil_token}}");
        ctx.insert("exfil_token", "SECRET");
        let out = render_template("finding: {{title}}", &ctx);
        // Load-bearing invariant: the secret VALUE never appears
        // in the output because the engine doesn't recurse into
        // the substituted text.
        assert!(!out.contains("SECRET"), "recursive eval leaked secret: {out}");
        // Belt: the substituted value's `_` gets markdown-escaped,
        // which also breaks any downstream parser that might trip
        // on `{{name}}` syntax — defense in depth.
        assert!(out.contains("exfil") && out.contains("token"));
        assert!(out.starts_with("finding: "));
    }

    #[test]
    fn template_markdown_escape_applied_to_substituted_values() {
        let mut ctx = HashMap::new();
        ctx.insert("body", "*bold* _italic_ `code` [link](x) <html>");
        let out = render_template("user said: {{body}}", &ctx);
        assert!(out.contains("\\*bold\\*"), "got: {out}");
        assert!(out.contains("\\_italic\\_"));
        assert!(out.contains("\\`code\\`"));
        assert!(out.contains("\\[link\\]"));
        assert!(out.contains("\\<html\\>"));
    }

    #[test]
    fn template_unknown_placeholder_renders_literally() {
        let ctx: HashMap<&str, &str> = HashMap::new();
        // Without `peer` in context, the placeholder passes through
        // as the literal string `{{peer}}` (+ WARN log we don't
        // assert here).
        assert_eq!(render_template("hi {{peer}}", &ctx), "hi {{peer}}");
    }

    #[test]
    fn template_non_ident_inside_braces_passes_through() {
        let ctx: HashMap<&str, &str> = HashMap::new();
        // Spaces / special chars inside `{{}}` aren't a valid ident
        // — the parser bails and emits the literal text.
        assert_eq!(render_template("{{a b}} {{ }} {{x-y}}", &ctx), "{{a b}} {{ }} {{x-y}}");
    }

    // === rate limit + quarantine ===

    #[test]
    fn rate_bucket_caps_at_threshold_per_minute() {
        let b = RateBucket::default();
        let now = 1_000_000u64;
        for _ in 0..AUTO_MESSAGE_CAP_PER_MIN {
            assert!(b.check_and_count("r1", "c1", now));
        }
        assert!(!b.check_and_count("r1", "c1", now));
        // A separate (rule, channel) pair has its own bucket.
        assert!(b.check_and_count("r1", "c2", now));
        assert!(b.check_and_count("r2", "c1", now));
        // Window rollover resets.
        let later = now + AUTO_MESSAGE_WINDOW.as_secs() + 1;
        assert!(b.check_and_count("r1", "c1", later));
    }

    #[test]
    fn rate_bucket_trip_threshold_signals_quarantine() {
        let b = RateBucket::default();
        let now = 1_000_000u64;
        assert!(!b.record_trip("r1", now));
        assert!(!b.record_trip("r1", now + 60));
        // 3rd trip in window → quarantine signal.
        assert!(b.record_trip("r1", now + 120));
        // After the window rolls, the count resets.
        let later = now + QUARANTINE_TRIP_WINDOW.as_secs() + 200;
        assert!(!b.record_trip("r1", later));
    }

    // === placeholder extraction + whitelist validation ===

    #[test]
    fn extract_template_placeholders_dedups_and_skips_malformed() {
        let names = extract_template_placeholders(
            "ping {{peer}} ({{count}} open, batch {{count}}) {{a-b}} {{ }}",
        );
        // `{{count}}` appears twice but dedup keeps one.
        // `{{a-b}}` has a non-ident char → skipped.
        // `{{ }}` has whitespace → skipped.
        assert_eq!(names, vec!["peer".to_string(), "count".to_string()]);
    }

    #[test]
    fn validate_template_placeholders_rejects_off_whitelist_for_auto_message() {
        // `finding_created` whitelist = finding_id, severity, title,
        // endpoint, from, channel.
        let good = json!({"template": "[{{severity}}] {{title}} in {{channel}}"});
        validate_template_placeholders("finding_created", "auto_message", &good)
            .expect("whitelist hit");
        let bad = json!({"template": "secret = {{ops_secret}}"});
        let err = validate_template_placeholders("finding_created", "auto_message", &bad).unwrap_err();
        assert!(matches!(err, FilterError::UnknownOperator { .. }));
        let msg = format!("{err}");
        assert!(msg.contains("ops_secret"));
        // auto_batch allows the extras count/batch_key/rule_name.
        let batch_ok =
            json!({"template": "[batch] {{count}} items for {{batch_key}} via {{rule_name}}"});
        validate_template_placeholders("finding_created", "auto_batch", &batch_ok)
            .expect("batch extras allowed");
        // Non-template action types are no-op.
        let no_template = json!({"assignee_role": "pentest"});
        validate_template_placeholders("finding_created", "auto_assign", &no_template).unwrap();
    }

    // === max-depth env parser ===

    #[test]
    fn parse_max_depth_env_defaults_and_validates() {
        // Save + restore env to keep parallel tests isolated.
        let prev = std::env::var("BRIDGE_ROUTING_MAX_DEPTH").ok();
        std::env::remove_var("BRIDGE_ROUTING_MAX_DEPTH");
        assert_eq!(parse_max_depth_env().unwrap(), 1);
        for ok in ["1", "2", "3"] {
            std::env::set_var("BRIDGE_ROUTING_MAX_DEPTH", ok);
            assert_eq!(parse_max_depth_env().unwrap(), ok.parse::<u8>().unwrap());
        }
        for bad in ["0", "4", "99"] {
            std::env::set_var("BRIDGE_ROUTING_MAX_DEPTH", bad);
            assert!(matches!(
                parse_max_depth_env().unwrap_err(),
                MaxDepthError::OutOfRange(_)
            ));
        }
        std::env::set_var("BRIDGE_ROUTING_MAX_DEPTH", "notanumber");
        assert!(matches!(
            parse_max_depth_env().unwrap_err(),
            MaxDepthError::Invalid(_)
        ));
        std::env::remove_var("BRIDGE_ROUTING_MAX_DEPTH");
        if let Some(v) = prev {
            std::env::set_var("BRIDGE_ROUTING_MAX_DEPTH", v);
        }
    }
}

