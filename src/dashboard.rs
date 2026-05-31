//! F19 — Dashboard templates (server-side maud + minimal vanilla JS).
//!
//! All routes live behind `is_memory_admin` gate (operator surface,
//! not per-peer view). REST-purist invariant: every GET handler is
//! pure read; mutations go through existing POST/PATCH routes via
//! inline form buttons. This is what keeps the dashboard immune to
//! classical CSRF (bearer header can't cross-origin without
//! CORS+JS, per pentest analysis msg 1779064521).
//!
//! Each sub-page calls `shell(title, body)` for the common chrome
//! (header + nav + footer + CSS + SSE script).

use maud::{html, Markup, DOCTYPE};

/// Inline CSS — minimal, no framework. Goal: readable from
/// `curl --html` if rendering breaks. Dark theme matches terminal
/// aesthetic; ops surface, not consumer product.
const CSS: &str = r#"
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  font: 14px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  margin: 0; padding: 0; background: #0d1117; color: #c9d1d9;
}
header {
  padding: 12px 24px; border-bottom: 1px solid #30363d;
  display: flex; justify-content: space-between; align-items: center;
  background: #161b22;
}
header h1 { font-size: 16px; margin: 0; color: #58a6ff; }
header .meta { color: #8b949e; font-size: 12px; }
nav { padding: 8px 24px; background: #161b22; border-bottom: 1px solid #30363d; }
nav a {
  color: #c9d1d9; text-decoration: none; margin-right: 16px;
  padding: 4px 8px; border-radius: 4px;
}
nav a:hover { background: #30363d; }
nav a.active { background: #1f6feb; color: #fff; }
main { padding: 24px; max-width: 1400px; margin: 0 auto; }
h2 { color: #58a6ff; font-size: 14px; margin: 16px 0 8px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
th, td {
  text-align: left; padding: 6px 12px;
  border-bottom: 1px solid #30363d; vertical-align: top;
}
th { background: #161b22; color: #8b949e; font-weight: normal; }
tr:hover { background: #161b22; }
.card {
  background: #161b22; border: 1px solid #30363d;
  border-radius: 6px; padding: 12px; margin-bottom: 12px;
}
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 10px;
  font-size: 11px; margin-right: 4px;
}
.badge.critical { background: #b22222; color: #fff; }
.badge.high { background: #d29922; color: #1c2128; }
.badge.medium { background: #58a6ff; color: #0d1117; }
.badge.low { background: #2ea043; color: #fff; }
.badge.info { background: #6e7681; color: #fff; }
.badge.open { background: #b22222; color: #fff; }
.badge.triaged { background: #d29922; color: #1c2128; }
.badge.fixed { background: #2ea043; color: #fff; }
.badge.wontfix { background: #6e7681; color: #fff; }
.badge.running { background: #2ea043; color: #fff; }
.badge.crashed { background: #b22222; color: #fff; }
.badge.exited { background: #6e7681; color: #fff; }
.badge.todo { background: #6e7681; color: #fff; }
.badge.in_progress { background: #1f6feb; color: #fff; }
.badge.done { background: #2ea043; color: #fff; }
.badge.cancelled { background: #6e7681; color: #fff; }
.sla-past { background: rgba(178,34,34,0.15); }
.muted { color: #8b949e; }
form.inline { display: inline; }
button, .btn {
  background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
  padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;
}
button:hover, .btn:hover { background: #30363d; }
button.primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
input, select, textarea {
  background: #0d1117; color: #c9d1d9;
  border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px;
}
footer {
  padding: 12px 24px; color: #8b949e; font-size: 11px;
  border-top: 1px solid #30363d; margin-top: 24px;
}
#sse-status {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  background: #6e7681; margin-right: 4px; vertical-align: middle;
}
#sse-status.live { background: #2ea043; }
#sse-status.lost { background: #b22222; }
.empty { color: #8b949e; padding: 16px; text-align: center; }
"#;

/// JS that opens the dashboard SSE stream and patches `[data-sse-target]`
/// elements when matching events arrive. Browser callers must reach
/// the SSE endpoint through a reverse proxy that injects the bearer
/// (per ops Q2 decision msg 1779064316). Pure vanilla, ~60 LOC.
const JS: &str = r#"
(function() {
  const status = document.getElementById('sse-status');
  let src = null;
  function open() {
    try {
      // Try EventSource; if 401 the user is reaching it without
      // the reverse-proxy bearer injection. Status badge stays red.
      src = new EventSource('/dashboard/sse', { withCredentials: true });
      src.onopen = () => { status.classList.add('live'); status.classList.remove('lost'); };
      src.onerror = () => {
        status.classList.add('lost'); status.classList.remove('live');
        if (src) { src.close(); src = null; }
        setTimeout(open, 5000);
      };
      src.onmessage = (e) => {
        let msg; try { msg = JSON.parse(e.data); } catch (_) { return; }
        // Bump a generic ticker counter for any event so the operator
        // knows the bridge is alive even if the current page doesn't
        // care about this specific event.
        const ticker = document.getElementById('event-ticker');
        if (ticker) ticker.textContent = String(parseInt(ticker.textContent || '0') + 1);
        // Per-event-type DOM patches: simple textContent updates on
        // elements with matching data-sse-target. Page-specific JS
        // can extend by listening on document for 'bridge-sse'.
        document.dispatchEvent(new CustomEvent('bridge-sse', { detail: msg }));
      };
    } catch (e) { /* no EventSource in this env */ }
  }
  open();
})();
"#;

/// Common page shell — header + nav + footer + inline CSS/JS.
/// Login page — only shown when `BRIDGE_DASHBOARD_USERS` is set.
pub fn login_page(error: Option<&str>) -> Markup {
    let body = html! {
        div style="max-width:360px;margin:80px auto;text-align:center" {
            h1 style="font-size:20px;color:#58a6ff;margin:0 0 24px" { "claude-bridge" }
            div class="card" style="text-align:left" {
                form method="post" action="/dashboard/login" {
                    @if let Some(e) = error {
                        p style="color:#b22222;margin:0 0 12px" { (e) }
                    }
                    label style="display:block;margin-bottom:4px;font-size:12px;color:#8b949e" { "user" }
                    input type="text" name="username" required style="width:100%;margin-bottom:12px";
                    label style="display:block;margin-bottom:4px;font-size:12px;color:#8b949e" { "password" }
                    input type="password" name="password" required style="width:100%;margin-bottom:16px";
                    button type="submit" class="primary" style="width:100%" { "sign in" }
                }
            }
            p class="muted" style="font-size:11px;margin-top:16px" {
                "operator: set " code { "BRIDGE_DASHBOARD_USERS=user:pass" }
                " to enable"
            }
        }
    };
    shell("", "login", body)
}

pub fn shell(active: &str, title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "claude-bridge · " (title) }
                style { (CSS) }
            }
            body {
                header {
                    h1 { "claude-bridge dashboard" }
                    span class="meta" {
                        span id="sse-status" {}
                        "events: " span id="event-ticker" { "0" }
                    }
                }
                nav {
                    (nav_link(active, "", "Home"))
                    (nav_link(active, "peers", "Peers"))
                    (nav_link(active, "findings", "Findings"))
                    (nav_link(active, "tasks", "Tasks"))
                    (nav_link(active, "dispatches", "Dispatches"))
                    (nav_link(active, "routing", "Routing"))
                    (nav_link(active, "watchers", "Watchers"))
                }
                main { (body) }
                footer {
                    "claude-bridge · F19 dashboard · admin surface · "
                    a href="https://github.com/ronbrain/claude-bridge"
                      style="color:#58a6ff;text-decoration:none" { "github" }
                }
                script { (maud::PreEscaped(JS)) }
            }
        }
    }
}

fn nav_link(active: &str, slug: &str, label: &str) -> Markup {
    let href = if slug.is_empty() { "/dashboard".to_string() } else { format!("/dashboard/{slug}") };
    let is_active = active == slug;
    html! {
        a href=(href) class=(if is_active { "active" } else { "" }) { (label) }
    }
}

/// Landing page — top-line counts + recent ticker. Pages render
/// from data the caller (handler in server.rs) already collected,
/// so this module stays pure-template (no AppState dep).
pub fn landing(
    peers_active: usize,
    open_findings_by_severity: &[(String, usize)],
    dispatches_pending: usize,
    tasks_active: usize,
    recent_messages: &[(String, String, String)], // (channel, from, content)
) -> Markup {
    let body = html! {
        section class="cards" {
            div class="card" {
                h2 { "Peers active" }
                div style="font-size:24px;color:#58a6ff" { (peers_active) }
            }
            div class="card" {
                h2 { "Open findings" }
                @if open_findings_by_severity.is_empty() {
                    div class="muted" { "none open" }
                } @else {
                    @for (sev, n) in open_findings_by_severity {
                        span class={"badge " (sev)} { (n) " " (sev) }
                    }
                }
            }
            div class="card" {
                h2 { "Dispatches pending" }
                div style="font-size:24px;color:#d29922" { (dispatches_pending) }
            }
            div class="card" {
                h2 { "Tasks active" }
                div style="font-size:24px;color:#1f6feb" { (tasks_active) }
            }
        }
        h2 { "Recent messages" }
        @if recent_messages.is_empty() {
            div class="empty" { "no messages yet" }
        } @else {
            table {
                thead { tr { th { "channel" } th { "from" } th { "content" } } }
                tbody {
                    @for (ch, from, content) in recent_messages {
                        tr {
                            td { "#" (ch) }
                            td { (from) }
                            td { (truncate(content, 120)) }
                        }
                    }
                }
            }
        }
    };
    shell("", "home", body)
}

pub fn peers_page(rows: &[PeerRow]) -> Markup {
    let body = html! {
        h2 { "Connected peers" }
        @if rows.is_empty() {
            div class="empty" { "no peers heartbeating" }
        } @else {
            table {
                thead { tr {
                    th { "name" } th { "idle" } th { "channel" }
                    th { "roles" } th { "skills" }
                    th { "open dispatches" } th { "status" }
                }}
                tbody {
                    @for p in rows {
                        tr {
                            td { strong { (p.name) } }
                            td { (p.idle_secs) "s" }
                            td { "#" (p.channel) }
                            td { (p.roles.join(", ")) }
                            td class="muted" { (truncate(&p.skills.join(", "), 40)) }
                            td { (p.open_dispatches) }
                            td { (truncate(&p.status, 60)) }
                        }
                    }
                }
            }
        }
    };
    shell("peers", "peers", body)
}

pub struct PeerRow {
    pub name: String,
    pub idle_secs: u64,
    pub channel: String,
    pub roles: Vec<String>,
    pub skills: Vec<String>,
    pub open_dispatches: usize,
    pub status: String,
}

pub fn findings_page(rows: &[FindingRow], filter_severity: Option<&str>, filter_status: Option<&str>) -> Markup {
    let body = html! {
        h2 { "Findings" }
        form method="get" action="/dashboard/findings"
             style="display:flex;gap:8px;margin-bottom:12px;align-items:center" {
            label { "severity:" }
            select name="severity" {
                option value="" { "all" }
                @for sev in ["critical","high","medium","low","info"] {
                    option value=(sev) selected=(filter_severity == Some(sev)) { (sev) }
                }
            }
            label { "status:" }
            select name="status" {
                option value="" { "all" }
                @for st in ["open","triaged","fixed","wontfix"] {
                    option value=(st) selected=(filter_status == Some(st)) { (st) }
                }
            }
            button type="submit" class="primary" { "filter" }
        }
        @if rows.is_empty() {
            div class="empty" { "no findings match" }
        } @else {
            table {
                thead { tr {
                    th { "id" } th { "severity" } th { "status" }
                    th { "title" } th { "endpoint" }
                    th { "from" } th { "channel" }
                }}
                tbody {
                    @for f in rows {
                        tr {
                            td class="muted" { (truncate(&f.id, 8)) }
                            td { span class={"badge " (f.severity)} { (f.severity) } }
                            td { span class={"badge " (f.status)} { (f.status) } }
                            td { (truncate(&f.title, 60)) }
                            td class="muted" { (truncate(&f.endpoint, 40)) }
                            td { (f.from) }
                            td { "#" (f.channel) }
                        }
                    }
                }
            }
        }
    };
    shell("findings", "findings", body)
}

pub struct FindingRow {
    pub id: String,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub endpoint: String,
    pub from: String,
    pub channel: String,
}

pub fn tasks_page(rows: &[TaskRow]) -> Markup {
    // Simple board grouped by status. F29 will enrich with claim
    // buttons + plan-approval UI; v1 is read-only.
    let mut by_status: std::collections::BTreeMap<&str, Vec<&TaskRow>> =
        std::collections::BTreeMap::new();
    for r in rows {
        by_status.entry(r.status.as_str()).or_default().push(r);
    }
    let body = html! {
        h2 { "Tasks" }
        @if rows.is_empty() {
            div class="empty" { "no tasks" }
        } @else {
            div class="cards" {
                @for (status, ts) in &by_status {
                    div class="card" {
                        h2 { span class={"badge " (status)} { (status) } " " (ts.len()) }
                        @for t in ts {
                            div style="border-top:1px solid #30363d;padding-top:8px;margin-top:8px" {
                                strong { (truncate(&t.title, 80)) }
                                div class="muted" style="font-size:11px" {
                                    "owner: " (if t.owner.is_empty() { "—" } else { &t.owner })
                                    " · channel: #" (t.channel)
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    shell("tasks", "tasks", body)
}

pub struct TaskRow {
    pub id: String,
    pub status: String,
    pub title: String,
    pub owner: String,
    pub channel: String,
}

pub fn dispatches_page(rows: &[DispatchRow], now_secs: u64, sla_secs: u64) -> Markup {
    let body = html! {
        h2 { "Open dispatches" " (SLA " (sla_secs/60) "min)" }
        @if rows.is_empty() {
            div class="empty" { "no open dispatches" }
        } @else {
            table {
                thead { tr {
                    th { "message_id" } th { "from" } th { "to" }
                    th { "channel" } th { "age" }
                }}
                tbody {
                    @for d in rows {
                        @let age = now_secs.saturating_sub(d.sent_at);
                        @let past_sla = age > sla_secs;
                        tr class=(if past_sla { "sla-past" } else { "" }) {
                            td class="muted" { (truncate(&d.message_id, 8)) }
                            td { (d.from) }
                            td { (d.to) }
                            td { "#" (d.channel) }
                            td {
                                (age / 60) "m"
                                @if past_sla { " " span class="badge open" { "stale" } }
                            }
                        }
                    }
                }
            }
        }
    };
    shell("dispatches", "dispatches", body)
}

pub struct DispatchRow {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub channel: String,
    pub sent_at: u64,
}

pub fn routing_page(rows: &[RoutingRow]) -> Markup {
    let body = html! {
        h2 { "Routing rules" }
        @if rows.is_empty() {
            div class="empty" { "no routing rules defined" }
        } @else {
            table {
                thead { tr {
                    th { "name" } th { "trigger" } th { "action" }
                    th { "priority" } th { "enabled" }
                }}
                tbody {
                    @for r in rows {
                        tr {
                            td { strong { (r.name) } }
                            td { (r.trigger_type) }
                            td { (r.action_type) }
                            td { (r.priority) }
                            td {
                                @if r.enabled {
                                    span class="badge running" { "on" }
                                } @else {
                                    span class="badge crashed" { "off" }
                                }
                            }
                        }
                    }
                }
            }
        }
        h2 { "Dry-run eval" }
        div class="card" {
            div class="muted" {
                "POST a JSON body to "
                code { "/routing-rules/eval" }
                " with " code { "{trigger_type, payload}" }
                " to see which rules would fire. Use a curl wrapper with the bearer header."
            }
        }
    };
    shell("routing", "routing", body)
}

pub struct RoutingRow {
    pub name: String,
    pub trigger_type: String,
    pub action_type: String,
    pub priority: i64,
    pub enabled: bool,
}

pub fn watchers_page(rows: &[WatcherRow], now_secs: u64) -> Markup {
    let body = html! {
        h2 { "Peer watchers (F26)" }
        @if rows.is_empty() {
            div class="empty" { "no watchers spawned" }
        } @else {
            table {
                thead { tr {
                    th { "peer" } th { "pid" } th { "status" }
                    th { "spawned_by" } th { "age" } th { "last_seen" } th { "ttl_remaining" }
                }}
                tbody {
                    @for w in rows {
                        @let age = now_secs.saturating_sub(w.spawned_at);
                        @let ttl_remaining = w.ttl_secs.saturating_sub(age);
                        @let last_seen_ago = now_secs.saturating_sub(w.last_seen);
                        tr {
                            td { strong { (w.peer) } }
                            td class="muted" { (w.pid) }
                            td { span class={"badge " (w.status)} { (w.status) } }
                            td { (w.spawned_by) }
                            td { (age / 60) "m" }
                            td { (last_seen_ago) "s ago" }
                            td { (ttl_remaining / 60) "m" }
                        }
                    }
                }
            }
        }
    };
    shell("watchers", "watchers", body)
}

pub struct WatcherRow {
    pub peer: String,
    pub pid: i32,
    pub status: String,
    pub spawned_by: String,
    pub spawned_at: u64,
    pub last_seen: u64,
    pub ttl_secs: u64,
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_renders_doctype_nav_and_active_marker() {
        let m = shell("findings", "findings", html! { p { "x" } });
        let s = m.into_string();
        assert!(s.starts_with("<!DOCTYPE html>"));
        assert!(s.contains("class=\"active\"")); // findings nav link
        assert!(s.contains("<title>claude-bridge · findings</title>"));
        assert!(s.contains("sse-status"));
        assert!(s.contains("EventSource('/dashboard/sse'"));
    }

    #[test]
    fn landing_includes_severity_badges_for_each_count() {
        let by_sev = vec![("critical".into(), 1usize), ("low".into(), 3usize)];
        let m = landing(2, &by_sev, 5, 4, &[]);
        let s = m.into_string();
        assert!(s.contains("badge critical"));
        assert!(s.contains("badge low"));
        // Counters render as numbers.
        assert!(s.contains(">2<")); // peers_active
        assert!(s.contains(">5<")); // dispatches_pending
        // Recent-messages empty state.
        assert!(s.contains("no messages yet"));
    }

    #[test]
    fn dispatches_page_marks_stale_rows() {
        let rows = vec![
            DispatchRow {
                message_id: "m1".into(),
                from: "alice".into(),
                to: "bob".into(),
                channel: "general".into(),
                sent_at: 0,
            },
            DispatchRow {
                message_id: "m2".into(),
                from: "alice".into(),
                to: "bob".into(),
                channel: "general".into(),
                sent_at: 9_000_000,
            },
        ];
        // now well past row 1's sent_at, well before row 2's.
        let s = dispatches_page(&rows, 1_000, 60).into_string();
        // Row 1 is past SLA (age > 60), row 2 isn't.
        assert!(s.contains("sla-past"));
        assert!(s.contains("stale"));
    }

    #[test]
    fn findings_filter_preserved_in_form_state() {
        let m = findings_page(&[], Some("high"), Some("open"));
        let s = m.into_string();
        // The select option for "high" + "open" should carry `selected`.
        assert!(s.contains("value=\"high\" selected"));
        assert!(s.contains("value=\"open\" selected"));
    }

    #[test]
    fn watchers_page_handles_empty_and_renders_ttl_math() {
        // Empty state.
        let m = watchers_page(&[], 0);
        assert!(m.into_string().contains("no watchers spawned"));
        // Populated.
        let rows = vec![WatcherRow {
            peer: "alice".into(),
            pid: 4242,
            status: "running".into(),
            spawned_by: "ops".into(),
            spawned_at: 0,
            last_seen: 0,
            ttl_secs: 3600,
        }];
        let s = watchers_page(&rows, 600).into_string();
        // age in minutes (600s = 10m), ttl_remaining 3000s = 50m.
        assert!(s.contains(">10m"));
        assert!(s.contains(">50m"));
        assert!(s.contains("badge running"));
    }
}
