//! Centralised runtime config.
//!
//! Replaces scattered `std::env::var(...)` calls in `main()` and
//! handler bodies with a single struct populated once at startup
//! and threaded into `AppState`. Adding a new tunable now lives in
//! one place; tests can construct a `Config::default()` without
//! mutating process env.

use std::time::Duration;

/// Errors `Config::from_env` returns when the startup invariants
/// of `ops-rule-no-silent-fail-open-defaults` aren't met. `main()`
/// surfaces these as a FATAL log + exit code 2 so an operator's
/// missing env var doesn't silently degrade to a state-bearing
/// failure mode (per data-loss incident on sv-s-bcloud + finding
/// `c9d0bfd9`).
#[derive(Debug, thiserror::Error)]
pub enum ConfigStartupError {
    #[error(
        "BRIDGE_DB_PATH empty and BRIDGE_DB_EPHEMERAL not set — refusing to start without \
         persistent storage. Set BRIDGE_DB_PATH=/path/to/bridge.db to enable sqlite-backed \
         persistence (recommended), OR set BRIDGE_DB_EPHEMERAL=1 to explicitly run in-memory-only \
         (state lost on every restart — see finding c9d0bfd9)."
    )]
    DbPathEmptyNotEphemeral,
    #[error(
        "BRIDGE_ROUTING_PEER_IDLE_SECS={0} out of range — must be 60..=3600 (per F17.4 / \
         0f4543 review 1779053200). Refusing to start so the routing engine doesn't fire \
         peer_idle triggers at a useless cadence."
    )]
    PeerIdleSecsOutOfRange(u64),
}

#[derive(Clone, Debug)]
pub struct Config {
    /// `0.0.0.0:<port>` to bind. From `PORT` (default 3001).
    pub bind: String,
    /// Path to sqlite store, or `None` for in-memory-only mode.
    /// From `BRIDGE_DB_PATH` — empty/unset disables persistence.
    pub db_path: Option<String>,
    /// CSV of origins accepted for cross-origin requests. From
    /// `BRIDGE_ALLOWED_ORIGINS`. Reserved for a future CORS layer;
    /// no enforcement today.
    pub allowed_origins: Vec<String>,
    /// In-memory cap on messages retained per channel. Larger ⇒
    /// more memory but longer scrollback. From
    /// `BRIDGE_HISTORY_LIMIT` (default 100).
    pub history_limit: usize,
    /// In-memory cap on findings per channel. From
    /// `BRIDGE_FINDING_LIMIT` (default 500).
    pub finding_limit: usize,
    /// Max retained artifacts globally. From
    /// `BRIDGE_ARTIFACT_LIMIT` (default 200).
    pub artifact_limit: usize,
    /// Heartbeat staleness threshold — peers idle beyond this drop
    /// off `list_peers`. From `BRIDGE_PEER_TTL_SECS` (default 120).
    pub peer_ttl: Duration,
    /// TTL applied to rows in `peer_status_history` so the audit
    /// trail doesn't grow unbounded. From
    /// `BRIDGE_PEER_HISTORY_TTL_SECS` (default 30 days, per ops
    /// dispatch 1779031354).
    pub peer_history_ttl: Duration,
    /// Maximum versions kept per memory key in `memory_history`.
    /// From `BRIDGE_MEMORY_HISTORY_KEEP` (default 5).
    pub memory_history_keep: usize,
    /// Threshold the `PeerIdleScanner` uses to emit `peer_idle`
    /// triggers — peers whose `last_seen` lag exceeds this fire
    /// through the routing engine. From `BRIDGE_ROUTING_PEER_IDLE_SECS`
    /// (default 300, range 60..=3600 per F17.4 / 0f4543 ask
    /// 1779053200; out-of-range refuses to start).
    pub routing_peer_idle_secs: u64,
    /// Dashboard login credentials: CSV of `user:pass` pairs.
    /// When non-empty, the dashboard exposes a login page.
    /// From `BRIDGE_DASHBOARD_USERS` (default empty = disabled).
    pub dashboard_users: std::collections::HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Default to loopback per pentest finding `dc633d7c`
            // (msg 1779042729). Operators wanting network exposure
            // must set `BRIDGE_BIND=0.0.0.0:<port>` explicitly,
            // which triggers a SEVERE warn at boot reminding them
            // to pair it with `BRIDGE_AUTH_TOKENS`. Closes the
            // "anyone reachable can hit /memory_set" surface.
            bind: "127.0.0.1:3001".into(),
            db_path: None,
            allowed_origins: Vec::new(),
            history_limit: 100,
            finding_limit: 500,
            artifact_limit: 200,
            peer_ttl: Duration::from_secs(120),
            peer_history_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            memory_history_keep: 5,
            routing_peer_idle_secs: 300,
            dashboard_users: std::collections::HashMap::new(),
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_duration_secs(name: &str, default: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}

impl Config {
    /// Read every supported env var, falling back to the `Default`
    /// for any that is unset, empty, or unparseable. Never fails —
    /// a typo'd var name silently uses the default, which is the
    /// existing behaviour for `PORT` etc. and avoids gating boot on
    /// trivial env-name corrections.
    pub fn from_env() -> Result<Self, ConfigStartupError> {
        let default = Self::default();
        // Bind resolution order:
        //   1. `BRIDGE_BIND` (full host:port) wins — explicit
        //      opt-in to whatever exposure the operator wants.
        //   2. `PORT` composes with the safe loopback default.
        //   3. Plain `Default::default()` (127.0.0.1:3001).
        // A `BRIDGE_BIND` that starts with `0.` or `0:` warns at
        // boot — this is the single most common foot-gun and worth
        // the explicit pointer back to the auth findings.
        let bind = match std::env::var("BRIDGE_BIND").ok().filter(|s| !s.is_empty()) {
            Some(b) => {
                if b.starts_with("0.0.0.0") || b.starts_with("0:") || b.starts_with("[::]") {
                    tracing::warn!(
                        bind = %b,
                        "SEVERE: BRIDGE_BIND exposes the bridge to all interfaces — \
                         ensure BRIDGE_AUTH_TOKENS is set (see finding dc633d7c). \
                         Without an auth token map, every host that can reach this \
                         port can hit every mutation endpoint."
                    );
                }
                b
            }
            None => {
                let port = std::env::var("PORT").unwrap_or_else(|_| "3001".into());
                format!("127.0.0.1:{port}")
            }
        };
        // Persistence resolution per ops-rule-no-silent-fail-open-
        // defaults + finding c9d0bfd9. The previous code silently
        // dropped to in-memory mode when BRIDGE_DB_PATH was unset,
        // which cost an experienced operator multi-engagement state
        // on sv-s-bcloud (2026-05-17). Now: refuse to start unless
        // the operator either points at a file OR explicitly opts
        // into ephemeral mode via BRIDGE_DB_EPHEMERAL=1. Same shape
        // as the auth bundle's BRIDGE_AUTH_PERMISSIVE gate.
        let db_path = std::env::var("BRIDGE_DB_PATH")
            .ok()
            .filter(|s| !s.is_empty());
        let ephemeral = std::env::var("BRIDGE_DB_EPHEMERAL")
            .ok()
            .as_deref()
            == Some("1");
        if db_path.is_none() && !ephemeral {
            return Err(ConfigStartupError::DbPathEmptyNotEphemeral);
        }
        if db_path.is_none() && ephemeral {
            tracing::warn!(
                "SEVERE: BRIDGE_DB_EPHEMERAL=1 — bridge is running with NO persistent storage. \
                 Every message, finding, dispatch, memory key, audit row, and peer status will \
                 be lost on the next restart. See finding c9d0bfd9. Set BRIDGE_DB_PATH=<file> \
                 to enable sqlite-backed persistence."
            );
        }
        let allowed_origins = std::env::var("BRIDGE_ALLOWED_ORIGINS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            bind,
            db_path,
            allowed_origins,
            history_limit: env_usize("BRIDGE_HISTORY_LIMIT", default.history_limit),
            finding_limit: env_usize("BRIDGE_FINDING_LIMIT", default.finding_limit),
            artifact_limit: env_usize("BRIDGE_ARTIFACT_LIMIT", default.artifact_limit),
            peer_ttl: env_duration_secs("BRIDGE_PEER_TTL_SECS", default.peer_ttl),
            peer_history_ttl: env_duration_secs(
                "BRIDGE_PEER_HISTORY_TTL_SECS",
                default.peer_history_ttl,
            ),
            memory_history_keep: env_usize(
                "BRIDGE_MEMORY_HISTORY_KEEP",
                default.memory_history_keep,
            ),
            routing_peer_idle_secs: {
                // F17.4 — operator-tunable per 0f4543 ask
                // 1779053200. Out-of-range refuses to start so a
                // 0 or 99999 doesn't silently degrade to default.
                let raw = std::env::var("BRIDGE_ROUTING_PEER_IDLE_SECS").ok();
                match raw.as_deref() {
                    None | Some("") => default.routing_peer_idle_secs,
                    Some(s) => {
                        let n: u64 = s
                            .parse()
                            .map_err(|_| ConfigStartupError::PeerIdleSecsOutOfRange(0))?;
                        if !(60..=3600).contains(&n) {
                            return Err(ConfigStartupError::PeerIdleSecsOutOfRange(n));
                        }
                        n
                    }
                }
            },
            dashboard_users: {
                // CSV of user:pass pairs for dashboard login.
                // Format: `BRIDGE_DASHBOARD_USERS=user1:pass1,user2:pass2`
                let raw = std::env::var("BRIDGE_DASHBOARD_USERS").unwrap_or_default();
                let mut users = std::collections::HashMap::new();
                for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if let Some((u, p)) = part.split_once(':') {
                        users.insert(u.trim().to_string(), p.trim().to_string());
                    }
                }
                if !users.is_empty() {
                    tracing::info!(users = users.len(), "dashboard login enabled");
                }
                users
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_refuses_empty_db_path_without_ephemeral_opt_in() {
        // Save + clear so we exercise the fail-closed gate.
        let prev_path = std::env::var("BRIDGE_DB_PATH").ok();
        let prev_eph = std::env::var("BRIDGE_DB_EPHEMERAL").ok();
        std::env::remove_var("BRIDGE_DB_PATH");
        std::env::remove_var("BRIDGE_DB_EPHEMERAL");
        let r = Config::from_env();
        assert!(
            matches!(r, Err(ConfigStartupError::DbPathEmptyNotEphemeral)),
            "empty BRIDGE_DB_PATH without BRIDGE_DB_EPHEMERAL must refuse to start"
        );
        // Opt-in path admits the empty path with a warn.
        std::env::set_var("BRIDGE_DB_EPHEMERAL", "1");
        let r = Config::from_env();
        assert!(r.is_ok(), "BRIDGE_DB_EPHEMERAL=1 must admit empty path");
        assert!(r.unwrap().db_path.is_none());
        // Explicit path also admits (orthogonal to the opt-in flag).
        std::env::set_var("BRIDGE_DB_PATH", "/tmp/bridge-test-config-only.db");
        let r = Config::from_env();
        assert!(r.is_ok());
        assert_eq!(r.unwrap().db_path.as_deref(), Some("/tmp/bridge-test-config-only.db"));
        // Restore env so we don't poison sibling tests.
        std::env::remove_var("BRIDGE_DB_EPHEMERAL");
        std::env::remove_var("BRIDGE_DB_PATH");
        if let Some(v) = prev_path {
            std::env::set_var("BRIDGE_DB_PATH", v);
        }
        if let Some(v) = prev_eph {
            std::env::set_var("BRIDGE_DB_EPHEMERAL", v);
        }
    }

    #[test]
    fn peer_idle_secs_env_range_enforced() {
        // F17.4 — out-of-range refuses, in-range admits, unset defaults to 300.
        let prev_path = std::env::var("BRIDGE_DB_PATH").ok();
        let prev_eph = std::env::var("BRIDGE_DB_EPHEMERAL").ok();
        let prev_idle = std::env::var("BRIDGE_ROUTING_PEER_IDLE_SECS").ok();
        // Keep DB path satisfied so the only thing we exercise is the new gate.
        std::env::set_var("BRIDGE_DB_EPHEMERAL", "1");
        std::env::remove_var("BRIDGE_DB_PATH");
        for ok in ["60", "300", "1800", "3600"] {
            std::env::set_var("BRIDGE_ROUTING_PEER_IDLE_SECS", ok);
            let c = Config::from_env().expect("in-range admits");
            assert_eq!(c.routing_peer_idle_secs, ok.parse::<u64>().unwrap());
        }
        for bad in ["0", "59", "3601", "99999"] {
            std::env::set_var("BRIDGE_ROUTING_PEER_IDLE_SECS", bad);
            assert!(matches!(
                Config::from_env().unwrap_err(),
                ConfigStartupError::PeerIdleSecsOutOfRange(_)
            ));
        }
        std::env::set_var("BRIDGE_ROUTING_PEER_IDLE_SECS", "notanumber");
        assert!(matches!(
            Config::from_env().unwrap_err(),
            ConfigStartupError::PeerIdleSecsOutOfRange(_)
        ));
        std::env::remove_var("BRIDGE_ROUTING_PEER_IDLE_SECS");
        let c = Config::from_env().expect("default admits");
        assert_eq!(c.routing_peer_idle_secs, 300);
        // Restore.
        std::env::remove_var("BRIDGE_DB_EPHEMERAL");
        for (k, v) in [
            ("BRIDGE_DB_PATH", prev_path),
            ("BRIDGE_DB_EPHEMERAL", prev_eph),
            ("BRIDGE_ROUTING_PEER_IDLE_SECS", prev_idle),
        ] {
            if let Some(val) = v {
                std::env::set_var(k, val);
            }
        }
    }

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.history_limit, 100);
        assert_eq!(c.peer_ttl, Duration::from_secs(120));
        assert!(c.db_path.is_none());
        // 30 days per ops dispatch — guard against accidental edits.
        assert_eq!(c.peer_history_ttl, Duration::from_secs(2_592_000));
        // Per finding `dc633d7c`: default MUST be loopback, not
        // 0.0.0.0. If this assert fails, someone is regressing the
        // critical-finding fix. Re-read the finding before changing.
        assert_eq!(c.bind, "127.0.0.1:3001");
    }
}
