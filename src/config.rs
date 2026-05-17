//! Centralised runtime config.
//!
//! Replaces scattered `std::env::var(...)` calls in `main()` and
//! handler bodies with a single struct populated once at startup
//! and threaded into `AppState`. Adding a new tunable now lives in
//! one place; tests can construct a `Config::default()` without
//! mutating process env.

use std::time::Duration;

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:3001".into(),
            db_path: None,
            allowed_origins: Vec::new(),
            history_limit: 100,
            finding_limit: 500,
            artifact_limit: 200,
            peer_ttl: Duration::from_secs(120),
            peer_history_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            memory_history_keep: 5,
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
    pub fn from_env() -> Self {
        let default = Self::default();
        let port = std::env::var("PORT").unwrap_or_else(|_| "3001".into());
        let bind = format!("0.0.0.0:{port}");
        let db_path = std::env::var("BRIDGE_DB_PATH")
            .ok()
            .filter(|s| !s.is_empty());
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
        Self {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.history_limit, 100);
        assert_eq!(c.peer_ttl, Duration::from_secs(120));
        assert!(c.db_path.is_none());
        // 30 days per ops dispatch — guard against accidental edits.
        assert_eq!(c.peer_history_ttl, Duration::from_secs(2_592_000));
    }
}
