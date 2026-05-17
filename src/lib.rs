use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod automation;
pub mod config;
pub mod error;
pub mod store;
pub use config::Config;
pub use error::{ApiError, ApiResult};

/// Bound a `&str`-like input by byte length, returning a 400-shaped
/// tuple-error compatible with axum handlers' current
/// `Result<T, (StatusCode, String)>` signature. Lets handlers write
/// `cap!(req.title, MAX_TITLE_LEN)` instead of the boilerplate
/// `cap(&req.title, MAX_TITLE_LEN, "title")?` — the field name is
/// the literal identifier so the error message stays accurate
/// without an explicit string arg.
///
/// Used by every write handler in server.rs (12+ sites). Centralised
/// to make changes to the error shape (Group D's later `ApiError`
/// migration) a single edit.
#[macro_export]
macro_rules! cap {
    ($value:expr, $max:expr) => {{
        let v = &$value;
        let max = $max;
        if v.len() > max {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                format!(
                    "{} too long ({}>{})",
                    stringify!($value).trim_start_matches("req.").trim_start_matches("&"),
                    v.len(),
                    max
                ),
            ));
        }
    }};
    ($value:expr, $max:expr, $field:expr) => {{
        let v = &$value;
        let max = $max;
        if v.len() > max {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                format!("{} too long ({}>{})", $field, v.len(), max),
            ));
        }
    }};
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub channel: String,
    pub from: String,
    pub content: String,
    pub timestamp: u64,
    /// Optional recipient list — identity names or role aliases. When
    /// empty (the default), the message is a broadcast and every
    /// subscriber on the channel sees it. When non-empty, clients are
    /// expected to filter: only surface to the model when this list
    /// includes the local instance's identity or one of its declared
    /// roles. Server stays unaware — filtering is client-side so the
    /// SSE stream doesn't need per-subscriber routing logic.
    #[serde(default)]
    pub to: Vec<String>,
    /// Optional thread grouping. Messages sharing the same
    /// `thread_id` form a conversation (a finding + its discussion +
    /// fix updates, for example). When empty, the message stands
    /// alone in the channel feed.
    #[serde(default)]
    pub thread_id: String,
    /// Pinned messages stay at the top of `read_messages` listings
    /// regardless of timestamp. Use for the "current state" doc, the
    /// skills board, or a long-lived link to a critical artifact.
    #[serde(default)]
    pub pinned: bool,
}

/// Severity ladder for structured findings. String-typed in the JSON
/// so clients in any language can author them without an enum import.
pub const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

/// Lifecycle states for a finding. `open` is the default at creation;
/// `triaged` means a human looked at it and acknowledged; `fixed` /
/// `wontfix` are terminal.
pub const STATUSES: &[&str] = &["open", "triaged", "fixed", "wontfix"];

/// Lifecycle states for a task in the work queue. Distinct from
/// findings: tasks are "do X", findings are "there's a bug Y".
pub const TASK_STATUSES: &[&str] = &["todo", "in_progress", "blocked", "done", "cancelled"];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub channel: String,
    pub from: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    /// HTTP method + path the finding affects, free-form. Empty when
    /// the finding isn't endpoint-scoped (e.g. an architecture issue).
    #[serde(default)]
    pub endpoint: String,
    pub status: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Latest triage note from `triage_finding`. Empty on creation.
    #[serde(default)]
    pub note: String,
    /// IDs of other findings/tasks this one blocks (this finishes
    /// before those can start).
    #[serde(default)]
    pub blocks: Vec<String>,
    /// IDs of other findings/tasks this one depends on.
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub channel: String,
    pub from: String,
    pub filename: String,
    pub size: usize,
    pub mime: String,
    pub created_at: u64,
}

/// Declared purpose of a channel. Set by `PUT /channels/{name}/topic`
/// and surfaced via `GET /channels` so peers can discover proper
/// routing before posting. Empty `topic` means "no purpose declared
/// yet" — peers should treat it as a free-form channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelTopic {
    pub name: String,
    pub topic: String,
    pub updated_by: String,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub last_seen: u64,
    /// Seconds since the peer's last heartbeat. Surfaced precomputed
    /// so clients (CLI, MCP, dashboard) don't all repeat the math.
    pub idle_secs: u64,
    /// Channel the peer last advertised. Optional — heartbeats can
    /// omit it when the client doesn't yet know which channel it'll
    /// be active on.
    #[serde(default)]
    pub channel: String,
    /// Roles this peer claims (e.g. ["pentest"], ["integration",
    /// "ops"]). Used by `send_message` so a sender can address
    /// `to: ["pentest"]` and the client resolves that to every peer
    /// currently advertising that role. Empty when the peer hasn't
    /// declared any.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Finer-grained capabilities than `roles`. Where `roles` says
    /// "what this peer is" (`pentest`, `fixer`), `skills` says "what
    /// this peer can do" (`svelte`, `csp`, `sqlx`, `rust-axum`). A
    /// task router (`find_peer_by_skill`) can pick the best match
    /// when assigning work without anyone needing to memorise who's
    /// good at what.
    #[serde(default)]
    pub skills: Vec<String>,
    /// Short human-readable status line — what the peer is currently
    /// doing, ETA, blocked-on note. Cleared when the peer goes
    /// silent (TTL = peer TTL).
    #[serde(default)]
    pub status: String,
}

/// A unit of work tracked separately from findings. Findings describe
/// problems discovered; tasks describe action items assigned to a
/// peer. Tasks have explicit owner + status so ops can answer "what
/// is X working on" and "what's blocked on whom" without paging the
/// whole chat history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub channel: String,
    /// Peer that created the task (usually ops or whoever discovered
    /// the need). Not necessarily the owner.
    pub from: String,
    pub title: String,
    pub description: String,
    /// Identity name or role of the assignee. When a role is given,
    /// the client can resolve it to the live peer(s) at read-time.
    /// Empty = unassigned (in the queue, waiting for pickup).
    #[serde(default)]
    pub owner: String,
    /// One of TASK_STATUSES. Default `todo`.
    pub status: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Latest free-form note added by `update_task` (typically an
    /// ETA, a blocker description, or a fix link).
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub blocks: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// A single key in the shared memory KV store. Channel-scoped so two
/// projects on the same bridge don't trample each other's keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub channel: String,
    pub key: String,
    pub value: String,
    pub updated_by: String,
    pub updated_at: u64,
    /// Optional unix-seconds expiry. The server lazy-expires on read
    /// rather than running a sweep thread — entries with `expires_at`
    /// past `now` look gone to `memory_get` but may persist on disk
    /// until the next overwrite.
    #[serde(default)]
    pub expires_at: u64,
}

// ─── Group A new types (Schema v2+) ────────────────────────────────
//
// These types back the post-v1 schema additions: structured peer
// status history (audit-only; live presence stays string-typed in
// server memory), dispatch tracking, memory version history, coverage
// snapshots, decision log, finding lifecycle, channel mirrors, and
// audit log. None of them participate in the hot-read path — they
// exist to make analytics, postmortem, and resume-index generation
// possible without grepping chat history.

/// Structured form of a peer's status. Persisted only as transition
/// history (`peer_status_history`); live presence stays `String` in
/// `PeerState` to preserve the intentional ephemeral semantics in
/// server.rs (see comment at AppState::peers).
pub const PEER_STATES: &[&str] = &["working", "blocked", "standby", "engagement_closed"];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    /// One of PEER_STATES.
    pub state: String,
    /// Required when state is `blocked` or `standby`. Free text;
    /// validated non-empty at write time, not by shape.
    #[serde(default)]
    pub reason: String,
    /// Unix-seconds when this state was entered.
    pub since: u64,
    /// Required when state is `blocked` — identity of the peer (or
    /// the artefact id) the caller is waiting on.
    #[serde(default)]
    pub blocked_by: String,
}

/// One row in `peer_status_history`. Append-only; written only when
/// the live peer's status changes from the previous row's value
/// (snapshot-on-transition, not on every heartbeat — protects the
/// writer lock).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatusHistory {
    pub id: String,
    pub peer: String,
    pub status: PeerStatus,
    pub recorded_at: u64,
}

/// A message sent with a non-empty `to:` list becomes a dispatch
/// row: a tracked unit of "X asked Y to do something". Ack and
/// completion are separate columns so the lifecycle is queryable
/// without rescanning chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dispatch {
    pub id: String,
    pub message_id: String,
    pub from: String,
    /// Comma-joined recipients — serialized form so the table stays
    /// scalar. Parsed back into `Vec<String>` at the API boundary.
    pub to: String,
    pub channel: String,
    pub sent_at: u64,
    /// Unix-seconds the recipient acknowledged. 0 = not yet acked.
    #[serde(default)]
    pub ack_at: u64,
    /// ETA the recipient committed at ack time. 0 = none.
    #[serde(default)]
    pub ack_eta_secs: u64,
    /// Unix-seconds the recipient marked done. 0 = open.
    #[serde(default)]
    pub completed_at: u64,
    /// Free-form outcome note at completion.
    #[serde(default)]
    pub outcome: String,
}

/// One historical version of a memory key. Latest N=5 kept per
/// (channel, key); older ones drop. Lets a peer `memory_diff` two
/// versions without a separate database.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryHistory {
    pub channel: String,
    pub key: String,
    pub version: u64,
    pub value: String,
    pub set_by: String,
    pub set_at: u64,
}

/// Coverage snapshot keyed by `(role, surface_type)`. Replaces the
/// ad-hoc `<role>-coverage-<date>` memory keys with a queryable
/// table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coverage {
    pub role: String,
    pub surface_type: String,
    pub current: u64,
    pub total: u64,
    /// Optional JSON object — breakdown by sub-category, free-form.
    #[serde(default)]
    pub breakdown: String,
    pub updated_by: String,
    pub updated_at: u64,
}

/// A first-class decision record. Replaces ad-hoc `decision-*`
/// memory keys; backed by FTS5 for text search.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub id: String,
    pub decision_text: String,
    pub reason: String,
    /// JSON array of strings. Empty when no alternatives recorded.
    #[serde(default)]
    pub alternatives: String,
    #[serde(default)]
    pub scope: String,
    pub decided_by: String,
    #[serde(default)]
    pub applies_to: String,
    pub decided_at: u64,
}

/// One row in `finding_transitions` — the full lifecycle of a
/// finding from `open` through any number of triage cycles to
/// `fixed` or `wontfix`. Hooked from `create_finding` and
/// `triage_finding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingTransition {
    pub finding_id: String,
    pub from_status: String,
    pub to_status: String,
    pub transitioned_by: String,
    pub at: u64,
    #[serde(default)]
    pub note: String,
}

/// Cross-channel memory mirror declaration. When a write happens to
/// `(source_channel, source_key)`, the server propagates to every
/// registered mirror with `target_channel.target_key`. Depth-limited
/// to 1 hop in the server to avoid cycles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MirrorLink {
    pub source_channel: String,
    pub source_key: String,
    pub target_channel: String,
    pub target_key: String,
    pub created_at: u64,
}

/// One row in `audit_log`. Append-only; one entry per write op.
/// `before_hash` / `after_hash` are sha256-truncated to 16 bytes
/// so the log does not itself store full payloads, but can be
/// joined back to source tables at a known point for forensics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub at: u64,
    pub actor: String,
    pub op: String,
    pub target_type: String,
    pub target_id: String,
    /// 16 hex chars (8 bytes) of sha256 over the prior row, "" if
    /// the row didn't exist before this op.
    #[serde(default)]
    pub before_hash: String,
    /// 16 hex chars of sha256 over the row after the op.
    #[serde(default)]
    pub after_hash: String,
    /// "ok" or a short error tag — full error strings stay in
    /// tracing logs to avoid mirroring sensitive content here.
    pub result: String,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
