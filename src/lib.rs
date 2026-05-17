use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod store;

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

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
