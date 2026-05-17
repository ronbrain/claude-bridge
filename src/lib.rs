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
}

/// Severity ladder for structured findings. String-typed in the JSON
/// so clients in any language can author them without an enum import.
pub const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

/// Lifecycle states for a finding. `open` is the default at creation;
/// `triaged` means a human looked at it and acknowledged; `fixed` /
/// `wontfix` are terminal.
pub const STATUSES: &[&str] = &["open", "triaged", "fixed", "wontfix"];

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
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
