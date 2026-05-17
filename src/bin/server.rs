use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{sse::{Event, KeepAlive, Sse}, IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use claude_bridge::{
    cap, now_secs, store::Store, Artifact, ChannelTopic, Finding, MemoryEntry, Message, Peer,
    Task, SEVERITIES, STATUSES, TASK_STATUSES,
};
use dashmap::DashMap;
use futures::Stream;
use serde::Deserialize;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;

const HISTORY_LIMIT: usize = 100;
const CHANNEL_CAPACITY: usize = 256;
const FINDING_LIMIT: usize = 500;
/// Artifact upload ceiling. 10 MB covers any reasonable PoC dump,
/// stack trace, or pcap snippet. Larger payloads belong in object
/// storage with a presigned URL shared via `share_endpoint`.
const ARTIFACT_MAX_BYTES: usize = 10 * 1024 * 1024;
/// Cap on artifacts retained in memory globally. The server is
/// ephemeral — restart drops everything — so this is just a guard
/// against an unbounded leak on a long-lived box.
const ARTIFACT_LIMIT: usize = 200;
/// A peer that hasn't checked in for this long is dropped from the
/// `/peers` response. Mirrors the heartbeat cadence of the MCP
/// client (20 s) with generous slack.
const PEER_TTL_SECS: u64 = 120;

// ── Per-input caps ────────────────────────────────────────────────
// All bounded explicitly so a single misbehaving caller (or auth'd
// bug) can't OOM the server. Numbers picked generously — covers
// every legitimate use we've seen — but bounded.
const MAX_CHANNEL_LEN: usize = 64;
const MAX_FROM_LEN: usize = 64;
const MAX_CONTENT_LEN: usize = 64 * 1024;
const MAX_TITLE_LEN: usize = 256;
const MAX_ENDPOINT_LEN: usize = 1024;
const MAX_DETAIL_LEN: usize = 64 * 1024;
const MAX_NOTE_LEN: usize = 4096;
const MAX_FILENAME_LEN: usize = 256;
const MAX_MIME_LEN: usize = 128;
const MAX_TOPIC_LEN: usize = 512;

/// Channels are created lazily on first POST. Without a cap on how
/// many can exist, a single client sending to /send/<uuid> in a loop
/// would blow the server's memory through `senders`/`history`/
/// `findings`/`artifacts` — all keyed by channel.
const MAX_CHANNELS: usize = 256;

/// Resolve the request's effective actor for audit-log + rate-
/// limit + ownership purposes. Order:
///   1. authenticated identity from the middleware (post-Step 2);
///   2. legacy `X-Bridge-From` header (permissive-mode bridges
///      that haven't onboarded tokens yet);
///   3. literal `"anonymous"`.
/// Per finding `cc3c33d6`: option 2 is spoofable on its own — it
/// stays only as a back-compat path while the registry is empty.
/// Once the registry has any entries, the middleware refuses
/// unauthenticated callers before this helper runs.
fn effective_actor(
    headers: &axum::http::HeaderMap,
    ext: Option<&claude_bridge::auth::AuthIdentity>,
) -> String {
    if let Some(id) = ext {
        if id.is_authenticated() {
            return id.as_actor().to_string();
        }
    }
    headers
        .get("x-bridge-from")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".into())
}

/// Append one audit-log row for a write op. Best-effort: a sqlite
/// failure here MUST NOT propagate as a 5xx — the audit log is
/// observability, not the source of truth. We log the failure via
/// `tracing` and let the original mutation stand. Callers pass
/// `before` = `None` for CREATEs and `after` = `None` for DELETEs;
/// the helper computes 128-bit truncated sha256 over the canonical
/// JSON form (see `claude_bridge::store::audit_hash_struct`) of
/// each.
///
/// Width: 32 hex chars (128-bit) per pentest review 1779038688.
fn write_audit<B, A>(
    store: &Store,
    actor: &str,
    op: &str,
    target_type: &str,
    target_id: &str,
    before: Option<&B>,
    after: Option<&A>,
) where
    B: serde::Serialize,
    A: serde::Serialize,
{
    use claude_bridge::store::audit_hash_struct;
    let entry = claude_bridge::AuditEntry {
        id: Uuid::new_v4().to_string(),
        at: now_secs(),
        actor: actor.to_string(),
        op: op.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        before_hash: before.map(audit_hash_struct).unwrap_or_default(),
        after_hash: after.map(audit_hash_struct).unwrap_or_default(),
        result: "ok".into(),
    };
    if let Err(e) = store.audit(&entry) {
        tracing::warn!(error = %e, op, target_type, target_id, "audit append failed");
    }
}

/// Sanitize a filename for the Content-Disposition header. Strips
/// CR/LF (header-injection guard) and double quotes (we wrap the
/// value in quotes), then truncates. Returns at least "artifact.bin"
/// when the input degenerates to empty.
fn safe_filename(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .take(MAX_FILENAME_LEN)
        .collect();
    if s.is_empty() { "artifact.bin".into() } else { s }
}

/// Validate a channel name shape — `[a-z0-9][a-z0-9-]{1,62}$`. Today
/// this is **warn-only**: invalid names log at WARN but the request
/// is still accepted. Lets us measure how many non-compliant channels
/// exist in the wild before flipping to enforcement (Group B4 phase
/// 2). Returns `false` for non-compliant.
///
/// Existing channels are grandfathered — the check only runs on the
/// first POST that lazily creates a channel; the cap is checked
/// before this, so the channel doesn't exist yet at the call site.
fn channel_name_valid(name: &str) -> bool {
    if name.len() < 2 || name.len() > 63 {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Validate a memory key shape — `<category>-<topic>[-<rest>]`
/// where category is one of the well-known prefixes from
/// `bridge-features-roadmap-v1` F2. Returns `false` if the key
/// doesn't match the family. Warn-only at the call site for now
/// per operator's "warn not reject" stance — flipping enforcement
/// on later is a one-line change at the handler.
const MEMORY_KEY_CATEGORIES: &[&str] = &[
    "ops-rule",
    "api-contract",
    "decision",
    "coverage",
    "snapshot",
    "session-resume",
    "plan",
    "finding-context",
    "integration-spec",
    "pattern",
];
fn memory_key_valid(key: &str) -> bool {
    if key.len() < 3 || key.len() > 256 {
        return false;
    }
    if !MEMORY_KEY_CATEGORIES
        .iter()
        .any(|c| key.starts_with(c) && key[c.len()..].starts_with('-'))
    {
        return false;
    }
    key.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == '_' || c == '/')
}

/// Cleanup helper used by every write path. Evicts the
/// oldest-by-arrival channel when at cap, so a single buggy client
/// can't grow `senders`/`history`/`findings`/`artifacts` unbounded
/// by spraying new channel names.
fn ensure_channel_capacity(state: &AppState, channel: &str) {
    if state.senders.contains_key(channel) {
        return;
    }
    if state.senders.len() < MAX_CHANNELS {
        return;
    }
    // Pick a victim — DashMap iteration order is unspecified, which
    // is fine here: the cap is a leak guard, not a fairness contract.
    if let Some(victim) = state.senders.iter().next().map(|kv| kv.key().clone()) {
        state.senders.remove(&victim);
        state.history.remove(&victim);
        state.findings.remove(&victim);
        // Drop persisted rows for the evicted channel too, otherwise
        // the DB would grow forever while the in-memory map stays
        // bounded.
        if let Some(store) = &state.store {
            let _ = store.drop_channel(&victim);
        }
        tracing::warn!(victim, "channel cap reached; evicted oldest");
    }
}

/// In-memory peer presence record. Fields mirror `Peer` minus the
/// derived `idle_secs` which `list_peers` computes at read time.
#[derive(Clone, Default)]
struct PeerState {
    last_seen: u64,
    channel: String,
    roles: Vec<String>,
    skills: Vec<String>,
    status: String,
}

#[derive(Clone)]
struct AppState {
    senders: Arc<DashMap<String, broadcast::Sender<Message>>>,
    history: Arc<DashMap<String, Vec<Message>>>,
    findings: Arc<DashMap<String, Vec<Finding>>>,
    artifacts: Arc<DashMap<String, (Artifact, Vec<u8>)>>,
    /// `name -> PeerState`. Updated by heartbeat POST /presence/{name};
    /// read by GET /peers. Intentionally NOT persisted — presence is
    /// a runtime concept; a peer presumed online after a server
    /// restart would be misleading.
    peers: Arc<DashMap<String, PeerState>>,
    /// Declared channel purposes, keyed by channel name. Returned by
    /// `GET /channels` so peers can discover routing before posting.
    topics: Arc<DashMap<String, ChannelTopic>>,
    /// Work queue, separate from findings. Channel-scoped.
    tasks: Arc<DashMap<String, Vec<Task>>>,
    /// Shared KV memory, keyed by (channel, key).
    memory: Arc<DashMap<(String, String), MemoryEntry>>,
    /// Optional sqlite store. `Some` when `BRIDGE_DB_PATH` is set
    /// in env; `None` keeps the legacy in-memory-only behaviour.
    /// Every write path forwards to the store when present.
    store: Option<Store>,
    /// Per-channel counter of SSE events dropped because a
    /// subscriber lagged past `CHANNEL_CAPACITY` in its broadcast
    /// ring buffer. Exposed via `GET /metrics` (Group C) so a slow
    /// peer is visible without grepping logs.
    sse_lag_drops: Arc<DashMap<String, u64>>,
    /// Token-bucket-lite for `/resume/{name}`. Key is `(requester,
    /// target)`; value is `(window_start_secs, call_count)`. Per
    /// pentest 1779040472: cheap query, expensive aggregation =
    /// asymmetric scraping risk; cap a single requester to 60/min
    /// per target. Implemented as a simple sliding-minute count to
    /// avoid pulling in `tower-governor` for one endpoint.
    resume_buckets: Arc<DashMap<(String, String), (u64, u32)>>,
}

impl AppState {
    fn new(store: Option<Store>) -> Self {
        Self {
            senders: Arc::new(DashMap::new()),
            history: Arc::new(DashMap::new()),
            findings: Arc::new(DashMap::new()),
            artifacts: Arc::new(DashMap::new()),
            peers: Arc::new(DashMap::new()),
            topics: Arc::new(DashMap::new()),
            tasks: Arc::new(DashMap::new()),
            memory: Arc::new(DashMap::new()),
            store,
            sse_lag_drops: Arc::new(DashMap::new()),
            resume_buckets: Arc::new(DashMap::new()),
        }
    }

    fn sender(&self, channel: &str) -> broadcast::Sender<Message> {
        self.senders
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }

    /// Rehydrate the DashMaps from disk on boot. Best-effort: a
    /// corrupt/missing db just logs and returns; the server keeps
    /// running with empty state.
    fn rehydrate(&self) {
        let Some(store) = &self.store else { return };
        match store.load_messages(HISTORY_LIMIT) {
            Ok(msgs) => {
                let mut count = 0;
                for m in msgs {
                    self.history
                        .entry(m.channel.clone())
                        .or_default()
                        .push(m.clone());
                    // Pre-warm the broadcast sender so the first
                    // subscriber after restart has a path.
                    let _ = self.sender(&m.channel);
                    count += 1;
                }
                tracing::info!(count, "rehydrated messages from sqlite");
            }
            Err(e) => tracing::warn!(error = %e, "rehydrate messages failed"),
        }
        match store.load_findings(FINDING_LIMIT) {
            Ok(fs) => {
                let mut count = 0;
                for f in fs {
                    self.findings.entry(f.channel.clone()).or_default().push(f);
                    count += 1;
                }
                tracing::info!(count, "rehydrated findings from sqlite");
            }
            Err(e) => tracing::warn!(error = %e, "rehydrate findings failed"),
        }
        match store.load_artifacts(ARTIFACT_LIMIT) {
            Ok(arts) => {
                let mut count = 0;
                for (art, bytes) in arts {
                    self.artifacts.insert(art.id.clone(), (art, bytes));
                    count += 1;
                }
                tracing::info!(count, "rehydrated artifacts from sqlite");
            }
            Err(e) => tracing::warn!(error = %e, "rehydrate artifacts failed"),
        }
        match store.load_topics() {
            Ok(ts) => {
                let count = ts.len();
                for t in ts {
                    self.topics.insert(t.name.clone(), t);
                }
                tracing::info!(count, "rehydrated channel topics from sqlite");
            }
            Err(e) => tracing::warn!(error = %e, "rehydrate topics failed"),
        }
        match store.load_tasks() {
            Ok(ts) => {
                let count = ts.len();
                for t in ts {
                    self.tasks.entry(t.channel.clone()).or_default().push(t);
                }
                tracing::info!(count, "rehydrated tasks from sqlite");
            }
            Err(e) => tracing::warn!(error = %e, "rehydrate tasks failed"),
        }
        match store.load_memory() {
            Ok(ms) => {
                let count = ms.len();
                for m in ms {
                    self.memory.insert((m.channel.clone(), m.key.clone()), m);
                }
                tracing::info!(count, "rehydrated memory from sqlite");
            }
            Err(e) => tracing::warn!(error = %e, "rehydrate memory failed"),
        }
    }
}

// ── Messages ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SendReq {
    // `from` removed per ops 1779046844 (Item 6 / orphan-identity
    // root-cause). Sender identity is derived authoritatively from
    // the auth bundle's AuthIdentity extension (or X-Bridge-From in
    // permissive mode). Any `from` field that legacy peers still
    // send on the wire is silently ignored — serde drops unknown
    // fields by default since we don't set deny_unknown_fields.
    content: String,
    /// Optional recipients (identity names or roles). Empty = broadcast.
    /// Clients filter on receive; the server just stores + relays.
    #[serde(default)]
    to: Vec<String>,
    /// Optional thread the message belongs to (free-form id). Lets
    /// the client group a finding + its discussion + fix updates.
    #[serde(default)]
    thread_id: String,
}

async fn send(
    Path(channel): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<SendReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    cap!(channel, MAX_CHANNEL_LEN, "channel");
    let from = effective_actor(&headers, ext.as_deref());
    cap!(from, MAX_FROM_LEN, "actor");
    cap!(req.content, MAX_CONTENT_LEN, "content");
    // Warn-only naming check: only on first-write that lazily
    // creates the channel. Existing channels are grandfathered.
    if !state.senders.contains_key(&channel) && !channel_name_valid(&channel) {
        tracing::warn!(channel = %channel, "non-compliant channel name (warn-only)");
    }
    ensure_channel_capacity(&state, &channel);

    let msg = Message {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: from.clone(),
        content: req.content,
        timestamp: now_secs(),
        to: req.to,
        thread_id: req.thread_id,
        pinned: false,
    };

    let id = msg.id.clone();

    {
        let mut h = state.history.entry(channel.clone()).or_default();
        h.push(msg.clone());
        if h.len() > HISTORY_LIMIT {
            let drain = h.len() - HISTORY_LIMIT;
            h.drain(0..drain);
        }
    }

    // Persistence — write-through after the in-memory update so the
    // hot read path never blocks on disk. Failures are logged but
    // don't 500 the client: better to lose a row to crash than to
    // reject a working send because the disk got tight.
    if let Some(store) = &state.store {
        if let Err(e) = store.insert_message(&msg) {
            tracing::warn!(error = %e, "persist message failed");
        }
        // Mirror the in-memory drain.
        let _ = store.prune_messages(&channel, HISTORY_LIMIT);
        // Track addressed messages as first-class dispatches. The
        // numeric IDs peers were eyeballing (`1779030818` etc.) are
        // just message timestamps used ad-hoc — now we have a real
        // table the escalation scanner can scan and `/ack`/`/complete`
        // endpoints can mutate.
        if !msg.to.is_empty() {
            let dispatch = claude_bridge::Dispatch {
                id: Uuid::new_v4().to_string(),
                message_id: msg.id.clone(),
                from: msg.from.clone(),
                to: msg.to.join(","),
                channel: msg.channel.clone(),
                sent_at: msg.timestamp,
                ack_at: 0,
                ack_eta_secs: 0,
                completed_at: 0,
                outcome: String::new(),
            };
            if let Err(e) = store.insert_dispatch(&dispatch) {
                tracing::warn!(error = %e, "persist dispatch failed");
            }
        }
        // Audit hook — INSERT, no prior row, after = serialized
        // message. Actor is req.from which we already validated.
        write_audit(
            store,
            &msg.from,
            "create",
            "message",
            &msg.id,
            None::<&Message>,
            Some(&msg),
        );
    }

    // Implicit presence — sending is a sign of life. Saves a separate
    // heartbeat round-trip for CLI-only callers (they don't run the
    // background heartbeat that the MCP client does).
    // Implicit presence on send. We don't know the sender's roles
    // here — preserve whatever was last advertised via heartbeat.
    // Implicit presence — preserve any roles/skills/status the peer
    // already advertised via heartbeat; just refresh last_seen and
    // channel.
    let mut prev = state
        .peers
        .get(&from)
        .map(|kv| kv.value().clone())
        .unwrap_or_default();
    prev.last_seen = now_secs();
    prev.channel = channel.clone();
    state.peers.insert(from.clone(), prev);

    let _ = state.sender(&channel).send(msg);

    Ok(Json(serde_json::json!({ "id": id, "ok": true })))
}

#[derive(Deserialize, Default)]
struct GetMessagesQuery {
    /// Unix-seconds — only return messages strictly newer than this.
    /// Combine with the per-client last-seen marker for incremental
    /// fetches.
    since: Option<u64>,
    /// Only return messages from this sender. Compose with `since`
    /// for the common "what did X say recently?" query.
    from: Option<String>,
    /// Maximum count returned. Defaults to HISTORY_LIMIT (100).
    limit: Option<usize>,
}

async fn get_messages(
    Path(channel): Path<String>,
    Query(q): Query<GetMessagesQuery>,
    State(state): State<AppState>,
) -> Json<Vec<Message>> {
    let all = state
        .history
        .get(&channel)
        .map(|h| h.value().clone())
        .unwrap_or_default();
    let filtered: Vec<Message> = all
        .into_iter()
        .filter(|m| q.since.map_or(true, |s| m.timestamp > s))
        .filter(|m| q.from.as_deref().map_or(true, |f| m.from == f))
        .collect();
    let limit = q.limit.unwrap_or(HISTORY_LIMIT);
    let len = filtered.len();
    let trimmed = if len > limit {
        filtered.into_iter().skip(len - limit).collect()
    } else {
        filtered
    };
    Json(trimmed)
}

async fn clear_messages(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> StatusCode {
    state.history.remove(&channel);
    if let Some(store) = &state.store {
        let _ = store.clear_messages(&channel);
    }
    StatusCode::OK
}

async fn stream_channel(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.sender(&channel).subscribe();
    let chan_for_log = channel.clone();
    let lag_counter = state.sse_lag_drops.clone();

    // `BroadcastStream` yields `Err(BroadcastStreamRecvError::Lagged(n))`
    // when a slow subscriber falls behind the channel's ring buffer
    // (CHANNEL_CAPACITY=256). Previously we silently `result.ok()`-
    // skipped those, so a stuck SSE consumer just lost events with
    // no signal anywhere. Now we count drops per channel and emit a
    // warn log including the lag count so ops can spot a misbehaving
    // peer without parsing the broadcast internals.
    let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
        Ok(msg) => {
            let data = serde_json::to_string(&msg).unwrap_or_default();
            Some(Ok::<_, Infallible>(Event::default().data(data)))
        }
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            let mut prev = lag_counter
                .entry(chan_for_log.clone())
                .or_insert(0u64);
            // DashMap entry guard derefs to RefMut; we mutate then
            // drop. n is u64, so saturate just in case.
            let new = prev.value().saturating_add(n);
            *prev = new;
            drop(prev);
            tracing::warn!(
                channel = %chan_for_log,
                lag = n,
                total_drops = new,
                "sse subscriber lagged; dropped events"
            );
            None
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

/// Return every known channel with its declared topic (empty when
/// no purpose has been set). Includes channels that exist only as a
/// declared topic with no traffic yet — that lets a peer discover
/// "where should I post X" before any messages have appeared.
async fn list_channels(State(state): State<AppState>) -> Json<Vec<ChannelTopic>> {
    let mut seen: std::collections::BTreeMap<String, ChannelTopic> =
        std::collections::BTreeMap::new();
    for e in state.senders.iter() {
        let name = e.key().clone();
        seen.insert(
            name.clone(),
            ChannelTopic {
                name,
                topic: String::new(),
                updated_by: String::new(),
                updated_at: 0,
            },
        );
    }
    for kv in state.topics.iter() {
        seen.insert(kv.key().clone(), kv.value().clone());
    }
    Json(seen.into_values().collect())
}

#[derive(Deserialize)]
struct SetTopicReq {
    // `from` removed per ops 1779046844 (Item 6) — see SendReq.
    topic: String,
}

/// Hard-delete a channel — wipes messages, findings, topic, the
/// in-memory broadcast sender, and (if persistence is on) the
/// corresponding sqlite rows. Used to clean up ghost channels
/// created by typos or misconfigured clients (`--channel
/// "a,b,c"` etc.). `clear_channel` only wipes history; this
/// removes the entry from `list_channels` entirely.
async fn delete_channel(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> StatusCode {
    state.senders.remove(&channel);
    state.history.remove(&channel);
    state.findings.remove(&channel);
    state.topics.remove(&channel);
    if let Some(store) = &state.store {
        let _ = store.drop_channel(&channel);
    }
    StatusCode::NO_CONTENT
}

async fn set_topic(
    Path(channel): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<SetTopicReq>,
) -> Result<Json<ChannelTopic>, (StatusCode, String)> {
    cap!(channel, MAX_CHANNEL_LEN, "channel");
    cap!(req.topic, MAX_TOPIC_LEN, "topic");
    let actor = effective_actor(&headers, ext.as_deref());
    cap!(actor, MAX_FROM_LEN, "actor");
    let t = ChannelTopic {
        name: channel.clone(),
        topic: req.topic,
        updated_by: actor,
        updated_at: now_secs(),
    };
    state.topics.insert(channel.clone(), t.clone());
    if let Some(store) = &state.store {
        if let Err(e) = store.upsert_topic(&t) {
            tracing::warn!(error = %e, "persist topic failed");
        }
    }
    Ok(Json(t))
}

async fn get_topic(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> Json<ChannelTopic> {
    let t = state
        .topics
        .get(&channel)
        .map(|kv| kv.value().clone())
        .unwrap_or_else(|| ChannelTopic {
            name: channel,
            topic: String::new(),
            updated_by: String::new(),
            updated_at: 0,
        });
    Json(t)
}

// ── Findings ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateFindingReq {
    // `from` removed per ops 1779046844 (Item 6) — see SendReq.
    severity: String,
    title: String,
    detail: String,
    #[serde(default)]
    endpoint: String,
}

async fn create_finding(
    Path(channel): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<CreateFindingReq>,
) -> Result<Json<Finding>, (StatusCode, String)> {
    cap!(channel, MAX_CHANNEL_LEN, "channel");
    cap!(req.endpoint, MAX_ENDPOINT_LEN, "endpoint");
    cap!(req.detail, MAX_DETAIL_LEN, "detail");
    if !SEVERITIES.contains(&req.severity.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("severity must be one of {SEVERITIES:?}"),
        ));
    }
    if req.title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title required".into()));
    }
    cap!(req.title, MAX_TITLE_LEN, "title");
    let actor = effective_actor(&headers, ext.as_deref());
    cap!(actor, MAX_FROM_LEN, "actor");
    ensure_channel_capacity(&state, &channel);
    let now = now_secs();
    let finding = Finding {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: actor.clone(),
        severity: req.severity,
        title: req.title,
        detail: req.detail,
        endpoint: req.endpoint,
        status: "open".into(),
        created_at: now,
        updated_at: now,
        note: String::new(),
        blocks: Vec::new(),
        depends_on: Vec::new(),
    };
    {
        let mut f = state.findings.entry(channel.clone()).or_default();
        f.push(finding.clone());
        if f.len() > FINDING_LIMIT {
            let drain = f.len() - FINDING_LIMIT;
            f.drain(0..drain);
        }
    }
    if let Some(store) = &state.store {
        if let Err(e) = store.upsert_finding(&finding) {
            tracing::warn!(error = %e, "persist finding failed");
        }
        let _ = store.prune_findings(&channel, FINDING_LIMIT);
        write_audit(
            store,
            &finding.from,
            "create",
            "finding",
            &finding.id,
            None::<&Finding>,
            Some(&finding),
        );
    }
    let mut prev = state
        .peers
        .get(&actor)
        .map(|kv| kv.value().clone())
        .unwrap_or_default();
    prev.last_seen = now_secs();
    prev.channel = channel.clone();
    state.peers.insert(actor, prev);
    Ok(Json(finding))
}

#[derive(Deserialize, Default)]
struct ListFindingsQuery {
    severity: Option<String>,
    status: Option<String>,
    from: Option<String>,
}

async fn list_findings(
    Path(channel): Path<String>,
    Query(q): Query<ListFindingsQuery>,
    State(state): State<AppState>,
) -> Json<Vec<Finding>> {
    let all = state
        .findings
        .get(&channel)
        .map(|f| f.value().clone())
        .unwrap_or_default();
    let filtered: Vec<Finding> = all
        .into_iter()
        .filter(|f| q.severity.as_deref().map_or(true, |s| f.severity == s))
        .filter(|f| q.status.as_deref().map_or(true, |s| f.status == s))
        .filter(|f| q.from.as_deref().map_or(true, |s| f.from == s))
        .collect();
    Json(filtered)
}

#[derive(Deserialize)]
struct TriageReq {
    status: String,
    #[serde(default)]
    note: String,
}

async fn triage_finding(
    Path((channel, id)): Path<(String, String)>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<TriageReq>,
) -> Result<Json<Finding>, (StatusCode, String)> {
    cap!(req.note, MAX_NOTE_LEN, "note");
    if !STATUSES.contains(&req.status.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("status must be one of {STATUSES:?}"),
        ));
    }
    // Distinguish "no such channel" (operator typo) from "channel
    // exists but id unknown" (stale finding id from a cleared list).
    let mut entry = match state.findings.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no findings on channel '{channel}'"))),
    };
    let found = entry.iter_mut().find(|f| f.id == id);
    let Some(f) = found else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("finding id '{id}' not found on channel '{channel}'"),
        ));
    };
    // Snapshot prior state for audit's before_hash — clone happens
    // before the in-place mutation so the hash reflects what the row
    // looked like to readers prior to this triage.
    let before = f.clone();
    f.status = req.status;
    f.note = req.note;
    f.updated_at = now_secs();
    let snapshot = f.clone();
    // Drop the DashMap guard before touching disk so we don't hold
    // the lock across a (sub-ms but still) blocking sqlite write.
    drop(entry);
    if let Some(store) = &state.store {
        if let Err(e) = store.upsert_finding(&snapshot) {
            tracing::warn!(error = %e, "persist triage failed");
        }
        // Actor resolves via authed identity (post-finding
        // `cc3c33d6` bundle) or falls back to header in permissive
        // mode.
        let actor = effective_actor(&headers, ext.as_deref());
        write_audit(
            store,
            &actor,
            "triage",
            "finding",
            &snapshot.id,
            Some(&before),
            Some(&snapshot),
        );
    }
    Ok(Json(snapshot))
}

/// Hard-delete a finding. Use this for false-positives or noisy
/// reports that pollute the queue — `triage_finding` only updates
/// status, so a `wontfix` still shows up in unfiltered lists.
async fn delete_finding(
    Path((channel, id)): Path<(String, String)>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut entry = match state.findings.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no findings on channel '{channel}'"))),
    };
    // Capture the row we're about to drop so audit `before_hash`
    // is non-empty. Searching twice (find→retain) avoids cloning a
    // whole Vec; the table is finding-count-per-channel sized so
    // O(n) on the typical 0..N is fine.
    let prior = entry.iter().find(|f| f.id == id).cloned();
    let before_len = entry.len();
    entry.retain(|f| f.id != id);
    if entry.len() == before_len {
        return Err((
            StatusCode::NOT_FOUND,
            format!("finding id '{id}' not found on channel '{channel}'"),
        ));
    }
    drop(entry);
    if let Some(store) = &state.store {
        let _ = store.delete_finding(&channel, &id);
        let actor = effective_actor(&headers, ext.as_deref());
        write_audit(
            store,
            &actor,
            "delete",
            "finding",
            &id,
            prior.as_ref(),
            None::<&Finding>,
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Artifacts ───────────────────────────────────────────────────────

async fn upload_artifact(
    Path(channel): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    cap!(channel, MAX_CHANNEL_LEN, "channel");
    if body.len() > ARTIFACT_MAX_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("max {} bytes", ARTIFACT_MAX_BYTES),
        ));
    }
    let from = headers
        .get("x-bridge-from")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    cap!(from, MAX_FROM_LEN, "x-bridge-from");
    let from = from.to_string();

    let raw_filename = headers
        .get("x-bridge-filename")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("artifact.bin");
    cap!(raw_filename, MAX_FILENAME_LEN, "x-bridge-filename");
    // Strip control chars / quotes BEFORE we touch the header — keeps
    // a malicious filename from injecting CR/LF into our response's
    // Content-Disposition.
    let filename = safe_filename(raw_filename);

    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    cap!(mime, MAX_MIME_LEN, "content-type");
    let mime = mime.to_string();

    ensure_channel_capacity(&state, &channel);

    // Soft eviction: when at capacity, drop the oldest entry by
    // created_at. Avoids growing indefinitely on a long-lived box.
    if state.artifacts.len() >= ARTIFACT_LIMIT {
        if let Some(oldest) = state
            .artifacts
            .iter()
            .min_by_key(|kv| kv.value().0.created_at)
            .map(|kv| kv.key().clone())
        {
            state.artifacts.remove(&oldest);
            // Mirror the eviction in sqlite so a long-running server
            // doesn't accumulate evicted artifacts on disk.
            if let Some(store) = &state.store {
                let _ = store.delete_artifact(&oldest);
            }
        }
    }

    let art = Artifact {
        id: Uuid::new_v4().to_string(),
        channel,
        from,
        filename: filename.clone(),
        size: body.len(),
        mime: mime.clone(),
        created_at: now_secs(),
    };
    let id = art.id.clone();
    let bytes = body.to_vec();
    if let Some(store) = &state.store {
        if let Err(e) = store.insert_artifact(&art, &bytes) {
            tracing::warn!(error = %e, "persist artifact failed");
        }
    }
    state.artifacts.insert(id.clone(), (art, bytes));
    Ok(Json(serde_json::json!({
        "id": id,
        "filename": filename,
        "size": body.len(),
        "url": format!("/artifact/{}", id),
    })))
}

async fn download_artifact(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, (StatusCode, String)> {
    let entry = state
        .artifacts
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, "artifact not found".into()))?;
    let (art, bytes) = entry.value().clone();
    let mut resp = bytes.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(&art.mime)
            .unwrap_or(header::HeaderValue::from_static("application/octet-stream")),
    );
    // Filename was already sanitized at upload time, but re-sanitize
    // here too — defense in depth in case the in-memory record was
    // ever crafted from a different code path.
    let safe = safe_filename(&art.filename);
    if let Ok(v) = header::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", safe)) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

async fn list_artifacts(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> Json<Vec<Artifact>> {
    let mut v: Vec<Artifact> = state
        .artifacts
        .iter()
        .filter(|kv| kv.value().0.channel == channel)
        .map(|kv| kv.value().0.clone())
        .collect();
    v.sort_by_key(|a| a.created_at);
    Json(v)
}

// ── Presence ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PresenceReq {
    #[serde(default)]
    channel: String,
    /// Roles this peer is claiming, e.g. ["pentest"] or
    /// ["integration","ops"]. Resolved server-side as a simple
    /// last-write-wins per peer name.
    #[serde(default)]
    roles: Vec<String>,
    /// Finer-grained skill list, e.g. ["svelte","csp","oauth"].
    /// Used by `find_peer_by_skill` to route task assignments
    /// without humans having to memorise who does what.
    #[serde(default)]
    skills: Vec<String>,
    /// Short status line ("working on b358d8ea, ETA 30min").
    /// Surfaced in `list_peers` so other peers can see at a glance
    /// what each instance is busy with.
    #[serde(default)]
    status: String,
}

const MAX_STATUS_LEN: usize = 280;

async fn heartbeat(
    Path(name): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PresenceReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    cap!(name, MAX_FROM_LEN, "name");
    cap!(req.channel, MAX_CHANNEL_LEN, "channel");
    cap!(req.status, MAX_STATUS_LEN, "status");
    // Cheap defense: bound the role + skill lists so a buggy/hostile
    // heartbeat can't blow memory through repeated huge declarations.
    let roles: Vec<String> = req
        .roles
        .into_iter()
        .filter(|r| !r.is_empty() && r.len() <= 64)
        .take(16)
        .collect();
    let skills: Vec<String> = req
        .skills
        .into_iter()
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .take(32)
        .collect();
    state.peers.insert(
        name,
        PeerState {
            last_seen: now_secs(),
            channel: req.channel,
            roles,
            skills,
            status: req.status,
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_peers(State(state): State<AppState>) -> Json<Vec<Peer>> {
    let now = now_secs();
    // Collect expired keys first, then drop them. Walking the map
    // while removing causes deadlocks under DashMap; this two-pass
    // approach keeps memory bounded across long-lived runs where
    // peer names rotate (ephemeral hostnames, probes, etc.).
    let expired: Vec<String> = state
        .peers
        .iter()
        .filter(|kv| now.saturating_sub(kv.value().last_seen) > PEER_TTL_SECS)
        .map(|kv| kv.key().clone())
        .collect();
    for k in expired {
        state.peers.remove(&k);
    }
    let mut peers: Vec<Peer> = state
        .peers
        .iter()
        .map(|kv| {
            let ps = kv.value().clone();
            Peer {
                name: kv.key().clone(),
                last_seen: ps.last_seen,
                idle_secs: now.saturating_sub(ps.last_seen),
                channel: ps.channel,
                roles: ps.roles,
                skills: ps.skills,
                status: ps.status,
            }
        })
        .collect();
    peers.sort_by_key(|p| p.idle_secs);
    Json(peers)
}

// ── Pin / unpin a message ────────────────────────────────────────────

async fn pin_message(
    Path((channel, id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    set_pinned_state(&state, &channel, &id, true).await
}

async fn unpin_message(
    Path((channel, id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    set_pinned_state(&state, &channel, &id, false).await
}

async fn set_pinned_state(
    state: &AppState,
    channel: &str,
    id: &str,
    pinned: bool,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut entry = match state.history.get_mut(channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no messages on channel '{channel}'"))),
    };
    let found = entry.iter_mut().find(|m| m.id == id);
    let Some(m) = found else {
        return Err((StatusCode::NOT_FOUND, format!("message id '{id}' not found on channel '{channel}'")));
    };
    m.pinned = pinned;
    drop(entry);
    if let Some(store) = &state.store {
        let _ = store.set_message_pinned(id, pinned);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Tasks ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateTaskReq {
    // `from` removed per ops 1779046844 (Item 6) — see SendReq.
    title: String,
    #[serde(default)]
    description: String,
    /// Identity name or role. Empty = unassigned.
    #[serde(default)]
    owner: String,
    #[serde(default)]
    blocks: Vec<String>,
    #[serde(default)]
    depends_on: Vec<String>,
}

const MAX_TASK_DESC_LEN: usize = 16 * 1024;
const TASK_LIMIT_PER_CHANNEL: usize = 500;

async fn create_task(
    Path(channel): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<CreateTaskReq>,
) -> Result<Json<Task>, (StatusCode, String)> {
    cap!(channel, MAX_CHANNEL_LEN, "channel");
    cap!(req.title, MAX_TITLE_LEN, "title");
    cap!(req.description, MAX_TASK_DESC_LEN, "description");
    if req.title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title required".into()));
    }
    let actor = effective_actor(&headers, ext.as_deref());
    cap!(actor, MAX_FROM_LEN, "actor");
    ensure_channel_capacity(&state, &channel);
    let now = now_secs();
    let task = Task {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: actor,
        title: req.title,
        description: req.description,
        owner: req.owner,
        status: "todo".into(),
        created_at: now,
        updated_at: now,
        note: String::new(),
        blocks: req.blocks,
        depends_on: req.depends_on,
    };
    {
        let mut t = state.tasks.entry(channel.clone()).or_default();
        t.push(task.clone());
        if t.len() > TASK_LIMIT_PER_CHANNEL {
            let drain = t.len() - TASK_LIMIT_PER_CHANNEL;
            t.drain(0..drain);
        }
    }
    if let Some(store) = &state.store {
        if let Err(e) = store.upsert_task(&task) {
            tracing::warn!(error = %e, "persist task failed");
        }
        write_audit(
            store,
            &task.from,
            "create",
            "task",
            &task.id,
            None::<&Task>,
            Some(&task),
        );
    }
    Ok(Json(task))
}

#[derive(Deserialize, Default)]
struct ListTasksQuery {
    status: Option<String>,
    owner: Option<String>,
}

async fn list_tasks(
    Path(channel): Path<String>,
    Query(q): Query<ListTasksQuery>,
    State(state): State<AppState>,
) -> Json<Vec<Task>> {
    let all = state
        .tasks
        .get(&channel)
        .map(|t| t.value().clone())
        .unwrap_or_default();
    let filtered: Vec<Task> = all
        .into_iter()
        .filter(|t| q.status.as_deref().map_or(true, |s| t.status == s))
        .filter(|t| q.owner.as_deref().map_or(true, |o| t.owner == o))
        .collect();
    Json(filtered)
}

#[derive(Deserialize)]
struct UpdateTaskReq {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

async fn update_task(
    Path((channel, id)): Path<(String, String)>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<UpdateTaskReq>,
) -> Result<Json<Task>, (StatusCode, String)> {
    if let Some(s) = &req.status {
        if !TASK_STATUSES.contains(&s.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("status must be one of {TASK_STATUSES:?}")));
        }
    }
    if let Some(n) = &req.note {
        cap!(n, MAX_NOTE_LEN, "note");
    }
    let mut entry = match state.tasks.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no tasks on channel '{channel}'"))),
    };
    let found = entry.iter_mut().find(|t| t.id == id);
    let Some(t) = found else {
        return Err((StatusCode::NOT_FOUND, format!("task id '{id}' not found on channel '{channel}'")));
    };
    let before = t.clone();
    if let Some(s) = req.status {
        t.status = s;
    }
    if let Some(o) = req.owner {
        t.owner = o;
    }
    if let Some(n) = req.note {
        t.note = n;
    }
    t.updated_at = now_secs();
    let snap = t.clone();
    drop(entry);
    if let Some(store) = &state.store {
        let _ = store.upsert_task(&snap);
        let actor = effective_actor(&headers, ext.as_deref());
        write_audit(
            store,
            &actor,
            "update",
            "task",
            &snap.id,
            Some(&before),
            Some(&snap),
        );
    }
    Ok(Json(snap))
}

async fn delete_task(
    Path((channel, id)): Path<(String, String)>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut entry = match state.tasks.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no tasks on channel '{channel}'"))),
    };
    let prior = entry.iter().find(|t| t.id == id).cloned();
    let before_len = entry.len();
    entry.retain(|t| t.id != id);
    if entry.len() == before_len {
        return Err((StatusCode::NOT_FOUND, format!("task id '{id}' not found on channel '{channel}'")));
    }
    drop(entry);
    if let Some(store) = &state.store {
        let _ = store.delete_task(&channel, &id);
        let actor = effective_actor(&headers, ext.as_deref());
        write_audit(
            store,
            &actor,
            "delete",
            "task",
            &id,
            prior.as_ref(),
            None::<&Task>,
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Shared memory (KV) ───────────────────────────────────────────────

#[derive(Deserialize)]
struct MemorySetReq {
    // `from` removed per ops 1779046844 (Item 6) — see SendReq.
    value: String,
    /// Optional TTL in seconds from now. 0 = no expiry.
    #[serde(default)]
    ttl_secs: u64,
}

const MAX_MEMORY_KEY_LEN: usize = 256;
const MAX_MEMORY_VAL_LEN: usize = 256 * 1024;

async fn memory_set(
    Path((channel, key)): Path<(String, String)>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    auth_ext: Option<axum::extract::Extension<claude_bridge::auth::AuthState>>,
    State(state): State<AppState>,
    Json(req): Json<MemorySetReq>,
) -> Result<Json<MemoryEntry>, (StatusCode, String)> {
    cap!(channel, MAX_CHANNEL_LEN, "channel");
    cap!(key, MAX_MEMORY_KEY_LEN, "key");
    cap!(req.value, MAX_MEMORY_VAL_LEN, "value");
    // Memory ownership (finding `0919a7db`): if a row already
    // exists, the writer's authenticated identity must match the
    // original `updated_by`. Admin allowlist (BRIDGE_MEMORY_ADMINS)
    // can bypass for ops cleanup. In permissive mode (no token
    // registry → AuthIdentity::Anonymous), the X-Bridge-From
    // header still has to match — back-compat path, not stronger
    // than the original threat model but no worse either.
    let actor = effective_actor(&headers, ext.as_deref());
    if let Some(prior) = state.memory.get(&(channel.clone(), key.clone())) {
        let owner = prior.value().updated_by.clone();
        drop(prior);
        let is_admin = auth_ext
            .as_deref()
            .map(|a| a.is_memory_admin(&actor))
            .unwrap_or(false);
        if !owner.is_empty() && owner != actor && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "memory key '{channel}/{key}' is owned by '{owner}'; \
                     '{actor}' cannot overwrite. Ask owner to rotate or \
                     request BRIDGE_MEMORY_ADMINS bypass."
                ),
            ));
        }
    }
    // Warn-only naming check per roadmap-v1 F2. Categorised keys
    // like `decision-…`, `ops-rule-…`, `coverage-…` pass; ad-hoc
    // names log a warn so operator can grep them and decide whether
    // to migrate before enforcement.
    if !memory_key_valid(&key) {
        tracing::warn!(key = %key, "non-compliant memory key (warn-only)");
    }
    let now = now_secs();
    // Per Item 6 (ops 1779046844): updated_by is ALWAYS the
    // effective_actor — never a body field. The body's `from`
    // was removed; in permissive mode the actor still comes
    // from X-Bridge-From header (registry-validated when present).
    cap!(actor, MAX_FROM_LEN, "actor");
    let updated_by = actor.clone();
    let entry = MemoryEntry {
        channel: channel.clone(),
        key: key.clone(),
        value: req.value,
        updated_by,
        updated_at: now,
        expires_at: if req.ttl_secs == 0 { 0 } else { now + req.ttl_secs },
    };
    // Capture pre-state for the audit's `before_hash`. The query
    // runs while we still hold the write intent so a racing reader
    // can't observe a midpoint, even though DashMap entries aren't
    // ACID. The hash is stable across concurrent same-value writes,
    // so a benign race is at worst a degenerate hash match.
    let before = state
        .memory
        .get(&(channel.clone(), key.clone()))
        .map(|kv| kv.value().clone());
    state.memory.insert((channel.clone(), key.clone()), entry.clone());
    if let Some(store) = &state.store {
        let _ = store.memory_set(&entry);
        write_audit(
            store,
            &entry.updated_by,
            if before.is_some() { "update" } else { "create" },
            "memory",
            &format!("{}/{}", channel, key),
            before.as_ref(),
            Some(&entry),
        );
    }
    Ok(Json(entry))
}

async fn memory_get(
    Path((channel, key)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<MemoryEntry>, StatusCode> {
    let entry = state
        .memory
        .get(&(channel, key))
        .map(|kv| kv.value().clone())
        .ok_or(StatusCode::NOT_FOUND)?;
    // Lazy expiry — entries past `expires_at` look gone to readers.
    if entry.expires_at != 0 && entry.expires_at < now_secs() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(entry))
}

async fn memory_delete(
    Path((channel, key)): Path<(String, String)>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    auth_ext: Option<axum::extract::Extension<claude_bridge::auth::AuthState>>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let actor = effective_actor(&headers, ext.as_deref());
    // Capture before-state for ownership check + audit before_hash.
    let before = state
        .memory
        .get(&(channel.clone(), key.clone()))
        .map(|kv| kv.value().clone());
    // Memory ownership (finding `0919a7db`): same rule as
    // memory_set — only the owner or a memory-admin can delete.
    if let Some(ref prior) = before {
        let is_admin = auth_ext
            .as_deref()
            .map(|a| a.is_memory_admin(&actor))
            .unwrap_or(false);
        if !prior.updated_by.is_empty() && prior.updated_by != actor && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "memory key '{channel}/{key}' is owned by '{}'; \
                     '{actor}' cannot delete.",
                    prior.updated_by
                ),
            ));
        }
    }
    state.memory.remove(&(channel.clone(), key.clone()));
    if let Some(store) = &state.store {
        let _ = store.memory_delete(&channel, &key);
        write_audit(
            store,
            &actor,
            "delete",
            "memory",
            &format!("{}/{}", channel, key),
            before.as_ref(),
            None::<&MemoryEntry>,
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn memory_list(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> Json<Vec<MemoryEntry>> {
    let now = now_secs();
    let mut v: Vec<MemoryEntry> = state
        .memory
        .iter()
        .filter(|kv| kv.key().0 == channel)
        .map(|kv| kv.value().clone())
        .filter(|e| e.expires_at == 0 || e.expires_at >= now)
        .collect();
    v.sort_by(|a, b| a.key.cmp(&b.key));
    Json(v)
}

// ── Peer health + resume + metrics ──────────────────────────────────

#[derive(serde::Serialize)]
struct PeerHealth {
    peer: String,
    /// `true` when we have a live presence record for this peer.
    /// JSON consumers should check this before doing arithmetic on
    /// `idle_secs` — replaces the prior `u64::MAX` sentinel that
    /// could overflow naive `idle_secs * something` math on the
    /// client side (pentest msg 1779040472).
    present: bool,
    /// Seconds since the peer's last heartbeat. `None` when the
    /// peer has no presence record (`present == false`).
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_secs: Option<u64>,
    channel: String,
    roles: Vec<String>,
    skills: Vec<String>,
    status: String,
    /// Open dispatches addressed to this peer that haven't been
    /// acked yet. Empty when persistence is disabled.
    pending_dispatches: Vec<PendingDispatch>,
    /// Findings created by or addressed to this peer that are still
    /// open. Channel-scoped sum across the in-memory map.
    open_findings: usize,
    /// Tasks the peer owns that are in `todo` or `in_progress`
    /// (anything not `done` / `cancelled`).
    active_tasks: usize,
}

#[derive(serde::Serialize)]
struct PendingDispatch {
    message_id: String,
    from: String,
    channel: String,
    sent_at: u64,
    age_secs: u64,
}

/// Composite health view for a peer. World-readable to any caller
/// reaching the bridge per ops dispatch 1779031396 — coord
/// transparency is the point. Returns the live presence record plus
/// derived counts (open findings, active tasks) and a pending-
/// dispatch list pulled from the dispatches table. Empty arrays
/// where persistence is off; never errors on a missing peer (returns
/// an `idle_secs = u64::MAX` sentinel so callers can distinguish
/// "unknown peer" from "peer present but quiet").
async fn peer_health(
    Path(name): Path<String>,
    State(state): State<AppState>,
) -> Json<PeerHealth> {
    let now = now_secs();
    let live = state.peers.get(&name).map(|kv| kv.value().clone());
    let (present, idle_secs, channel, roles, skills, status) = match live {
        Some(p) => (
            true,
            Some(now.saturating_sub(p.last_seen)),
            p.channel,
            p.roles,
            p.skills,
            p.status,
        ),
        None => (false, None, String::new(), Vec::new(), Vec::new(), String::new()),
    };

    // Pending dispatches addressed to this peer. The `to_` column
    // is comma-joined; we filter in SQL with LIKE so the partial
    // `dispatches_pending` index is still usable for the date
    // range scan and the LIKE narrows the result set without
    // requiring a separate index.
    let pending = if let Some(store) = &state.store {
        store
            .open_dispatches_for_peer(&name, 50)
            .unwrap_or_default()
            .into_iter()
            .map(|d| PendingDispatch {
                message_id: d.message_id,
                from: d.from,
                channel: d.channel,
                sent_at: d.sent_at,
                age_secs: now.saturating_sub(d.sent_at),
            })
            .collect()
    } else {
        Vec::new()
    };

    // Open findings + active tasks: scan in-memory state which is
    // already the source of truth for live views. Channel-agnostic;
    // intent is "everything this peer has on its plate".
    let mut open_findings = 0usize;
    for kv in state.findings.iter() {
        for f in kv.value() {
            if (f.from == name) && f.status == "open" {
                open_findings += 1;
            }
        }
    }
    let mut active_tasks = 0usize;
    for kv in state.tasks.iter() {
        for t in kv.value() {
            if t.owner == name && (t.status == "todo" || t.status == "in_progress") {
                active_tasks += 1;
            }
        }
    }

    Json(PeerHealth {
        peer: name,
        present,
        idle_secs,
        channel,
        roles,
        skills,
        status,
        pending_dispatches: pending,
        open_findings,
        active_tasks,
    })
}

#[derive(serde::Serialize)]
struct BridgeMetrics {
    peers_active: usize,
    channels: usize,
    messages_total: usize,
    findings_total: usize,
    findings_open: usize,
    tasks_total: usize,
    tasks_active: usize,
    artifacts: usize,
    sse_lag_drops: std::collections::BTreeMap<String, u64>,
    dispatches_pending: usize,
}

async fn metrics(State(state): State<AppState>) -> Json<BridgeMetrics> {
    let peers_active = state.peers.len();
    let channels = state.senders.len();
    let messages_total: usize = state.history.iter().map(|kv| kv.value().len()).sum();
    let mut findings_total = 0usize;
    let mut findings_open = 0usize;
    for kv in state.findings.iter() {
        let v = kv.value();
        findings_total += v.len();
        findings_open += v.iter().filter(|f| f.status == "open").count();
    }
    let mut tasks_total = 0usize;
    let mut tasks_active = 0usize;
    for kv in state.tasks.iter() {
        let v = kv.value();
        tasks_total += v.len();
        tasks_active += v
            .iter()
            .filter(|t| t.status == "todo" || t.status == "in_progress")
            .count();
    }
    let dispatches_pending = if let Some(store) = &state.store {
        store.count_open_dispatches().unwrap_or(0)
    } else {
        0
    };
    let sse_lag_drops: std::collections::BTreeMap<String, u64> = state
        .sse_lag_drops
        .iter()
        .map(|kv| (kv.key().clone(), *kv.value()))
        .collect();
    Json(BridgeMetrics {
        peers_active,
        channels,
        messages_total,
        findings_total,
        findings_open,
        tasks_total,
        tasks_active,
        artifacts: state.artifacts.len(),
        sse_lag_drops,
        dispatches_pending,
    })
}

/// Build a markdown resume for `name` — assembles their public
/// memory keys, active dispatches, and open findings into a brief
/// useful for next-session pickup.
///
/// Disclosure scope per ops 1779031396 + pentest 1779031342:
/// - `_private_` prefix on memory keys → excluded entirely
/// - Memory rows past `expires_at` (TTL elapsed) → excluded
/// - Secret-shaped value fragments (Bearer eyJ…, password=…,
///   api_key=…, sk_… variants) → redacted to `[REDACTED:<type>]`
/// - 256-char value truncate from earlier draft DROPPED per ops
///   1779031354 refinement — resume completeness matters more than
///   summary brevity; peers wanting short forms write `summary-*`
///   keys explicitly.
///
/// Rate-limit per requester is a TODO — needs tower-governor or a
/// simple DashMap bucket. Tracked in `decision-resume-endpoint`.
const RESUME_RATE_WINDOW_SECS: u64 = 60;
const RESUME_RATE_LIMIT: u32 = 60;

/// Bumps the per-(requester, target) bucket and returns whether the
/// caller is within budget. Sliding window via simple reset-on-
/// rollover; precise enough for the threat model (scraping
/// detection, not high-precision QoS).
fn resume_within_limit(state: &AppState, requester: &str, target: &str) -> bool {
    let now = now_secs();
    let key = (requester.to_string(), target.to_string());
    let mut entry = state
        .resume_buckets
        .entry(key)
        .or_insert((now, 0u32));
    let (window_start, count) = *entry.value();
    if now.saturating_sub(window_start) >= RESUME_RATE_WINDOW_SECS {
        *entry.value_mut() = (now, 1);
        return true;
    }
    if count >= RESUME_RATE_LIMIT {
        return false;
    }
    *entry.value_mut() = (window_start, count + 1);
    true
}

async fn resume_endpoint(
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Per finding `cc3c33d6`: rate-limit key MUST be the authed
    // identity (not the spoofable header), otherwise the limiter
    // is trivially bypassed by varying the X-Bridge-From header
    // string. `effective_actor` prefers the authed identity and
    // falls back to the header only in permissive mode.
    let requester = effective_actor(&headers, ext.as_deref());
    if !resume_within_limit(&state, &requester, &name) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!(
                "rate limited: {} resumes/min/target. Try again in <={}s.\n",
                RESUME_RATE_LIMIT, RESUME_RATE_WINDOW_SECS
            ),
        )
            .into_response();
    }
    let now = now_secs();
    let mut out = String::with_capacity(4096);
    out.push_str(&format!("# Resume — {name}\n\nGenerated: {now} (unix-secs)\n\n"));

    // Live presence
    if let Some(p) = state.peers.get(&name).map(|kv| kv.value().clone()) {
        out.push_str("## Live presence\n");
        out.push_str(&format!(
            "- last_seen: {}s ago\n- channel: {}\n- roles: {:?}\n- skills: {:?}\n- status: {}\n\n",
            now.saturating_sub(p.last_seen),
            p.channel,
            p.roles,
            p.skills,
            p.status
        ));
    } else {
        out.push_str("## Live presence\n\n_no recent heartbeat_\n\n");
    }

    // Open dispatches
    if let Some(store) = &state.store {
        let pend = store.open_dispatches_for_peer(&name, 50).unwrap_or_default();
        out.push_str(&format!("## Open dispatches ({})\n", pend.len()));
        for d in &pend {
            out.push_str(&format!(
                "- `{}` from `{}` in #{} — sent {}s ago\n",
                d.message_id,
                d.from,
                d.channel,
                now.saturating_sub(d.sent_at)
            ));
        }
        out.push('\n');
    }

    // Open findings authored by the peer
    let mut findings_block = String::new();
    let mut nf = 0usize;
    for kv in state.findings.iter() {
        for f in kv.value() {
            if f.from == name && f.status == "open" {
                findings_block.push_str(&format!(
                    "- [{}] `{}` — {} in #{}\n",
                    f.severity, f.id, f.title, f.channel
                ));
                nf += 1;
            }
        }
    }
    out.push_str(&format!("## Open findings authored ({nf})\n"));
    out.push_str(&findings_block);
    out.push('\n');

    // Memory keys — public, unexpired, redacted
    let mut mem_block = String::new();
    let mut nm = 0usize;
    for kv in state.memory.iter() {
        let entry = kv.value();
        if entry.updated_by != name {
            continue;
        }
        if entry.key.starts_with("_private_") {
            continue;
        }
        if entry.expires_at != 0 && entry.expires_at <= now {
            continue;
        }
        nm += 1;
        let snippet = redact_secrets(&entry.value);
        mem_block.push_str(&format!(
            "### `{}/{}` (updated {}s ago)\n```\n{}\n```\n\n",
            entry.channel,
            entry.key,
            now.saturating_sub(entry.updated_at),
            snippet
        ));
    }
    out.push_str(&format!("## Memory keys authored ({nm})\n"));
    out.push_str(&mem_block);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        out,
    )
        .into_response()
}

/// Redact known secret patterns from a string. Cheap pass via byte
/// matching on common prefixes — caller's `value` is opaque so we
/// can't parse structure; we just blank out the recognisable
/// shapes. Anything not matched passes through. Per ops 1779031396
/// + pentest 1779031342.
fn redact_secrets(s: &str) -> String {
    // Find each occurrence of a sensitive prefix and snip the token
    // that follows. Cheap state machine — adequate for the bridge's
    // single-machine resume endpoint; not a substitute for a real
    // DLP scanner.
    let patterns: &[(&str, &str)] = &[
        ("Bearer ey", "[REDACTED:jwt]"),
        ("password=", "[REDACTED:password]"),
        ("password\":", "[REDACTED:password]"),
        ("api_key=", "[REDACTED:api_key]"),
        ("api_key\":", "[REDACTED:api_key]"),
        ("sk_live_", "[REDACTED:stripe-secret]"),
        ("sk_test_", "[REDACTED:stripe-secret]"),
        ("AKIA", "[REDACTED:aws-access-key]"),
        // Per pentest 1779040472 + operator 1779040495:
        // Gezer SDK / load-balancer API keys (see
        // `gezer-lb-origin-contract` memory key).
        ("gz_", "[REDACTED:gezer-key]"),
        // Stripe webhook signing secret (operator-provisioned,
        // expected shape from Stripe).
        ("whsec_", "[REDACTED:stripe-webhook-secret]"),
        // Finding `fe91e015` (pentest 0f4543 1779042794, ops
        // 1779043036): widen coverage to SSH/PEM private keys,
        // Anthropic, GitHub PAT family, and Slack tokens. Each
        // pattern is a prefix that uniquely identifies the secret
        // family; the per-pattern delimiter walk below truncates
        // at whitespace/quotes/punctuation so we don't redact
        // beyond the token itself.
        ("ssh-rsa AAAA", "[REDACTED:ssh-rsa]"),
        ("ssh-ed25519 AAAA", "[REDACTED:ssh-ed25519]"),
        ("ssh-dss AAAA", "[REDACTED:ssh-dss]"),
        ("ecdsa-sha2-nistp", "[REDACTED:ssh-ecdsa]"),
        ("-----BEGIN ", "[REDACTED:pem-block]"),
        ("sk-ant-", "[REDACTED:anthropic-key]"),
        // GitHub Personal Access Token / OAuth / user-to-server /
        // server-to-server / refresh-token prefixes — all sized
        // ~40 chars after the prefix in current GitHub format.
        ("ghp_", "[REDACTED:github-pat]"),
        ("gho_", "[REDACTED:github-oauth]"),
        ("ghu_", "[REDACTED:github-user-token]"),
        ("ghs_", "[REDACTED:github-server-token]"),
        ("ghr_", "[REDACTED:github-refresh]"),
        // Slack token family (xoxb-, xoxp-, xoxa-, xoxs-, xoxr-).
        // Lower-case-only because Slack docs and runtime emit
        // them lower; the prefix is the discriminator.
        ("xoxb-", "[REDACTED:slack-bot]"),
        ("xoxp-", "[REDACTED:slack-user]"),
        ("xoxa-", "[REDACTED:slack-app]"),
        ("xoxs-", "[REDACTED:slack-config]"),
        ("xoxr-", "[REDACTED:slack-refresh]"),
    ];
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let bytes = s.as_bytes();
    'outer: while i < bytes.len() {
        for (pat, redact) in patterns {
            if s[i..].starts_with(pat) {
                out.push_str(redact);
                // Skip until whitespace, comma, quote or end —
                // these are the typical token delimiters.
                let start = i + pat.len();
                let mut j = start;
                while j < bytes.len() {
                    let c = bytes[j];
                    if c == b' ' || c == b',' || c == b'"' || c == b'\n' || c == b'\r' || c == b';'
                    {
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue 'outer;
            }
        }
        // No pattern matched at this position — push the char and
        // advance by its UTF-8 byte length so we don't slice mid-
        // code-point.
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Prometheus text-exposition format. One sample per gauge; for
/// labelled counters we emit a line per label. The newline before
/// EOF is required by the spec; `format!` macros take care of it.
async fn metrics_prometheus(State(state): State<AppState>) -> impl IntoResponse {
    let m = metrics(State(state)).await.0;
    let mut out = String::with_capacity(1024);
    out.push_str("# HELP bridge_peers_active live peer count\n");
    out.push_str("# TYPE bridge_peers_active gauge\n");
    out.push_str(&format!("bridge_peers_active {}\n", m.peers_active));
    out.push_str("# HELP bridge_channels declared channel count\n");
    out.push_str("# TYPE bridge_channels gauge\n");
    out.push_str(&format!("bridge_channels {}\n", m.channels));
    out.push_str("# HELP bridge_messages_total in-memory retained messages\n");
    out.push_str("# TYPE bridge_messages_total gauge\n");
    out.push_str(&format!("bridge_messages_total {}\n", m.messages_total));
    out.push_str("# HELP bridge_findings_open open findings across all channels\n");
    out.push_str("# TYPE bridge_findings_open gauge\n");
    out.push_str(&format!("bridge_findings_open {}\n", m.findings_open));
    out.push_str("# HELP bridge_findings_total all findings across all channels\n");
    out.push_str("# TYPE bridge_findings_total gauge\n");
    out.push_str(&format!("bridge_findings_total {}\n", m.findings_total));
    out.push_str("# HELP bridge_tasks_active todo+in_progress tasks across all channels\n");
    out.push_str("# TYPE bridge_tasks_active gauge\n");
    out.push_str(&format!("bridge_tasks_active {}\n", m.tasks_active));
    out.push_str("# HELP bridge_dispatches_pending dispatches not yet acked\n");
    out.push_str("# TYPE bridge_dispatches_pending gauge\n");
    out.push_str(&format!("bridge_dispatches_pending {}\n", m.dispatches_pending));
    out.push_str("# HELP bridge_artifacts retained artifact count\n");
    out.push_str("# TYPE bridge_artifacts gauge\n");
    out.push_str(&format!("bridge_artifacts {}\n", m.artifacts));
    out.push_str("# HELP bridge_sse_lag_drops_total SSE events dropped due to subscriber lag\n");
    out.push_str("# TYPE bridge_sse_lag_drops_total counter\n");
    for (channel, n) in &m.sse_lag_drops {
        // Escape `"` and `\` in channel labels per the prometheus
        // exposition spec. Real channel names are simple ASCII so
        // this is defensive.
        let safe = channel.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!(
            "bridge_sse_lag_drops_total{{channel=\"{safe}\"}} {n}\n"
        ));
    }
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        out,
    )
}

// ── Routing rules (F17) ─────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateRoutingRuleReq {
    name: String,
    trigger_type: String,
    /// JSON object. Validated by `routing::validate_filter` before
    /// landing in the DB — per Q2 ops decision, unknown ops reject
    /// at insert time (no silent no-match fallback).
    #[serde(default)]
    trigger_filter: serde_json::Value,
    action_type: String,
    #[serde(default)]
    action_params: serde_json::Value,
    /// 0–100. Higher = scanner picks first.
    #[serde(default = "default_routing_priority")]
    priority: i64,
}

fn default_routing_priority() -> i64 {
    50
}

const MAX_ROUTING_NAME_LEN: usize = 128;
const MAX_ROUTING_JSON_LEN: usize = 8 * 1024;

async fn create_routing_rule(
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<CreateRoutingRuleReq>,
) -> Result<Json<claude_bridge::RoutingRule>, (StatusCode, String)> {
    cap!(req.name, MAX_ROUTING_NAME_LEN, "name");
    if !claude_bridge::TRIGGER_TYPES.contains(&req.trigger_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "trigger_type must be one of {:?}",
                claude_bridge::TRIGGER_TYPES
            ),
        ));
    }
    if !claude_bridge::ACTION_TYPES.contains(&req.action_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "action_type must be one of {:?}",
                claude_bridge::ACTION_TYPES
            ),
        ));
    }
    if !(0..=100).contains(&req.priority) {
        return Err((
            StatusCode::BAD_REQUEST,
            "priority must be in 0..=100".into(),
        ));
    }
    // Q2: fail at insert on bad filter syntax. Pentest's
    // ops-rule-no-silent-fail-open-defaults applied to the rule
    // language itself.
    if let Err(e) = claude_bridge::routing::validate_filter(&req.trigger_filter) {
        return Err((StatusCode::BAD_REQUEST, format!("trigger_filter: {e}")));
    }
    let filter_json = req.trigger_filter.to_string();
    let params_json = req.action_params.to_string();
    cap!(filter_json, MAX_ROUTING_JSON_LEN, "trigger_filter");
    cap!(params_json, MAX_ROUTING_JSON_LEN, "action_params");
    let actor = effective_actor(&headers, ext.as_deref());
    let rule = claude_bridge::RoutingRule {
        id: Uuid::new_v4().to_string(),
        name: req.name,
        trigger_type: req.trigger_type,
        trigger_filter: filter_json,
        action_type: req.action_type,
        action_params: params_json,
        enabled: true,
        priority: req.priority,
        created_by: actor.clone(),
        created_at: now_secs(),
    };
    if let Some(store) = &state.store {
        if let Err(e) = store.insert_routing_rule(&rule) {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("persist routing rule failed: {e}"),
            ));
        }
        write_audit(
            store,
            &actor,
            "create",
            "routing_rule",
            &rule.id,
            None::<&claude_bridge::RoutingRule>,
            Some(&rule),
        );
    } else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence disabled; routing rules require BRIDGE_DB_PATH".into(),
        ));
    }
    Ok(Json(rule))
}

#[derive(Deserialize, Default)]
struct ListRoutingRulesQuery {
    trigger_type: Option<String>,
    enabled: Option<bool>,
}

async fn list_routing_rules(
    Query(q): Query<ListRoutingRulesQuery>,
    State(state): State<AppState>,
) -> Result<Json<Vec<claude_bridge::RoutingRule>>, (StatusCode, String)> {
    let store = state.store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "persistence disabled; routing rules require BRIDGE_DB_PATH".into(),
    ))?;
    let rules = store
        .list_routing_rules(q.trigger_type.as_deref(), q.enabled)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("list routing rules failed: {e}"),
            )
        })?;
    Ok(Json(rules))
}

#[derive(Deserialize, Default)]
struct UpdateRoutingRuleReq {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    trigger_filter: Option<serde_json::Value>,
    #[serde(default)]
    action_params: Option<serde_json::Value>,
    #[serde(default)]
    priority: Option<i64>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn update_routing_rule(
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
    Json(req): Json<UpdateRoutingRuleReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let store = state.store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "persistence disabled".into(),
    ))?;
    // Validate filter ahead of UPDATE (Q2 invariant — never let
    // a bad-syntax filter persist).
    if let Some(f) = &req.trigger_filter {
        if let Err(e) = claude_bridge::routing::validate_filter(f) {
            return Err((StatusCode::BAD_REQUEST, format!("trigger_filter: {e}")));
        }
    }
    if let Some(p) = req.priority {
        if !(0..=100).contains(&p) {
            return Err((
                StatusCode::BAD_REQUEST,
                "priority must be in 0..=100".into(),
            ));
        }
    }
    if let Some(n) = &req.name {
        cap!(n, MAX_ROUTING_NAME_LEN, "name");
    }
    let filter_str = req.trigger_filter.as_ref().map(|v| v.to_string());
    let params_str = req.action_params.as_ref().map(|v| v.to_string());
    if let Some(s) = &filter_str {
        cap!(s, MAX_ROUTING_JSON_LEN, "trigger_filter");
    }
    if let Some(s) = &params_str {
        cap!(s, MAX_ROUTING_JSON_LEN, "action_params");
    }
    let mut touched = 0usize;
    if req.name.is_some() || filter_str.is_some() || params_str.is_some() || req.priority.is_some()
    {
        touched += store
            .update_routing_rule(
                &id,
                req.name.as_deref(),
                filter_str.as_deref(),
                params_str.as_deref(),
                req.priority,
            )
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("update failed: {e}"),
                )
            })?;
    }
    if let Some(e) = req.enabled {
        touched += store.set_routing_rule_enabled(&id, e).map_err(|e2| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("toggle failed: {e2}"),
            )
        })?;
    }
    let actor = effective_actor(&headers, ext.as_deref());
    write_audit(
        store,
        &actor,
        "update",
        "routing_rule",
        &id,
        None::<&claude_bridge::RoutingRule>,
        None::<&claude_bridge::RoutingRule>,
    );
    if touched == 0 {
        Err((StatusCode::NOT_FOUND, format!("routing rule '{id}' not found or nothing to update")))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

async fn delete_routing_rule(
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: Option<axum::extract::Extension<claude_bridge::auth::AuthIdentity>>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let store = state.store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "persistence disabled".into(),
    ))?;
    let n = store
        .delete_routing_rule(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("delete failed: {e}")))?;
    if n == 0 {
        return Err((StatusCode::NOT_FOUND, format!("routing rule '{id}' not found")));
    }
    let actor = effective_actor(&headers, ext.as_deref());
    write_audit(
        store,
        &actor,
        "delete",
        "routing_rule",
        &id,
        None::<&claude_bridge::RoutingRule>,
        None::<&claude_bridge::RoutingRule>,
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct EvalRoutingReq {
    trigger_type: String,
    payload: serde_json::Value,
}

#[derive(serde::Serialize)]
struct EvalRoutingResp {
    matched: Vec<EvalMatch>,
}

#[derive(serde::Serialize)]
struct EvalMatch {
    rule_id: String,
    rule_name: String,
    action_type: String,
    action_params: serde_json::Value,
}

/// Dry-run: given a synthetic trigger context, returns the rules
/// that would fire. Doesn't actually emit actions. Useful for
/// authoring rules + verifying their filter shape before enabling.
async fn eval_routing(
    State(state): State<AppState>,
    Json(req): Json<EvalRoutingReq>,
) -> Result<Json<EvalRoutingResp>, (StatusCode, String)> {
    let store = state.store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "persistence disabled".into(),
    ))?;
    if !claude_bridge::TRIGGER_TYPES.contains(&req.trigger_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("trigger_type must be one of {:?}", claude_bridge::TRIGGER_TYPES),
        ));
    }
    let rules = store
        .rules_for_trigger(&req.trigger_type)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("read rules failed: {e}")))?;
    let matched = claude_bridge::routing::eval(&rules, &req.trigger_type, &req.payload);
    Ok(Json(EvalRoutingResp {
        matched: matched
            .into_iter()
            .map(|m| EvalMatch {
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                action_type: m.action_type,
                action_params: m.action_params,
            })
            .collect(),
    }))
}

// ── Dispatches ──────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct AckDispatchReq {
    /// Caller's commitment for when they'll complete. 0 = unspecified.
    #[serde(default)]
    eta_secs: u64,
}

async fn ack_dispatch(
    Path(message_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<AckDispatchReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let Some(store) = &state.store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence disabled; dispatch tracking requires BRIDGE_DB_PATH".into(),
        ));
    };
    let n = store
        .ack_dispatch(&message_id, now_secs(), req.eta_secs)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("ack failed: {e}")))?;
    if n == 0 {
        // Distinguish "no such message_id" from "already acked".
        // Both return NOT_FOUND today to keep the API shape stable;
        // a follow-up can split via a separate read if useful.
        Err((StatusCode::NOT_FOUND, "no open dispatch with that message_id".into()))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

#[derive(Deserialize, Default)]
struct CompleteDispatchReq {
    #[serde(default)]
    outcome: String,
}

const MAX_OUTCOME_LEN: usize = 1024;

async fn complete_dispatch(
    Path(message_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<CompleteDispatchReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    cap!(req.outcome, MAX_OUTCOME_LEN, "outcome");
    let Some(store) = &state.store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence disabled; dispatch tracking requires BRIDGE_DB_PATH".into(),
        ));
    };
    let n = store
        .complete_dispatch(&message_id, now_secs(), &req.outcome)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("complete failed: {e}")))?;
    if n == 0 {
        Err((StatusCode::NOT_FOUND, "no open dispatch with that message_id".into()))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Wiring ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cfg = match claude_bridge::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            // Same fail-closed gate as the auth bundle. Per ops-rule-
            // no-silent-fail-open-defaults: missing persistence env
            // must refuse to start, not silently degrade.
            eprintln!("FATAL: {e}");
            std::process::exit(2);
        }
    };
    tracing::info!(?cfg, "loaded runtime config");

    // Optional persistence. `db_path = Some(_)` enables write-through
    // sqlite + boot-time rehydrate. `None` keeps the legacy
    // in-memory-only mode where state is lost on restart.
    let store = match cfg.db_path.as_deref() {
        Some(path) => match Store::open(std::path::Path::new(path)) {
            Ok(s) => {
                tracing::info!(path, "persistence enabled (sqlite)");
                Some(s)
            }
            Err(e) => {
                tracing::error!(path, error = %e, "could not open sqlite db; running in-memory only");
                None
            }
        },
        None => {
            tracing::info!("BRIDGE_DB_PATH unset — running in-memory only (state lost on restart)");
            None
        }
    };

    let state = AppState::new(store.clone());
    state.rehydrate();

    // Background automation loop. Shared 60s base tick per ops
    // dispatch 1779031875 — every additional scanner pushes into
    // `registry` instead of starting its own interval. Heartbeat
    // proves the loop is alive in dev; peer-history prune runs
    // hourly. More scanners (dispatch escalation, peer-drop notice,
    // finding-SLA) land as they're wired into mutation hooks.
    // Snapshot closure — clones the peer-presence DashMap into a
    // simple `(name, last_seen, channel)` Vec at call time so the
    // scanner sees a consistent view without holding a DashMap
    // guard. Stored as an Arc<dyn Fn(...)> in the ctx so it lives
    // for the loop's lifetime.
    let peers_for_snapshot = state.peers.clone();
    let auto_ctx = claude_bridge::automation::AutomationCtx {
        store: store.clone(),
        peer_history_ttl_secs: cfg.peer_history_ttl.as_secs(),
        dispatch_sla_secs: 15 * 60, // 15 minutes per roadmap-v1 F5
        escalated: Arc::new(dashmap::DashSet::new()),
        senders: state.senders.clone(),
        peers_snapshot: Arc::new(move || {
            peers_for_snapshot
                .iter()
                .map(|kv| {
                    let ps = kv.value();
                    (kv.key().clone(), ps.last_seen, ps.channel.clone())
                })
                .collect()
        }),
    };
    let registry: Vec<Arc<dyn claude_bridge::automation::Scanner>> = vec![
        Arc::new(claude_bridge::automation::HeartbeatScanner),
        Arc::new(claude_bridge::automation::PeerHistoryPruneScanner),
        Arc::new(claude_bridge::automation::DispatchEscalationScanner),
        Arc::new(claude_bridge::automation::PeerDropScanner {
            seen: Arc::new(dashmap::DashSet::new()),
        }),
    ];
    let _automation_handle = claude_bridge::automation::spawn_loop(
        Duration::from_secs(60),
        auto_ctx,
        registry,
    );

    // Load the auth registry once at boot. Per finding `dc633d7c`
    // bundle + pentest pre-review 1779043445 + ops accept 1779043473:
    // FAIL-CLOSED. If BRIDGE_AUTH_TOKENS is empty AND
    // BRIDGE_AUTH_PERMISSIVE is not explicitly set, the server
    // refuses to start with the exact error string the operator
    // approved. Permissive mode is an explicit opt-in only.
    let auth_state = match claude_bridge::auth::AuthState::from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(2);
        }
    };

    // Memory-ownership migration (finding `0919a7db` bundle): any
    // existing memory row whose `updated_by` is the pre-auth-bundle
    // placeholder (`unknown`/`anonymous`) OR doesn't map to a known
    // registry identity gets rewritten to ownerless. Ownerless
    // rows are claimable by the first authenticated writer.
    // Memory-admin allowlist is folded into `known` so admin-
    // authored rows stay claimed by the admin.
    if let Some(store_ref) = &store {
        let mut known = auth_state.known_identities();
        for a in auth_state.memory_admins.iter() {
            known.insert(a.clone());
        }
        // Per Item 7 (ops 1779046844): findings authored by
        // identities that don't map to the auth registry get a
        // `[orphan-<prior>]` rename so list_findings makes the
        // attribution gap visible. Enforce mode only — in
        // permissive mode every identity looks unknown and we'd
        // torch the whole table.
        if !auth_state.is_permissive() {
            match store_ref.orphan_unmapped_finding_authors(&known) {
                Ok(0) => tracing::info!("finding-author migration: no rows needed orphaning"),
                Ok(n) => tracing::info!(
                    renamed = n,
                    "finding-author migration: rewrote {n} rows to [orphan-…] (identities outside registry+admins)"
                ),
                Err(e) => {
                    eprintln!("FATAL: finding-author migration failed in enforce mode: {e}");
                    eprintln!("       See finding 9fe0e927 for the FTS-rebuild equivalent on the memory side.");
                    std::process::exit(2);
                }
            }
        } else {
            tracing::info!(
                "finding-author migration skipped — permissive mode (no registry to define orphans against)"
            );
        }
        match store_ref.orphan_unmapped_memory_owners(&known) {
            Ok(0) => tracing::info!("memory-ownership migration: no rows needed orphaning"),
            Ok(n) => tracing::info!(
                orphaned = n,
                "memory-ownership migration: rewrote {n} rows to ownerless (claimable by first authed writer)"
            ),
            Err(e) => {
                // Per finding 9fe0e927: the migration failure on
                // paledo was masked as WARN-only — operator never
                // noticed the boot path left ownership in an
                // inconsistent state. In enforce mode the bridge
                // now refuses to start; in permissive mode it
                // logs ERROR (not WARN) and continues so the
                // operator has a way to come up and diagnose.
                if !auth_state.is_permissive() {
                    eprintln!(
                        "FATAL: memory-ownership migration failed in enforce mode: {e}"
                    );
                    eprintln!(
                        "       Likely FTS5 shadow-table inconsistency (finding 9fe0e927)."
                    );
                    eprintln!(
                        "       Try: sqlite3 \"$BRIDGE_DB_PATH\" \"INSERT INTO memory_fts(memory_fts) VALUES('rebuild');\""
                    );
                    eprintln!(
                        "       Then restart. If failure persists, set BRIDGE_AUTH_PERMISSIVE=1 to come up + investigate."
                    );
                    std::process::exit(2);
                }
                tracing::error!(
                    error = %e,
                    "memory-ownership migration FAILED. Permissive mode allows boot to continue, \
                     but ownership of existing memory rows is unenforceable until the underlying \
                     issue (see finding 9fe0e927) is resolved."
                );
            }
        }
    }

    // Split the router into "authed" (everything sensitive) and
    // "public" (Prometheus scrape only) so the layer applies once
    // and we don't fight axum's route-by-route layer order.
    let authed = Router::new()
        // Messages
        .route("/send/{channel}", post(send))
        .route("/messages/{channel}", get(get_messages))
        .route("/messages/{channel}", delete(clear_messages))
        .route("/stream/{channel}", get(stream_channel))
        .route("/channels", get(list_channels))
        .route("/channels/{channel}/topic", get(get_topic).put(set_topic))
        .route("/channels/{channel}", delete(delete_channel))
        // Findings
        .route("/findings/{channel}", post(create_finding))
        .route("/findings/{channel}", get(list_findings))
        .route("/findings/{channel}/{id}", patch(triage_finding))
        .route("/findings/{channel}/{id}", delete(delete_finding))
        // Artifacts. Upload + list are channel-scoped under
        // /artifacts/<channel>; download is by global id under
        // /artifact/<id> (singular) so the route shapes don't collide
        // in axum's matcher trie.
        //
        // Per-route body-limit override: the global 1 MB cap
        // (finding `ccf87dff`) would clip legitimate artifact
        // uploads. Bump to ARTIFACT_MAX_BYTES = 10 MB just for
        // this route; the handler already enforces the same
        // ceiling itself, so this just lets the request reach the
        // handler.
        .route(
            "/artifacts/{channel}",
            post(upload_artifact).layer(axum::extract::DefaultBodyLimit::max(ARTIFACT_MAX_BYTES)),
        )
        .route("/artifacts/{channel}/list", get(list_artifacts))
        .route("/artifact/{id}", get(download_artifact))
        // Pin / unpin messages
        .route("/messages/{channel}/{id}/pin", post(pin_message).delete(unpin_message))
        // Tasks (work queue, distinct from findings)
        .route("/tasks/{channel}", post(create_task).get(list_tasks))
        .route("/tasks/{channel}/{id}", patch(update_task).delete(delete_task))
        // Shared memory KV
        .route("/memory/{channel}", get(memory_list))
        .route("/memory/{channel}/{key}",
               get(memory_get).put(memory_set).delete(memory_delete))
        // Presence
        .route("/presence/{name}", post(heartbeat))
        .route("/peers", get(list_peers))
        // Dispatch lifecycle. Keyed by `message_id` rather than
        // dispatch internal id so peers can call these with the id
        // they already have from `send_message`'s response.
        .route("/dispatches/{message_id}/ack", post(ack_dispatch))
        .route("/dispatches/{message_id}/complete", post(complete_dispatch))
        // F17 routing rules — author/list/update/delete + eval dry-run.
        // Requires persistence (503 if BRIDGE_DB_PATH unset / ephemeral).
        .route("/routing-rules", post(create_routing_rule).get(list_routing_rules))
        .route("/routing-rules/{id}", patch(update_routing_rule).delete(delete_routing_rule))
        .route("/routing-rules/eval", post(eval_routing))
        // Observability — authed per finding `cc3c33d6` (was world-
        // readable; identity is now needed for per-(requester,
        // target) rate-limit bucket on /resume).
        .route("/peer/{name}/health", get(peer_health))
        .route("/resume/{name}", get(resume_endpoint))
        .route("/metrics", get(metrics))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            claude_bridge::auth::require_auth,
        ))
        .with_state(state.clone());

    let public = Router::new()
        // Prometheus scrape kept unauthed — typical Prom deployments
        // don't speak bearer tokens; ops fronts this with a reverse
        // proxy ACL. The payload is aggregate-only counts, no
        // per-peer secrets.
        .route("/metrics/prometheus", get(metrics_prometheus))
        .with_state(state.clone());

    // Store the auth state in the app for handlers that need to
    // consult the memory-admin allowlist or re-resolve identity.
    //
    // DefaultBodyLimit (finding `ccf87dff`, pentest 0f4543
    // 1779042805): axum's implicit 2MB cap was undocumented and
    // surfaced as "request too long" 413s for legitimate artifact
    // uploads up to 10MB. Pin it explicitly to 1 MB for the
    // general router so DoS-by-large-body is bounded; the
    // artifact-upload route already enforces its own
    // `ARTIFACT_MAX_BYTES = 10 * 1024 * 1024` ceiling, so we
    // layer an override on that single route's branch so it
    // doesn't get clipped at the global limit. /metrics +
    // /metrics/prometheus + everything else stays at 1 MB.
    use axum::extract::DefaultBodyLimit;
    const GLOBAL_BODY_LIMIT_BYTES: usize = 1024 * 1024;
    let app = Router::new()
        .merge(authed)
        .merge(public)
        .layer(axum::extract::Extension(auth_state))
        // Apply 1 MB default to everything…
        .layer(DefaultBodyLimit::max(GLOBAL_BODY_LIMIT_BYTES));

    tracing::info!("claude-bridge server on {}", cfg.bind);
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_rate_limit_caps_per_pair_and_resets_on_window() {
        // Construct a bare AppState directly — no need to spin up
        // the full server for an isolated rate-limit assertion.
        let state = AppState::new(None);
        let req = "alice";
        let tgt = "bob";
        // First 60 calls succeed.
        for _ in 0..super::RESUME_RATE_LIMIT {
            assert!(resume_within_limit(&state, req, tgt));
        }
        // The 61st in the same window is rejected.
        assert!(!resume_within_limit(&state, req, tgt));
        // A different requester or target shares no bucket.
        assert!(resume_within_limit(&state, "carol", tgt));
        assert!(resume_within_limit(&state, req, "dan"));
        // Simulate window rollover by rewinding the bucket's
        // window_start. (Black-box test using public Arc<DashMap>.)
        if let Some(mut e) = state.resume_buckets.get_mut(&(req.into(), tgt.into())) {
            let (_old, count) = *e.value();
            e.value_mut().0 = now_secs().saturating_sub(super::RESUME_RATE_WINDOW_SECS + 1);
            // count is preserved; the helper notices the window
            // expired and resets to 1 on next call.
            let _ = count;
        }
        // After rollover, the next call succeeds (resets to 1).
        assert!(resume_within_limit(&state, req, tgt));
    }

    #[test]
    fn channel_name_valid_examples() {
        // Compliant
        assert!(channel_name_valid("general"));
        assert!(channel_name_valid("pale-pentest"));
        assert!(channel_name_valid("pale-sdk"));
        assert!(channel_name_valid("a1"));
        assert!(channel_name_valid("0test"));
        // Non-compliant
        assert!(!channel_name_valid(""));
        assert!(!channel_name_valid("a"));
        assert!(!channel_name_valid("-leading-dash"));
        assert!(!channel_name_valid("Capital"));
        assert!(!channel_name_valid("under_score"));
        assert!(!channel_name_valid("a,b,c"));
        assert!(!channel_name_valid(&"x".repeat(64)));
    }

    #[test]
    fn redact_secrets_blanks_known_patterns() {
        // JWT-shaped Bearer token → redacted.
        let r = redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
        assert!(r.contains("[REDACTED:jwt]"), "got: {r}");
        assert!(!r.contains("eyJhbGciOiJIUzI1NiJ9"));
        // password= form → redacted.
        let r = redact_secrets("postgres://user:password=hunter2 host:5432");
        assert!(r.contains("[REDACTED:password]"), "got: {r}");
        assert!(!r.contains("hunter2"));
        // Stripe live key → redacted.
        let r = redact_secrets("STRIPE_KEY=sk_live_abc123def456");
        assert!(r.contains("[REDACTED:stripe-secret]"));
        // AWS access key prefix → redacted.
        let r = redact_secrets("aws=AKIAIOSFODNN7EXAMPLE");
        assert!(r.contains("[REDACTED:aws-access-key]"));
        // Non-secret content passes through unchanged.
        let r = redact_secrets("hello world, no secrets here");
        assert_eq!(r, "hello world, no secrets here");
        // Gezer LB API key — per gezer-lb-origin-contract memory.
        let r = redact_secrets("GEZER_KEY=gz_c32b802343b555ea12345");
        assert!(r.contains("[REDACTED:gezer-key]"), "got: {r}");
        assert!(!r.contains("c32b802343b555ea"));
        // Stripe webhook signing secret — operator-provisioned shape.
        let r = redact_secrets("STRIPE_WEBHOOK_SECRET=whsec_abc123def456789");
        assert!(r.contains("[REDACTED:stripe-webhook-secret]"), "got: {r}");
        assert!(!r.contains("abc123def456"));

        // Finding fe91e015 expansion: SSH/PEM/Anthropic/GitHub/Slack.
        let r = redact_secrets("authorized_keys: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx user@host");
        assert!(r.contains("[REDACTED:ssh-rsa]"));
        assert!(!r.contains("AAAAB3NzaC1yc2E"));
        let r = redact_secrets("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1234567890 ed25519@host");
        assert!(r.contains("[REDACTED:ssh-ed25519]"));
        // PEM header — the BEGIN line is the secret-family marker.
        let r = redact_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...");
        assert!(r.contains("[REDACTED:pem-block]"));
        // Anthropic API key prefix.
        let r = redact_secrets("ANTHROPIC_API_KEY=sk-ant-api03-AAAAAA-deadbeef");
        assert!(r.contains("[REDACTED:anthropic-key]"));
        assert!(!r.contains("deadbeef"));
        // GitHub PAT family — each prefix mapped to a distinct tag.
        for (prefix, tag) in &[
            ("ghp_AAAA1234567890BBBB", "[REDACTED:github-pat]"),
            ("gho_AAAA1234567890BBBB", "[REDACTED:github-oauth]"),
            ("ghu_AAAA1234567890BBBB", "[REDACTED:github-user-token]"),
            ("ghs_AAAA1234567890BBBB", "[REDACTED:github-server-token]"),
            ("ghr_AAAA1234567890BBBB", "[REDACTED:github-refresh]"),
        ] {
            let r = redact_secrets(&format!("TOKEN={prefix} other"));
            assert!(r.contains(tag), "got: {r}");
            assert!(!r.contains("AAAA1234567890BBBB"), "leaked body for {prefix}");
        }
        // Slack token family.
        for (prefix, tag) in &[
            ("xoxb-1234-5678-abc", "[REDACTED:slack-bot]"),
            ("xoxp-1234-5678-abc", "[REDACTED:slack-user]"),
            ("xoxa-1234-5678-abc", "[REDACTED:slack-app]"),
            ("xoxs-1234-5678-abc", "[REDACTED:slack-config]"),
            ("xoxr-1234-5678-abc", "[REDACTED:slack-refresh]"),
        ] {
            let r = redact_secrets(&format!("SLACK_TOKEN={prefix}"));
            assert!(r.contains(tag), "got: {r}");
            assert!(!r.contains("1234-5678-abc"), "leaked body for {prefix}");
        }
    }

    #[test]
    fn memory_key_valid_examples() {
        // Compliant (categorised)
        assert!(memory_key_valid("decision-bridge-group-a-schema"));
        assert!(memory_key_valid("ops-rule-no-client-side-credit-flows"));
        assert!(memory_key_valid("coverage-2026-05-17"));
        assert!(memory_key_valid("pattern-ws-auth-cookie-extension"));
        assert!(memory_key_valid("session-resume-2026-05-17"));
        // Non-compliant
        assert!(!memory_key_valid("Capital-letter")); // uppercase
        assert!(!memory_key_valid("random-key")); // no known category
        assert!(!memory_key_valid("decision_no_dash")); // category not delimited by '-'
        assert!(!memory_key_valid("ab")); // too short
        assert!(!memory_key_valid("")); // empty
    }
}
