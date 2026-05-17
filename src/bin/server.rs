use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{sse::{Event, KeepAlive, Sse}, IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use claude_bridge::{
    now_secs, store::Store, Artifact, ChannelTopic, Finding, MemoryEntry, Message, Peer, Task,
    SEVERITIES, STATUSES, TASK_STATUSES,
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

fn cap(s: &str, max: usize, field: &str) -> Result<(), (StatusCode, String)> {
    if s.len() > max {
        Err((
            StatusCode::BAD_REQUEST,
            format!("{field} too long ({}>{max})", s.len()),
        ))
    } else {
        Ok(())
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
    from: String,
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
    State(state): State<AppState>,
    Json(req): Json<SendReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    cap(&channel, MAX_CHANNEL_LEN, "channel")?;
    cap(&req.from, MAX_FROM_LEN, "from")?;
    cap(&req.content, MAX_CONTENT_LEN, "content")?;
    ensure_channel_capacity(&state, &channel);

    let msg = Message {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: req.from.clone(),
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
        .get(&req.from)
        .map(|kv| kv.value().clone())
        .unwrap_or_default();
    prev.last_seen = now_secs();
    prev.channel = channel.clone();
    state.peers.insert(req.from.clone(), prev);

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

    let stream = BroadcastStream::new(rx).filter_map(|result| {
        result.ok().map(|msg| {
            let data = serde_json::to_string(&msg).unwrap_or_default();
            Ok::<_, Infallible>(Event::default().data(data))
        })
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
    from: String,
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
    State(state): State<AppState>,
    Json(req): Json<SetTopicReq>,
) -> Result<Json<ChannelTopic>, (StatusCode, String)> {
    cap(&channel, MAX_CHANNEL_LEN, "channel")?;
    cap(&req.from, MAX_FROM_LEN, "from")?;
    cap(&req.topic, MAX_TOPIC_LEN, "topic")?;
    let t = ChannelTopic {
        name: channel.clone(),
        topic: req.topic,
        updated_by: req.from,
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
    from: String,
    severity: String,
    title: String,
    detail: String,
    #[serde(default)]
    endpoint: String,
}

async fn create_finding(
    Path(channel): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<CreateFindingReq>,
) -> Result<Json<Finding>, (StatusCode, String)> {
    cap(&channel, MAX_CHANNEL_LEN, "channel")?;
    cap(&req.from, MAX_FROM_LEN, "from")?;
    cap(&req.endpoint, MAX_ENDPOINT_LEN, "endpoint")?;
    cap(&req.detail, MAX_DETAIL_LEN, "detail")?;
    if !SEVERITIES.contains(&req.severity.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("severity must be one of {SEVERITIES:?}"),
        ));
    }
    if req.title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title required".into()));
    }
    cap(&req.title, MAX_TITLE_LEN, "title")?;
    ensure_channel_capacity(&state, &channel);
    let now = now_secs();
    let finding = Finding {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: req.from.clone(),
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
    }
    let mut prev = state
        .peers
        .get(&req.from)
        .map(|kv| kv.value().clone())
        .unwrap_or_default();
    prev.last_seen = now_secs();
    prev.channel = channel.clone();
    state.peers.insert(req.from, prev);
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
    State(state): State<AppState>,
    Json(req): Json<TriageReq>,
) -> Result<Json<Finding>, (StatusCode, String)> {
    cap(&req.note, MAX_NOTE_LEN, "note")?;
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
    }
    Ok(Json(snapshot))
}

/// Hard-delete a finding. Use this for false-positives or noisy
/// reports that pollute the queue — `triage_finding` only updates
/// status, so a `wontfix` still shows up in unfiltered lists.
async fn delete_finding(
    Path((channel, id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut entry = match state.findings.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no findings on channel '{channel}'"))),
    };
    let before = entry.len();
    entry.retain(|f| f.id != id);
    if entry.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            format!("finding id '{id}' not found on channel '{channel}'"),
        ));
    }
    drop(entry);
    if let Some(store) = &state.store {
        let _ = store.delete_finding(&channel, &id);
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
    cap(&channel, MAX_CHANNEL_LEN, "channel")?;
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
    cap(from, MAX_FROM_LEN, "x-bridge-from")?;
    let from = from.to_string();

    let raw_filename = headers
        .get("x-bridge-filename")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("artifact.bin");
    cap(raw_filename, MAX_FILENAME_LEN, "x-bridge-filename")?;
    // Strip control chars / quotes BEFORE we touch the header — keeps
    // a malicious filename from injecting CR/LF into our response's
    // Content-Disposition.
    let filename = safe_filename(raw_filename);

    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    cap(mime, MAX_MIME_LEN, "content-type")?;
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
    cap(&name, MAX_FROM_LEN, "name")?;
    cap(&req.channel, MAX_CHANNEL_LEN, "channel")?;
    cap(&req.status, MAX_STATUS_LEN, "status")?;
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
    from: String,
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
    State(state): State<AppState>,
    Json(req): Json<CreateTaskReq>,
) -> Result<Json<Task>, (StatusCode, String)> {
    cap(&channel, MAX_CHANNEL_LEN, "channel")?;
    cap(&req.from, MAX_FROM_LEN, "from")?;
    cap(&req.title, MAX_TITLE_LEN, "title")?;
    cap(&req.description, MAX_TASK_DESC_LEN, "description")?;
    if req.title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title required".into()));
    }
    ensure_channel_capacity(&state, &channel);
    let now = now_secs();
    let task = Task {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: req.from,
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
    State(state): State<AppState>,
    Json(req): Json<UpdateTaskReq>,
) -> Result<Json<Task>, (StatusCode, String)> {
    if let Some(s) = &req.status {
        if !TASK_STATUSES.contains(&s.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("status must be one of {TASK_STATUSES:?}")));
        }
    }
    if let Some(n) = &req.note {
        cap(n, MAX_NOTE_LEN, "note")?;
    }
    let mut entry = match state.tasks.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no tasks on channel '{channel}'"))),
    };
    let found = entry.iter_mut().find(|t| t.id == id);
    let Some(t) = found else {
        return Err((StatusCode::NOT_FOUND, format!("task id '{id}' not found on channel '{channel}'")));
    };
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
    }
    Ok(Json(snap))
}

async fn delete_task(
    Path((channel, id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut entry = match state.tasks.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, format!("no tasks on channel '{channel}'"))),
    };
    let before = entry.len();
    entry.retain(|t| t.id != id);
    if entry.len() == before {
        return Err((StatusCode::NOT_FOUND, format!("task id '{id}' not found on channel '{channel}'")));
    }
    drop(entry);
    if let Some(store) = &state.store {
        let _ = store.delete_task(&channel, &id);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Shared memory (KV) ───────────────────────────────────────────────

#[derive(Deserialize)]
struct MemorySetReq {
    from: String,
    value: String,
    /// Optional TTL in seconds from now. 0 = no expiry.
    #[serde(default)]
    ttl_secs: u64,
}

const MAX_MEMORY_KEY_LEN: usize = 256;
const MAX_MEMORY_VAL_LEN: usize = 256 * 1024;

async fn memory_set(
    Path((channel, key)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(req): Json<MemorySetReq>,
) -> Result<Json<MemoryEntry>, (StatusCode, String)> {
    cap(&channel, MAX_CHANNEL_LEN, "channel")?;
    cap(&key, MAX_MEMORY_KEY_LEN, "key")?;
    cap(&req.value, MAX_MEMORY_VAL_LEN, "value")?;
    cap(&req.from, MAX_FROM_LEN, "from")?;
    let now = now_secs();
    let entry = MemoryEntry {
        channel: channel.clone(),
        key: key.clone(),
        value: req.value,
        updated_by: req.from,
        updated_at: now,
        expires_at: if req.ttl_secs == 0 { 0 } else { now + req.ttl_secs },
    };
    state.memory.insert((channel.clone(), key.clone()), entry.clone());
    if let Some(store) = &state.store {
        let _ = store.memory_set(&entry);
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
    State(state): State<AppState>,
) -> StatusCode {
    state.memory.remove(&(channel.clone(), key.clone()));
    if let Some(store) = &state.store {
        let _ = store.memory_delete(&channel, &key);
    }
    StatusCode::NO_CONTENT
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

// ── Wiring ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let addr = format!("0.0.0.0:{}", port);

    // Optional persistence. When BRIDGE_DB_PATH is set, the server
    // mirrors every write to sqlite and rehydrates DashMaps on boot
    // so a restart doesn't lose chat / findings / artifacts.
    let store = match std::env::var("BRIDGE_DB_PATH") {
        Ok(path) if !path.is_empty() => match Store::open(std::path::Path::new(&path)) {
            Ok(s) => {
                tracing::info!(path, "persistence enabled (sqlite)");
                Some(s)
            }
            Err(e) => {
                tracing::error!(path, error = %e, "could not open sqlite db; running in-memory only");
                None
            }
        },
        _ => {
            tracing::info!("BRIDGE_DB_PATH unset — running in-memory only (state lost on restart)");
            None
        }
    };

    let state = AppState::new(store);
    state.rehydrate();

    let app = Router::new()
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
        .route("/artifacts/{channel}", post(upload_artifact))
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
        .with_state(state);

    tracing::info!("claude-bridge server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
