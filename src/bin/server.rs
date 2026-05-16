use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{sse::{Event, KeepAlive, Sse}, IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use claude_bridge::{now_secs, Artifact, Finding, Message, Peer, SEVERITIES, STATUSES};
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

#[derive(Clone)]
struct AppState {
    senders: Arc<DashMap<String, broadcast::Sender<Message>>>,
    history: Arc<DashMap<String, Vec<Message>>>,
    findings: Arc<DashMap<String, Vec<Finding>>>,
    artifacts: Arc<DashMap<String, (Artifact, Vec<u8>)>>,
    /// `name -> (last_seen_secs, channel)`. Updated by heartbeat
    /// POST /presence/{name}; read by GET /peers.
    peers: Arc<DashMap<String, (u64, String)>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            senders: Arc::new(DashMap::new()),
            history: Arc::new(DashMap::new()),
            findings: Arc::new(DashMap::new()),
            artifacts: Arc::new(DashMap::new()),
            peers: Arc::new(DashMap::new()),
        }
    }

    fn sender(&self, channel: &str) -> broadcast::Sender<Message> {
        self.senders
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }
}

// ── Messages ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SendReq {
    from: String,
    content: String,
}

async fn send(
    Path(channel): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<SendReq>,
) -> Json<serde_json::Value> {
    let msg = Message {
        id: Uuid::new_v4().to_string(),
        channel: channel.clone(),
        from: req.from.clone(),
        content: req.content,
        timestamp: now_secs(),
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

    // Implicit presence — sending is a sign of life. Saves a separate
    // heartbeat round-trip for CLI-only callers (they don't run the
    // background heartbeat that the MCP client does).
    state
        .peers
        .insert(req.from.clone(), (now_secs(), channel.clone()));

    let _ = state.sender(&channel).send(msg);

    Json(serde_json::json!({ "id": id, "ok": true }))
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

async fn list_channels(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.senders.iter().map(|e| e.key().clone()).collect())
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
    if !SEVERITIES.contains(&req.severity.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("severity must be one of {SEVERITIES:?}"),
        ));
    }
    if req.title.is_empty() || req.title.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "title required, ≤256 chars".into(),
        ));
    }
    if req.detail.len() > 64 * 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            "detail ≤64 KB; attach a PoC via /artifacts for larger payloads".into(),
        ));
    }
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
    };
    {
        let mut f = state.findings.entry(channel.clone()).or_default();
        f.push(finding.clone());
        if f.len() > FINDING_LIMIT {
            let drain = f.len() - FINDING_LIMIT;
            f.drain(0..drain);
        }
    }
    state
        .peers
        .insert(req.from, (now_secs(), channel.clone()));
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
    if !STATUSES.contains(&req.status.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("status must be one of {STATUSES:?}"),
        ));
    }
    let mut entry = match state.findings.get_mut(&channel) {
        Some(e) => e,
        None => return Err((StatusCode::NOT_FOUND, "channel has no findings".into())),
    };
    let found = entry.iter_mut().find(|f| f.id == id);
    let Some(f) = found else {
        return Err((StatusCode::NOT_FOUND, "finding id not found".into()));
    };
    f.status = req.status;
    f.note = req.note;
    f.updated_at = now_secs();
    Ok(Json(f.clone()))
}

// ── Artifacts ───────────────────────────────────────────────────────

async fn upload_artifact(
    Path(channel): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if body.len() > ARTIFACT_MAX_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("max {} bytes", ARTIFACT_MAX_BYTES),
        ));
    }
    let from = headers
        .get("x-bridge-from")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let filename = headers
        .get("x-bridge-filename")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("artifact.bin")
        .to_string();
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

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
    state.artifacts.insert(id.clone(), (art, body.to_vec()));
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
        header::HeaderValue::from_str(&art.mime).unwrap_or(header::HeaderValue::from_static("application/octet-stream")),
    );
    if let Ok(v) = header::HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        art.filename.replace('"', "")
    )) {
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
}

async fn heartbeat(
    Path(name): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PresenceReq>,
) -> StatusCode {
    state.peers.insert(name, (now_secs(), req.channel));
    StatusCode::NO_CONTENT
}

async fn list_peers(State(state): State<AppState>) -> Json<Vec<Peer>> {
    let now = now_secs();
    let mut peers: Vec<Peer> = state
        .peers
        .iter()
        .filter(|kv| now.saturating_sub(kv.value().0) <= PEER_TTL_SECS)
        .map(|kv| {
            let (last_seen, channel) = kv.value().clone();
            Peer {
                name: kv.key().clone(),
                last_seen,
                idle_secs: now.saturating_sub(last_seen),
                channel,
            }
        })
        .collect();
    peers.sort_by_key(|p| p.idle_secs);
    Json(peers)
}

// ── Wiring ──────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let app = Router::new()
        // Messages
        .route("/send/{channel}", post(send))
        .route("/messages/{channel}", get(get_messages))
        .route("/messages/{channel}", delete(clear_messages))
        .route("/stream/{channel}", get(stream_channel))
        .route("/channels", get(list_channels))
        // Findings
        .route("/findings/{channel}", post(create_finding))
        .route("/findings/{channel}", get(list_findings))
        .route("/findings/{channel}/{id}", patch(triage_finding))
        // Artifacts. Upload + list are channel-scoped under
        // /artifacts/<channel>; download is by global id under
        // /artifact/<id> (singular) so the route shapes don't collide
        // in axum's matcher trie.
        .route("/artifacts/{channel}", post(upload_artifact))
        .route("/artifacts/{channel}/list", get(list_artifacts))
        .route("/artifact/{id}", get(download_artifact))
        // Presence
        .route("/presence/{name}", post(heartbeat))
        .route("/peers", get(list_peers))
        .with_state(AppState::new());

    tracing::info!("claude-bridge server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
