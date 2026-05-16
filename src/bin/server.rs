use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    routing::{delete, get, post},
    Json, Router,
};
use claude_bridge::{now_secs, Message};
use dashmap::DashMap;
use futures::Stream;
use serde::Deserialize;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;

const HISTORY_LIMIT: usize = 100;
const CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
struct AppState {
    senders: Arc<DashMap<String, broadcast::Sender<Message>>>,
    history: Arc<DashMap<String, Vec<Message>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            senders: Arc::new(DashMap::new()),
            history: Arc::new(DashMap::new()),
        }
    }

    fn sender(&self, channel: &str) -> broadcast::Sender<Message> {
        self.senders
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }
}

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
        from: req.from,
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

    let _ = state.sender(&channel).send(msg);

    Json(serde_json::json!({ "id": id, "ok": true }))
}

async fn get_messages(
    Path(channel): Path<String>,
    State(state): State<AppState>,
) -> Json<Vec<Message>> {
    Json(
        state
            .history
            .get(&channel)
            .map(|h| h.value().clone())
            .unwrap_or_default(),
    )
}

async fn clear(
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let app = Router::new()
        .route("/send/{channel}", post(send))
        .route("/messages/{channel}", get(get_messages))
        .route("/messages/{channel}", delete(clear))
        .route("/stream/{channel}", get(stream_channel))
        .route("/channels", get(list_channels))
        .with_state(AppState::new());

    tracing::info!("claude-bridge server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
