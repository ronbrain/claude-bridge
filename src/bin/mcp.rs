use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser, Clone)]
#[command(name = "bridge-mcp", about = "Claude Bridge MCP server")]
struct Args {
    /// Bridge server URL
    #[arg(long, default_value = "http://localhost:3001")]
    server: String,

    /// Default channel for this instance
    #[arg(long, default_value = "general")]
    channel: String,

    /// Name shown to the other instance
    #[arg(long, default_value = "instance")]
    name: String,
}

#[derive(Deserialize)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

fn ok(id: Value, result: Value) -> RpcResponse {
    RpcResponse { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
}

fn err(id: Value, code: i32, msg: &str) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(json!({ "code": code, "message": msg })),
    }
}

fn text(id: Value, s: impl Into<String>) -> RpcResponse {
    ok(id, json!({ "content": [{ "type": "text", "text": s.into() }] }))
}

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "send_message",
                "description": "Send a message to the other Claude Code instance in real time. Use this to share findings, ask questions, or coordinate tasks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": { "type": "string", "description": "Message to send" },
                        "channel": { "type": "string", "description": "Channel (default: configured channel)" }
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "read_messages",
                "description": "Read recent messages from the shared channel. Use `since` (unix-seconds) and `from` to filter incrementally — pass the timestamp of the latest message you already saw to get only new ones.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "since": { "type": "number", "description": "Unix-seconds — only newer messages" },
                        "from": { "type": "string", "description": "Filter to one sender" },
                        "limit": { "type": "number", "description": "Max messages to return (default 100)" }
                    }
                }
            },
            {
                "name": "list_peers",
                "description": "List the Claude Code instances currently connected to the bridge (last heartbeat within 120s). Use before sending — silence on the other end is sometimes the bridge being dead, not the peer ignoring you.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "share_endpoint",
                "description": "Share an HTTP endpoint with the pentesting instance so it can test it. Include auth tokens, headers, and any relevant context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url":     { "type": "string", "description": "Full URL to test" },
                        "method":  { "type": "string", "description": "HTTP method (GET, POST, etc.)" },
                        "headers": { "type": "object", "description": "HTTP headers including auth" },
                        "body":    { "type": "string", "description": "Request body (JSON or raw)" },
                        "notes":   { "type": "string", "description": "Context about what this endpoint does" },
                        "channel": { "type": "string" }
                    },
                    "required": ["url", "method"]
                }
            },
            {
                "name": "report_finding",
                "description": "Report a security finding. Lands in the findings stream (separate from chat) with status=open; use list_findings to query and triage_finding to update.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title":    { "type": "string" },
                        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                        "endpoint": { "type": "string" },
                        "detail":   { "type": "string" },
                        "channel":  { "type": "string" }
                    },
                    "required": ["title", "severity", "detail"]
                }
            },
            {
                "name": "list_findings",
                "description": "List structured findings, optionally filtered. Use `status:\"open\"` to show what still needs work, or `severity:\"critical\"` to triage by impact.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel":  { "type": "string" },
                        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                        "status":   { "type": "string", "enum": ["open", "triaged", "fixed", "wontfix"] },
                        "from":     { "type": "string" }
                    }
                }
            },
            {
                "name": "triage_finding",
                "description": "Update the status of a finding. Use after the SaaS team has looked at it (triaged), shipped a fix (fixed), or decided not to act (wontfix).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id":      { "type": "string" },
                        "status":  { "type": "string", "enum": ["open", "triaged", "fixed", "wontfix"] },
                        "note":    { "type": "string", "description": "Optional triage note" },
                        "channel": { "type": "string" }
                    },
                    "required": ["id", "status"]
                }
            },
            {
                "name": "delete_finding",
                "description": "Hard-delete a finding. Use for false-positives or noisy reports — `triage_finding` only updates status, so a wontfix still pollutes unfiltered lists.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id":      { "type": "string" },
                        "channel": { "type": "string" }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "share_artifact",
                "description": "Upload a small file (≤10 MB) to the bridge and share its download URL. Use for PoC payloads, request/response dumps, screenshots, traces. Returns the artifact id + URL the peer can GET.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": { "type": "string" },
                        "content":  { "type": "string", "description": "Raw text content or base64-encoded bytes" },
                        "base64":   { "type": "boolean", "description": "Set true when `content` is base64" },
                        "mime":     { "type": "string", "description": "MIME type (default text/plain or octet-stream)" },
                        "notes":    { "type": "string" },
                        "channel":  { "type": "string" }
                    },
                    "required": ["filename", "content"]
                }
            },
            {
                "name": "clear_channel",
                "description": "Clear all messages from a channel to start fresh. Does NOT clear findings — those live in their own stream.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "channel": { "type": "string" } }
                }
            }
        ]
    })
}

/// Fire the heartbeat in a background task — runs until the returned
/// `AbortHandle` is invoked, swallowing transient HTTP errors. The
/// server treats a peer as offline after 120s without a heartbeat,
/// so 20s gives ~6× headroom.
///
/// The caller drops the handle when stdin closes (Claude Code shutting
/// down the MCP), aborting the loop so we don't leave a zombie POSTer
/// running until the OS reaps us.
fn spawn_heartbeat(args: Arc<Args>, client: reqwest::Client) -> tokio::task::AbortHandle {
    let h = tokio::spawn(async move {
        let url = format!("{}/presence/{}", args.server, args.name);
        loop {
            let _ = client
                .post(&url)
                .json(&json!({ "channel": args.channel }))
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    });
    h.abort_handle()
}

#[tokio::main]
async fn main() {
    let args = Arc::new(Args::parse());
    let client = reqwest::Client::new();

    // Mark ourselves online before serving the first request — the
    // peer's `list_peers` call right after we boot should see us.
    // Hold the abort handle so we can shut the background loop down
    // cleanly when stdin closes (Claude Code is shutting us down).
    let heartbeat = spawn_heartbeat(args.clone(), client.clone());

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = stdout;
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => {
                heartbeat.abort();
                break;
            }
            Ok(_) => {}
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: RpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let id = req.id.clone().unwrap_or(Value::Null);

        let response = match req.method.as_str() {
            "initialize" => ok(id, json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "claude-bridge", "version": "0.2.0" }
            })),

            "notifications/initialized" => continue,

            "ping" => ok(id, json!({})),

            "tools/list" => ok(id, tools_list()),

            "tools/call" => {
                let params = req.params.unwrap_or(json!({}));
                let name = params["name"].as_str().unwrap_or("");
                let args_val = &params["arguments"];

                match name {
                    "send_message" => {
                        let content = args_val["content"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();

                        let res = client
                            .post(format!("{}/send/{}", args.server, channel))
                            .json(&json!({ "from": args.name, "content": content }))
                            .send()
                            .await;

                        match res {
                            Ok(r) if r.status().is_success() =>
                                text(id, format!("[bridge] sent to '{}' ✓", channel)),
                            _ =>
                                text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "read_messages" => {
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();
                        let mut qs: Vec<(&str, String)> = Vec::new();
                        if let Some(s) = args_val["since"].as_u64() {
                            qs.push(("since", s.to_string()));
                        }
                        if let Some(f) = args_val["from"].as_str() {
                            qs.push(("from", f.to_string()));
                        }
                        if let Some(l) = args_val["limit"].as_u64() {
                            qs.push(("limit", l.to_string()));
                        }
                        let res = client
                            .get(format!("{}/messages/{}", args.server, channel))
                            .query(&qs)
                            .send()
                            .await;

                        match res {
                            Ok(r) => {
                                let msgs: Vec<Value> =
                                    r.json().await.unwrap_or_default();

                                if msgs.is_empty() {
                                    text(id, format!("[bridge] no messages in '{}'", channel))
                                } else {
                                    let formatted = msgs
                                        .iter()
                                        .map(|m| {
                                            format!(
                                                "[{}] {}: {}",
                                                m["timestamp"].as_u64().unwrap_or(0),
                                                m["from"].as_str().unwrap_or("?"),
                                                m["content"].as_str().unwrap_or("")
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n---\n");
                                    text(id, formatted)
                                }
                            }
                            _ => text(id, "[bridge] ERROR: could not read messages"),
                        }
                    }

                    "list_peers" => {
                        let res = client.get(format!("{}/peers", args.server)).send().await;
                        match res {
                            Ok(r) => {
                                let peers: Vec<Value> = r.json().await.unwrap_or_default();
                                if peers.is_empty() {
                                    text(id, "[bridge] no peers online (nobody heartbeating)")
                                } else {
                                    let formatted = peers
                                        .iter()
                                        .map(|p| {
                                            format!(
                                                "• {} — idle {}s on #{}",
                                                p["name"].as_str().unwrap_or("?"),
                                                p["idle_secs"].as_u64().unwrap_or(0),
                                                p["channel"].as_str().unwrap_or("?")
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    text(id, formatted)
                                }
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "share_endpoint" => {
                        let url = args_val["url"].as_str().unwrap_or("").to_string();
                        let method = args_val["method"].as_str().unwrap_or("GET").to_string();
                        let notes = args_val["notes"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();

                        let content = format!(
                            "🎯 ENDPOINT\nURL: {}\nMethod: {}\nHeaders: {}\nBody: {}\nNotes: {}",
                            url,
                            method,
                            args_val["headers"],
                            args_val["body"].as_str().unwrap_or(""),
                            notes
                        );

                        let _ = client
                            .post(format!("{}/send/{}", args.server, channel))
                            .json(&json!({ "from": args.name, "content": content }))
                            .send()
                            .await;

                        text(id, format!("[bridge] endpoint shared: {} {}", method, url))
                    }

                    "report_finding" => {
                        let title = args_val["title"].as_str().unwrap_or("").to_string();
                        let severity = args_val["severity"].as_str().unwrap_or("info").to_string();
                        let endpoint = args_val["endpoint"].as_str().unwrap_or("").to_string();
                        let detail = args_val["detail"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();

                        let res = client
                            .post(format!("{}/findings/{}", args.server, channel))
                            .json(&json!({
                                "from": args.name,
                                "severity": severity,
                                "title": title,
                                "detail": detail,
                                "endpoint": endpoint
                            }))
                            .send()
                            .await;

                        match res {
                            Ok(r) if r.status().is_success() => {
                                let v: Value = r.json().await.unwrap_or(json!({}));
                                let fid = v["id"].as_str().unwrap_or("?");
                                // Also drop a short chat ping so the peer's
                                // between-turn watcher wakes them up. The
                                // finding itself lives in the structured stream.
                                let ping = format!(
                                    "🔴 finding [{}] {} — id={}",
                                    severity, title, fid
                                );
                                let _ = client
                                    .post(format!("{}/send/{}", args.server, channel))
                                    .json(&json!({ "from": args.name, "content": ping }))
                                    .send()
                                    .await;
                                text(id, format!("[bridge] finding reported (id {})", fid))
                            }
                            Ok(r) => {
                                let status = r.status();
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {status}: {body}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "list_findings" => {
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();
                        let mut qs: Vec<(&str, String)> = Vec::new();
                        for k in ["severity", "status", "from"] {
                            if let Some(v) = args_val[k].as_str() {
                                qs.push((k, v.to_string()));
                            }
                        }
                        let res = client
                            .get(format!("{}/findings/{}", args.server, channel))
                            .query(&qs)
                            .send()
                            .await;
                        match res {
                            Ok(r) => {
                                let fs: Vec<Value> = r.json().await.unwrap_or_default();
                                if fs.is_empty() {
                                    text(id, format!("[bridge] no findings in '{channel}' (with filters)"))
                                } else {
                                    let formatted = fs
                                        .iter()
                                        .map(|f| {
                                            format!(
                                                "• [{}] {} | {} | from={} | id={}\n   {}",
                                                f["status"].as_str().unwrap_or("?"),
                                                f["severity"].as_str().unwrap_or("?"),
                                                f["title"].as_str().unwrap_or(""),
                                                f["from"].as_str().unwrap_or("?"),
                                                f["id"].as_str().unwrap_or("?"),
                                                f["endpoint"].as_str().unwrap_or("(no endpoint)")
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    text(id, formatted)
                                }
                            }
                            _ => text(id, "[bridge] ERROR: could not list findings"),
                        }
                    }

                    "delete_finding" => {
                        let id_param = args_val["id"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();
                        let res = client
                            .delete(format!("{}/findings/{}/{}", args.server, channel, id_param))
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() =>
                                text(id, format!("[bridge] finding {} deleted", id_param)),
                            Ok(r) => {
                                let s = r.status();
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {body}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "triage_finding" => {
                        let id_param = args_val["id"].as_str().unwrap_or("").to_string();
                        let status = args_val["status"].as_str().unwrap_or("").to_string();
                        let note = args_val["note"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();
                        let res = client
                            .patch(format!("{}/findings/{}/{}", args.server, channel, id_param))
                            .json(&json!({ "status": status, "note": note }))
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() =>
                                text(id, format!("[bridge] finding {} → {}", id_param, status)),
                            Ok(r) => {
                                let s = r.status();
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {body}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "share_artifact" => {
                        let filename = args_val["filename"].as_str().unwrap_or("artifact.bin").to_string();
                        let content_str = args_val["content"].as_str().unwrap_or("");
                        let is_b64 = args_val["base64"].as_bool().unwrap_or(false);
                        let mime = args_val["mime"]
                            .as_str()
                            .unwrap_or(if is_b64 { "application/octet-stream" } else { "text/plain" })
                            .to_string();
                        let notes = args_val["notes"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();

                        // Decode if claimed base64; otherwise treat as raw text bytes.
                        let bytes: Vec<u8> = if is_b64 {
                            match decode_base64(content_str) {
                                Ok(b) => b,
                                Err(e) => {
                                    let response = text(id, format!("[bridge] ERROR: bad base64: {e}"));
                                    let mut out = serde_json::to_string(&response).unwrap();
                                    out.push('\n');
                                    let _ = writer.write_all(out.as_bytes()).await;
                                    let _ = writer.flush().await;
                                    continue;
                                }
                            }
                        } else {
                            content_str.as_bytes().to_vec()
                        };

                        let res = client
                            .post(format!("{}/artifacts/{}", args.server, channel))
                            .header("content-type", &mime)
                            .header("x-bridge-from", &args.name)
                            .header("x-bridge-filename", &filename)
                            .body(bytes)
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let v: Value = r.json().await.unwrap_or(json!({}));
                                let aid = v["id"].as_str().unwrap_or("?").to_string();
                                let size = v["size"].as_u64().unwrap_or(0);
                                // Drop a chat ping so the peer's between-turn
                                // watcher wakes them up and they see the URL.
                                let ping = format!(
                                    "📎 artifact: {} ({} bytes)\nDownload: {}/artifact/{}\nNotes: {}",
                                    filename, size, args.server, aid, notes
                                );
                                let _ = client
                                    .post(format!("{}/send/{}", args.server, channel))
                                    .json(&json!({ "from": args.name, "content": ping }))
                                    .send()
                                    .await;
                                text(
                                    id,
                                    format!(
                                        "[bridge] artifact uploaded (id {}, {} bytes): {}/artifact/{}",
                                        aid, size, args.server, aid
                                    ),
                                )
                            }
                            Ok(r) => {
                                let s = r.status();
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {body}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "clear_channel" => {
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or(&args.channel)
                            .to_string();

                        let _ = client
                            .delete(format!("{}/messages/{}", args.server, channel))
                            .send()
                            .await;

                        text(id, format!("[bridge] channel '{}' cleared", channel))
                    }

                    _ => err(id, -32601, "unknown tool"),
                }
            }

            _ => err(id, -32601, &format!("unknown method: {}", req.method)),
        };

        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        let _ = writer.write_all(out.as_bytes()).await;
        let _ = writer.flush().await;
    }
}

/// Tiny standard-base64 decoder. We avoid the `base64` crate dep
/// because the rest of this binary is stdlib + reqwest + serde and
/// adding a transitive dependency for ~30 lines is poor taste.
fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if s.len() % 4 != 0 {
        return Err(format!("length {} not a multiple of 4", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut v = [0u8; 4];
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                v[i] = 0;
            } else {
                v[i] = table[c as usize];
                if v[i] == 255 {
                    return Err(format!("bad char {:?}", c as char));
                }
            }
        }
        let triple =
            ((v[0] as u32) << 18) | ((v[1] as u32) << 12) | ((v[2] as u32) << 6) | v[3] as u32;
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        // hand-encoded "Hello, world!" → "SGVsbG8sIHdvcmxkIQ=="
        assert_eq!(
            decode_base64("SGVsbG8sIHdvcmxkIQ==").unwrap(),
            b"Hello, world!".to_vec()
        );
        assert_eq!(decode_base64("YWI=").unwrap(), b"ab".to_vec());
        assert_eq!(decode_base64("YQ==").unwrap(), b"a".to_vec());
        assert_eq!(decode_base64("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(decode_base64("not_base64!").is_err());
        assert!(decode_base64("ABC").is_err()); // length 3 not multiple of 4
    }
}
