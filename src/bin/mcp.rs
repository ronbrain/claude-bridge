use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
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
                "description": "Read recent messages from the shared channel. Use this to see what the other instance has sent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string", "description": "Channel to read (default: configured channel)" }
                    }
                }
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
                "description": "Report a security finding to the other instance. Use this after discovering a vulnerability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title":    { "type": "string", "description": "Short title of the finding" },
                        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                        "endpoint": { "type": "string", "description": "Affected endpoint" },
                        "detail":   { "type": "string", "description": "Full description and proof" },
                        "channel":  { "type": "string" }
                    },
                    "required": ["title", "severity", "detail"]
                }
            },
            {
                "name": "clear_channel",
                "description": "Clear all messages from a channel to start fresh.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" }
                    }
                }
            }
        ]
    })
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let client = reqwest::Client::new();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = stdout;
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
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
                "serverInfo": { "name": "claude-bridge", "version": "0.1.0" }
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

                        let res = client
                            .get(format!("{}/messages/{}", args.server, channel))
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

                        let content = format!(
                            "🔴 FINDING [{severity}]\nTitle: {title}\nEndpoint: {endpoint}\n\n{detail}"
                        );

                        let _ = client
                            .post(format!("{}/send/{}", args.server, channel))
                            .json(&json!({ "from": args.name, "content": content }))
                            .send()
                            .await;

                        text(id, format!("[bridge] finding '{}' reported ✓", title))
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
