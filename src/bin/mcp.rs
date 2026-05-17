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

    /// Name shown to the other instance. When left at the default
    /// (`auto`), the MCP derives a per-session identity of the form
    /// `<host>/<short-session-id>` so two Claude Code sessions on
    /// the same host appear as distinct peers. The lookup uses the
    /// same session file the SessionStart hook writes (PPID chain),
    /// so it works without any extra config — install the hook and
    /// don't pass `--name` and you're done. Pass an explicit value
    /// to override (e.g. for one-shot CLI testing).
    #[arg(long, default_value = "auto")]
    name: String,

    /// Roles this instance claims (e.g. `pentest`, `integration`,
    /// `ops`). Comma-separated. Sent on every heartbeat so other
    /// peers can address `to: ["pentest"]` and have it resolve to
    /// the live instance(s) claiming that role. Empty = no role.
    #[arg(long, default_value = "")]
    role: String,
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
                "description": "Send a message to the other Claude Code instance in real time. Use this to share findings, ask questions, or coordinate tasks.\n\n**Routing**: each channel has a declared `topic` describing what it's for — call `list_channels` first if unsure where a message belongs. The confirmation echoes the channel's current topic so you can catch misroutes immediately.\n\n**Addressing (optional)**: pass `to` as a list of identity names (`paledo/9c4e1d`) and/or role aliases (`pentest`, `integration`). Roles resolve against the live `/peers` list — the message is delivered to every peer currently advertising that role. Leave `to` empty for a broadcast (every subscriber sees it). Use addressing when only one specific instance should act, even though other instances are subscribed to the channel.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": { "type": "string", "description": "Message to send" },
                        "channel": { "type": "string", "description": "Channel (default: configured channel)" },
                        "to":      { "type": "array",  "items": { "type": "string" }, "description": "Optional recipients — identity names and/or roles. Empty = broadcast." }
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
                "name": "list_channels",
                "description": "List every known channel with its declared topic (purpose). Use this BEFORE `send_message` when you're unsure which channel a message belongs in — posting pentest findings into an integration channel, or vice versa, pollutes the stream and forces a manual cleanup.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "set_channel_topic",
                "description": "Declare or update the topic (purpose) of a channel. The topic is shown by `list_channels` and echoed in `send_message` confirmations, so peers can see what each channel is reserved for. Use a short one-liner.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "topic":   { "type": "string", "description": "One-line purpose, e.g. \"Gezer↔Pale integration only — pentest goes to #pale-pentest\"" }
                    },
                    "required": ["channel", "topic"]
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
        loop {
            // Re-resolve BOTH name and roles on every heartbeat.
            // SessionStart may write the rendezvous file after the
            // MCP child has started (race: Claude Code spawns MCP
            // and SessionStart in parallel with no ordering
            // guarantee). Re-deriving each tick means the first
            // heartbeat after SessionStart wins, and the peer entry
            // corrects itself within 20s instead of staying stuck
            // on `hostname` until the next MCP restart.
            let name = current_name(&args.name);
            let roles = resolve_roles(&args.role);
            // URL-encode `/` (and `?`, `#`) in the name. Auto-derived
            // identities like `paledo/0f4543` contain a slash that
            // axum's `/presence/{name}` route would otherwise split
            // into two path segments → 404 → silent heartbeat loss.
            let url = format!("{}/presence/{}", args.server, encode_path_segment(&name));
            let _ = client
                .post(&url)
                .json(&json!({ "channel": args.channel, "roles": roles }))
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    });
    h.abort_handle()
}

/// Percent-encode the reserved characters that would otherwise break
/// path matching when the name is interpolated into a URL. We don't
/// pull in the `percent-encoding` crate for this — only a handful of
/// chars matter for our `<host>/<short-sid>` identity format.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'/' => out.push_str("%2F"),
            b'?' => out.push_str("%3F"),
            b'#' => out.push_str("%23"),
            b'%' => out.push_str("%25"),
            b' ' => out.push_str("%20"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Resolve the name to use right now. Explicit `--name foo` wins;
/// otherwise derive `<host>/<short-sid>` (or hostname fallback).
/// Called per-heartbeat and per-send so a delayed SessionStart
/// auto-corrects the peer identity within one tick.
fn current_name(flag: &str) -> String {
    if flag != "auto" && flag != "instance" && !flag.is_empty() {
        return flag.to_string();
    }
    derive_name()
}

/// Build the auto-derived `<host>/<short-session-id>` name used when
/// `--name` is left at the default. Mirrors what bridge-identity.sh
/// does for the shell-side hooks so MCP, watcher, and drain all
/// agree on the same identity for the same Claude Code session.
///
/// Resolution: env var first (set in bash but NOT in MCP children —
/// Claude Code intentionally doesn't propagate it to mcpServer
/// stdio launches), then the rendezvous file
/// `~/.cache/bridge/session-<claude_pid>` written by SessionStart.
fn derive_name() -> String {
    let host = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "instance".into());
    if let Some(sid) = current_session_id() {
        let short: String = sid.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect();
        if !short.is_empty() {
            return format!("{host}/{short}");
        }
    }
    host
}

/// Find this process's owning Claude Code session_id. Used by
/// `derive_name()` and `resolve_roles()` — see those for context.
///
/// 1. `$CLAUDE_CODE_SESSION_ID` if present.
/// 2. Walk the parent chain to find the first ancestor with
///    `comm = "claude"`, read its cmdline for a UUID arg (works
///    for `claude --resume <uuid>`), or fall back to reading
///    `~/.cache/bridge/session-<claude_pid>` written by the
///    SessionStart hook.
fn current_session_id() -> Option<String> {
    if let Ok(sid) = std::env::var("CLAUDE_CODE_SESSION_ID") {
        if !sid.is_empty() {
            return Some(sid);
        }
    }
    let claude_pid = find_claude_ancestor_pid()?;
    // Rendezvous file is the canonical source (SessionStart wrote
    // the same session_id Claude Code reports to its hooks). Try it
    // before the cmdline scrape so we don't depend on argv layout.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let cache_dir =
        std::env::var("BRIDGE_CACHE_DIR").unwrap_or_else(|_| format!("{home}/.cache/bridge"));
    let path = format!("{cache_dir}/session-{claude_pid}");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    // Fallback: grep the claude process cmdline for a UUID. Covers
    // `claude --resume <uuid>` when SessionStart hasn't run yet.
    let cmdline = std::fs::read_to_string(format!("/proc/{claude_pid}/cmdline")).ok()?;
    for tok in cmdline.split('\0') {
        if looks_like_uuid(tok) {
            return Some(tok.to_string());
        }
    }
    None
}

/// Walk parent IDs until we find a process whose `comm` is `claude`.
/// Returns its PID. Bounded to 10 hops so a runaway loop is impossible.
fn find_claude_ancestor_pid() -> Option<u32> {
    let mut pid = std::os::unix::process::parent_id();
    for _ in 0..10 {
        if pid <= 1 {
            return None;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        if comm.trim() == "claude" {
            return Some(pid);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rsplit_once(')').map(|(_, rest)| rest)?.trim();
        let parts: Vec<&str> = after.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        pid = parts[1].parse().ok()?;
    }
    None
}

/// Cheap UUID heuristic — 8-4-4-4-12 hex with hyphens.
fn looks_like_uuid(s: &str) -> bool {
    let s = s.as_bytes();
    if s.len() != 36 {
        return false;
    }
    for (i, &b) in s.iter().enumerate() {
        let expect_hyphen = matches!(i, 8 | 13 | 18 | 23);
        if expect_hyphen {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Roles resolution precedence (highest first):
///   1. `--role` flag explicitly set.
///   2. `$BRIDGE_ROLE` env var.
///   3. `~/.cache/bridge/roles/<CLAUDE_CODE_SESSION_ID>` — the file
///      the `bridge role` CLI and the SessionStart hook write.
fn resolve_roles(flag: &str) -> Vec<String> {
    let split_csv = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    };
    if !flag.is_empty() {
        return split_csv(flag);
    }
    if let Ok(env) = std::env::var("BRIDGE_ROLE") {
        if !env.is_empty() {
            return split_csv(&env);
        }
    }
    if let Some(sid) = current_session_id() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let cache_dir = std::env::var("BRIDGE_CACHE_DIR")
            .unwrap_or_else(|_| format!("{home}/.cache/bridge"));
        let role_file = format!("{cache_dir}/roles/{sid}");
        if let Ok(s) = std::fs::read_to_string(&role_file) {
            return split_csv(&s);
        }
    }
    Vec::new()
}

#[tokio::main]
async fn main() {
    let parsed = Args::parse();
    let args = Arc::new(parsed);
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
                        let to_raw: Vec<String> = args_val["to"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        // Resolve roles to identity names by querying
                        // /peers — every name that matches an entry's
                        // `roles` is added. Bare identity names (those
                        // that match a peer `name`) pass through. This
                        // happens client-side so the server stays a
                        // dumb relay.
                        let resolved_to = resolve_recipients(
                            &client, &args.server, &to_raw,
                        )
                        .await;

                        let res = client
                            .post(format!("{}/send/{}", args.server, channel))
                            .json(&json!({
                                "from": current_name(&args.name),
                                "content": content,
                                "to": resolved_to,
                            }))
                            .send()
                            .await;

                        match res {
                            Ok(r) if r.status().is_success() => {
                                // Fetch the channel topic so the
                                // confirmation echoes what the channel
                                // is for — catches misroutes on the
                                // turn the send happens, not days later.
                                let topic_resp = client
                                    .get(format!("{}/channels/{}/topic", args.server, channel))
                                    .send()
                                    .await;
                                let topic = match topic_resp {
                                    Ok(r) => r
                                        .json::<Value>()
                                        .await
                                        .ok()
                                        .and_then(|v| v["topic"].as_str().map(|s| s.to_string()))
                                        .unwrap_or_default(),
                                    Err(_) => String::new(),
                                };
                                let to_tag = if resolved_to.is_empty() {
                                    " (broadcast)".to_string()
                                } else {
                                    format!(" — to: {}", resolved_to.join(", "))
                                };
                                let msg = if topic.is_empty() {
                                    format!("[bridge] sent to '{channel}'{to_tag} ✓ (no topic declared — call set_channel_topic if this channel has a specific purpose)")
                                } else {
                                    format!("[bridge] sent to '{channel}'{to_tag} ✓ — topic: {topic}")
                                };
                                text(id, msg)
                            }
                            _ =>
                                text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "list_channels" => {
                        let res = client
                            .get(format!("{}/channels", args.server))
                            .send()
                            .await;
                        match res {
                            Ok(r) => {
                                let chans: Vec<Value> = r.json().await.unwrap_or_default();
                                if chans.is_empty() {
                                    text(id, "[bridge] no channels yet")
                                } else {
                                    let formatted = chans
                                        .iter()
                                        .map(|c| {
                                            let name = c["name"].as_str().unwrap_or("?");
                                            let topic = c["topic"].as_str().unwrap_or("");
                                            if topic.is_empty() {
                                                format!("• #{name} — (no topic)")
                                            } else {
                                                format!("• #{name} — {topic}")
                                            }
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    text(id, formatted)
                                }
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "set_channel_topic" => {
                        let channel = args_val["channel"].as_str().unwrap_or("").to_string();
                        let topic = args_val["topic"].as_str().unwrap_or("").to_string();
                        if channel.is_empty() {
                            text(id, "[bridge] ERROR: channel required")
                        } else {
                            let res = client
                                .put(format!("{}/channels/{}/topic", args.server, channel))
                                .json(&json!({ "from": current_name(&args.name), "topic": topic }))
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] #{channel} topic set: {topic}")),
                                Ok(r) => {
                                    let s = r.status();
                                    let body = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {body}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
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
                                            let roles: Vec<String> = p["roles"]
                                                .as_array()
                                                .map(|a| a.iter()
                                                    .filter_map(|v| v.as_str().map(String::from))
                                                    .collect())
                                                .unwrap_or_default();
                                            let role_tag = if roles.is_empty() {
                                                String::new()
                                            } else {
                                                format!(" [roles: {}]", roles.join(","))
                                            };
                                            format!(
                                                "• {} — idle {}s on #{}{}",
                                                p["name"].as_str().unwrap_or("?"),
                                                p["idle_secs"].as_u64().unwrap_or(0),
                                                p["channel"].as_str().unwrap_or("?"),
                                                role_tag,
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
                            .json(&json!({ "from": current_name(&args.name), "content": content }))
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
                                "from": current_name(&args.name),
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
                                    .json(&json!({ "from": current_name(&args.name), "content": ping }))
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
                            .header("x-bridge-from", current_name(&args.name))
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
                                    .json(&json!({ "from": current_name(&args.name), "content": ping }))
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

/// Resolve a list of identity-or-role strings into concrete peer
/// names. Anything that matches a peer's `roles` array contributes
/// every matching peer's `name`; anything that matches a peer's
/// `name` passes through unchanged; bare strings with no match are
/// kept as-is (so an offline peer's identity stays addressable —
/// the daemon writes the message to disk and the peer picks it up
/// on reconnect). De-duplicated; order preserved by first
/// appearance.
async fn resolve_recipients(
    client: &reqwest::Client,
    server: &str,
    raw: &[String],
) -> Vec<String> {
    if raw.is_empty() {
        return Vec::new();
    }
    // Single /peers fetch — no point hitting the server per token.
    let peers: Vec<Value> = match client.get(format!("{server}/peers")).send().await {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut push = |s: String, out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    };
    for token in raw {
        let mut matched_role = false;
        for p in &peers {
            let roles: Vec<String> = p["roles"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if roles.iter().any(|r| r == token) {
                if let Some(name) = p["name"].as_str() {
                    push(name.to_string(), &mut out, &mut seen);
                    matched_role = true;
                }
            }
        }
        if !matched_role {
            // Either a literal identity or an unknown token; either
            // way pass it through verbatim so the addressee can match
            // when they later come online.
            push(token.clone(), &mut out, &mut seen);
        }
    }
    out
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
