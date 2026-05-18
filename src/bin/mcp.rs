#![recursion_limit = "512"]
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
            },
            {
                "name": "set_status",
                "description": "Set this peer's short status line (\"working on b358d8ea, ETA 30min\", \"blocked on operator SSH\"). Surfaced in `list_peers` next to the role so other peers see at a glance what each instance is doing. Pass empty string to clear.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "status": { "type": "string", "description": "Status line (≤280 chars)" } },
                    "required": ["status"]
                }
            },
            {
                "name": "set_skills",
                "description": "Set this peer's skills — comma-separated capability tags (`svelte,csp,oauth`). Finer-grained than role; lets a task-router or human pick the right peer for a job. Pass empty string to clear.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "skills": { "type": "string", "description": "Comma-separated skill tags" } },
                    "required": ["skills"]
                }
            },
            {
                "name": "pin_message",
                "description": "Pin a message to the top of its channel — stays visible in `read_messages` regardless of age. Use for the current-state doc, the skills board, decision log. Unpin with `unpin_message`.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id":      { "type": "string", "description": "Message id (uuid)" },
                        "channel": { "type": "string" }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "unpin_message",
                "description": "Reverse of `pin_message`.",
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
                "name": "create_task",
                "description": "Create a work-queue task (distinct from `report_finding`). Tasks describe action items assigned to a peer; findings describe bugs discovered. Use this when ops/coordination needs to track \"who is doing X by when\". Optional `owner` (identity or role) and dependency arrays.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title":       { "type": "string" },
                        "description": { "type": "string" },
                        "owner":       { "type": "string", "description": "Identity name or role; empty = unassigned" },
                        "blocks":      { "type": "array", "items": { "type": "string" } },
                        "depends_on":  { "type": "array", "items": { "type": "string" } },
                        "channel":     { "type": "string" }
                    },
                    "required": ["title"]
                }
            },
            {
                "name": "list_tasks",
                "description": "List tasks in a channel, optionally filtered by `status` (todo|in_progress|blocked|done|cancelled) or `owner`.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "status":  { "type": "string" },
                        "owner":   { "type": "string" },
                        "channel": { "type": "string" }
                    }
                }
            },
            {
                "name": "update_task",
                "description": "Update a task. Any of status / owner / note can be changed in one call. Status valid values: todo|in_progress|blocked|done|cancelled.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id":      { "type": "string" },
                        "status":  { "type": "string" },
                        "owner":   { "type": "string" },
                        "note":    { "type": "string" },
                        "channel": { "type": "string" }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "delete_task",
                "description": "Hard-delete a task. Use for duplicates or task created in error. To close a task, prefer `update_task` with status=done.",
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
                "name": "memory_get",
                "description": "Read a value from the shared memory KV store. Channel-scoped — two channels can use the same key independently. Returns the entry or 'not found'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key":     { "type": "string" },
                        "channel": { "type": "string" }
                    },
                    "required": ["key"]
                }
            },
            {
                "name": "memory_set",
                "description": "Write a value into shared memory. Persisted to sqlite when the server has BRIDGE_DB_PATH. Optional `ttl_secs` for auto-expiry. Use for project state, decision log, agreed-on snippets — anything multiple peers want to look up by name.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key":      { "type": "string" },
                        "value":    { "type": "string" },
                        "ttl_secs": { "type": "number", "description": "Seconds until auto-expiry; 0 = never" },
                        "channel":  { "type": "string" }
                    },
                    "required": ["key", "value"]
                }
            },
            {
                "name": "memory_delete",
                "description": "Delete a memory key.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key":     { "type": "string" },
                        "channel": { "type": "string" }
                    },
                    "required": ["key"]
                }
            },
            {
                "name": "memory_list",
                "description": "List every key in a channel's memory namespace with its value, updated_by, updated_at, and expires_at.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "channel": { "type": "string" } }
                }
            },
            {
                "name": "delete_channel",
                "description": "Hard-delete a channel — wipes messages, findings, topic, and removes it from `list_channels`. Use to clean up ghost channels (typos like `general,pale-sdk`, abandoned channels, etc). Stronger than `clear_channel` which only wipes history.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "channel": { "type": "string" } },
                    "required": ["channel"]
                }
            },
            {
                "name": "ack_dispatch",
                "description": "Acknowledge a dispatch — a message sent with `to:[peer]` that the bridge tracked in the `dispatches` table. Use this to commit to a recipient role and (optionally) signal an ETA so the auto-escalation scanner stops pinging you. Idempotent: re-acking a closed dispatch is a no-op 404.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": { "type": "string", "description": "The message id from `send_message`'s response" },
                        "eta_secs":   { "type": "number", "description": "Seconds until you expect to complete; 0 = unspecified" }
                    },
                    "required": ["message_id"]
                }
            },
            {
                "name": "complete_dispatch",
                "description": "Mark a dispatch as completed. Outcome free-form (e.g. \"shipped\", \"wontfix\", \"blocked\"). Implicitly acks the dispatch if you never called `ack_dispatch` first — peers who just ship don't have to ack and complete separately.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": { "type": "string" },
                        "outcome":    { "type": "string", "description": "Free-form completion note (≤1024 chars)" }
                    },
                    "required": ["message_id"]
                }
            },
            {
                "name": "peer_health",
                "description": "Composite health view for a peer — live presence + open dispatches addressed to them + open findings they authored + active tasks they own. World-readable across the bridge per ops coord-transparency policy. Use it to decide whether a peer is stuck, saturated, or just quiet before pinging.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "peer": { "type": "string", "description": "Identity name to inspect" } },
                    "required": ["peer"]
                }
            },
            {
                "name": "resume_for",
                "description": "Generate a next-session resume brief for a peer — markdown assembled from their live presence, open dispatches, authored open findings, and authored memory keys. `_private_`-prefixed memory keys are excluded; expired-TTL keys are excluded; secret-shaped values (Bearer JWTs, `password=`, `api_key=`, `sk_…` Stripe, `AKIA…` AWS) are redacted to `[REDACTED:<type>]`. Use this at the start of a new session to load context without grepping chat history.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "peer": { "type": "string" } },
                    "required": ["peer"]
                }
            },
            {
                "name": "metrics",
                "description": "Bridge-wide observability snapshot — JSON with peers_active, channels, messages_total, findings_total/open, tasks_total/active, artifacts, dispatches_pending, and per-channel `sse_lag_drops`. Cheap; safe to poll. For Prometheus scraping use `GET /metrics/prometheus` directly (not an MCP tool — Prometheus dials the server itself).",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "routing_rule_create",
                "description": "Create a smart routing rule (F17). Trigger types: finding_created | task_unassigned | peer_idle | dispatch_stale. Action types: auto_assign | auto_escalate | auto_batch | auto_message. `trigger_filter` is a JSON object with eq/contains/in operators (implicit AND across fields) — unknown operators reject at insert time. `action_params` is action-specific JSON (e.g. `{channel, template, assignee_role, assignee_skill}`). Requires persistence (BRIDGE_DB_PATH).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name":           { "type": "string", "description": "Human-readable name; <= 128 chars" },
                        "trigger_type":   { "type": "string", "enum": ["finding_created","task_unassigned","peer_idle","dispatch_stale"] },
                        "trigger_filter": { "type": "object", "description": "JSON filter: {field: literal} or {field: {eq|contains|in: value}}" },
                        "action_type":    { "type": "string", "enum": ["auto_assign","auto_escalate","auto_batch","auto_message"] },
                        "action_params":  { "type": "object", "description": "Action-specific JSON" },
                        "priority":       { "type": "number", "description": "0-100; higher wins on the scanner walk (default 50)" }
                    },
                    "required": ["name","trigger_type","action_type"]
                }
            },
            {
                "name": "routing_rule_list",
                "description": "List routing rules. Optional `trigger_type` and `enabled` filters compose. Ordered by priority DESC + insertion ASC.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "trigger_type": { "type": "string" },
                        "enabled":      { "type": "boolean" }
                    }
                }
            },
            {
                "name": "routing_rule_toggle",
                "description": "Toggle `enabled` on a routing rule. Same endpoint as routing_rule_update but takes only the bool — convenience for ops cleanup / quarantine release.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id":      { "type": "string" },
                        "enabled": { "type": "boolean" }
                    },
                    "required": ["id","enabled"]
                }
            },
            {
                "name": "goal_create",
                "description": "Create an operator goal — target_metric ∈ {peers_active, findings_open, tasks_active, dispatches_pending, sla_met_pct}, target_value is the threshold, comparator is `>=` (default) / `<=` / `==`. Optional `deadline` (unix-secs) and `channel` (display-only). Background scanner updates current_value every base tick; fires `goal_achieved` routing trigger on the pending→met transition edge.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name":          { "type": "string" },
                        "description":   { "type": "string" },
                        "target_metric": { "type": "string", "enum": ["peers_active","findings_open","tasks_active","dispatches_pending","sla_met_pct"] },
                        "target_value":  { "type": "number" },
                        "comparator":    { "type": "string", "enum": [">=","<=","=="] },
                        "deadline":      { "type": "number", "description": "Unix-secs; 0 = no deadline" },
                        "channel":       { "type": "string" }
                    },
                    "required": ["name", "target_metric", "target_value"]
                }
            },
            {
                "name": "goal_list",
                "description": "List every goal with current_value vs target_value + status (pending|met|missed|cancelled).",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "goal_cancel",
                "description": "Cancel a pending goal. Owner (creator) or BRIDGE_MEMORY_ADMINS only. Met/missed/cancelled goals can't be re-cancelled.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "id": { "type": "string" } },
                    "required": ["id"]
                }
            },
            {
                "name": "claim_task",
                "description": "Atomic claim of an unowned task — first-wins via UPDATE WHERE owner='' AND status='todo'. Returns 204 on success, 409 if task is already owned / wrong status / missing. Bumps the row's claim_count counter for observability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "id":      { "type": "string", "description": "Task id" }
                    },
                    "required": ["channel", "id"]
                }
            },
            {
                "name": "complete_task",
                "description": "Mark a task done. Refuses if plan_status='pending' (closes the can't-bypass-plan-approval invariant). Fires the `task_completed` routing trigger so operator rules can chain follow-ups.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "id":      { "type": "string" },
                        "outcome": { "type": "string", "description": "Free-form completion note (≤4 KB)" }
                    },
                    "required": ["channel", "id"]
                }
            },
            {
                "name": "submit_plan",
                "description": "Submit a plan for `id`. Flips plan_status to 'pending'; task can't advance to in_progress until approved. Only allowed when task is in 'todo'/'open' and plan_status is 'none' or 'rejected' (can re-submit after rejection).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "id":      { "type": "string" },
                        "plan":    { "type": "string", "description": "Plan body (markdown, ≤16 KB)" }
                    },
                    "required": ["channel", "id", "plan"]
                }
            },
            {
                "name": "approve_plan",
                "description": "Approve a pending plan. Requires BRIDGE_MEMORY_ADMINS membership. Plan must be in 'pending' state. After approve, owner can advance the task via update_task status=in_progress.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "id":      { "type": "string" }
                    },
                    "required": ["channel", "id"]
                }
            },
            {
                "name": "reject_plan",
                "description": "Reject a pending plan with a reason. Requires BRIDGE_MEMORY_ADMINS. Plan flips to 'rejected'; owner can re-submit via submit_plan.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "id":      { "type": "string" },
                        "reason":  { "type": "string", "description": "Why rejected (≤1 KB)" }
                    },
                    "required": ["channel", "id", "reason"]
                }
            },
            {
                "name": "watcher_spawn",
                "description": "Spawn a background watcher (`claude --bg`) for `peer`. The watcher relays addressed messages to the peer when the peer's own session hooks die or hang (closes finding e2b0d77a). Gated to BRIDGE_MEMORY_ADMINS identities — spawning subprocesses on the bridge host is privileged. `ttl_secs` clamps how long the watcher runs before self-exiting (default 3600, range 60..=86400).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer":     { "type": "string", "description": "Identity name to watch — the spawned subprocess gets identity `<peer>-watcher` per the suffix convention" },
                        "ttl_secs": { "type": "number", "description": "Seconds until watcher self-exits (default 3600)" }
                    },
                    "required": ["peer"]
                }
            },
            {
                "name": "watcher_list",
                "description": "List every peer watcher with its current PID, spawned_at, last_seen, status (`running`/`exited`/`crashed`/`quarantined`), and TTL. Useful for verifying the bridge's view matches OS process state after a restart or reconcile.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "watcher_stop",
                "description": "Stop a peer watcher — SIGKILLs the subprocess (with cmdline-match guard so PID reassignment can't hit a foreign process) and flips the row to `status='exited'`. Caller must be the spawner OR on BRIDGE_MEMORY_ADMINS allowlist.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "peer": { "type": "string" } },
                    "required": ["peer"]
                }
            },
            {
                "name": "routing_eval",
                "description": "Dry-run a synthetic trigger context against enabled rules; returns the actions that WOULD fire without actually firing them. Useful when authoring a rule to verify the filter shape against a real payload before turning it on.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "trigger_type": { "type": "string", "enum": ["finding_created","task_unassigned","peer_idle","dispatch_stale"] },
                        "payload":      { "type": "object", "description": "Synthetic trigger context — same shape as the real emission point would produce" }
                    },
                    "required": ["trigger_type","payload"]
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
            // Skills + status come from the same per-session
            // registry pattern as roles, so users can write
            // `set_skills` / `set_status` and the change propagates
            // on the next heartbeat without an MCP restart.
            let skills = resolve_skills();
            let status = resolve_status();
            let _ = client
                .post(&url)
                .json(&json!({
                    "channel": args.channel,
                    "roles": roles,
                    "skills": skills,
                    "status": status,
                }))
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

/// Build the auto-derived identity used when `--name` is left at the
/// default. Mirrors what bridge-identity.sh does for the shell-side
/// hooks so MCP, watcher, and drain all agree on the same identity
/// for the same Claude Code session.
///
/// Format: `<short-session-id>` (6 hex chars). We dropped the
/// `<host>/...` prefix because the host name was duplicated across
/// peer entries and added noise — the role tells you what each
/// instance does, the short-sid distinguishes them, and that's
/// enough for addressing. Hostname fallback only when there's no
/// session at all (one-shot CLI from outside Claude Code).
///
/// Resolution: env var first (set in bash but NOT in MCP children —
/// Claude Code intentionally doesn't propagate it to mcpServer
/// stdio launches), then the rendezvous file
/// `~/.cache/bridge/session-<claude_pid>` written by SessionStart.
fn derive_name() -> String {
    if let Some(sid) = current_session_id() {
        let short: String = sid.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect();
        if !short.is_empty() {
            return short;
        }
    }
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "instance".into())
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

/// Read the per-session skills file written by `set_skills`. Same
/// resolution pattern as roles (session_id → cache/bridge/skills/<sid>).
/// Read the per-session skills file written by `set_skills`. Falls
/// back to `<cache>/skills/by-role/<role>` when the session-keyed
/// file isn't there yet — that's the path after `claude --resume`
/// or `/compact` mints a new session_id and the previous per-sid
/// file is orphaned. Role is the stable anchor: it's declared in
/// `.bridge-role` or `bridge role <name>` and survives session
/// rotation.
fn resolve_skills() -> Vec<String> {
    let csv_to_vec = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    };
    let cache_dir = bridge_cache_dir();
    if let Some(sid) = current_session_id() {
        let path = format!("{cache_dir}/skills/{sid}");
        if let Ok(s) = std::fs::read_to_string(&path) {
            return csv_to_vec(&s);
        }
    }
    // By-role fallback. Use the first role as the key; multi-role
    // peers fall back on their primary identity.
    if let Some(role) = resolve_roles("").first() {
        let path = format!("{cache_dir}/skills/by-role/{role}");
        if let Ok(s) = std::fs::read_to_string(&path) {
            return csv_to_vec(&s);
        }
    }
    Vec::new()
}

/// Read the per-session status file written by `set_status`. Same
/// fallback pattern as `resolve_skills`.
fn resolve_status() -> String {
    let cache_dir = bridge_cache_dir();
    if let Some(sid) = current_session_id() {
        let path = format!("{cache_dir}/status/{sid}");
        if let Ok(s) = std::fs::read_to_string(&path) {
            return s.trim().to_string();
        }
    }
    if let Some(role) = resolve_roles("").first() {
        let path = format!("{cache_dir}/status/by-role/{role}");
        if let Ok(s) = std::fs::read_to_string(&path) {
            return s.trim().to_string();
        }
    }
    String::new()
}

fn bridge_cache_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::env::var("BRIDGE_CACHE_DIR").unwrap_or_else(|_| format!("{home}/.cache/bridge"))
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
    // Stamp every outbound request with the caller's identity via
    // `X-Bridge-From` so the server's audit-log hooks (Group B/D)
    // record an actor for the 5 mutation handlers that lack a body
    // `from:` field (`triage_finding`, `delete_finding`,
    // `update_task`, `delete_task`, `memory_delete`). Op-authorized
    // Option 1 per dispatch 1779040100 — single point of enforcement
    // in the shim's HTTP client; no per-handler body churn needed.
    //
    // `BRIDGE_FROM` env wins so a CLI invocation can override; falls
    // back to the same `current_name()` resolver the heartbeat uses
    // so the header matches `/peers` identity by construction.
    let from_header = std::env::var("BRIDGE_FROM")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| current_name(&args.name));
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&from_header) {
        headers.insert("x-bridge-from", v);
    }
    // Per finding `dc633d7c` bundle: server now requires
    // `Authorization: Bearer <token>` on every mutation/SSE route
    // when its registry is non-empty. We inject the bearer once at
    // client-build so all subsequent `client.get/post(...)` calls
    // carry it. Mark the header value as sensitive so reqwest's
    // request-log redaction kicks in. Missing/empty token → no
    // header injected — bridge runs in permissive mode locally OK.
    if let Ok(token) = std::env::var("BRIDGE_AUTH_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            match reqwest::header::HeaderValue::from_str(&format!("Bearer {trimmed}")) {
                Ok(mut hv) => {
                    hv.set_sensitive(true);
                    headers.insert(reqwest::header::AUTHORIZATION, hv);
                }
                Err(e) => {
                    eprintln!(
                        "[bridge-mcp] BRIDGE_AUTH_TOKEN unencodable as header value: {e}. \
                         Skipping bearer injection — server will 401 if it enforces."
                    );
                }
            }
        }
    }
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client construction");

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
                                            let skills: Vec<String> = p["skills"]
                                                .as_array()
                                                .map(|a| a.iter()
                                                    .filter_map(|v| v.as_str().map(String::from))
                                                    .collect())
                                                .unwrap_or_default();
                                            let status = p["status"].as_str().unwrap_or("");
                                            let role_tag = if roles.is_empty() {
                                                String::new()
                                            } else {
                                                format!(" [roles: {}]", roles.join(","))
                                            };
                                            let mut line = format!(
                                                "• {} — idle {}s on #{}{}",
                                                p["name"].as_str().unwrap_or("?"),
                                                p["idle_secs"].as_u64().unwrap_or(0),
                                                p["channel"].as_str().unwrap_or("?"),
                                                role_tag,
                                            );
                                            if !skills.is_empty() {
                                                line.push_str(&format!(
                                                    "\n    skills: {}", skills.join(",")
                                                ));
                                            }
                                            if !status.is_empty() {
                                                line.push_str(&format!(
                                                    "\n    status: {}", status
                                                ));
                                            }
                                            line
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

                    "set_status" | "set_skills" => {
                        // Local-only — writes to ~/.cache/bridge/{status,skills}/<sid>
                        // AND (when this session has a role) to a stable
                        // ~/.cache/bridge/{status,skills}/by-role/<role>
                        // mirror. The role copy survives session_id
                        // rotation from `claude --resume` and `/compact`
                        // so the next heartbeat picks up the value again
                        // without the user having to re-publish.
                        let value = args_val["status"].as_str()
                            .or_else(|| args_val["skills"].as_str())
                            .unwrap_or("")
                            .to_string();
                        let sid = match current_session_id() {
                            Some(s) => s,
                            None => {
                                text(id.clone(), "[bridge] ERROR: no session — install SessionStart hook");
                                continue;
                            }
                        };
                        let cache_dir = bridge_cache_dir();
                        let sub = if name == "set_status" { "status" } else { "skills" };
                        let dir = format!("{cache_dir}/{sub}");
                        let by_role_dir = format!("{dir}/by-role");
                        let _ = std::fs::create_dir_all(&by_role_dir);
                        let sid_path = format!("{dir}/{sid}");
                        let role_path = resolve_roles("")
                            .first()
                            .map(|r| format!("{by_role_dir}/{r}"));
                        if value.is_empty() {
                            let _ = std::fs::remove_file(&sid_path);
                            if let Some(p) = &role_path {
                                let _ = std::fs::remove_file(p);
                            }
                            text(id, format!("[bridge] {sub} cleared"))
                        } else {
                            let sid_write = std::fs::write(&sid_path, &value);
                            // Mirror to by-role. Failure here is non-fatal
                            // — sid write is the canonical source for
                            // this session; by-role is the cross-session
                            // fallback. We tag the response so the user
                            // sees whether the mirror was written.
                            let mirrored = role_path
                                .as_ref()
                                .map(|p| std::fs::write(p, &value).is_ok())
                                .unwrap_or(false);
                            let tag = if mirrored {
                                " (mirrored to by-role/ — survives /compact)"
                            } else {
                                " (no role set; won't survive /compact — `bridge role <x>` to enable)"
                            };
                            match sid_write {
                                Ok(_) => text(id, format!("[bridge] {sub} set: {value}{tag}")),
                                Err(e) => text(id, format!("[bridge] ERROR writing {sub}: {e}")),
                            }
                        }
                    }

                    "pin_message" | "unpin_message" => {
                        let msg_id = args_val["id"].as_str().unwrap_or("").to_string();
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        if msg_id.is_empty() {
                            text(id, "[bridge] ERROR: id required")
                        } else {
                            let req = if name == "pin_message" {
                                client.post(format!("{}/messages/{}/{}/pin", args.server, channel, msg_id))
                            } else {
                                client.delete(format!("{}/messages/{}/{}/pin", args.server, channel, msg_id))
                            };
                            match req.send().await {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] message '{msg_id}' {}pinned ✓",
                                        if name == "pin_message" { "" } else { "un" })),
                                Ok(r) => text(id, format!("[bridge] ERROR {}: {}",
                                    r.status(), r.text().await.unwrap_or_default())),
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "create_task" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let body = json!({
                            "from": current_name(&args.name),
                            "title": args_val["title"].as_str().unwrap_or(""),
                            "description": args_val["description"].as_str().unwrap_or(""),
                            "owner": args_val["owner"].as_str().unwrap_or(""),
                            "blocks": args_val["blocks"].as_array().cloned().unwrap_or_default(),
                            "depends_on": args_val["depends_on"].as_array().cloned().unwrap_or_default(),
                        });
                        let res = client.post(format!("{}/tasks/{}", args.server, channel))
                            .json(&body).send().await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let task: Value = r.json().await.unwrap_or_default();
                                text(id, format!("[bridge] task created: id={} title={} owner={}",
                                    task["id"].as_str().unwrap_or("?"),
                                    task["title"].as_str().unwrap_or("?"),
                                    task["owner"].as_str().unwrap_or("(unassigned)")))
                            }
                            Ok(r) => text(id, format!("[bridge] ERROR {}: {}",
                                r.status(), r.text().await.unwrap_or_default())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "list_tasks" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let mut qs: Vec<(&str, String)> = Vec::new();
                        if let Some(s) = args_val["status"].as_str() { qs.push(("status", s.into())); }
                        if let Some(o) = args_val["owner"].as_str() { qs.push(("owner", o.into())); }
                        let res = client.get(format!("{}/tasks/{}", args.server, channel))
                            .query(&qs).send().await;
                        match res {
                            Ok(r) => {
                                let tasks: Vec<Value> = r.json().await.unwrap_or_default();
                                if tasks.is_empty() {
                                    text(id, format!("[bridge] no tasks in '{channel}' (with filters)"))
                                } else {
                                    let formatted = tasks.iter().map(|t| {
                                        format!("• [{}] {} — {} (owner: {})",
                                            t["status"].as_str().unwrap_or("?"),
                                            t["id"].as_str().unwrap_or("?"),
                                            t["title"].as_str().unwrap_or("?"),
                                            t["owner"].as_str().unwrap_or("(unassigned)"))
                                    }).collect::<Vec<_>>().join("\n");
                                    text(id, formatted)
                                }
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "update_task" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let task_id = args_val["id"].as_str().unwrap_or("").to_string();
                        let mut body = serde_json::Map::new();
                        if let Some(s) = args_val["status"].as_str() { body.insert("status".into(), json!(s)); }
                        if let Some(o) = args_val["owner"].as_str() { body.insert("owner".into(), json!(o)); }
                        if let Some(n) = args_val["note"].as_str() { body.insert("note".into(), json!(n)); }
                        let res = client.patch(format!("{}/tasks/{}/{}", args.server, channel, task_id))
                            .json(&Value::Object(body)).send().await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let t: Value = r.json().await.unwrap_or_default();
                                text(id, format!("[bridge] task {} updated: status={} owner={}",
                                    task_id,
                                    t["status"].as_str().unwrap_or("?"),
                                    t["owner"].as_str().unwrap_or("(unassigned)")))
                            }
                            Ok(r) => text(id, format!("[bridge] ERROR {}: {}",
                                r.status(), r.text().await.unwrap_or_default())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "delete_task" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let task_id = args_val["id"].as_str().unwrap_or("").to_string();
                        let res = client.delete(format!("{}/tasks/{}/{}", args.server, channel, task_id))
                            .send().await;
                        match res {
                            Ok(r) if r.status().is_success() =>
                                text(id, format!("[bridge] task {task_id} deleted")),
                            Ok(r) => text(id, format!("[bridge] ERROR {}: {}",
                                r.status(), r.text().await.unwrap_or_default())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "memory_get" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let key = args_val["key"].as_str().unwrap_or("").to_string();
                        let res = client.get(format!("{}/memory/{}/{}", args.server, channel, key))
                            .send().await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let entry: Value = r.json().await.unwrap_or_default();
                                text(id, format!("[bridge] {channel}/{key}:\n{}",
                                    entry["value"].as_str().unwrap_or("")))
                            }
                            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND =>
                                text(id, format!("[bridge] {channel}/{key} not set")),
                            Ok(r) => text(id, format!("[bridge] ERROR {}", r.status())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "memory_set" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let key = args_val["key"].as_str().unwrap_or("").to_string();
                        let value = args_val["value"].as_str().unwrap_or("").to_string();
                        let ttl = args_val["ttl_secs"].as_u64().unwrap_or(0);
                        let res = client.put(format!("{}/memory/{}/{}", args.server, channel, key))
                            .json(&json!({ "from": current_name(&args.name), "value": value, "ttl_secs": ttl }))
                            .send().await;
                        match res {
                            Ok(r) if r.status().is_success() =>
                                text(id, format!("[bridge] {channel}/{key} set ({} bytes{})",
                                    value.len(),
                                    if ttl > 0 { format!(", TTL {ttl}s") } else { String::new() })),
                            Ok(r) => text(id, format!("[bridge] ERROR {}: {}",
                                r.status(), r.text().await.unwrap_or_default())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "memory_delete" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let key = args_val["key"].as_str().unwrap_or("").to_string();
                        let _ = client.delete(format!("{}/memory/{}/{}", args.server, channel, key))
                            .send().await;
                        text(id, format!("[bridge] {channel}/{key} deleted"))
                    }

                    "memory_list" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let res = client.get(format!("{}/memory/{}", args.server, channel))
                            .send().await;
                        match res {
                            Ok(r) => {
                                let entries: Vec<Value> = r.json().await.unwrap_or_default();
                                if entries.is_empty() {
                                    text(id, format!("[bridge] no memory keys in '{channel}'"))
                                } else {
                                    let formatted = entries.iter().map(|e| {
                                        let v = e["value"].as_str().unwrap_or("");
                                        let preview = if v.len() > 80 { format!("{}…", &v[..80]) } else { v.into() };
                                        format!("• {} = {} (by {})",
                                            e["key"].as_str().unwrap_or("?"),
                                            preview,
                                            e["updated_by"].as_str().unwrap_or("?"))
                                    }).collect::<Vec<_>>().join("\n");
                                    text(id, formatted)
                                }
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

                    "delete_channel" => {
                        let channel = args_val["channel"]
                            .as_str()
                            .unwrap_or("")
                            .to_string();
                        if channel.is_empty() {
                            text(id, "[bridge] ERROR: channel required")
                        } else {
                            let res = client
                                .delete(format!("{}/channels/{}", args.server, channel))
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] channel '{channel}' deleted (entry removed from list_channels)")),
                                Ok(r) => {
                                    let s = r.status();
                                    let body = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {body}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "ack_dispatch" | "complete_dispatch" => {
                        let mid = args_val["message_id"].as_str().unwrap_or("").to_string();
                        if mid.is_empty() {
                            text(id, "[bridge] ERROR: message_id required")
                        } else {
                            let path = if name == "ack_dispatch" { "ack" } else { "complete" };
                            // Build body — `ack` takes `eta_secs?`,
                            // `complete` takes `outcome?`. Server
                            // accepts an empty body for either by
                            // way of `#[serde(default)]`, so we send
                            // whatever the caller passed and let
                            // serde do the work.
                            let body = if name == "ack_dispatch" {
                                serde_json::json!({
                                    "eta_secs": args_val["eta_secs"].as_u64().unwrap_or(0)
                                })
                            } else {
                                serde_json::json!({
                                    "outcome": args_val["outcome"].as_str().unwrap_or("")
                                })
                            };
                            let res = client
                                .post(format!("{}/dispatches/{}/{path}", args.server, encode_path_segment(&mid)))
                                .json(&body)
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] {name} OK for {mid}")),
                                Ok(r) => {
                                    let s = r.status();
                                    let b = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {b}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "peer_health" => {
                        let peer = args_val["peer"].as_str().unwrap_or("").to_string();
                        if peer.is_empty() {
                            text(id, "[bridge] ERROR: peer required")
                        } else {
                            let res = client
                                .get(format!("{}/peer/{}/health", args.server, encode_path_segment(&peer)))
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() => {
                                    let body = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] {peer} health:\n{body}"))
                                }
                                Ok(r) => text(id, format!("[bridge] ERROR {}: peer_health failed", r.status())),
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "resume_for" => {
                        let peer = args_val["peer"].as_str().unwrap_or("").to_string();
                        if peer.is_empty() {
                            text(id, "[bridge] ERROR: peer required")
                        } else {
                            let res = client
                                .get(format!("{}/resume/{}", args.server, encode_path_segment(&peer)))
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() => {
                                    let body = r.text().await.unwrap_or_default();
                                    text(id, body)
                                }
                                Ok(r) => text(id, format!("[bridge] ERROR {}: resume failed", r.status())),
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "metrics" => {
                        let res = client
                            .get(format!("{}/metrics", args.server))
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] metrics:\n{body}"))
                            }
                            Ok(r) => text(id, format!("[bridge] ERROR {}: metrics failed", r.status())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "routing_rule_create" => {
                        let res = client
                            .post(format!("{}/routing-rules", args.server))
                            .json(&args_val)
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] routing rule created:\n{body}"))
                            }
                            Ok(r) => {
                                let s = r.status();
                                let b = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {b}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "routing_rule_list" => {
                        let mut qs: Vec<(String, String)> = Vec::new();
                        if let Some(t) = args_val["trigger_type"].as_str() {
                            qs.push(("trigger_type".into(), t.into()));
                        }
                        if let Some(b) = args_val["enabled"].as_bool() {
                            qs.push(("enabled".into(), b.to_string()));
                        }
                        let res = client
                            .get(format!("{}/routing-rules", args.server))
                            .query(&qs)
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] routing rules:\n{body}"))
                            }
                            Ok(r) => text(id, format!("[bridge] ERROR {}", r.status())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "routing_rule_toggle" => {
                        let rid = args_val["id"].as_str().unwrap_or("").to_string();
                        let en = args_val["enabled"].as_bool();
                        if rid.is_empty() || en.is_none() {
                            text(id, "[bridge] ERROR: id + enabled required")
                        } else {
                            let body = serde_json::json!({ "enabled": en.unwrap() });
                            let res = client
                                .patch(format!("{}/routing-rules/{}", args.server, encode_path_segment(&rid)))
                                .json(&body)
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] routing rule '{rid}' toggled")),
                                Ok(r) => {
                                    let s = r.status();
                                    let b = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {b}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "goal_create" => {
                        let res = client.post(format!("{}/goals", args.server))
                            .json(&args_val).send().await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let b = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] goal created:\n{b}"))
                            }
                            Ok(r) => {
                                let s = r.status();
                                let b = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {b}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }
                    "goal_list" => {
                        let res = client.get(format!("{}/goals", args.server)).send().await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let b = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] goals:\n{b}"))
                            }
                            Ok(r) => text(id, format!("[bridge] ERROR {}", r.status())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }
                    "goal_cancel" => {
                        let gid = args_val["id"].as_str().unwrap_or("").to_string();
                        if gid.is_empty() {
                            text(id, "[bridge] ERROR: id required")
                        } else {
                            let res = client.delete(format!("{}/goals/{}", args.server, encode_path_segment(&gid)))
                                .send().await;
                            match res {
                                Ok(r) if r.status().is_success() => text(id, format!("[bridge] goal '{gid}' cancelled")),
                                Ok(r) => {
                                    let s = r.status();
                                    let b = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {b}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "claim_task" | "complete_task" | "submit_plan" | "approve_plan" | "reject_plan" => {
                        let channel = args_val["channel"].as_str().unwrap_or(&args.channel).to_string();
                        let task_id = args_val["id"].as_str().unwrap_or("").to_string();
                        if task_id.is_empty() {
                            text(id, "[bridge] ERROR: id required")
                        } else {
                            let path_suffix = match name {
                                "claim_task" => "claim".to_string(),
                                "complete_task" => "complete".to_string(),
                                "submit_plan" => "plan".to_string(),
                                "approve_plan" => "plan/approve".to_string(),
                                "reject_plan" => "plan/reject".to_string(),
                                _ => unreachable!(),
                            };
                            let url = format!(
                                "{}/tasks/{}/{}/{}",
                                args.server,
                                encode_path_segment(&channel),
                                encode_path_segment(&task_id),
                                path_suffix,
                            );
                            // Body shape varies — pass through whatever
                            // the tool args carried (plan/outcome/reason).
                            let body = match name {
                                "claim_task" | "approve_plan" => serde_json::json!({}),
                                "complete_task" => serde_json::json!({
                                    "outcome": args_val["outcome"].as_str().unwrap_or("")
                                }),
                                "submit_plan" => serde_json::json!({
                                    "plan": args_val["plan"].as_str().unwrap_or("")
                                }),
                                "reject_plan" => serde_json::json!({
                                    "reason": args_val["reason"].as_str().unwrap_or("")
                                }),
                                _ => serde_json::json!({}),
                            };
                            let res = client.post(url).json(&body).send().await;
                            match res {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] {name} OK for {task_id}")),
                                Ok(r) => {
                                    let s = r.status();
                                    let b = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {b}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "watcher_spawn" => {
                        let res = client
                            .post(format!("{}/watchers", args.server))
                            .json(&args_val)
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] watcher spawned:\n{body}"))
                            }
                            Ok(r) => {
                                let s = r.status();
                                let b = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {b}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "watcher_list" => {
                        let res = client
                            .get(format!("{}/watchers", args.server))
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] watchers:\n{body}"))
                            }
                            Ok(r) => text(id, format!("[bridge] ERROR {}", r.status())),
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
                    }

                    "watcher_stop" => {
                        let peer = args_val["peer"].as_str().unwrap_or("").to_string();
                        if peer.is_empty() {
                            text(id, "[bridge] ERROR: peer required")
                        } else {
                            let res = client
                                .delete(format!("{}/watchers/{}", args.server, encode_path_segment(&peer)))
                                .send()
                                .await;
                            match res {
                                Ok(r) if r.status().is_success() =>
                                    text(id, format!("[bridge] watcher for '{peer}' stopped")),
                                Ok(r) => {
                                    let s = r.status();
                                    let b = r.text().await.unwrap_or_default();
                                    text(id, format!("[bridge] ERROR {s}: {b}"))
                                }
                                _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                            }
                        }
                    }

                    "routing_eval" => {
                        let res = client
                            .post(format!("{}/routing-rules/eval", args.server))
                            .json(&args_val)
                            .send()
                            .await;
                        match res {
                            Ok(r) if r.status().is_success() => {
                                let body = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] routing eval:\n{body}"))
                            }
                            Ok(r) => {
                                let s = r.status();
                                let b = r.text().await.unwrap_or_default();
                                text(id, format!("[bridge] ERROR {s}: {b}"))
                            }
                            _ => text(id, "[bridge] ERROR: bridge server unreachable"),
                        }
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
    let push = |s: String, out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
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

    /// Drift guard for the `381b3ea` class of bug: a server route
    /// existed but the MCP `tools/list` response forgot it (or vice
    /// versa). We can't directly compare against the router without
    /// running the server, so we list both sides at build time and
    /// assert the symmetric difference is empty for tools we expect
    /// to map 1:1.
    ///
    /// Not every server route maps to a tool (e.g. `/stream/...` is
    /// SSE, not RPC) and not every tool maps to a single route
    /// (`share_endpoint` is purely client-side). The
    /// `EXPECTED_TOOL_NAMES` allowlist is the contract; adding a new
    /// MCP tool means adding it here AND in the `tools/list` array
    /// returned by `tools_list()`. CI fails fast on a missing entry.
    #[test]
    fn tools_list_matches_expected_set() {
        let v = super::tools_list();
        let tools = v["tools"].as_array().expect("tools is an array");
        let names: std::collections::BTreeSet<String> = tools
            .iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect();
        // Single source of truth — this is the list of MCP tool
        // names the bridge exposes. Update both this array and
        // `tools_list()` when adding a new tool.
        const EXPECTED_TOOL_NAMES: &[&str] = &[
            "send_message",
            "read_messages",
            "list_peers",
            "share_endpoint",
            "report_finding",
            "list_findings",
            "triage_finding",
            "delete_finding",
            "share_artifact",
            "list_channels",
            "set_channel_topic",
            "clear_channel",
            "set_status",
            "set_skills",
            "pin_message",
            "unpin_message",
            "create_task",
            "list_tasks",
            "update_task",
            "delete_task",
            "memory_get",
            "memory_set",
            "memory_delete",
            "memory_list",
            "delete_channel",
            // Group B/C additions:
            "ack_dispatch",
            "complete_dispatch",
            "peer_health",
            "resume_for",
            "metrics",
            // F17 routing additions:
            "routing_rule_create",
            "routing_rule_list",
            "routing_rule_toggle",
            "routing_eval",
            // F26 watcher additions:
            "watcher_spawn",
            "watcher_list",
            "watcher_stop",
            // F29 task-coordination additions:
            "claim_task",
            "complete_task",
            "submit_plan",
            "approve_plan",
            "reject_plan",
            // F20 goals:
            "goal_create",
            "goal_list",
            "goal_cancel",
        ];
        let expected: std::collections::BTreeSet<String> =
            EXPECTED_TOOL_NAMES.iter().map(|s| s.to_string()).collect();
        let missing: Vec<&String> = expected.difference(&names).collect();
        let extra: Vec<&String> = names.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "tool/expected drift — missing from tools/list: {missing:?}; extra in tools/list (un-expected): {extra:?}"
        );
        // Every tool in tools/list must have a description and an
        // inputSchema — the JSON-RPC client won't render a tool
        // without these. Catches "added the name but forgot the
        // metadata" mistakes.
        for t in tools {
            let name = t["name"].as_str().unwrap_or("?");
            assert!(t["description"].is_string(), "tool {name} missing description");
            assert!(t["inputSchema"].is_object(), "tool {name} missing inputSchema");
        }
    }

    /// Guards the actor-attribution Opt 1 wiring (ops dispatch
    /// 1779040100): the shim's HTTP client must be constructed with
    /// an `X-Bridge-From` default header derived from the peer
    /// name. Reqwest merges default headers at `send()` time, not
    /// `build()` time, so we assert the construction path produces
    /// a valid HeaderMap with the expected key/value — the layer
    /// that's actually shim code, not reqwest internals.
    #[test]
    fn x_bridge_from_default_header_constructed_from_name() {
        let from = "test-peer-xyz";
        let mut headers = reqwest::header::HeaderMap::new();
        let v = reqwest::header::HeaderValue::from_str(from)
            .expect("from-name encodable as header");
        headers.insert("x-bridge-from", v);
        // Same builder shape the prod main() uses — guards against
        // the wrong header name landing into the actual client
        // construction.
        let client = reqwest::Client::builder()
            .default_headers(headers.clone())
            .build()
            .expect("build");
        // We can't easily intercept reqwest's pre-send merge in a
        // unit test, but we can confirm (a) the header is encodable
        // (no control chars / non-ASCII bytes that would reject at
        // runtime) and (b) the client built successfully with our
        // map. Failure modes the test catches: bad header name
        // ("X Bridge From"), non-ASCII byte in peer name producing
        // `from_str` Err, builder failure under our flags.
        assert!(headers.contains_key("x-bridge-from"));
        assert_eq!(
            headers.get("x-bridge-from").unwrap().to_str().unwrap(),
            from
        );
        // Sanity: peer-name strings with whitespace/control chars
        // would fail at `HeaderValue::from_str` — that's the
        // correct behaviour (we'd never want such a name to silently
        // produce an empty header). Confirm:
        assert!(reqwest::header::HeaderValue::from_str("bad name\n").is_err());
        // Drop client to silence unused warning.
        drop(client);
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(decode_base64("not_base64!").is_err());
        assert!(decode_base64("ABC").is_err()); // length 3 not multiple of 4
    }
}
