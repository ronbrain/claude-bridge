# claude-bridge

A lightweight MCP server + relay that lets two (or more) Claude Code
instances talk to each other in real time. One instance shares an
endpoint or a finding, the other reads it on its next tick — no manual
copy-paste between terminals.

The repo ships three binaries:

| Binary | Role |
|---|---|
| `bridge-server` | Central HTTP relay. Holds messages, findings, artifacts, tasks, shared-memory KV, dispatches, audit log, and presence state for every channel. Authenticates peers via bearer-token registry (fail-closed by default). One per topology. |
| `bridge-mcp` | Stdio MCP client. Each Claude Code instance runs one, points it at the server, exposes 30 tools to the model. Auto-injects `Authorization: Bearer` + `X-Bridge-From` on every request. |
| `bridge` | Human CLI — talk to a channel from your terminal without spawning a Claude session. Same env-var contract as `bridge-mcp`. |

Beyond the bus itself the repo ships a coordination layer on top —
per-session identities, declared roles, addressed messages, channel
topics, work-queue tasks, shared-memory KV (FTS-indexed), tracked
dispatches with auto-escalation, an audit log, and a Prometheus
exporter — so N Claude Code instances on the same host stay
distinguishable and only act on what's actually for them. See
[Identity, roles, and addressing](#identity-roles-and-addressing)
and [Authentication](#authentication).

## What's new (post-sprint)

Recent sprint (commits `6b4603a → 9cdb7ae → 04fb21c → 763474d`)
landed a substantial coordination + security overhaul. If you ran
an earlier bridge, the **breaking changes** you'll notice on
restart:

- **Persistence is now required by default.** `BRIDGE_DB_PATH` must
  be set, OR `BRIDGE_DB_EPHEMERAL=1` to opt into ephemeral mode.
- **Bind defaults to `127.0.0.1:3001`.** `BRIDGE_BIND=0.0.0.0:<port>`
  is the explicit opt-in for wider exposure.
- **Auth required in enforce mode.** Without `BRIDGE_AUTH_PERMISSIVE=1`,
  empty `BRIDGE_AUTH_TOKENS` refuses to start. Peers configure
  `BRIDGE_AUTH_TOKEN` (raw) in their MCP shim env.
- **Body `from` field removed from request schemas.** Identity is
  authoritative from the bearer (or `X-Bridge-From` in permissive
  mode). Old clients still work — serde silently drops the
  unknown field.

Substantial **additive** changes:

- **18 new HTTP routes** — tasks, memory KV, dispatch lifecycle,
  peer health, resume generator, metrics (JSON + Prometheus).
- **18 new MCP tools** alongside the original 12 — see [Tools
  exposed to Claude](#tools-exposed-to-claude).
- **Audit log** records every mutation with before/after hashes.
- **Background automation loop** — heartbeat, peer-history prune,
  dispatch escalation (15 min SLA + auto-ping), peer-drop notifier.
- **Memory KV with FTS5 + ownership enforcement + soft-delete**.
- **Secret redaction** on `/resume/{name}` (JWT / password /
  api_key / Stripe / AWS / Gezer / SSH / PEM / Anthropic / GitHub
  PAT family / Slack).
- **3 new CLI subcommands**: `bridge health <peer>`,
  `bridge metrics`, `bridge dispatches`.

## Build

```sh
git clone https://github.com/ronbrain/claude-bridge.git
cd claude-bridge
cargo build --release
sudo install -m 755 \
  target/release/bridge-server \
  target/release/bridge-mcp \
  target/release/bridge \
  /usr/local/bin/
```

The binaries are static enough to copy between Linux x86_64 boxes
without rebuild.

## Topology

Pick one of:

1. **Single VPS, local-only.** Server runs on `127.0.0.1:3001`,
   bridge-mcp talks to `http://localhost:3001`. Use when you want
   shared state across sessions on the same machine (or scratchpad
   for one Claude Code instance to leave notes for the next session).
2. **Multi-VPS.** One VPS runs the server bound to a reachable
   interface (WireGuard IP, public IP, etc.); every other VPS
   configures bridge-mcp with that URL. Same channel name on both
   ends and you have a coordination bus.

### `bridge-server` env vars

| Var | Default | Notes |
|---|---|---|
| `PORT` | `3001` | TCP port. Composed with the safe loopback default into `127.0.0.1:<PORT>` unless `BRIDGE_BIND` overrides. |
| `BRIDGE_BIND` | _(unset → `127.0.0.1:<PORT>`)_ | Full `host:port` bind string. Setting to `0.0.0.0:<port>` (or `[::]:`/`0:`) fires a SEVERE warn at boot reminding you to pair it with `BRIDGE_AUTH_TOKENS` (finding `dc633d7c`). |
| `BRIDGE_DB_PATH` | _(unset → refuse-to-start)_ | Path to sqlite file. **Required** unless `BRIDGE_DB_EPHEMERAL=1`. Example: `/var/lib/claude-bridge/bridge.db`. See [Persistence](#persistence). |
| `BRIDGE_DB_EPHEMERAL` | _(unset)_ | Set to `1` to opt INTO in-memory-only mode (state lost on every restart). Refusing-to-start without it is the fix for finding `c9d0bfd9`. |
| `BRIDGE_AUTH_TOKENS` | _(unset)_ | CSV of `<sha256-hex>:<identity>` pairs — see [Authentication](#authentication). Operators store hashes, never raw tokens. |
| `BRIDGE_AUTH_PERMISSIVE` | _(unset)_ | Set to `1` to opt INTO running unauthenticated. Required when `BRIDGE_AUTH_TOKENS` is empty; otherwise the server refuses to start (finding `dc633d7c`). |
| `BRIDGE_MEMORY_ADMINS` | _(unset)_ | CSV of identities that bypass memory-key ownership checks. Use for ops cleanup paths. |
| `BRIDGE_HISTORY_LIMIT` | `100` | Per-channel in-memory cap on retained messages. |
| `BRIDGE_FINDING_LIMIT` | `500` | Per-channel in-memory cap on retained findings. |
| `BRIDGE_ARTIFACT_LIMIT` | `200` | Global cap on artifacts retained in memory (LRU-evicted by `created_at`). |
| `BRIDGE_PEER_TTL_SECS` | `120` | Heartbeat staleness threshold — peers idle past this drop off `list_peers`. |
| `BRIDGE_PEER_HISTORY_TTL_SECS` | `2592000` (30 d) | TTL on rows in `peer_status_history` so the audit trail doesn't grow unbounded. |
| `BRIDGE_MEMORY_HISTORY_KEEP` | `5` | Versions per memory key retained in `memory_history`. |

The bind default flipped to `127.0.0.1:3001` per finding `dc633d7c`.
Operators wanting wider exposure (multi-VPS, WireGuard mesh, etc.)
set `BRIDGE_BIND=0.0.0.0:3001` explicitly and pair it with
`BRIDGE_AUTH_TOKENS`. UFW rule for the explicit-opt-in case:
`sudo ufw allow from 10.99.0.0/24 to any port 3001`.

### Persistence

The server **refuses to start** when `BRIDGE_DB_PATH` is unset
unless the operator explicitly opts into ephemeral mode with
`BRIDGE_DB_EPHEMERAL=1`. This is the
`ops-rule-no-silent-fail-open-defaults` pattern applied after a
data-loss incident on sv-s-bcloud — see finding `c9d0bfd9`.

To run with persistence (the recommended path), set
`BRIDGE_DB_PATH` to a sqlite file path:

```sh
sudo mkdir -p /var/lib/claude-bridge
sudo chown ubuntu /var/lib/claude-bridge
BRIDGE_DB_PATH=/var/lib/claude-bridge/bridge.db PORT=3001 bridge-server
```

systemd unit with persistence:

```ini
[Service]
ExecStart=/usr/local/bin/bridge-server
Environment=PORT=3001
Environment=BRIDGE_DB_PATH=/var/lib/claude-bridge/bridge.db
Restart=always
User=ubuntu
```

How it works:

- Sqlite bundled into the binary (`rusqlite + bundled`) — no
  `libsqlite3` runtime dep.
- Schema is created on first run via a versioned **migration runner**
  (`run_migrations` in `src/store.rs`) backed by a `schema_version`
  table. Each migration runs under `BEGIN IMMEDIATE` so partial
  failure rolls back cleanly. WAL mode for write-while-read.
- **Downgrade detection** (finding `752cc548`): if `schema_version`
  has a row newer than this binary knows about, boot refuses with
  a FATAL error citing the version delta and the recovery
  procedure — older binaries can't be tricked into skipping
  invariants by running against a newer DB.
- Every write path mirrors to disk **after** the in-memory update
  succeeds — the hot read path doesn't block on disk.
- Boot rehydrates messages / findings / artifacts / topics / tasks /
  memory back into the DashMaps, honouring the in-memory caps from
  the env vars table above.
- A failed sqlite write logs a warning but does NOT fail the HTTP
  request — better to lose a row to crash than reject a working send
  because the disk got tight.
- **Memory-ownership orphan migration** runs at boot in enforce
  mode: rows whose `updated_by` doesn't map to a known identity
  (registry ∪ memory admins) get rewritten ownerless so the first
  authenticated writer can re-claim. Wrapped in a transaction
  with a defensive FTS5 rebuild — closes finding `9fe0e927`.
- **Finding-author orphan migration** parallel: rows authored by
  identities outside the registry get renamed to `[orphan-<prior>]`
  so the attribution gap is visible in `list_findings`. Enforce
  mode only — closes the `saas` orphan-identity class.
- Channel evictions (when >256 channels) cascade-delete the
  channel's rows from the DB so disk usage stays bounded.

Backup is `cp bridge.db bridge.db.bak` (or `sqlite3 .backup`). The
file is the entire state.

Presence (`/peers`) is intentionally NOT persisted — a peer
presumed online after a server restart would be misleading. Peers
re-register via heartbeat within 20 s of the MCP client reconnecting.
The append-only `peer_status_history` table records every status
transition for postmortem queries.

### Authentication

The server validates a shared-secret `Authorization: Bearer <token>`
header on every mutation, stream, and observability route. Operators
seed the registry via env, peers seed their own shim env with the
raw bearer; the shim auto-injects both `Authorization` and
`X-Bridge-From` on every request.

**Default is fail-CLOSED** (finding `dc633d7c`): if
`BRIDGE_AUTH_TOKENS` is unset/empty AND `BRIDGE_AUTH_PERMISSIVE` is
not `1`, the server refuses to start with a FATAL error. The
unsafe path requires an explicit operator-typed opt-in.

**Cut tokens** (recommended: 32 bytes random per peer):

```sh
# Peer-side: raw token (paste into the peer's BRIDGE_AUTH_TOKEN env).
RAW=$(openssl rand -hex 32)
echo "$RAW"

# Server-side: hash (paste into BRIDGE_AUTH_TOKENS, prefixed with identity).
printf '%s' "$RAW" | sha256sum | awk '{print $1}'
```

**Configure the server**:

```sh
BRIDGE_AUTH_TOKENS="\
<hash-of-alice-token>:alice,\
<hash-of-bob-token>:bob,\
<hash-of-ops-token>:ops" \
BRIDGE_MEMORY_ADMINS=ops \
BRIDGE_DB_PATH=/var/lib/claude-bridge/bridge.db \
bridge-server
```

**Configure each peer** (`bridge-mcp` and `bridge` CLI):

```sh
export BRIDGE_AUTH_TOKEN=<raw-token-this-peer-was-issued>
```

The MCP shim picks the env up at startup and constructs its reqwest
client with the bearer as a default header. The shim flags the
header as sensitive so reqwest's request-logging redacts the value.

**Permissive (interim) mode** — boot with no registry:

```sh
BRIDGE_AUTH_PERMISSIVE=1 BRIDGE_DB_PATH=/var/lib/claude-bridge/bridge.db \
bridge-server
# SEVERE warn at boot — every request resolves to AuthIdentity::Anonymous.
# X-Bridge-From header (legacy path) carries identity for audit
# attribution; ownership checks fall back to it.
```

Flipping back closed: cut tokens (see above), set
`BRIDGE_AUTH_TOKENS` + restart, unset `BRIDGE_AUTH_PERMISSIVE`.
Existing peers using the matching token continue uninterrupted.

**Memory ownership** (finding `0919a7db`): once authenticated,
`memory_set` and `memory_delete` only allow the original
`updated_by` to overwrite/delete a key. Operators listed in
`BRIDGE_MEMORY_ADMINS` bypass for ops cleanup.

**SSE subscribe** (`/stream/{channel}`) is authed too — peers
connect via reqwest/curl/MCP shim which send headers. Browser
`EventSource` cannot natively send `Authorization`; front it with
a reverse proxy if you need a browser subscriber.

`/metrics/prometheus` is the only route deliberately left unauthed
so existing Prometheus scrapers work without per-scrape token
config. Front it with a reverse-proxy ACL if needed; the payload
is aggregate-only counts, no per-peer secrets.

## systemd unit

`/etc/systemd/system/claude-bridge.service`:

```ini
[Unit]
Description=Claude Bridge Server
After=network.target

[Service]
ExecStart=/usr/local/bin/bridge-server
Environment=PORT=3001
Restart=always
RestartSec=2
User=ubuntu

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now claude-bridge
systemctl is-active claude-bridge   # → active
```

## Register the MCP client in Claude Code

Use the official CLI — it writes to the correct config file
(`~/.claude.json`, not `settings.json`) and registers the tools so
they surface in the next session:

```sh
claude mcp add -s user bridge /usr/local/bin/bridge-mcp \
  -e BRIDGE_AUTH_TOKEN=<raw-token-issued-to-this-peer> \
  -- \
  --server http://localhost:3001 \
  --channel main
```

`-e BRIDGE_AUTH_TOKEN=...` is required when the server has any
tokens configured (enforce mode). Omit it only when the server is
running with `BRIDGE_AUTH_PERMISSIVE=1`. See
[Authentication](#authentication) for token issuance.

Don't pass `--name` — the MCP auto-derives a per-session identity
from `CLAUDE_CODE_SESSION_ID` (format: `<6-hex>`) so two sessions on
the same host show up as distinct peers. Don't pass `--role` either
— set it per-session at runtime with `bridge role <name>` or by
dropping a `.bridge-role` file in the project root. See
[Identity, roles, and addressing](#identity-roles-and-addressing).

The `--` separator is important so `claude` doesn't try to interpret
the bridge args as its own flags.

Scope options:

- `-s user`   — applies to every project on this machine (recommended)
- `-s project` — current project only (`./.claude.json`)
- `-s local`   — current session

### Verify

```sh
$ claude mcp list
…
bridge: /usr/local/bin/bridge-mcp --server http://localhost:3001 --channel main --name your-host - ✓ Connected
```

Smoke test without spawning a session — speak MCP directly to the
stdio binary:

```sh
cat <<'EOF' | bridge-mcp --server http://localhost:3001 --channel main --name probe
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_message","arguments":{"content":"hello"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_messages","arguments":{}}}
EOF
```

Expect to see your `hello` message echoed back in the
`read_messages` result.

## Multi-instance example

**VPS-A** (`66.70.188.209`, the SaaS box):

```sh
PORT=3001 bridge-server   # or via systemd

claude mcp add -s user bridge /usr/local/bin/bridge-mcp -- \
  --server http://localhost:3001 \
  --channel pentest \
  --name saas
```

**VPS-B** (the pentester instance, on the same WireGuard mesh):

```sh
claude mcp add -s user bridge /usr/local/bin/bridge-mcp -- \
  --server http://10.99.0.5:3001 \
  --channel pentest \
  --name pentester
```

Now both Claude Code instances see the same five tools on the
`pentest` channel.

## `bridge` CLI for humans

When you want to participate from the terminal without spinning up a
Claude session — quick check on the channel, send a note, run a
triage from your editor — use the `bridge` binary. Same env-var
contract as `bridge-mcp`:

```sh
export BRIDGE_SERVER=http://YOUR_BRIDGE_SERVER:3001
export BRIDGE_CHANNEL=general
export BRIDGE_SELF=$(hostname)
export BRIDGE_AUTH_TOKEN=<raw-token-issued-to-this-peer>  # required in enforce mode
```

```sh
bridge send "deploying fix in 10"
bridge tail 20
bridge tail 50 --from saas --since 1778800000
bridge peers
bridge findings --status open --severity critical
bridge triage <finding-id> fixed --note "shipped in v1.2.3"
bridge upload ./poc.txt --notes "minimum repro for SQLi"
bridge clear

# Observability subcommands (Group C):
bridge health <peer>                # composite peer-health snapshot
bridge metrics                      # bridge-wide aggregates table
bridge dispatches --for <peer>...   # open-dispatches breakdown
                                    #   (omit --for for the global count)

# Read or set the role for the current Claude Code session.
# Works from any subshell launched inside a session.
bridge role            # read
bridge role pentest    # set
bridge role ""         # clear
```

Each subcommand has `--help` with the full flag list.

## Tools exposed to Claude

30 tools. All accept an optional `channel` arg to override the
default for one call.

> Sender identity for every write tool is derived authoritatively
> from the auth bundle's bearer token (or `X-Bridge-From` header in
> permissive mode). The body `from` field that earlier versions
> accepted is gone; the shim auto-injects the right header per
> peer config.

### Coordination

| Tool | Purpose | Required args |
|---|---|---|
| `send_message` | Free-form note; optional `to: [<name\|role>]` for addressed delivery. Server tracks `to:`-non-empty calls as **dispatches** in a queryable table. | `content` |
| `read_messages` | Read recent messages; supports `since`, `from`, `limit` filters | — |
| `list_peers` | Who's connected right now (heartbeat ≤120s) with their declared roles + skills + status line | — |
| `set_status` | Publish this peer's short status line (≤280 chars). Surfaces in `list_peers`. | `status` |
| `set_skills` | Publish this peer's skills tag list (`svelte,csp,oauth`). Surfaces in `list_peers`. | `skills` |
| `list_channels` | Every known channel with its declared topic — call before `send_message` if unsure where a message belongs | — |
| `set_channel_topic` | Declare/update the one-line purpose of a channel | `channel`, `topic` |
| `pin_message` / `unpin_message` | Pin a message to the top of `read_messages` listings (skills board, decision log, current state doc) | `id` |
| `clear_channel` | Wipe message history (findings + artifacts + memory survive) | — |
| `delete_channel` | Hard-delete a channel — wipes history, findings, topic | `channel` |

### Findings

| Tool | Purpose | Required args |
|---|---|---|
| `report_finding` | Log a structured finding (separate stream from chat) | `title`, `severity`, `detail` |
| `list_findings` | Query findings by `severity` / `status` / `from` | — |
| `triage_finding` | Update a finding's status (`open` → `triaged` → `fixed`/`wontfix`) | `id`, `status` |
| `delete_finding` | Hard-delete a finding (false positives, noisy reports) | `id` |
| `share_endpoint` | Hand off an HTTP endpoint for the peer to test | `url`, `method` |
| `share_artifact` | Upload a small file (≤10 MB) and share its download URL | `filename`, `content` |

### Tasks (work queue)

| Tool | Purpose | Required args |
|---|---|---|
| `create_task` | New task. Distinct from `report_finding`: tasks are action items, findings are bugs. Optional `owner` (identity or role) + `blocks` / `depends_on` arrays. | `title` |
| `list_tasks` | Query by `status` (`todo` / `in_progress` / `blocked` / `done` / `cancelled`) or `owner` | — |
| `update_task` | Any of `status` / `owner` / `note` changed in one call | `id` |
| `delete_task` | Hard-delete; for duplicates / created-in-error. Prefer `update_task status=done` to close. | `id` |

### Memory KV (channel-scoped, FTS-indexed, ownership-enforced)

| Tool | Purpose | Required args |
|---|---|---|
| `memory_set` | Write a value. Ownership enforced post auth-bundle (only original `updated_by` or `BRIDGE_MEMORY_ADMINS` can overwrite). Optional `ttl_secs` for auto-expiry. | `key`, `value` |
| `memory_get` | Read a value by key. Channel-scoped. | `key` |
| `memory_delete` | Delete a key. Ownership-enforced. | `key` |
| `memory_list` | List every key in the channel's namespace with value + `updated_by` + `updated_at` + `expires_at` | — |

### Dispatch lifecycle

Sending a `send_message` with `to: [peer]` creates a tracked
dispatch row. The `DispatchEscalationScanner` (60 s tick, 15 min
SLA per roadmap-v1 F5) auto-posts a `[bridge-auto]` ping into the
channel when an unacked dispatch ages past SLA.

| Tool | Purpose | Required args |
|---|---|---|
| `ack_dispatch` | Acknowledge a dispatch you were addressed in. Optional `eta_secs` commitment. Idempotent — re-ack on closed dispatch is a no-op 404. | `message_id` |
| `complete_dispatch` | Mark a dispatch done. Free-form `outcome`. Implicitly acks if you never called `ack_dispatch` first. | `message_id` |

### Observability

| Tool | Purpose | Required args |
|---|---|---|
| `peer_health` | Composite view: live presence + open dispatches addressed to peer + open findings authored + active tasks owned. `present: bool` + nullable `idle_secs` (no `u64::MAX` sentinel). | `peer` |
| `resume_for` | Markdown brief assembled for next-session pickup — live presence + open dispatches + authored findings + authored memory keys. `_private_`-prefixed keys excluded, expired-TTL keys excluded, secret-shaped values redacted via `redact_secrets()` (covers JWT / password / api_key / Stripe / AWS / SSH / PEM / Anthropic / GitHub PAT family / Slack). Per-(requester, target) rate-limited 60/min. | `peer` |
| `metrics` | Bridge-wide JSON snapshot: peers_active, channels, messages_total, findings_total/open, tasks_total/active, artifacts, dispatches_pending, per-channel `sse_lag_drops`. | — |

> `GET /metrics/prometheus` (text-exposition format) is also served
> for Prometheus scrapers — not exposed as an MCP tool because
> Prometheus scrapes the HTTP endpoint directly.

## Identity, roles, and addressing

When more than one Claude Code instance runs on the same machine,
they need to be distinguishable to peers and the operator needs a
way to send a message that wakes only ONE of them. The repo solves
this with three composable pieces, all keyed off Claude Code's
`$CLAUDE_CODE_SESSION_ID`.

### Per-session identity

`bridge-mcp` auto-derives its `name` from
`$CLAUDE_CODE_SESSION_ID` (or, when that env isn't propagated —
Claude Code passes it to bash hooks but not to MCP stdio children
— it walks up to the parent `claude` process and reads the
rendezvous file the SessionStart hook wrote). The default name is
the first 6 hex chars of the session UUID:

```
0f4543, 6b5ff5, 9bcf8c, 979712
```

Two sessions on the same machine show up as distinct peers — no
collisions, no manual `--name` config. Pass `--name <fixed>` only
if you have a specific reason; the default is the right thing.

### Roles

Each session can claim a role like `pentest`, `integration`,
`fixer`, `ops`. Roles are arbitrary strings — the bridge doesn't
enforce a list. Two ways to set:

**Manual** (from inside a session):

```sh
bridge role pentest
# next heartbeat (≤20s) re-publishes with roles=[pentest]
```

**Auto** (per-project): drop a `.bridge-role` file in the project
root with one line:

```sh
echo pentest > ~/work/some-project/.bridge-role
# SessionStart hook reads it and writes the role on first launch.
# Manual `bridge role <name>` wins thereafter — auto only applies
# when no role is already set for the session.
```

The role is persisted under `~/.cache/bridge/roles/<session_id>`,
so resuming a session via `claude --resume <sid>` keeps the role.

### Addressed messages

`send_message` accepts an optional `to: [<name|role>]`. When set,
peers whose identity OR role doesn't match silently ignore the
message — their watcher doesn't fire, their drain hook doesn't
surface anything. Empty `to` (the default) is broadcast, behaves
exactly like before.

```jsonc
// Wake only the pentest instance (resolves the role → identities at
// send time by querying /peers).
send_message(content: "regression on finding f3ca…", to: ["pentest"])

// Direct to a specific identity, even if offline (the daemon writes
// to the log, the peer picks it up on reconnect).
send_message(content: "look at the diff for X", to: ["9bcf8c"])

// Multiple recipients — both wake.
send_message(content: "joint review", to: ["pentest", "integration"])
```

Resolution is client-side: `bridge-mcp` queries `/peers` for any
token in `to` that matches a peer's declared role, expands it to
that peer's `name`, and posts the resolved list to the server. The
server is a dumb relay — filtering happens in the watcher / drain
hook on each receiver.

The `send_message` confirmation echoes the resolved recipients:

```
[bridge] sent to 'general' — to: 0f4543, 6b5ff5 ✓ — topic: …
```

### Channel topics

Each channel has an optional one-line topic. `list_channels` shows
them; `send_message`'s confirmation echoes the topic of the channel
you posted to so a misroute (posting integration content into the
pentest channel) surfaces on the turn it happens, not days later.

```sh
set_channel_topic(channel: "pale-sdk", topic: "Integration only — pentest goes to #pale-pentest")
list_channels
# • #general      — Coordination, cross-cutting, decisions
# • #pale-sdk     — Integration only — pentest goes to #pale-pentest
# • #pale-pentest — Pentest only — findings, regressions, fix reports
```

Topics persist in sqlite (when `BRIDGE_DB_PATH` is set).

### Findings lifecycle

`report_finding` creates a `{status: open}` record in the findings
stream and drops a chat ping so the peer's watcher wakes them. From
there:

```
report_finding (open) → list_findings (triage queue) → triage_finding
                                                       (open|triaged|fixed|wontfix)
```

`list_findings` filters compose:

```
list_findings(status: "open")                  # everything not yet acted on
list_findings(severity: "critical")            # only criticals
list_findings(status: "fixed", from: "saas")   # what saas has shipped
```

### Artifacts

For payloads larger than fits comfortably in a chat message (request
dumps, screenshots, pcap snippets, PoC scripts), use
`share_artifact` instead of inlining:

```
share_artifact(
  filename: "sqli-poc.sh",
  content:  "#!/bin/sh\ncurl -X POST https://api.example.com/login -d 'a OR 1=1'",
  notes:    "minimum repro for finding fe…",
)
```

Hard cap 10 MB per artifact, 200 artifacts in memory globally
(LRU-evicted by `created_at`). Use a presigned S3 / object-storage
URL via `share_endpoint` for anything bigger.

### Typical usage

**From the SaaS instance** — share something for the pentester:

```
share_endpoint(
  url: "https://api.example.com/v2/auth/validate-email",
  method: "POST",
  headers: {"Authorization": "Bearer eyJ..."},
  body: '{"email":"test@test.com"}',
  notes: "no rate limit, validates JWT, talks to identity-svc"
)
```

**From the pentester instance** — pick it up, test, report back:

```
read_messages(channel: "pentest")
# … runs the test …
report_finding(
  title: "Email enumeration via timing side-channel",
  severity: "medium",
  endpoint: "POST /v2/auth/validate-email",
  detail: "Response time delta of 220ms between existing/missing emails. PoC: …"
)
```

## Recommended channel layout

- `pentest` — endpoints to test + findings
- `general` — coordination chatter
- `saas` / `infra` / per-project — context dumps and notes for the
  next session on a given codebase

## Auto-notify — wake Claude on incoming messages

Without this, you have to manually tell Claude "check the bridge"
every time the other instance posts something. With the
`asyncRewake` hook + the SSE stream the server exposes, the second
Claude Code instance auto-resumes the moment a peer message arrives.

Install all the hooks (the watcher + the helpers it needs to derive
identity and role per session):

```sh
mkdir -p ~/.claude/hooks
install -m 755 \
  hooks/bridge-watch.sh \
  hooks/bridge-session-start.sh \
  hooks/bridge-identity.sh \
  hooks/bridge-role.sh \
  hooks/bridge-claude-pid.sh \
  ~/.claude/hooks/
```

The watcher reads `$BRIDGE_CHANNEL` (comma-separated for multi-channel
listening — recommend `general,<your-topic-channels>` so addressed
notifications via `#general` always reach you regardless of role).
Identity and role come from the helpers — no hardcoded `SELF` to
edit.

Wire the hook in `~/.claude/settings.json` (note the CSV channel
list and the SessionStart hook for the role registry):

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/bridge-session-start.sh" }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "BRIDGE_CHANNEL=general,pale-sdk,pale-pentest ~/.claude/hooks/bridge-watch.sh",
            "asyncRewake": true,
            "rewakeMessage": "New message on the claude-bridge channel — read and respond:",
            "rewakeSummary": "Bridge message from peer"
          }
        ]
      }
    ]
  }
}
```

`bridge-watch.sh` is single-instance per session — it writes a
pidfile in `/tmp/bridge-watch-<sid>.pid` and kills any prior
watcher process group before subscribing. Claude Code re-invokes
Stop hooks on every Stop attempt; without this, leaked subscribers
from earlier turns would each catch every new message and the
model would see duplicates.

How it works:

- The hook fires when Claude finishes responding.
- `asyncRewake: true` means it runs in the background while you're
  idle/typing.
- The script long-polls `GET /stream/<channel>` over SSE (the bridge
  server already exposes this — no server change needed).
- When a foreign message arrives, the script prints it to stdout and
  exits with code 2.
- Claude Code treats exit code 2 from an asyncRewake hook as a wake
  signal and resumes with stdout injected as `additionalContext`
  prefixed by `rewakeMessage`.
- If you start typing first, the hook is cancelled — no stale wakes.

Verify the script end-to-end without spawning a session:

```sh
( BRIDGE_SELF=me ~/.claude/hooks/bridge-watch.sh; echo "EXIT=$?" ) &
sleep 1
curl -s -X POST http://YOUR_BRIDGE_SERVER:3001/send/general \
  -H 'content-type: application/json' \
  -d '{"from":"other","content":"wake up"}'
wait
# Expect:  EXIT=2 + the message content
```

Caveat: the watcher only listens between turns. While Claude is
actively processing your prompt, an incoming message doesn't wake
anything (Claude is already awake). For full coverage during busy
turns too, layer the daemon below.

### Daemon — catches messages during busy turns

The watcher above only listens when Claude is idle. The daemon
variant runs as a systemd user service, long-polls the SSE stream
forever (one subscriber per channel when `BRIDGE_CHANNEL` is CSV),
and appends new peer messages to `~/.cache/bridge/messages.jsonl`
(append-only, rotated every 100 appends to the last 10k lines). A
companion `UserPromptSubmit` hook drains that file at the start of
every user turn — so even if a message arrived while Claude was
mid-edit, you see it on the very next prompt.

The drain hook keeps a **per-session offset** at
`~/.cache/bridge/offsets/<session_id>`. Two Claude Code instances
on the same host each maintain their own cursor, so every instance
sees every message exactly once — instead of the first instance to
drain swallowing the lot. The drain is wrapped in a per-session
flock; render-before-advance gives at-least-once delivery (a crash
mid-write of the offset leaves the message un-acked for next turn).
Every drain logs one line to `~/.cache/bridge/drain.log` with
`(pid, ppid, offset transition, surfaced count)` for diagnosing
missed messages.

Install:

```sh
install -m 755 hooks/bridge-daemon.sh ~/.claude/hooks/
install -m 755 hooks/bridge-drain-unread.sh ~/.claude/hooks/
mkdir -p ~/.config/systemd/user
install -m 644 hooks/bridge-daemon.service ~/.config/systemd/user/
# Edit ~/.config/systemd/user/bridge-daemon.service to set BRIDGE_*
# vars — recommend BRIDGE_CHANNEL=general,<your-channels> so the
# daemon catches addressed traffic from #general regardless of
# topical channel.
sudo loginctl enable-linger "$USER"   # so the service runs without login
systemctl --user daemon-reload
systemctl --user enable --now bridge-daemon
systemctl --user status bridge-daemon
```

Add the UserPromptSubmit hook to `~/.claude/settings.json` next to
the Stop hook:

```json
{
  "hooks": {
    "Stop": [ /* … the asyncRewake watcher above … */ ],
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/bridge-drain-unread.sh" }
        ]
      }
    ]
  }
}
```

The two hooks compose:

- **Stop + asyncRewake watcher** → wake Claude when a message arrives
  while idle (no waiting for the next user turn)
- **UserPromptSubmit + daemon drain** → surface any messages that
  arrived during a busy turn, on the very next prompt

Both consume the same SSE stream from the bridge server; there's no
duplication-of-truth, both just present it differently.

End-to-end verify the daemon:

```sh
# In one terminal:
journalctl --user -u bridge-daemon -f

# In another (or from the peer instance):
curl -s -X POST http://YOUR_BRIDGE_SERVER:3001/send/general \
  -H 'content-type: application/json' \
  -d '{"from":"peer","content":"daemon test"}'

# Confirm the log received it:
tail -n1 ~/.cache/bridge/messages.jsonl

# Then drain manually to inspect:
echo '{"session_id":"'"$CLAUDE_CODE_SESSION_ID"'"}' | \
  ~/.claude/hooks/bridge-drain-unread.sh
# Should print the message and advance ~/.cache/bridge/offsets/<sid>
```

## Suggested usage outside pentesting

The bridge is just a typed key-value bus with a channel scope, so it
works for:

- **Scratchpad / cross-session memory.** Leave a note on the channel
  before `/clear`; pick it up on the next `claude` invocation
  (`read_messages` is your first tool call).
- **Hand-off between agents.** One Claude Code instance researches,
  posts findings to the channel; another implements based on them.
- **Long-running task coordination.** Worker instance polls
  `read_messages` on a `/loop` cadence for new work.

## Security notes

- **Auth is shared-secret bearer tokens** seeded via env. Operators
  store sha256 hashes of tokens (never raw); peers store their
  raw token and the shim hashes + looks up at request time.
  Constant-time hash compare via `subtle::ConstantTimeEq` — no
  timing oracle. See [Authentication](#authentication).
- **Fail-closed defaults** (`ops-rule-no-silent-fail-open-defaults`):
  empty `BRIDGE_AUTH_TOKENS` → refuse-to-start unless
  `BRIDGE_AUTH_PERMISSIVE=1`; missing `BRIDGE_DB_PATH` → refuse
  unless `BRIDGE_DB_EPHEMERAL=1`. The unsafe path is always an
  explicit operator opt-in.
- **Bind defaults to `127.0.0.1`** — wider exposure (`BRIDGE_BIND=0.0.0.0:…`)
  is an explicit opt-in that fires a SEVERE warn at boot.
- **Identity in the audit trail is the authed identity** — body
  `from` fields were removed from request schemas (Item 6). Every
  audit-log row, every memory-key `updated_by`, every dispatch's
  `from` is the bearer-resolved identity (or `X-Bridge-From` only
  in explicit permissive mode).
- **Audit log** records every mutation (`audit_log` table) with
  before/after sha256-truncated-128-bit hashes (`canonical_json`
  for stable serialization). Forensic joins by `target_type` +
  `target_id`. Reachable via `GET /audit?since=&op=` (capability-
  gated when wired) or direct SQL.
- **Memory ownership** enforced — only `updated_by` (or
  `BRIDGE_MEMORY_ADMINS`) can overwrite/delete. Existing rows with
  legacy `unknown`/`anonymous` author are auto-orphaned at boot in
  enforce mode and re-claimable.
- **Secret redaction** on `/resume/{name}` output — JWT / password /
  api_key / Stripe / AWS / Gezer / SSH / PEM / Anthropic / GitHub PAT
  family / Slack token family all redacted.
- **Body-limit DoS surface bounded** — 1 MB global cap with a
  per-route 10 MB override for artifact upload.
- **Schema downgrade** refused — running an older binary against a
  newer DB exits FATAL at boot with the version delta and the
  recovery procedure.
- **Persistence** is now the default — coordination state survives
  restarts. Ephemeral mode is the opt-in.
- Don't paste production secrets through `share_endpoint`. Use
  references (`see env var X on box Y`) rather than literal tokens.
  The bridge's redact pass catches common shapes but isn't a
  substitute for hygiene at the source.

For multi-VPS deploys you still want a perimeter (WireGuard /
firewall) — the bridge auth is a complementary control, not a
substitute. UFW rule for the explicit-opt-in `BRIDGE_BIND=0.0.0.0`
case: `sudo ufw allow from 10.99.0.0/24 to any port 3001`.

## HTTP endpoint reference

Use these directly from `curl` or your own client. The MCP and CLI
binaries are thin wrappers.

Every route except `GET /metrics/prometheus` requires
`Authorization: Bearer <token>` when the server is in enforce
mode. `GET` routes have an implicit 1 MB body limit
(`DefaultBodyLimit::max(1MB)`, finding `ccf87dff`); `POST /artifacts/{channel}`
has a per-route override to 10 MB.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| **Coordination** | | | |
| POST | `/send/{channel}` | ✓ | Send a message. Body `{content, to?: [<name\|role>], thread_id?}` — `from` removed; identity derived from bearer or `X-Bridge-From`. Server inserts a dispatch row when `to:` non-empty. |
| GET | `/messages/{channel}?since=&from=&limit=` | ✓ | List messages (filterable) |
| DELETE | `/messages/{channel}` | ✓ | Clear message history |
| GET | `/stream/{channel}` | ✓ | Server-sent events stream (one event per new message) |
| POST | `/messages/{channel}/{id}/pin` | ✓ | Pin a message |
| DELETE | `/messages/{channel}/{id}/pin` | ✓ | Unpin |
| GET | `/channels` | ✓ | List known channels (`[{name, topic, updated_by, updated_at}]`) |
| GET | `/channels/{channel}/topic` | ✓ | Get a single channel's topic |
| PUT | `/channels/{channel}/topic` | ✓ | Set a topic (body `{topic}`) |
| DELETE | `/channels/{channel}` | ✓ | Hard-delete channel |
| **Findings** | | | |
| POST | `/findings/{channel}` | ✓ | Create finding (body `{severity, title, detail, endpoint?}`) |
| GET | `/findings/{channel}?severity=&status=&from=` | ✓ | List findings (filterable) |
| PATCH | `/findings/{channel}/{id}` | ✓ | Triage (update status/note) |
| DELETE | `/findings/{channel}/{id}` | ✓ | Hard-delete a finding |
| POST | `/artifacts/{channel}` | ✓ | Upload artifact (≤10 MB, headers: `x-bridge-filename`, `content-type`) |
| GET | `/artifacts/{channel}/list` | ✓ | List artifacts |
| GET | `/artifact/{id}` | ✓ | Download artifact (singular path) |
| **Tasks** | | | |
| POST | `/tasks/{channel}` | ✓ | Create task (body `{title, description?, owner?, blocks?, depends_on?}`) |
| GET | `/tasks/{channel}?status=&owner=` | ✓ | List tasks |
| PATCH | `/tasks/{channel}/{id}` | ✓ | Update task (status/owner/note) |
| DELETE | `/tasks/{channel}/{id}` | ✓ | Hard-delete a task |
| **Memory KV** | | | |
| GET | `/memory/{channel}` | ✓ | List all keys in the channel |
| GET | `/memory/{channel}/{key}` | ✓ | Get one key (lazy-expires past `expires_at`) |
| PUT | `/memory/{channel}/{key}` | ✓ | Set (body `{value, ttl_secs?}`). Ownership-enforced. |
| DELETE | `/memory/{channel}/{key}` | ✓ | Delete. Ownership-enforced. |
| **Dispatches** | | | |
| POST | `/dispatches/{message_id}/ack` | ✓ | Ack a dispatch (body `{eta_secs?}`). 503 if persistence off; 404 if unknown/closed. |
| POST | `/dispatches/{message_id}/complete` | ✓ | Complete a dispatch (body `{outcome?}`) |
| **Presence + observability** | | | |
| POST | `/presence/{name}` | ✓ | Heartbeat (body `{channel?, roles?, skills?, status?}`) |
| GET | `/peers` | ✓ | List online peers (heartbeat ≤`BRIDGE_PEER_TTL_SECS`) |
| GET | `/peer/{name}/health` | ✓ | Composite peer health — JSON `{peer, present, idle_secs, channel, roles, skills, status, pending_dispatches, open_findings, active_tasks}` |
| GET | `/resume/{name}` | ✓ | Markdown resume brief — see [Tools / Observability](#observability) |
| GET | `/metrics` | ✓ | JSON aggregates |
| GET | `/metrics/prometheus` | **✗** | Text-exposition format — left unauthed for scrape compatibility, front with reverse-proxy ACL |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `claude mcp list` shows `✗ Failed to connect` | bridge-server not running; check `systemctl status claude-bridge` |
| Tools don't appear in the current `claude` session | MCP servers load at startup — start a new session |
| `Connection refused` from another VPS | server bound to wrong interface, or firewall — check `ss -tlnp \| grep 3001` |
| Messages don't show up across instances | both instances must point at the SAME server URL and use the SAME channel string |
| `bridge-daemon` service inactive after reboot | `loginctl enable-linger $USER` not run — user services need lingering to start without login |
| Drain hook prints nothing | check `~/.cache/bridge/drain.log` for the most recent run — `surfaced=0` means filtering or no new messages; `lock timeout` means a previous drain is hung. Daemon health: `systemctl --user status bridge-daemon`. |
| Same message appears N times to the model | leaked `bridge-watch.sh` from prior turns. Latest version uses a per-session pidfile; if you see multiple in `pgrep -fa bridge-watch.sh`, `pkill -f bridge-watch.sh` and let the next Stop hook re-spawn one. |
| `list_peers` empty but instance is connected | the MCP client only heartbeats every 20s — wait one cycle, or send a message (sending implicitly marks presence) |
| Peer name is `<hostname>` instead of `<short-sid>` | SessionStart hook not installed or didn't run. Install `hooks/bridge-session-start.sh` and `claude --resume` once. |
| `bridge role` says "could not determine session_id" | running outside a Claude Code session, or SessionStart never ran. Fix: install the SessionStart hook and `claude --resume`. |
| Addressed message woke a peer it wasn't meant for | the peer claimed the role you addressed. Check `list_peers` for who's currently advertising that role; use the identity (short-sid) directly for a 1:1 send. |
| `delete_channel` returns 204 but channel still appears | older `bridge-server` doesn't have the route; rebuild + restart the server (commit `0caa7ef` or later). |
| Server exits at boot with `FATAL: BRIDGE_DB_PATH empty and BRIDGE_DB_EPHEMERAL not set` | Set `BRIDGE_DB_PATH=/path/to/bridge.db` (recommended) OR `BRIDGE_DB_EPHEMERAL=1` (explicit in-memory). Finding `c9d0bfd9` made this fail-closed. |
| Server exits at boot with `FATAL: BRIDGE_AUTH_TOKENS empty and BRIDGE_AUTH_PERMISSIVE not set` | Cut tokens per [Authentication](#authentication) or set `BRIDGE_AUTH_PERMISSIVE=1` to opt INTO running unauthenticated. Finding `dc633d7c`. |
| Server exits at boot with `FATAL: memory-ownership migration failed in enforce mode` | Likely FTS5 shadow-table inconsistency (finding `9fe0e927`). Run the suggested `sqlite3 "$BRIDGE_DB_PATH" "INSERT INTO memory_fts(memory_fts) VALUES('rebuild');"` to self-repair, then restart. |
| Server exits at boot with `schema_version has vX applied but this binary only knows up to vY` | Downgrade attempt (finding `752cc548`) — you're running an older binary against a newer DB. Pull the matching tag, or follow the recovery procedure in the FATAL message. |
| `401 Unauthorized` with `missing Authorization: Bearer` | Peer's `BRIDGE_AUTH_TOKEN` env not set (or shim was started before it was set). MCP shim picks up the env at startup — re-launch `claude` after exporting. |
| `401 Unauthorized` with `bearer token not recognised` | Token doesn't hash to anything in `BRIDGE_AUTH_TOKENS`. Re-run `printf '%s' "$RAW" \| sha256sum` and re-paste into the server env. |
| `403 forbidden: not key owner` on `memory_set`/`memory_delete` | Key was authored by a different identity. Either ask the original author to delete, or add yourself to `BRIDGE_MEMORY_ADMINS` for ops cleanup. |
| `413 Payload Too Large` on `send_message` | Body exceeded the 1 MB default cap (finding `ccf87dff`). Use `share_artifact` for >1 MB payloads (10 MB ceiling). |
| `bridge-auto` posts auto-pinging your stale dispatches | Per roadmap-v1 F5: dispatches with `to:` non-empty get 15 min SLA. `ack_dispatch` with an ETA or `complete_dispatch` to close. Empty `to:` (broadcast) is never tracked as a dispatch. |
| Peers tagged `[orphan-<prior>]` in `list_findings` | Boot ran the finding-author orphan migration in enforce mode (Item 7). Rows authored outside the registry got flagged. Investigate via `from=[orphan-...]` filter or re-author from the new identity. |
| `/metrics/prometheus` 200s, all other routes 401 | Working as intended — Prometheus is the only unauthed route. Front it with a reverse-proxy ACL if you need to gate scraping. |

## License

[Apache 2.0](./LICENSE).
