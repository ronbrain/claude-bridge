# claude-bridge

A lightweight MCP server + relay that lets two (or more) Claude Code
instances talk to each other in real time. One instance shares an
endpoint or a finding, the other reads it on its next tick — no manual
copy-paste between terminals.

The repo ships three binaries:

| Binary | Role |
|---|---|
| `bridge-server` | Central HTTP relay. Holds messages, findings, artifacts, and presence state for every channel. One per topology. |
| `bridge-mcp` | Stdio MCP client. Each Claude Code instance runs one, points it at the server, exposes twelve tools to the model. |
| `bridge` | Human CLI — talk to a channel from your terminal without spawning a Claude session. Same env-var contract as `bridge-mcp`. |

Beyond the bus itself the repo ships a coordination layer on top —
per-session identities, declared roles, addressed messages, and
channel topics — so N Claude Code instances on the same host stay
distinguishable and only act on what's actually for them. See
[Identity, roles, and addressing](#identity-roles-and-addressing).

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
| `PORT` | `3001` | TCP port to listen on. |
| `BRIDGE_DB_PATH` | _(unset)_ | When set, enables sqlite persistence — see [Persistence](#persistence) below. Example: `/var/lib/claude-bridge/bridge.db`. |

> The server currently binds to `0.0.0.0` regardless of any `BIND`
> env var — restrict via firewall or run on a private interface when
> multi-VPS. UFW rule: `sudo ufw allow from 10.99.0.0/24 to any port 3001`.

### Persistence

By default the server is **in-memory only** — a restart drops every
message, finding, and artifact. Coordination tools usually want
durability across restarts, especially for findings (you don't want
to lose the open queue when the box reboots).

Opt in by setting `BRIDGE_DB_PATH` to a sqlite file path:

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
- Schema is created on first run (`CREATE TABLE IF NOT EXISTS`),
  WAL mode for write-while-read.
- Every write path mirrors to disk **after** the in-memory update
  succeeds — the hot read path doesn't block on disk.
- Boot rehydrates messages / findings / artifacts back into the
  DashMaps, honouring the same in-memory caps (100 messages /
  channel, 500 findings / channel, 200 artifacts globally).
- A failed sqlite write logs a warning but does NOT fail the HTTP
  request — better to lose a row to crash than reject a working send
  because the disk got tight.
- Channel evictions (when >256 channels) cascade-delete the
  channel's rows from the DB so disk usage stays bounded.

Backup is `cp bridge.db bridge.db.bak` (or `sqlite3 .backup`). The
file is the entire state.

Presence (`/peers`) is intentionally NOT persisted — a peer
presumed online after a server restart would be misleading. Peers
re-register via heartbeat within 20 s of the MCP client reconnecting.

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
  -- \
  --server http://localhost:3001 \
  --channel main
```

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

# Read or set the role for the current Claude Code session.
# Works from any subshell launched inside a session.
bridge role            # read
bridge role pentest    # set
bridge role ""         # clear
```

Each subcommand has `--help` with the full flag list.

## Tools exposed to Claude

Twelve tools. All accept an optional `channel` arg to override the
default for one call.

| Tool | Purpose | Required args |
|---|---|---|
| `send_message` | Free-form note to the channel; optional `to: [<name\|role>]` for addressed delivery | `content` |
| `read_messages` | Read recent messages; supports `since`, `from`, `limit` filters | — |
| `list_peers` | Who's connected right now (heartbeat ≤120s) with their declared roles | — |
| `list_channels` | Every known channel with its declared topic — call before `send_message` if unsure where a message belongs | — |
| `set_channel_topic` | Declare/update the one-line purpose of a channel | `channel`, `topic` |
| `share_endpoint` | Hand off an HTTP endpoint for the peer to test | `url`, `method` |
| `report_finding` | Log a structured finding (separate stream from chat) | `title`, `severity`, `detail` |
| `list_findings` | Query findings by `severity` / `status` / `from` | — |
| `triage_finding` | Update a finding's status (`open` → `triaged` → `fixed`/`wontfix`) | `id`, `status` |
| `delete_finding` | Hard-delete a finding (false positives, noisy reports) | `id` |
| `share_artifact` | Upload a small file (≤10 MB) and share its download URL | `filename`, `content` |
| `clear_channel` | Wipe message history (findings + artifacts survive) | — |
| `delete_channel` | Hard-delete a channel — wipes history, findings, topic, and removes it from `list_channels` | `channel` |

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

- The server has **no auth** built in. If exposing beyond localhost,
  put it behind WireGuard / a firewall / a reverse proxy that
  enforces auth. Anyone who can reach the port can read and write
  every channel.
- Messages are held in memory only — `bridge-server` restart drops
  the channel state. That's intentional: keep coordination
  ephemeral, push durable state to the codebase.
- Don't paste production secrets through `share_endpoint`. Use
  references (`see env var X on box Y`) rather than literal tokens.

## HTTP endpoint reference

Use these directly from `curl` or your own client. The MCP and CLI
binaries are thin wrappers.

| Method | Path | Purpose |
|---|---|---|
| POST | `/send/{channel}` | Send a message |
| GET | `/messages/{channel}?since=&from=&limit=` | List messages (filterable) |
| DELETE | `/messages/{channel}` | Clear message history |
| GET | `/stream/{channel}` | Server-sent events stream (one event per new message) |
| GET | `/channels` | List known channels (returns `[{name, topic, updated_by, updated_at}]`) |
| GET | `/channels/{channel}/topic` | Get a single channel's topic |
| PUT | `/channels/{channel}/topic` | Set a channel's topic (body `{from, topic}`) |
| DELETE | `/channels/{channel}` | Hard-delete a channel (history + findings + topic + sender) |
| POST | `/findings/{channel}` | Create finding |
| GET | `/findings/{channel}?severity=&status=&from=` | List findings (filterable) |
| PATCH | `/findings/{channel}/{id}` | Triage (update status/note) |
| DELETE | `/findings/{channel}/{id}` | Hard-delete a finding |
| POST | `/artifacts/{channel}` | Upload artifact (raw bytes, headers: `x-bridge-from`, `x-bridge-filename`, `content-type`) |
| GET | `/artifacts/{channel}/list` | List artifacts in a channel |
| GET | `/artifact/{id}` | Download artifact (note: singular `artifact`) |
| POST | `/presence/{name}` | Heartbeat (body `{channel, roles?}` — name is path-encoded so `/` in identities works) |
| GET | `/peers` | List online peers (heartbeat ≤120s) with their declared roles |

`POST /send/{channel}` body schema:
`{from, content, to?: [<name|role>]}` — empty `to` is broadcast.
Clients filter on receive; the server is a dumb relay.

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

## License

[Apache 2.0](./LICENSE).
