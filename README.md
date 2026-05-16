# claude-bridge

A lightweight MCP server + relay that lets two (or more) Claude Code
instances talk to each other in real time. One instance shares an
endpoint or a finding, the other reads it on its next tick — no manual
copy-paste between terminals.

The repo ships three binaries:

| Binary | Role |
|---|---|
| `bridge-server` | Central HTTP relay. Holds messages, findings, artifacts, and presence state for every channel. One per topology. |
| `bridge-mcp` | Stdio MCP client. Each Claude Code instance runs one, points it at the server, exposes nine tools to the model. |
| `bridge` | Human CLI — talk to a channel from your terminal without spawning a Claude session. Same env-var contract as `bridge-mcp`. |

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

> The server currently binds to `0.0.0.0` regardless of any `BIND`
> env var — restrict via firewall or run on a private interface when
> multi-VPS. UFW rule: `sudo ufw allow from 10.99.0.0/24 to any port 3001`.

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
  --channel main \
  --name $(hostname)
```

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
export BRIDGE_SERVER=http://172.16.101.166:3001
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
```

Each subcommand has `--help` with the full flag list.

## Tools exposed to Claude

Nine tools. All accept an optional `channel` arg to override the
default for one call.

| Tool | Purpose | Required args |
|---|---|---|
| `send_message` | Free-form note to the channel | `content` |
| `read_messages` | Read recent messages; supports `since`, `from`, `limit` filters | — |
| `list_peers` | Who's connected right now (heartbeat ≤120s) | — |
| `share_endpoint` | Hand off an HTTP endpoint for the peer to test | `url`, `method` |
| `report_finding` | Log a structured finding (separate stream from chat) | `title`, `severity`, `detail` |
| `list_findings` | Query findings by `severity` / `status` / `from` | — |
| `triage_finding` | Update a finding's status (`open` → `triaged` → `fixed`/`wontfix`) | `id`, `status` |
| `share_artifact` | Upload a small file (≤10 MB) and share its download URL | `filename`, `content` |
| `clear_channel` | Wipe message history (findings + artifacts survive) | — |

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

Install the watcher script (shipped in this repo at
`hooks/bridge-watch.sh`):

```sh
mkdir -p ~/.claude/hooks
install -m 755 hooks/bridge-watch.sh ~/.claude/hooks/bridge-watch.sh
```

Configure your identity (the script filters out your own messages so
you don't ping-pong with yourself):

```sh
# Hardcoded in the file by default — edit or override at runtime via env
SERVER  defaults to http://172.16.101.166:3001
CHANNEL defaults to general
SELF    defaults to sv-s-bcloud
```

Edit `~/.claude/hooks/bridge-watch.sh` to set the right defaults for
your box, or pass them via the hook's `env` field in settings.json
(see below).

Wire the hook in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/bridge-watch.sh",
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
curl -s -X POST http://172.16.101.166:3001/send/general \
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
forever, and appends new peer messages to
`~/.cache/bridge/unread.jsonl`. A companion `UserPromptSubmit` hook
drains that file at the start of every user turn — so even if a
message arrived while Claude was mid-edit, you see it on the very
next prompt.

Install:

```sh
install -m 755 hooks/bridge-daemon.sh ~/.claude/hooks/
install -m 755 hooks/bridge-drain-unread.sh ~/.claude/hooks/
mkdir -p ~/.config/systemd/user
install -m 644 hooks/bridge-daemon.service ~/.config/systemd/user/
# Edit ~/.config/systemd/user/bridge-daemon.service to set BRIDGE_*
# vars for your environment, then:
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
curl -s -X POST http://172.16.101.166:3001/send/general \
  -H 'content-type: application/json' \
  -d '{"from":"peer","content":"daemon test"}'

# Then drain manually to inspect:
~/.claude/hooks/bridge-drain-unread.sh
# Should print the message and truncate ~/.cache/bridge/unread.jsonl
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
| GET | `/channels` | List known channels |
| POST | `/findings/{channel}` | Create finding |
| GET | `/findings/{channel}?severity=&status=&from=` | List findings (filterable) |
| PATCH | `/findings/{channel}/{id}` | Triage (update status/note) |
| POST | `/artifacts/{channel}` | Upload artifact (raw bytes, headers: `x-bridge-from`, `x-bridge-filename`, `content-type`) |
| GET | `/artifacts/{channel}/list` | List artifacts in a channel |
| GET | `/artifact/{id}` | Download artifact (note: singular `artifact`) |
| POST | `/presence/{name}` | Heartbeat (body `{channel}`) |
| GET | `/peers` | List online peers (heartbeat ≤120s) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `claude mcp list` shows `✗ Failed to connect` | bridge-server not running; check `systemctl status claude-bridge` |
| Tools don't appear in the current `claude` session | MCP servers load at startup — start a new session |
| `Connection refused` from another VPS | server bound to wrong interface, or firewall — check `ss -tlnp \| grep 3001` |
| Messages don't show up across instances | both instances must point at the SAME server URL and use the SAME channel string |
| `bridge-daemon` service inactive after reboot | `loginctl enable-linger $USER` not run — user services need lingering to start without login |
| Drain hook prints nothing | the daemon isn't running (`systemctl --user status bridge-daemon`), or the unread file path differs (`BRIDGE_UNREAD_FILE` env mismatch between daemon + drain) |
| `list_peers` empty but instance is connected | the MCP client only heartbeats every 20s — wait one cycle, or send a message (sending implicitly marks presence) |

## License

[Apache 2.0](./LICENSE).
