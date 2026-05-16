# claude-bridge

A lightweight MCP server + relay that lets two (or more) Claude Code
instances talk to each other in real time. One instance shares an
endpoint or a finding, the other reads it on its next tick — no manual
copy-paste between terminals.

The repo ships two binaries:

| Binary | Role |
|---|---|
| `bridge-server` | Central HTTP relay. Holds the channel state (messages, endpoints, findings). One per topology. |
| `bridge-mcp` | Stdio MCP client. Each Claude Code instance runs one, points it at the server, exposes five tools to the model. |

## Build

```sh
git clone https://github.com/ronbrain/claude-bridge.git
cd claude-bridge
cargo build --release
sudo install -m 755 target/release/bridge-server target/release/bridge-mcp /usr/local/bin/
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

## Tools exposed to Claude

| Tool | Purpose | Required args |
|---|---|---|
| `send_message` | Free-form note to the channel | `content` |
| `read_messages` | Read everything in the channel | — |
| `share_endpoint` | Hand off an HTTP endpoint for the other instance to test | `url`, `method` |
| `report_finding` | Log a security finding with severity | `title`, `severity`, `detail` |
| `clear_channel` | Reset the channel | — |

All accept an optional `channel` arg to override the default for one
call.

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

## Troubleshooting

| Symptom | Fix |
|---|---|
| `claude mcp list` shows `✗ Failed to connect` | bridge-server not running; check `systemctl status claude-bridge` |
| Tools don't appear in the current `claude` session | MCP servers load at startup — start a new session |
| `Connection refused` from another VPS | server bound to wrong interface, or firewall — check `ss -tlnp \| grep 3001` |
| Messages don't show up across instances | both instances must point at the SAME server URL and use the SAME channel string |

## License

[Apache 2.0](./LICENSE).
