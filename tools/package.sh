#!/usr/bin/env bash
# F24 — Plugin packaging script.
#
# Bundles bridge binaries + skills + starter settings into a
# distributable zip that operators can extract on a fresh host.
#
# Usage:
#   ./tools/package.sh [<out-dir>]
#
# Output:
#   <out-dir>/bridge-plugin-<version>.zip
#
# Default <out-dir> is dist/ in the repo root.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Version from Cargo.toml's first `version = "..."` line under [package].
version="$(awk '/^\[package\]/{p=1; next} p && /^version *= */{
    gsub(/.*= *"?|"?$/, "", $0); print; exit
}' Cargo.toml)"
[ -n "$version" ] || version="0.0.0-unknown"

out_dir="${1:-dist}"
mkdir -p "$out_dir"

# Build release binaries.
echo "[package] cargo build --release --bins"
cargo build --release --bins

# Stage the bundle.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/bin" "$stage/skills" "$stage/hooks" "$stage/share"

install -m 755 target/release/bridge-server   "$stage/bin/"
install -m 755 target/release/bridge-mcp      "$stage/bin/"
install -m 755 target/release/bridge          "$stage/bin/"
install -m 755 target/release/claude-bridge   "$stage/bin/"

# F25 skills — copy whatever's in skills/ verbatim. Operators
# drop these into ~/.claude/skills/ to enable /relay /handoff
# /claim-task slash commands.
cp -a skills/*.md "$stage/skills/" 2>/dev/null || true

# Hook scripts (if present) — operator installs to ~/.claude/hooks/.
cp -a hooks/*.sh "$stage/hooks/" 2>/dev/null || true
cp -a hooks/*.service "$stage/hooks/" 2>/dev/null || true

# Starter settings.json — minimal example wiring the MCP server
# + the recommended Stop/UserPromptSubmit hooks.
cat > "$stage/share/settings.example.json" <<'JSON'
{
  "_comment": "Starter settings for claude-bridge. Drop into ~/.claude/settings.json (merge with your existing config). Replace BRIDGE_AUTH_TOKEN with the raw token your operator issued.",
  "mcpServers": {
    "bridge": {
      "command": "/usr/local/bin/bridge-mcp",
      "args": ["--server", "https://bridge.example.com:3001", "--channel", "general"],
      "env": {
        "BRIDGE_AUTH_TOKEN": "REPLACE_WITH_YOUR_RAW_TOKEN"
      }
    }
  },
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "~/.claude/hooks/bridge-session-start.sh" } ] }
    ],
    "Stop": [
      { "hooks": [ {
          "type": "command",
          "command": "BRIDGE_CHANNEL=general ~/.claude/hooks/bridge-watch.sh",
          "asyncRewake": true,
          "rewakeMessage": "New bridge message — read and respond:",
          "rewakeSummary": "Bridge message from peer"
      } ] }
    ],
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "~/.claude/hooks/bridge-drain-unread.sh" } ] }
    ]
  }
}
JSON

# README for the bundle.
cat > "$stage/README.md" <<MD
# claude-bridge plugin bundle

Version: \`$version\`
Built: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`

## Install

1. Copy binaries:
   \`\`\`sh
   sudo install -m 755 bin/* /usr/local/bin/
   \`\`\`

2. Install hooks (optional but recommended for auto-wake):
   \`\`\`sh
   mkdir -p ~/.claude/hooks
   cp hooks/* ~/.claude/hooks/
   chmod +x ~/.claude/hooks/*.sh
   \`\`\`

3. Install skills (F25):
   \`\`\`sh
   mkdir -p ~/.claude/skills
   cp skills/* ~/.claude/skills/
   \`\`\`
   This enables \`/relay\`, \`/handoff\`, \`/claim-task\` slash commands.

4. Merge \`share/settings.example.json\` into your \`~/.claude/settings.json\`.
   Replace \`REPLACE_WITH_YOUR_RAW_TOKEN\` with the bearer your operator
   issued (see Authentication in the main README for token issuance).

5. Restart your Claude Code session. The bridge MCP tools surface
   in \`/mcp\` and the hooks fire automatically.

## What's in this bundle

- \`bin/\` — 4 statically-bundled binaries (bridge-server, bridge-mcp,
  bridge, claude-bridge).
- \`skills/\` — 3 custom skill markdown files (relay, handoff, claim-task).
- \`hooks/\` — bridge-session-start.sh, bridge-watch.sh,
  bridge-drain-unread.sh (when packaged with hook scripts present).
- \`share/settings.example.json\` — starter MCP + hook config.

## Operator: server-side setup

The above instructions are for PEER hosts. The bridge SERVER also
runs from the same \`bridge-server\` binary; see the project README
for systemd unit, env-var contract (BRIDGE_AUTH_TOKENS,
BRIDGE_DB_PATH, BRIDGE_BIND), and ops-rule documentation.
MD

# Zip it up.
out="$out_dir/bridge-plugin-$version.zip"
( cd "$stage" && zip -rq "$OLDPWD/$out" . )
echo "[package] wrote $out ($(du -h "$out" | awk '{print $1}'))"
