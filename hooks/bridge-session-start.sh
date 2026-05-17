#!/usr/bin/env bash
# SessionStart hook — auto-assigns a role for this session if the
# project directory (cwd or any ancestor) contains a `.bridge-role`
# file. The role is persisted under
# ~/.cache/bridge/roles/<session_id> so it survives session
# resumption: Claude Code re-opens the same session_id, the role
# file is still there, the instance reclaims its role automatically.
# The user can also set the role manually at any time via
# `bridge role <name>` from inside the session.
#
# Identity comes from $CLAUDE_CODE_SESSION_ID (set by Claude Code in
# every child process), so there's no PPID dance — every bridge tool
# in the session can find the role file the same way.
#
# Always exits 0 — failing here would block session start and the
# bridge is a nice-to-have, not a hard dependency.

set -uo pipefail

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"
mkdir -p "$CACHE_DIR/roles" 2>/dev/null || exit 0

hook_input="$(cat 2>/dev/null || true)"
# Prefer the env var — the hook input also carries session_id but
# the env is the canonical Claude-Code-set value and works
# identically for every other tool.
sid="${CLAUDE_CODE_SESSION_ID:-}"
[[ -z "$sid" ]] && sid="$(printf '%s' "$hook_input" | jq -r '.session_id // empty' 2>/dev/null)"
[[ -z "$sid" ]] && exit 0
sid="${sid//\//_}"
sid="${sid//../_}"

cwd="$(printf '%s' "$hook_input" | jq -r '.cwd // empty' 2>/dev/null)"

# Auto-role: walk up from cwd looking for `.bridge-role`. First hit
# wins. Empty/whitespace-only file is treated as "no role" so a
# stale empty file doesn't clobber a role set manually via the CLI.
role_file="${CACHE_DIR}/roles/${sid}"
if [[ -n "$cwd" && -d "$cwd" ]]; then
  dir="$cwd"
  while [[ "$dir" != "/" && -n "$dir" ]]; do
    if [[ -f "$dir/.bridge-role" ]]; then
      role="$(head -n1 "$dir/.bridge-role" 2>/dev/null | tr -d '[:space:]')"
      if [[ -n "$role" ]]; then
        printf '%s\n' "$role" > "${role_file}.tmp" \
          && mv "${role_file}.tmp" "$role_file"
      fi
      break
    fi
    dir="$(dirname "$dir")"
  done
fi

# GC: drop roles/* files older than 30 days. Each is tiny but in
# long-lived shells they pile up across hundreds of sessions.
find "$CACHE_DIR/roles" -maxdepth 1 -type f -mtime +30 \
  -delete 2>/dev/null || true

exit 0
