#!/usr/bin/env bash
# SessionStart hook — records this Claude Code instance's session_id
# under ~/.cache/bridge/session-${PPID} so the other bridge hooks
# (watch, drain) and the MCP child can later derive a stable
# per-session identity (BRIDGE_SELF=<host>/<short-id>) without
# needing the session_id on their own stdin.
#
# Also auto-assigns a role for this session if the project directory
# (cwd or any ancestor) contains a `.bridge-role` file. The role is
# persisted under ~/.cache/bridge/roles/<session_id> so it survives
# session resumption: Claude Code re-opens the same session_id, the
# role file is still there, the instance reclaims its role
# automatically. The user can also set the role manually at any time
# via `bridge role <name>` from inside the session.
#
# Why PPID? Both this hook and the other bridge hooks run as direct
# children of the Claude Code process, so their PPID is identical.
# That makes ~/.cache/bridge/session-${PPID} a stable rendezvous
# point for any process spawned by the same Claude Code session.
#
# Always exits 0 — failing here would block session start and the
# bridge is a nice-to-have, not a hard dependency.

set -uo pipefail

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"
mkdir -p "$CACHE_DIR" "$CACHE_DIR/roles" 2>/dev/null || exit 0

hook_input="$(cat 2>/dev/null || true)"
sid="$(printf '%s' "$hook_input" | jq -r '.session_id // empty' 2>/dev/null)"
cwd="$(printf '%s' "$hook_input" | jq -r '.cwd // empty' 2>/dev/null)"
[[ -z "$sid" ]] && exit 0

# Sanitize — session_id is uuid-like, but a forged hook stdin could
# carry slashes that would let an attacker break out of the cache
# directory below.
sid="${sid//\//_}"
sid="${sid//../_}"

# Record session_id → PPID. Both this hook and any sibling bridge
# hook from the same Claude Code process can find each other through
# ~/.cache/bridge/session-${PPID}.
printf '%s\n' "$sid" > "${CACHE_DIR}/session-${PPID}.tmp" \
  && mv "${CACHE_DIR}/session-${PPID}.tmp" "${CACHE_DIR}/session-${PPID}"

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

# GC: drop session-* and roles/* files older than 7 days. Each is
# tiny (~40 bytes) but in long-lived shells they pile up across
# hundreds of sessions. Cheap to run on every start.
find "$CACHE_DIR" -maxdepth 1 -name 'session-*' -type f -mtime +7 \
  -delete 2>/dev/null || true
find "$CACHE_DIR/roles" -maxdepth 1 -type f -mtime +7 \
  -delete 2>/dev/null || true

exit 0
