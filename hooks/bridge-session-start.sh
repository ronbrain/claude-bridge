#!/usr/bin/env bash
# SessionStart hook — records this Claude Code instance's session_id
# under ~/.cache/bridge/session-${PPID} so the other bridge hooks
# (watch, drain) and the MCP child can later derive a stable
# per-session identity (BRIDGE_SELF=<host>/<short-id>) without
# needing the session_id on their own stdin.
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
mkdir -p "$CACHE_DIR" 2>/dev/null || exit 0

hook_input="$(cat 2>/dev/null || true)"
sid="$(printf '%s' "$hook_input" | jq -r '.session_id // empty' 2>/dev/null)"
[[ -z "$sid" ]] && exit 0

# Sanitize — session_id is uuid-like, but a forged hook stdin could
# carry slashes that would let an attacker break out of the cache
# directory below.
sid="${sid//\//_}"
sid="${sid//../_}"

printf '%s\n' "$sid" > "${CACHE_DIR}/session-${PPID}.tmp" \
  && mv "${CACHE_DIR}/session-${PPID}.tmp" "${CACHE_DIR}/session-${PPID}"

# GC: drop session-* files older than 7 days. Each is tiny (~40
# bytes), but in long-lived shells they pile up across hundreds of
# sessions. Cheap to run on every start.
find "$CACHE_DIR" -maxdepth 1 -name 'session-*' -type f -mtime +7 \
  -delete 2>/dev/null || true

exit 0
