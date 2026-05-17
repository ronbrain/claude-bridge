#!/usr/bin/env bash
# Shared helper — emits this session's role on stdout (comma-separated
# if multiple). Other bridge scripts source it
# (`ROLES="$(~/.claude/hooks/bridge-role.sh)"`) so they all agree on
# the same per-session role and pick up changes the user makes via
# `bridge role <name>` dynamically.
#
# Resolution order:
#   1. $BRIDGE_ROLE env — explicit override always wins.
#   2. ~/.cache/bridge/roles/<session_id>, where session_id is
#      resolved by walking the PPID chain back to the Claude Code
#      process that wrote session-${ppid} at SessionStart.
#   3. Empty — no role declared; bridge treats the instance as
#      broadcast-only (it'll never match an addressed message).

set -uo pipefail

if [[ -n "${BRIDGE_ROLE:-}" ]]; then
  printf '%s\n' "$BRIDGE_ROLE"
  exit 0
fi

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"

# Same PPID walk as bridge-identity.sh — find the session-${ppid} file
# left by SessionStart.
sid=""
for candidate_pid in "$PPID" "$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')"; do
  [[ -z "$candidate_pid" ]] && continue
  sid_file="${CACHE_DIR}/session-${candidate_pid}"
  if [[ -s "$sid_file" ]]; then
    sid="$(cat "$sid_file" 2>/dev/null || true)"
    [[ -n "$sid" ]] && break
  fi
done

[[ -z "$sid" ]] && exit 0

role_file="${CACHE_DIR}/roles/${sid}"
[[ -s "$role_file" ]] || exit 0

tr -d '\r' < "$role_file" | head -n1 | tr -d '[:space:]'
echo
