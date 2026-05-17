#!/usr/bin/env bash
# Shared helper — emits this session's role on stdout (comma-separated
# if multiple). Other bridge scripts source it
# (`ROLES="$(~/.claude/hooks/bridge-role.sh)"`) so they all agree on
# the same per-session role and pick up changes the user makes via
# `bridge role <name>` dynamically.
#
# Resolution:
#   1. $BRIDGE_ROLE env — explicit override always wins.
#   2. ~/.cache/bridge/roles/<CLAUDE_CODE_SESSION_ID> — the file the
#      `bridge role` CLI writes and the SessionStart hook may
#      pre-populate from a `.bridge-role` file in the project root.
#   3. Empty — no role declared; bridge treats the instance as
#      broadcast-only (it'll never match an addressed message).

set -uo pipefail

if [[ -n "${BRIDGE_ROLE:-}" ]]; then
  printf '%s\n' "$BRIDGE_ROLE"
  exit 0
fi

sid="${CLAUDE_CODE_SESSION_ID:-}"
[[ -z "$sid" ]] && exit 0

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"
role_file="${CACHE_DIR}/roles/${sid}"
[[ -s "$role_file" ]] || exit 0

tr -d '\r' < "$role_file" | head -n1 | tr -d '[:space:]'
echo
