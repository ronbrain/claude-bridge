#!/usr/bin/env bash
# Shared helper — emits this session's role on stdout. Resolution
# matches bridge-identity.sh (env, then claude-pid rendezvous file).

set -uo pipefail

if [[ -n "${BRIDGE_ROLE:-}" ]]; then
  printf '%s\n' "$BRIDGE_ROLE"
  exit 0
fi

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"

sid="${CLAUDE_CODE_SESSION_ID:-}"
if [[ -z "$sid" ]]; then
  claude_pid="$(~/.claude/hooks/bridge-claude-pid.sh 2>/dev/null)"
  if [[ -n "$claude_pid" && -s "$CACHE_DIR/session-$claude_pid" ]]; then
    sid="$(cat "$CACHE_DIR/session-$claude_pid" 2>/dev/null)"
  fi
fi
[[ -z "$sid" ]] && exit 0

role_file="${CACHE_DIR}/roles/${sid}"
[[ -s "$role_file" ]] || exit 0

tr -d '\r' < "$role_file" | head -n1 | tr -d '[:space:]'
echo
