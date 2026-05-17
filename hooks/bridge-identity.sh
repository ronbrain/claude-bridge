#!/usr/bin/env bash
# Shared helper — emits this session's BRIDGE_SELF on stdout.
#
# Resolution:
#   1. $BRIDGE_SELF override.
#   2. $CLAUDE_CODE_SESSION_ID (set in bash hook context but NOT
#      in MCP stdio children — that's why we need step 3 too).
#   3. ~/.cache/bridge/session-<claude_pid> written by SessionStart,
#      where <claude_pid> is the Claude Code ancestor process found
#      by walking the parent chain.
#   4. Hostname only — last-resort fallback.

set -uo pipefail

if [[ -n "${BRIDGE_SELF:-}" ]]; then
  printf '%s\n' "$BRIDGE_SELF"
  exit 0
fi

host="$(hostname -s 2>/dev/null || hostname)"

sid="${CLAUDE_CODE_SESSION_ID:-}"
if [[ -z "$sid" ]]; then
  CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"
  claude_pid="$(~/.claude/hooks/bridge-claude-pid.sh 2>/dev/null)"
  if [[ -n "$claude_pid" && -s "$CACHE_DIR/session-$claude_pid" ]]; then
    sid="$(cat "$CACHE_DIR/session-$claude_pid" 2>/dev/null)"
  fi
fi

if [[ -z "$sid" ]]; then
  printf '%s\n' "$host"
  exit 0
fi

short="${sid//-/}"
short="${short:0:6}"
printf '%s/%s\n' "$host" "$short"
