#!/usr/bin/env bash
# Shared helper — emits this session's BRIDGE_SELF on stdout. Other
# bridge scripts source it (`SELF="$(~/.claude/hooks/bridge-identity.sh)"`)
# so they all agree on the same per-session identity.
#
# Resolution:
#   1. $BRIDGE_SELF — explicit override always wins. Use this when
#      you want a fixed name like `paledo/pentest`.
#   2. $CLAUDE_CODE_SESSION_ID — set by Claude Code in every child
#      process. We shorten to the first 6 hex chars and prepend the
#      short hostname so peers see `paledo/9c4e1d`.
#   3. Hostname only — last-resort fallback when running outside a
#      Claude Code session (one-shot CLI, hook tests).

set -uo pipefail

if [[ -n "${BRIDGE_SELF:-}" ]]; then
  printf '%s\n' "$BRIDGE_SELF"
  exit 0
fi

host="$(hostname -s 2>/dev/null || hostname)"
sid="${CLAUDE_CODE_SESSION_ID:-}"

if [[ -z "$sid" ]]; then
  printf '%s\n' "$host"
  exit 0
fi

# 6 hex chars is enough collision resistance for the handful of
# concurrent sessions a single user is likely to run.
short="${sid//-/}"
short="${short:0:6}"
printf '%s/%s\n' "$host" "$short"
