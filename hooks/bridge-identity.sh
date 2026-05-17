#!/usr/bin/env bash
# Shared helper — emits this session's BRIDGE_SELF on stdout. Other
# bridge scripts source it (`SELF="$(~/.claude/hooks/bridge-identity.sh)"`)
# so they all agree on the same per-session identity.
#
# Resolution order:
#   1. $BRIDGE_SELF — explicit override always wins. Use this when
#      you want a fixed name like `paledo/pentest`.
#   2. session-${PPID} file written by bridge-session-start.sh. The
#      file contains the Claude Code session_id; we shorten it to
#      the first 6 hex chars and prepend the short hostname so peers
#      see `paledo/9c4e1d`.
#   3. Hostname only — last-resort fallback. Loses per-session
#      uniqueness but keeps things working when SessionStart didn't
#      fire (one-shot CLI calls, hook tests).

set -uo pipefail

if [[ -n "${BRIDGE_SELF:-}" ]]; then
  printf '%s\n' "$BRIDGE_SELF"
  exit 0
fi

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"
host="$(hostname -s 2>/dev/null || hostname)"

# Walk up from our caller. PPID is the script that sourced us;
# its PPID is Claude Code itself, where the session file lives.
# (Direct $PPID worked for hooks before — keeping a fallback in
# case some caller invokes us through an extra shell layer.)
sid=""
for candidate_pid in "$PPID" "$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')"; do
  [[ -z "$candidate_pid" ]] && continue
  sid_file="${CACHE_DIR}/session-${candidate_pid}"
  if [[ -s "$sid_file" ]]; then
    sid="$(cat "$sid_file" 2>/dev/null || true)"
    [[ -n "$sid" ]] && break
  fi
done

if [[ -z "$sid" ]]; then
  printf '%s\n' "$host"
  exit 0
fi

# Short id — 6 hex chars is enough collision resistance for the
# handful of concurrent sessions a single user is likely to run.
short="${sid:0:6}"
printf '%s/%s\n' "$host" "$short"
