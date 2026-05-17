#!/usr/bin/env bash
# Shared helper — emits the PID of the Claude Code process that owns
# our current process tree on stdout. Bash hooks and the bridge CLI
# can reach it via parent walk; MCP (direct child of claude) finds
# it in one step.
#
# Used as a rendezvous key: SessionStart writes
# `~/.cache/bridge/session-<claude-pid>` with the session_id, and
# every other tool reads that file by computing the same PID.
#
# Exits 0 with empty stdout when no claude process is found in the
# ancestor chain (e.g. the script runs from a detached cron job).

set -uo pipefail

pid="${1:-$PPID}"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ -z "$pid" || "$pid" == "0" || "$pid" == "1" ]] && exit 0
  comm="$(cat /proc/$pid/comm 2>/dev/null || true)"
  if [[ "$comm" == "claude" ]]; then
    printf '%s\n' "$pid"
    exit 0
  fi
  # /proc/<pid>/stat field 4 is ppid; field 2 (comm in parens) can
  # contain spaces, so anchor on the LAST ')' before splitting.
  stat="$(cat /proc/$pid/stat 2>/dev/null || true)"
  [[ -z "$stat" ]] && exit 0
  after="${stat##*)}"
  read -ra parts <<< "$after"
  pid="${parts[1]:-}"
done
