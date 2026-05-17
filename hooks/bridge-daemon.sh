#!/usr/bin/env bash
# Standalone daemon variant of bridge-watch.sh. Runs forever, never
# exits on a successful message. Appends every peer message (one JSON
# per line) to $LOG_FILE — an append-only monotonic log.
#
# The drain hook (`bridge-drain-unread.sh`) reads this log with a
# per-session offset so multiple Claude Code instances on the same
# machine each see every message exactly once (instead of the first
# instance to drain swallowing the lot, which is what happened with
# the old shared-unread.jsonl "drain-and-truncate" model).
#
# Difference from bridge-watch.sh (the asyncRewake hook):
#   * watch: exits 2 on first foreign message → wakes Claude between
#     turns. Stops listening once Claude wakes. Per-session (each
#     instance subscribes independently to SSE).
#   * daemon: keeps listening forever; new messages pile in
#     $LOG_FILE; the UserPromptSubmit hook surfaces them at the
#     start of every user turn even if Claude is busy when they arrive.

set -uo pipefail

SERVER="${BRIDGE_SERVER:-http://172.16.101.166:3001}"
CHANNEL="${BRIDGE_CHANNEL:-general}"
# `hostname -s` (short) keeps the peer name compact; the FQDN-version
# can leak DNS suffixes into the channel and looks noisy in /peers.
# Override BRIDGE_SELF explicitly for ambiguous-hostname boxes.
SELF="${BRIDGE_SELF:-$(hostname -s 2>/dev/null || hostname)}"
LOG_FILE="${BRIDGE_LOG_FILE:-$HOME/.cache/bridge/messages.jsonl}"
# Trim threshold — keep this many most-recent lines. Each line is
# typically <2KB so 10000 ≈ 20MB worst case.
LOG_MAX_LINES="${BRIDGE_LOG_MAX_LINES:-10000}"

mkdir -p "$(dirname "$LOG_FILE")"

append_count=0

# The SSE connection can drop on bridge-server restart / network blip.
# Outer loop reconnects with backoff so the daemon survives forever.
backoff=2
while true; do
  # Consume the stream — `< <(curl …)` keeps the while in the main
  # shell so appends write to the parent's FD, not a subshell's.
  while IFS= read -r line; do
    [[ "$line" == data:* ]] || continue
    payload="${line#data: }"
    [[ "$payload" == "ping" ]] && continue

    from="$(printf '%s' "$payload" | jq -r '.from // empty' 2>/dev/null)"
    [[ -z "$from" ]] && continue
    [[ "$from" == "$SELF" ]] && continue

    # Append raw JSON — the drain hook formats it. Flock guards
    # against concurrent appends (multiple daemons, paranoia).
    {
      flock -x 9
      printf '%s\n' "$payload" >> "$LOG_FILE"

      # Periodic trim — every 100 appends, keep only the most-recent
      # LOG_MAX_LINES. Cheap on small files, prevents unbounded
      # growth across long-lived daemons.
      append_count=$(( append_count + 1 ))
      if (( append_count % 100 == 0 )); then
        tmp="${LOG_FILE}.trim.$$"
        if tail -n "$LOG_MAX_LINES" "$LOG_FILE" > "$tmp" 2>/dev/null; then
          mv "$tmp" "$LOG_FILE"
        else
          rm -f "$tmp"
        fi
      fi
    } 9>"${LOG_FILE}.lock"

    # Successful event → reset backoff
    backoff=2
  done < <(curl -sN --no-buffer --max-time 0 "${SERVER}/stream/${CHANNEL}" 2>/dev/null)

  # Stream closed (server restart, network glitch). Wait + reconnect.
  sleep "$backoff"
  if [ "$backoff" -lt 60 ]; then
    backoff=$(( backoff * 2 ))
  fi
done
