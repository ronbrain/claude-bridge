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
# Multi-channel: $BRIDGE_CHANNEL accepts a comma-separated list (same
# as bridge-watch.sh). Each channel runs in its own background
# subprocess with its own SSE connection and reconnect loop; all
# writers funnel into the same $LOG_FILE behind a flock.

set -uo pipefail

SERVER="${BRIDGE_SERVER:-http://172.16.101.166:3001}"
CHANNELS_RAW="${BRIDGE_CHANNEL:-general}"
SELF="${BRIDGE_SELF:-$(hostname -s 2>/dev/null || hostname)}"
LOG_FILE="${BRIDGE_LOG_FILE:-$HOME/.cache/bridge/messages.jsonl}"
LOG_MAX_LINES="${BRIDGE_LOG_MAX_LINES:-10000}"

mkdir -p "$(dirname "$LOG_FILE")"

IFS=',' read -ra CHANNELS <<< "$CHANNELS_RAW"
TRIMMED=()
for c in "${CHANNELS[@]}"; do
  c="${c// /}"
  [[ -n "$c" ]] && TRIMMED+=("$c")
done
[[ ${#TRIMMED[@]} -eq 0 ]] && TRIMMED=("general")

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

watch_one() {
  local channel="$1"
  local append_count=0
  local backoff=2
  while true; do
    while IFS= read -r line; do
      [[ "$line" == data:* ]] || continue
      local payload="${line#data: }"
      [[ "$payload" == "ping" ]] && continue

      local from
      from="$(printf '%s' "$payload" | jq -r '.from // empty' 2>/dev/null)"
      [[ -z "$from" ]] && continue
      [[ "$from" == "$SELF" ]] && continue

      # Append raw JSON — flock guards against concurrent appends
      # from the sibling watchers (one per channel).
      {
        flock -x 9
        printf '%s\n' "$payload" >> "$LOG_FILE"
        append_count=$(( append_count + 1 ))
        if (( append_count % 100 == 0 )); then
          local tmp="${LOG_FILE}.trim.$$"
          if tail -n "$LOG_MAX_LINES" "$LOG_FILE" > "$tmp" 2>/dev/null; then
            mv "$tmp" "$LOG_FILE"
          else
            rm -f "$tmp"
          fi
        fi
      } 9>"${LOG_FILE}.lock"

      backoff=2
    done < <(curl -sN --no-buffer --max-time 0 "${SERVER}/stream/${channel}" 2>/dev/null)

    sleep "$backoff"
    if [ "$backoff" -lt 60 ]; then
      backoff=$(( backoff * 2 ))
    fi
  done
}

# Spawn one watcher per channel.
for c in "${TRIMMED[@]}"; do
  watch_one "$c" &
  PIDS+=("$!")
done

# Block on any child; if one dies the script keeps the others alive
# until systemd restart cycles us.
wait -n
