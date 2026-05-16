#!/usr/bin/env bash
# Standalone daemon variant of bridge-watch.sh. Runs forever, never
# exits on a successful message. Appends every peer message (one JSON
# per line) to $UNREAD_FILE so the UserPromptSubmit hook can drain it
# on the next user turn.
#
# Difference from bridge-watch.sh (the asyncRewake hook):
#   * watch: exits 2 on first foreign message → wakes Claude between
#     turns. Stops listening once Claude wakes.
#   * daemon: keeps listening forever; new messages pile in
#     $UNREAD_FILE; the UserPromptSubmit hook surfaces them at the
#     start of every user turn even if Claude is busy when they arrive.
#
# Run both for full coverage:
#   - Stop hook + asyncRewake → wake Claude when idle
#   - Daemon → catch messages that arrived during a busy turn

set -uo pipefail

SERVER="${BRIDGE_SERVER:-http://172.16.101.166:3001}"
CHANNEL="${BRIDGE_CHANNEL:-general}"
# `hostname -s` (short) keeps the peer name compact; the FQDN-version
# can leak DNS suffixes into the channel and looks noisy in /peers.
# Override BRIDGE_SELF explicitly for ambiguous-hostname boxes.
SELF="${BRIDGE_SELF:-$(hostname -s 2>/dev/null || hostname)}"
UNREAD_FILE="${BRIDGE_UNREAD_FILE:-$HOME/.cache/bridge/unread.jsonl}"

mkdir -p "$(dirname "$UNREAD_FILE")"

# The SSE connection can drop on bridge-server restart / network blip.
# Outer loop reconnects with backoff so the daemon survives forever.
backoff=2
while true; do
  # Consume the stream — `< <(curl …)` keeps the while in the main
  # shell so `append` writes go to the parent's FD, not a subshell's.
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
      printf '%s\n' "$payload" >> "$UNREAD_FILE"
    } 9>"${UNREAD_FILE}.lock"

    # Successful event → reset backoff
    backoff=2
  done < <(curl -sN --no-buffer --max-time 0 "${SERVER}/stream/${CHANNEL}" 2>/dev/null)

  # Stream closed (server restart, network glitch). Wait + reconnect.
  sleep "$backoff"
  if [ "$backoff" -lt 60 ]; then
    backoff=$(( backoff * 2 ))
  fi
done
