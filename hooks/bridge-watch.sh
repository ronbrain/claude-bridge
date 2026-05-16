#!/usr/bin/env bash
# Long-polls the claude-bridge SSE stream and exits with code 2 the
# moment a message from anyone OTHER than this instance arrives.
# Claude's `asyncRewake` Stop hook treats exit code 2 as a signal to
# re-wake the model with stdout as the additional context.
#
# Behavior:
#   * Connects to /stream/<channel> on the remote bridge-server.
#   * Filters out SSE keepalive lines (start with `:` or contain "ping").
#   * Filters out our own messages (`from == $SELF`) so we don't
#     ping-pong with ourselves.
#   * On the first foreign message: print it and exit 2.
#   * Any other exit (network glitch, server restart, user starts
#     typing) is fine — the hook re-runs at the next Stop event.

set -euo pipefail

SERVER="${BRIDGE_SERVER:-http://172.16.101.166:3001}"
CHANNEL="${BRIDGE_CHANNEL:-general}"
SELF="${BRIDGE_SELF:-sv-s-bcloud}"

# `--no-buffer` flushes per-line so we react instantly instead of
# waiting for the curl receive buffer to fill.
# `--max-time 0` keeps the long-poll open until either a message
# arrives or the asyncRewake watcher is cancelled by the next turn.
#
# Process substitution `< <(curl ...)` is intentional — piping curl
# into `while` forks a subshell, and `exit 2` inside that subshell
# only exits the subshell, NOT the parent script. The rewake signal
# would be lost. Process sub keeps the `while` in the main shell.
while IFS= read -r line; do
    # SSE shape: `data: {json}` or `:ping` keepalive. Skip anything
    # that isn't a data frame.
    [[ "$line" == data:* ]] || continue
    payload="${line#data: }"

    # Skip the literal "ping" frame just in case axum uses .text() for
    # keepalive in some path.
    [[ "$payload" == "ping" ]] && continue

    # Pull `from` field. If parsing fails (malformed JSON), skip.
    from="$(printf '%s' "$payload" | jq -r '.from // empty' 2>/dev/null)"
    [[ -z "$from" ]] && continue
    [[ "$from" == "$SELF" ]] && continue

    # Got a real foreign message — surface it and exit 2 to rewake.
    content="$(printf '%s' "$payload" | jq -r '.content // ""' 2>/dev/null)"
    ts="$(printf '%s' "$payload" | jq -r '.timestamp // ""' 2>/dev/null)"
    printf '[%s] %s on #%s:\n%s\n' "$ts" "$from" "$CHANNEL" "$content"
    exit 2
  done < <(curl -sN --no-buffer --max-time 0 "${SERVER}/stream/${CHANNEL}" 2>/dev/null)

# Stream closed cleanly without a message (server restart, etc.) —
# normal exit, no rewake.
exit 0
