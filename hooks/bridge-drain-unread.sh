#!/usr/bin/env bash
# UserPromptSubmit hook companion to bridge-daemon.sh.
#
# Reads the shared append-only log written by the daemon, surfaces
# only messages this session hasn't seen yet, then advances the
# per-session offset. Multiple Claude Code instances on the same
# machine each maintain their own offset, so every instance sees
# every message exactly once.
#
# Exits 0 with empty stdout when there's nothing new — no noise on
# every turn when the channel is quiet.

set -uo pipefail

LOG_FILE="${BRIDGE_LOG_FILE:-$HOME/.cache/bridge/messages.jsonl}"
OFFSET_DIR="${BRIDGE_OFFSET_DIR:-$HOME/.cache/bridge/offsets}"

# The hook receives a JSON payload on stdin including the session_id
# Claude Code assigns to this instance. We key the offset on that so
# each instance has its own cursor. Fall back to PPID when there's no
# session_id (e.g. someone invokes the hook by hand to test).
hook_input="$(cat 2>/dev/null || true)"
sid="$(printf '%s' "$hook_input" | jq -r '.session_id // empty' 2>/dev/null)"
[[ -z "$sid" ]] && sid="anon-${PPID:-$$}"
# Defensive: strip anything that could traverse out of OFFSET_DIR — a
# malformed or forged session_id with slashes would be path traversal.
sid="${sid//\//_}"
sid="${sid//../_}"

mkdir -p "$OFFSET_DIR"
offset_file="$OFFSET_DIR/$sid"

# First run for this session: anchor the offset at "now" so we don't
# replay the entire history of messages that arrived before this
# instance ever existed. The user starting a fresh session doesn't
# want a wall of stale chat — only what arrives from here on.
if [[ ! -f "$offset_file" ]]; then
  date +%s > "$offset_file"
  exit 0
fi

offset="$(cat "$offset_file" 2>/dev/null || echo 0)"
# A corrupted offset file must not break the hook.
[[ "$offset" =~ ^[0-9]+$ ]] || offset=0

[[ -s "$LOG_FILE" ]] || exit 0

# Filter unread (timestamp > offset). Single jq pass collects them
# into an array so we can both render and compute the new max.
# `-n` so jq reads exclusively via `inputs` — without it jq consumes
# the first JSON value before the filter runs, which on a 1-line log
# means the only message is silently swallowed.
unread_json="$(jq -cn --argjson off "$offset" \
  '[inputs | select(.timestamp > $off)]' \
  < "$LOG_FILE" 2>/dev/null || echo '[]')"

count="$(printf '%s' "$unread_json" | jq 'length' 2>/dev/null || echo 0)"
[[ "$count" -eq 0 ]] && exit 0

new_max="$(printf '%s' "$unread_json" | jq 'map(.timestamp) | max // 0' 2>/dev/null)"
[[ -z "$new_max" || "$new_max" == "null" ]] && new_max="$offset"

{
  echo "📬 Unread bridge messages (${count}) — arrived while you were away:"
  echo
  printf '%s' "$unread_json" | jq -r '.[] | "[\(.timestamp)] \(.from) on #\(.channel):\n\(.content)\n---"'
} 2>/dev/null || true

# Atomic update of the offset so a crash mid-write can't leave a
# partial number that fails the regex check on the next run.
printf '%s\n' "$new_max" > "${offset_file}.tmp" && mv "${offset_file}.tmp" "$offset_file"

exit 0
