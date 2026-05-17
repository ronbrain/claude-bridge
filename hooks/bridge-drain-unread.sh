#!/usr/bin/env bash
# UserPromptSubmit hook companion to bridge-daemon.sh.
#
# Reads the shared append-only log written by the daemon, surfaces
# only messages this session hasn't seen yet, then advances the
# per-session offset. Multiple Claude Code instances on the same
# machine each maintain their own offset, so every instance sees
# every message exactly once.
#
# Concurrency: wrapped in a per-session flock so two simultaneous
# invocations of this hook (Claude Code firing it twice for the
# same turn, or a tail-end overlap with the previous turn's drain)
# serialise on the same offset file. Without the lock, two reads
# would both compute "unread = same set", both print, but only one
# would land in the model's context — and worse, the second writer
# would silently re-overwrite the offset with nothing new visible.

set -uo pipefail

LOG_FILE="${BRIDGE_LOG_FILE:-$HOME/.cache/bridge/messages.jsonl}"
OFFSET_DIR="${BRIDGE_OFFSET_DIR:-$HOME/.cache/bridge/offsets}"
TRACE_FILE="${BRIDGE_DRAIN_TRACE:-$HOME/.cache/bridge/drain.log}"

# Per-session identity + roles for the `to` addressing filter.
SELF_NAME="$(~/.claude/hooks/bridge-identity.sh 2>/dev/null || hostname -s)"
SELF_ROLES="$(~/.claude/hooks/bridge-role.sh 2>/dev/null || echo)"

# Firehose mode: surface every peer message regardless of the
# `to` addressing filter. Use for ops / observability roles that
# need the full feed. Enabled by:
#   - $BRIDGE_DRAIN_ALL in env (any non-empty value), or
#   - touch ~/.cache/bridge/drain-all/<session_id>
DRAIN_ALL=0
if [[ -n "${BRIDGE_DRAIN_ALL:-}" ]]; then
  DRAIN_ALL=1
elif [[ -n "${CLAUDE_CODE_SESSION_ID:-}" && -f "${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}/drain-all/${CLAUDE_CODE_SESSION_ID}" ]]; then
  DRAIN_ALL=1
fi

# Per-session offset key.
hook_input="$(cat 2>/dev/null || true)"
sid="${CLAUDE_CODE_SESSION_ID:-}"
[[ -z "$sid" ]] && sid="$(printf '%s' "$hook_input" | jq -r '.session_id // empty' 2>/dev/null)"
[[ -z "$sid" ]] && sid="anon-${PPID:-$$}"
sid="${sid//\//_}"
sid="${sid//../_}"

mkdir -p "$OFFSET_DIR"
offset_file="$OFFSET_DIR/$sid"
lock_file="${offset_file}.lock"

# Append a single-line trace so a future "I missed a message" debug
# can correlate: when did drain run, what offset did it see, how
# many surfaced. Lives next to the log so the operator can `tail -f`.
trace() {
  printf '[%s] sid=%s pid=%s ppid=%s %s\n' \
    "$(date +%s)" "${sid:0:8}" "$$" "${PPID:-0}" "$*" \
    >> "$TRACE_FILE" 2>/dev/null || true
}

# Serialise. Any concurrent invocation blocks here until the first
# one finishes, then re-reads the (now-advanced) offset and finds
# nothing — which is correct: the first drain delivered the batch,
# the second has nothing to do.
exec 8>"$lock_file"
if ! flock -w 10 8; then
  trace "lock timeout — bailing"
  exit 0
fi

if [[ ! -f "$offset_file" ]]; then
  date +%s > "$offset_file"
  trace "anchored offset (first run for this sid)"
  exit 0
fi

offset="$(cat "$offset_file" 2>/dev/null || echo 0)"
[[ "$offset" =~ ^[0-9]+$ ]] || offset=0

if [[ ! -s "$LOG_FILE" ]]; then
  trace "log empty, offset=$offset"
  exit 0
fi

combined="$(SELF_NAME="$SELF_NAME" SELF_ROLES="$SELF_ROLES" DRAIN_ALL="$DRAIN_ALL" \
  jq -cn --argjson off "$offset" '
    ($ENV.SELF_ROLES // "") | split(",") | map(select(length>0)) as $roles
    | ($ENV.SELF_NAME // "") as $name
    | (($ENV.DRAIN_ALL // "0") != "0") as $firehose
    | [inputs | select(.timestamp > $off)] as $all
    | [
        ($all | map(select(
            $firehose
            or ((.to // []) | length) == 0
            or ((.to // []) | index($name))
            or ((.to // []) | map(. as $t | $roles | index($t)) | any)
          ))),
        ($all | map(.timestamp) | max // 0)
      ]' \
  < "$LOG_FILE" 2>/dev/null || echo '[[],0]')"

unread_json="$(printf '%s' "$combined" | jq -c '.[0]' 2>/dev/null || echo '[]')"
absolute_max="$(printf '%s' "$combined" | jq -r '.[1]' 2>/dev/null || echo 0)"
count="$(printf '%s' "$unread_json" | jq 'length' 2>/dev/null || echo 0)"

new_max="$absolute_max"
[[ -z "$new_max" || "$new_max" == "null" || "$new_max" == "0" ]] && new_max="$offset"

if [[ "$count" -eq 0 ]]; then
  # Even when nothing matched our addressing filter, advance the
  # offset so a flood of messages-not-for-us doesn't replay forever.
  printf '%s\n' "$new_max" > "${offset_file}.tmp" && mv "${offset_file}.tmp" "$offset_file"
  trace "offset $offset → $new_max, surfaced=0"
  exit 0
fi

# Render BEFORE advancing the offset. If a downstream tool reads
# stdout (Claude Code's hook injector) but somehow drops it, we
# don't want to have already moved the cursor past those messages.
# Note: this guarantees at-least-once delivery (a crash mid-write
# of the offset file leaves the message un-acked → next turn
# re-surfaces) which is the right failure mode for chat.
{
  echo "📬 Unread bridge messages (${count}) — arrived while you were away:"
  echo
  printf '%s' "$unread_json" | jq -r '.[]
    | ((.to // []) | join(",")) as $to
    | (if $to != "" then ("→ to: " + $to + "\n") else "" end) as $tl
    | "[\(.timestamp)] \(.from) on #\(.channel):\n\($tl)\(.content)\n---"'
} 2>/dev/null || true

printf '%s\n' "$new_max" > "${offset_file}.tmp" && mv "${offset_file}.tmp" "$offset_file"
trace "offset $offset → $new_max, surfaced=$count"

exit 0
