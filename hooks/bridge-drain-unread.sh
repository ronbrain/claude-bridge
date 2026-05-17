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

# Per-session identity + roles for the `to` addressing filter. A
# message with non-empty `.to` only surfaces when it includes either
# our identity or one of our roles.
SELF_NAME="$(~/.claude/hooks/bridge-identity.sh 2>/dev/null || hostname -s)"
SELF_ROLES="${BRIDGE_ROLE:-}"

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
#
# Addressing filter inside the same jq: keep messages where `.to` is
# empty/missing (broadcast) OR includes our identity OR includes one
# of our roles. Offset still advances for filtered-out messages —
# they were "seen" even if not surfaced — so a peer message
# addressed to someone else doesn't replay forever.
# One jq pass: emit a 2-element array [unread_for_us, absolute_max].
# Reading the log once is enough — splitting filtered and absolute
# work into separate jq invocations was wasted I/O.
combined="$(SELF_NAME="$SELF_NAME" SELF_ROLES="$SELF_ROLES" \
  jq -cn --argjson off "$offset" '
    ($ENV.SELF_ROLES // "") | split(",") | map(select(length>0)) as $roles
    | ($ENV.SELF_NAME // "") as $name
    | [inputs | select(.timestamp > $off)] as $all
    | [
        ($all | map(select(
            ((.to // []) | length) == 0
            or ((.to // []) | index($name))
            or ((.to // []) | map(. as $t | $roles | index($t)) | any)
          ))),
        ($all | map(.timestamp) | max // 0)
      ]' \
  < "$LOG_FILE" 2>/dev/null || echo '[[],0]')"

unread_json="$(printf '%s' "$combined" | jq -c '.[0]' 2>/dev/null || echo '[]')"
absolute_max="$(printf '%s' "$combined" | jq -r '.[1]' 2>/dev/null || echo 0)"
count="$(printf '%s' "$unread_json" | jq 'length' 2>/dev/null || echo 0)"

# Always advance the offset — even when nothing was addressed to us —
# so the cursor doesn't get stuck replaying the same not-for-us
# messages on every turn.
new_max="$absolute_max"
[[ -z "$new_max" || "$new_max" == "null" || "$new_max" == "0" ]] && new_max="$offset"
printf '%s\n' "$new_max" > "${offset_file}.tmp" && mv "${offset_file}.tmp" "$offset_file"

[[ "$count" -eq 0 ]] && exit 0

{
  echo "📬 Unread bridge messages (${count}) — arrived while you were away:"
  echo
  printf '%s' "$unread_json" | jq -r '.[]
    | ((.to // []) | join(",")) as $to
    | (if $to != "" then ("→ to: " + $to + "\n") else "" end) as $tl
    | "[\(.timestamp)] \(.from) on #\(.channel):\n\($tl)\(.content)\n---"'
} 2>/dev/null || true

exit 0
