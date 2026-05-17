#!/usr/bin/env bash
# Long-polls one or more bridge channels via SSE and exits with code 2
# the moment a message from anyone OTHER than this instance arrives.
# Claude's `asyncRewake` Stop hook treats exit 2 as a wake signal with
# stdout as additional context.
#
# Multi-channel: $BRIDGE_CHANNEL accepts a comma-separated list. Each
# channel runs in its own subprocess; the first one to see a foreign
# message drops its message into a slot file; the parent polls slots
# and exits 2 with the message on stdout.

set -uo pipefail

SERVER="${BRIDGE_SERVER:-http://172.16.101.166:3001}"
CHANNELS_RAW="${BRIDGE_CHANNEL:-general}"
# Per-session identity (host/short-session-id). Falls back to plain
# hostname if SessionStart never ran. Other peers address us with
# this exact string.
SELF="$(~/.claude/hooks/bridge-identity.sh 2>/dev/null || echo sv-s-bcloud)"
# Comma-separated roles this instance claims. Used to match messages
# addressed `to: [<role>]` even when they don't name us literally.
# Resolved via the bridge-role helper so the role can be set per
# session (via .bridge-role in cwd or `bridge role <name>`) without
# requiring a static env var in settings.json.
ROLES_RAW="$(~/.claude/hooks/bridge-role.sh 2>/dev/null || echo)"

# Single-instance lock per session. Claude Code re-invokes this hook
# on every Stop attempt; old invocations from previous turns can
# linger and stay subscribed to the SSE stream. When a new message
# arrives, every leaked subscriber catches it and fires its own
# Stop-blocking-error — the model sees the same message N times.
# Killing the previous instance (PID in pidfile) before starting
# ensures exactly one watcher per session.
SID_KEY="${CLAUDE_CODE_SESSION_ID:-$(hostname -s)}"
PIDFILE="${BRIDGE_WATCH_PIDFILE:-/tmp/bridge-watch-${SID_KEY//\//_}.pid}"
if [[ -f "$PIDFILE" ]]; then
  old_pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [[ -n "$old_pid" && "$old_pid" != "$$" ]] && kill -0 "$old_pid" 2>/dev/null; then
    # Kill the old watcher's process group so its child watch_one
    # subprocesses (each with its own SSE curl) die too.
    pkill -TERM -P "$old_pid" 2>/dev/null || true
    kill -TERM "$old_pid" 2>/dev/null || true
  fi
fi
echo "$$" > "$PIDFILE"

IFS=',' read -ra CHANNELS <<< "$CHANNELS_RAW"
TRIMMED=()
for c in "${CHANNELS[@]}"; do
    c="${c// /}"
    [[ -n "$c" ]] && TRIMMED+=("$c")
done
[[ ${#TRIMMED[@]} -eq 0 ]] && TRIMMED=("general")

SLOTDIR="$(mktemp -d /tmp/bridge-watch.XXXXXX)"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$SLOTDIR"
}
trap cleanup EXIT

watch_one() {
    local channel="$1"
    local slot="$2"
    while IFS= read -r line; do
        [[ "$line" == data:* ]] || continue
        local payload="${line#data: }"
        [[ "$payload" == "ping" ]] && continue

        local from
        from="$(printf '%s' "$payload" | jq -r '.from // empty' 2>/dev/null)"
        [[ -z "$from" ]] && continue
        [[ "$from" == "$SELF" ]] && continue

        # Addressing filter — if `to` is non-empty and doesn't include
        # us (by identity OR by one of our roles), this message is
        # for someone else; don't wake. Empty `to` = broadcast.
        local to_arr
        to_arr="$(printf '%s' "$payload" | jq -c '.to // []' 2>/dev/null)"
        if [[ "$to_arr" != "[]" && -n "$to_arr" && "$to_arr" != "null" ]]; then
            local match
            match="$(SELF_NAME="$SELF" SELF_ROLES="$ROLES_RAW" \
                jq -nr --argjson to "$to_arr" '
                    ($ENV.SELF_ROLES // "") | split(",") | map(select(length>0)) as $roles
                    | ($ENV.SELF_NAME // "") as $name
                    | $to | map(select(. == $name or (. as $t | $roles | index($t))))
                    | length' 2>/dev/null)"
            [[ "${match:-0}" -eq 0 ]] && continue
        fi

        local content ts to_display to_line
        content="$(printf '%s' "$payload" | jq -r '.content // ""' 2>/dev/null)"
        ts="$(printf '%s' "$payload" | jq -r '.timestamp // ""' 2>/dev/null)"
        to_display="$(printf '%s' "$payload" | jq -r '(.to // []) | join(",")' 2>/dev/null)"
        to_line=""
        [[ -n "$to_display" ]] && to_line="→ to: ${to_display}"$'\n'
        # Atomic write: build into a `.partial` then mv. The poller
        # only reads slots that are fully formed, so it can't catch
        # us mid-write.
        printf '[%s] %s on #%s:\n%s%s\n' "$ts" "$from" "$channel" "$to_line" "$content" > "${slot}.partial"
        mv "${slot}.partial" "$slot"
        return 0
    done < <(curl -sN --no-buffer --max-time 0 "${SERVER}/stream/${channel}" 2>/dev/null)
}

# Spawn one watcher per channel, each with its own slot file.
i=0
for c in "${TRIMMED[@]}"; do
    watch_one "$c" "$SLOTDIR/$i" &
    PIDS+=("$!")
    i=$((i + 1))
done

# Poll. SSE messages are infrequent → 200ms interval is plenty
# responsive without burning CPU. Cap at 6h as a sanity stop.
deadline=$(( $(date +%s) + 21600 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    for slot in "$SLOTDIR"/*; do
        [[ -f "$slot" && ! "$slot" =~ \.partial$ ]] || continue
        cat "$slot"
        exit 2
    done
    sleep 0.2
done
exit 0
