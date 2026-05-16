#!/usr/bin/env bash
# UserPromptSubmit hook companion to bridge-daemon.sh.
#
# When Claude is about to handle a new user prompt, this hook reads
# everything the daemon accumulated since last time, prints a tidy
# summary on stdout (injected into the model's context per Claude
# Code's hook protocol), and truncates the cache.
#
# Exits 0 with empty stdout when there's nothing to surface — no
# noise on every turn when the channel is quiet.

set -euo pipefail

UNREAD_FILE="${BRIDGE_UNREAD_FILE:-$HOME/.cache/bridge/unread.jsonl}"
LOCK_FILE="${UNREAD_FILE}.lock"

[[ -s "$UNREAD_FILE" ]] || exit 0

# Atomic snapshot + truncate so messages arriving mid-drain aren't
# lost. Rename is atomic on the same filesystem.
mkdir -p "$(dirname "$LOCK_FILE")"
{
  flock -x 9
  if [[ ! -s "$UNREAD_FILE" ]]; then
    exit 0
  fi
  mv "$UNREAD_FILE" "${UNREAD_FILE}.draining"
  : > "$UNREAD_FILE"
} 9>"$LOCK_FILE"

count=$(wc -l < "${UNREAD_FILE}.draining")

# Render. Each line is a Message JSON; flatten to a chronological
# bullet list with from/channel/timestamp.
{
  echo "📬 Unread bridge messages (${count}) — arrived while you were away:"
  echo
  jq -r '"[\(.timestamp)] \(.from) on #\(.channel):\n\(.content)\n---"' \
    < "${UNREAD_FILE}.draining"
} 2>/dev/null || true

rm -f "${UNREAD_FILE}.draining"
exit 0
