#!/usr/bin/env bash
# SessionStart hook. Two responsibilities:
#
# 1. Write `~/.cache/bridge/session-<claude_pid>` so MCP (which
#    doesn't inherit $CLAUDE_CODE_SESSION_ID — Claude Code passes it
#    to bash shells, not to mcpServer stdio children) can find the
#    session_id by walking back to the same Claude Code PID.
#
# 2. If `.bridge-role` exists in cwd (or any ancestor), persist it
#    to `~/.cache/bridge/roles/<session_id>` so the instance
#    auto-claims a role on session start. The user can override at
#    any time with `bridge role <name>`.
#
# Always exits 0.

set -uo pipefail

CACHE_DIR="${BRIDGE_CACHE_DIR:-$HOME/.cache/bridge}"
mkdir -p "$CACHE_DIR/roles" 2>/dev/null || exit 0

hook_input="$(cat 2>/dev/null || true)"
sid="${CLAUDE_CODE_SESSION_ID:-}"
[[ -z "$sid" ]] && sid="$(printf '%s' "$hook_input" | jq -r '.session_id // empty' 2>/dev/null)"
[[ -z "$sid" ]] && exit 0
sid="${sid//\//_}"
sid="${sid//../_}"

cwd="$(printf '%s' "$hook_input" | jq -r '.cwd // empty' 2>/dev/null)"

# Anchor: the Claude Code PID this hook is running under. Walk the
# parent chain (we may have been launched through an intermediate
# shell) until we find a process with comm=claude.
claude_pid="$(~/.claude/hooks/bridge-claude-pid.sh 2>/dev/null)"
if [[ -n "$claude_pid" ]]; then
  printf '%s\n' "$sid" > "${CACHE_DIR}/session-${claude_pid}.tmp" \
    && mv "${CACHE_DIR}/session-${claude_pid}.tmp" "${CACHE_DIR}/session-${claude_pid}"
fi

# Auto-role from `.bridge-role` in cwd (or any ancestor dir). Only
# applies when the role file for this session doesn't exist yet —
# otherwise we'd clobber an explicit `bridge role <name>` the user
# ran in a previous turn every time Claude Code resumes the session.
# First run wins for auto; manual always wins thereafter.
role_file="${CACHE_DIR}/roles/${sid}"
if [[ ! -s "$role_file" && -n "$cwd" && -d "$cwd" ]]; then
  dir="$cwd"
  while [[ "$dir" != "/" && -n "$dir" ]]; do
    if [[ -f "$dir/.bridge-role" ]]; then
      role="$(head -n1 "$dir/.bridge-role" 2>/dev/null | tr -d '[:space:]')"
      if [[ -n "$role" ]]; then
        printf '%s\n' "$role" > "${role_file}.tmp" \
          && mv "${role_file}.tmp" "$role_file"
      fi
      break
    fi
    dir="$(dirname "$dir")"
  done
fi

# GC: drop stale rendezvous + role files older than 30 days.
find "$CACHE_DIR" -maxdepth 1 -name 'session-*' -type f -mtime +30 \
  -delete 2>/dev/null || true
find "$CACHE_DIR/roles" -maxdepth 1 -type f -mtime +30 \
  -delete 2>/dev/null || true

# Drain any messages that piled up while Claude was down. Without
# this, the watcher (Stop asyncRewake) only kicks in after the first
# turn ends and the drain (UserPromptSubmit) only fires when the user
# types — so after `claude --resume`, messages that arrived during
# the downtime stay invisible until the user types anything.
# Forward the SessionStart hook JSON we already consumed to the drain
# so its session_id detection still works.
if [[ -x "$HOME/.claude/hooks/bridge-drain-unread.sh" ]]; then
  printf '%s' "$hook_input" | "$HOME/.claude/hooks/bridge-drain-unread.sh" 2>/dev/null || true
fi

exit 0
