---
name: handoff
description: Formally hand off work-in-flight to another peer with an audit trail. Captures (1) current state snapshot of the task/context, (2) explicit transfer-of-ownership message, (3) memory key for next-session pickup. Use when finishing a shift, going on standby for >2h, or rotating peers on a long engagement.
---

# /handoff — Formal handoff to another peer

When you're stepping away from active work that another peer needs
to pick up, this skill produces three durable artifacts:

1. **State snapshot** — what's done, what's pending, what blockers.
2. **Transfer message** — addressed to the incoming peer (or role)
   on the same channel, explicit about ownership change.
3. **Memory key** — `handoff-<from>-to-<to>-<date>` so the next
   session reads context first, not your chat history.

## Invocation

```
/handoff --to <peer-or-role> --task "<short task title>" \
         [--channel <ch>] [--memory-key <name>]
```

Example:

```
/handoff --to fixer --task "wire dispatch_stale routing emit" \
         --channel general \
         --memory-key handoff-rust-dev-to-fixer-2026-05-18
```

## What gets recorded

- **In the channel** (via `send_message`):
  - Recipient(s) addressed via `to: [<peer-or-role>]`
  - Subject line: `[HANDOFF] <task title>`
  - Body sections: Done / In-flight / Pending / Blockers / Next-action
- **In memory** (via `memory_set`):
  - Key: as specified (or auto-derived)
  - Value: same handoff content + timestamp + cross-links via `[[…]]`
- **In audit log** (automatic):
  - Two write_audit rows: one from send_message, one from memory_set
  - actor = your authenticated identity (handoff attribution
    survives compaction)

## When NOT to use

- Quick status updates between turns — use `set_status` instead.
- Sharing a single artifact — use `share_artifact`.
- Reporting a finding — use `report_finding`.

Handoff is for transferring AUTHORITY over work, not for routine
coordination chatter.

## Authority

Self-service; you decide when to hand off. Recipient may decline
(via reply on same channel) — handoff doesn't auto-claim on their
side. For task-board work, pair with `claim_task` on the receiver
side.

## See also

- `pattern-handoff-with-audit-trail` if persisted in memory
- MCP tools: `send_message`, `memory_set`, `set_status`
- Companion skill: `/claim-task` (receiver-side pickup)
