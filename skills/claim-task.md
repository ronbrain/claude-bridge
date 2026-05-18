---
name: claim-task
description: Atomically claim ownership of an unowned task from the bridge work queue. Uses the bridge's claim_task MCP tool (F29 — first-wins UPDATE WHERE owner=''), updates status, sets status line, optionally submits a plan if the task category requires one. Use when picking up handed-off work or when scanning list_tasks for unowned items.
---

# /claim-task — Take ownership of a queued task

The bridge's task board (F29) supports atomic claim — two peers
racing to grab the same task get exactly one winner via UPDATE
WHERE owner=''. This skill wraps that flow plus the conventional
follow-up steps (status announcement + optional plan submission).

## Invocation

```
/claim-task --id <task-id> [--plan "<plan body>"]
```

Or call MCP tools directly:

```python
# 1. Find an unowned task in your lane.
list_tasks(channel="general", owner="")
# pick one matching your skills

# 2. Atomic claim — refuses if already owned.
claim_task(channel="general", id=task_id)

# 3. Announce + plan (if the task requires plan-approval gate).
set_status(f"claimed task {task_id[:8]}: …")
submit_plan(channel="general", id=task_id, plan="step 1; step 2; …")

# 4. Work; on done:
complete_task(channel="general", id=task_id, outcome="shipped commit <sha>")
```

## What this skill does

1. **Read state**: `list_tasks` filtered to `owner=''` in your channel.
2. **Atomic claim**: `claim_task` — returns 204 if you got it,
   409 if someone else won (no retry, gracefully report failure).
3. **Status update**: `set_status` with a one-line claim
   announcement so other peers see you took it.
4. **Optional plan**: when `--plan` is provided, `submit_plan`
   immediately. For tasks that require operator approval before
   `in_progress`, wait for `approve_plan` (operator's call).

## What happens on race-loss

If two peers `claim_task` the same id concurrently:
- One gets 204, status flips to owned-by-them.
- Other gets 409 "task not claimable — already owned".
- Loser falls back to the next unowned task. No retry on the same id.

## When NOT to use

- Working on a task you authored yourself — just `update_task` to set
  owner.
- Picking up a finding (not a task) — findings have their own
  `triage_finding` workflow.
- Plan-gated work where you don't yet have approval — submit
  plan first, wait for approve, then advance.

## Authority

Self-service per `bridge-brain-rules-v1` Rule 3.1.
Plan-approval gate (when active) gates the actual work, not the
claim itself.

## See also

- F29 task coordination spec (decision-bridge-f29-task-coordination)
- MCP tools: `list_tasks`, `claim_task`, `update_task`,
  `submit_plan`, `complete_task`
- Companion skill: `/handoff` (sender-side)
