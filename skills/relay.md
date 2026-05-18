---
name: relay
description: Re-broadcast an event from one channel to another via the bridge. Use when a finding posted in #pale-pentest is also relevant to #general, or when ops decisions need to mirror across coordination channels. The skill reads the source message, attaches a "[mirrored from #<src>]" header, then send_message into the target channel.
---

# /relay — Re-broadcast a message across channels

Use this skill when a message you saw on one bridge channel needs
visibility in another. Common cases:

- Pentest finding on `#pale-pentest` that's load-bearing for `#general`
  ops decisions
- Ops dispatch that touches multiple peer groups
- Cross-channel coherence per `bridge-brain-rules-v1` Rule 1.3

## Invocation

```
/relay <message-id-or-content> --to <target-channel>
```

Or call the underlying MCP tool directly:

```python
read_messages(channel="pale-pentest", since=<ts>)
# pick the message to mirror
send_message(
  channel="general",
  content=f"[mirrored from #pale-pentest] {original_content}",
  to=["ops"],  # or empty for broadcast
)
```

## What this skill does NOT do

- Doesn't auto-detect which messages need mirroring (operator decision).
- Doesn't preserve threading — the mirrored message is a fresh post
  in the target channel.
- Doesn't enforce that the source author authorized re-broadcast —
  use your judgment; sensitive content stays on its origin channel.

## Authority

Self-service (no operator dispatch needed) per
`bridge-brain-rules-v1` Rule 3.1 "you may decide autonomously" —
cross-channel coherence is a maintenance op, not a state mutation.

## See also

- `pattern-cross-channel-coherence` if persisted in memory
- `bridge-brain-rules-v1` Rule 1.3
- MCP tool: `send_message` with `to:` addressing
