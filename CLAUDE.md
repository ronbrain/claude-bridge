# CLAUDE.md — claude-bridge repo agent guide

Operational nuances for Claude Code agents working on this repo. Read
once at session start; trust commits + the live bridge state over
anything stale here.

## What this repo is

A small Rust MCP server + relay so multiple Claude Code instances can
coordinate on shared state (messages, findings, tasks, memory KV,
dispatches, routing rules). Three binaries: `bridge-server` (the HTTP
relay), `bridge-mcp` (per-Claude stdio shim), `bridge` (human CLI).

Single workspace, single crate. No sub-crates. SQLite for persistence
(rusqlite + bundled). Tower-governor for rate limit. Axum 0.7. Maud for
dashboard templates. sqlite-vec for F18 semantic search.

## Build + test

```
cargo build --release --bins      # 4 binaries land in target/release/
cargo test --workspace            # expect all green; pure unit + integration, no network
```

`cargo test` from a clean shell will fail `config::tests::peer_idle_secs_env_range_enforced`
if neither `BRIDGE_DB_PATH` nor `BRIDGE_DB_EPHEMERAL=1` is set — the
F23.0 fail-closed gate trips before the F17.4 range check. Workaround:
`BRIDGE_DB_EPHEMERAL=1 cargo test`. The test itself should env-shim
this; tracked as a known minor and fixed in a follow-up.

## Branch + commit conventions

- **Always work on `main`.** No feature branches.
- **One feature per commit.** Subject line: `feat(bridge): F<N> — <title>`.
  Bug fixes: `fix(bridge): <area> — <title>`. Docs: `docs(...)`.
- **Migrations immutable once shipped.** Never edit `migrations/v*.sql`
  after it's landed; add a new file with the next version number.
- **Never `--no-verify`, never amend a pushed commit.** Roll forward
  with a new commit if a hook failed.
- **Decision keys** post-ship: `memory_set` to `decision-bridge-f<N>-<topic>`
  with what shipped + the trade-offs you closed. Future you reads this.

## The per-feature pre-review pattern

Established convention for any change touching auth, persistence,
network exposure, audit, or new protocol surface:

1. **Plan** (dispatch to ops + pentest before coding) — schema, types,
   handlers, tests, 4–6 open design questions.
2. **Pentest pre-review** returns 🟢 SHIP / 🟡 design-delta / 🔴 block,
   surface-by-surface.
3. **Ops decisions** on the design questions (Option A/B/C with
   rationale).
4. **Code** with all decisions locked.
5. **Re-read protocol** (mandatory): before commit/push, walk
   `read_messages` for addressed messages on relevant channels since
   your last status. Mid-flight corrections during long coding windows
   land here. The reason this rule exists is a real cost: a fail-open
   default shipped against the original plan because the pre-review
   correction arrived during the coding window and wasn't seen until
   after push.
6. **Ship report** (commit hash, tests, surface coverage, what each
   surface closes by finding ID) dispatched to ops + pentest.
7. **Pentest post-review** verdicts.
8. **Decision key** persisted.

Skip the per-feature dance for tiny <30min, no-behavior-change fixes.
Apply it for anything else.

## Patterns you'll reach for (memory keys)

These live in the bridge memory KV (channel `general`). `memory_list`
before designing — these are canonical:

- `pattern-atomic-status-flip-race-fix` — `UPDATE table SET status=...
  WHERE id=$1 AND status IN (<valid prev states>)` + `rows_affected
  == 0 → bail`. Acts as both transition and lock. Loser tx bails
  before touching state.
- `pattern-fail-closed-env-opt-in` — boot refuses to start unless an
  explicit `*_PERMISSIVE=1` opt-in is set when the env-loaded
  registry is empty. Used for auth tokens, DB path, routing max-depth.
- `pattern-per-feature-pre-review-gate` — the workflow above.
- `pattern-i18n-builder-closure` — JS sibling project; not relevant here.

Codify new patterns as `pattern-<name>` keys when a fix-shape
generalises to a class of issues. Don't re-derive next time.

## Fail-closed defaults (don't regress these)

Per `ops-rule-no-silent-fail-open-defaults`:

- `BRIDGE_DB_PATH` unset + `BRIDGE_DB_EPHEMERAL` not set → refuse to
  start (finding `c9d0bfd9`).
- `BRIDGE_AUTH_TOKENS` empty + `BRIDGE_AUTH_PERMISSIVE` not set →
  refuse to start (finding `dc633d7c`).
- `BRIDGE_ROUTING_MAX_DEPTH` outside `1..=3` → refuse to start.
- `BRIDGE_ROUTING_PEER_IDLE_SECS` outside `60..=3600` → refuse to start.

If you add a new env that affects persistence, auth, network exposure,
audit, or secret material — apply the same shape. Default = fail
closed. Unsafe path requires explicit opt-in env. SEVERE warn at boot
citing the finding ID that motivated it. No "legacy default" framing.

## Identity + ownership invariants

Per Items 6+7 of the auth-bundle sprint:

- **Handlers derive identity from `effective_actor()`, never from
  request body.** `from` fields are removed from `*Req` structs.
  Serde drops legacy clients' `from` silently → backwards compat.
- **Ownership-enforced tables** (`memory`, `findings`, `routing_rules`):
  first write claims `updated_by`/`created_by`. Subsequent writes
  require `auth_identity == prior.owner` OR caller in
  `BRIDGE_MEMORY_ADMINS`.
- **Orphan migrations**: at enforce-mode boot only, owners not in
  `(registry ∪ memory_admins)` get rewritten to ownerless (`''`) so
  the first authenticated peer can re-claim. Permissive mode skips
  (no registry to define orphans against).
- **Watcher identity convention**: subprocesses spawned by F26 use
  identity `<peer>-watcher`. `AuthIdentity::is_watcher()` recognises
  the suffix. Watcher's `POST /watchers/{peer}/heartbeat` cross-checks
  that the bearer's identity == `<peer>-watcher` so peers can't
  keep each other's watchers alive.

When adding new handlers that mutate state: use `effective_actor()`,
add ownership enforcement if the row is owned, mirror the orphan
migration shape if the table needs one.

## Persistence + WAL

- SQLite WAL mode for write-while-read.
- `Store::checkpoint_wal_on_shutdown` runs `PRAGMA wal_checkpoint(TRUNCATE)`
  in the SIGTERM/SIGINT handler (F23.0). Without this, a graceful
  restart leaves uncommitted WAL frames + the next boot rehydrates
  empty. Don't bypass the signal handler.
- Migrations run under `BEGIN IMMEDIATE`. Add new ones with
  `v<next>_<short_name>.sql` in `migrations/` + register in
  `MIGRATIONS` const in `src/store.rs`.

## Routing engine guardrails (F17)

- **Filter DSL** is intentionally tiny: JSON `{field: literal}`
  (eq), `{field: {contains: "x"}}`, `{field: {in: [...]}}`. Implicit
  AND between top-level fields. Validated at insert (no silent
  no-match on unknown ops).
- **Template substitution** is single-pass `{{name}}` regex with a
  whitelist of placeholders per trigger type (see `placeholders_for`).
  Substituted values never re-evaluate (closes secondary template
  injection — pentest concern `5f...` during F17 pre-review).
- **Cycle depth** capped via `BRIDGE_ROUTING_MAX_DEPTH` (default 1).
  Don't increase the default without a real use case.
- **Rate bucket**: 10/min per `(rule_id, channel)` + 3-trips-in-5min
  → auto-quarantine the rule (`enabled=0`) + post a `bridge-auto`
  message to `ops` role with re-enable instructions. Protects
  against flaky rules spamming a channel while ops is afk.

## Working with the live bridge during dev

The repo dev binary at `target/release/bridge-server` is what the
running service uses (per systemd `ExecStart=...`). Just `cargo build`
+ `sudo systemctl restart claude-bridge`.

State preserves across restarts now (F23.0). Old DB schemas auto-
migrate on boot.

When you change handler signatures or add tools, every connected MCP
shim cached the tool list at its own session start. They won't see
your new tools until the peer's Claude Code session is restarted
(`/exit + claude --resume`). Heads-up the user.

## Bridge restart workflow (with operator)

You can build + test locally; deploying needs operator. Convention:

1. **You**: `git push` your commits.
2. **You** notify operator: "ready for restart, HEAD = `<hash>`,
   `cargo test` N/N pass, what changed".
3. **Operator**: `git pull`, `cargo build --release --bins`, `sudo
   install -m 755 target/release/{bridge-server,bridge-mcp,bridge,claude-bridge}
   /usr/local/bin/`, `sudo systemctl restart claude-bridge`.
4. **Operator** confirms reattach.

For F26 watchers to keep working post-restart, operator may need to
re-spawn them (`watcher_spawn(peer=...)` for each previously-watched
peer). Or set up a startup script that re-spawns the known set.

## Things that have bitten this repo (don't repeat)

- **systemd drop-in override missing `[Service]` header** → silently
  ignored. Always start the file with `[Service]`.
- **`ProtectHome=read-only` + watcher subprocesses** → watchers fail
  with `Read-only file system`. Add `ReadWritePaths=` for the cache
  dirs.
- **Spawned subprocess without `PATH` env** → `claude` not found.
  Set `Environment=PATH=` in the systemd unit.
- **Test env not setting `BRIDGE_DB_EPHEMERAL=1`** → tests that
  trip the fail-closed gate before the assertion under test.
- **Shipped commit against superseded plan** because pre-review
  correction arrived during the long coding window. Re-read addressed
  channel messages before push.
- **Filed pattern memory keys after ops already broadcast them as
  filed** → 403 ownership conflict + duplicate work. `memory_list`
  before filing.
- **Bridge restart with `BRIDGE_DB_PATH` unset on a prior boot**
  → in-memory mode, all session state lost. Persistence is required;
  the fail-closed gate is non-negotiable.
- **Generated tokens with `echo` instead of `printf '%s'`** when
  computing sha256 → trailing newline → hash mismatch vs server CSV
  → 401 unauth. Always `printf '%s'`.

## When the operator says "do" or "try"

It's authorization to proceed with whatever you most recently
proposed. Don't re-confirm; act, then report. For destructive or
shared-infra actions (sudo, cross-host config push, secret rotation),
the auto-classifier may still block — re-summarise + ask for explicit
go in that case.

## When the operator goes quiet

Continue work on the queue. Don't poll the bridge or wake them. If
you finish your assigned scope, set status + go to standby. If
something needs operator action (secret rotation, cross-host SSH
they haven't authorised, etc.) — leave a clear summary and stop.
