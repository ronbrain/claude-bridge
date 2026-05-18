//! SQLite-backed persistence for messages, findings, and artifacts.
//!
//! Opt-in via the `BRIDGE_DB_PATH` env var. When set, the server
//! opens (or creates) a sqlite file at that path, loads the
//! existing state into the in-memory DashMaps on boot, and
//! mirrors every write (message, finding, artifact create/update/
//! delete) into the file before returning success to the client.
//!
//! The hot path stays in-memory — sqlite is a write-through cache
//! for crash recovery and server restarts. Reads still go through
//! the DashMaps so latency doesn't change.
//!
//! Schema: see [`init`]. Idempotent (`CREATE TABLE IF NOT EXISTS`)
//! so a bridge upgrade against an old DB just adds new tables.
//!
//! Concurrency: rusqlite is synchronous. We hold a single
//! `parking_lot::Mutex<Connection>` — every op is sub-millisecond
//! on local disk; the lock contention is negligible compared to
//! the network RTT each request already pays.

use parking_lot::Mutex;
use rusqlite::{params, Connection, Result as SqliteResult};
use std::path::Path;
use std::sync::{Arc, Once};

/// F18 — register the sqlite-vec extension as a SQLite auto-extension
/// exactly once per process. Subsequent `Connection::open` calls pick
/// it up automatically (registers the `vec0` virtual table module
/// + scalar fns like `vec_distance_cosine`). Idempotent thanks to
/// `Once`. Safe because sqlite3_auto_extension is a known global
/// FFI hook and we pass a function pointer with C ABI.
fn register_sqlite_vec_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        unsafe {
            rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
                sqlite_vec::sqlite3_vec_init as *const (),
            )));
        }
    });
}

use crate::{Artifact, AuditEntry, ChannelTopic, Finding, MemoryEntry, Message, Task};

/// Width of `audit_hash` output in **bytes** (hex chars = 2×). 16 =
/// 128-bit per pentest review (msg 1779038688): single per-pair
/// collision probability of ~1.5e-31 at 10K rows/year and stays in
/// the "no thinking required" zone even under multi-decade
/// retention and future federation. Schema column is `TEXT`, so
/// changing this is a single edit — no migration. 64-bit (8) would
/// also be acceptable per the bridge's current scale; 128 was
/// chosen for forensic confidence + future-proof.
const AUDIT_HASH_BYTES: usize = 16;

/// Truncated sha256 over a serialized row, used by the audit log to
/// support forensic joins without storing the full payload in the
/// log itself.
///
/// **Callers should pass a canonical serialization** — i.e. one that
/// produces identical bytes given identical struct values regardless
/// of field-set ordering, allocation, or build environment. Use
/// [`audit_hash_struct`] when you have a `serde::Serialize` value;
/// it goes through `canonical_json` to dodge `serde_json`'s
/// insertion-order pitfall.
pub fn audit_hash(serialized: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(serialized);
    let out = h.finalize();
    let mut hex = String::with_capacity(AUDIT_HASH_BYTES * 2);
    for b in out.iter().take(AUDIT_HASH_BYTES) {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Render `v` to a deterministic JSON byte buffer with object keys
/// sorted lexicographically at every depth. Avoids `serde_json`'s
/// "preserves insertion order" hazard (per pentest review nit) —
/// write-time and read-time hashes will match as long as the struct
/// contents do.
pub fn canonical_json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let val: serde_json::Value = serde_json::to_value(v).unwrap_or(serde_json::Value::Null);
    let mut out = Vec::with_capacity(256);
    write_canonical(&val, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value::*;
    match v {
        Null => out.extend_from_slice(b"null"),
        Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        String(s) => out.extend_from_slice(
            serde_json::to_vec(s).unwrap_or_default().as_slice(),
        ),
        Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Object(map) => {
            // Sorted keys are the whole point.
            let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_vec(k).unwrap_or_default().as_slice(),
                );
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
    }
}

/// Hash a serde-serialisable value via the canonical JSON form. The
/// standard call site for the audit hook: `audit_hash_struct(&row)`.
pub fn audit_hash_struct<T: serde::Serialize>(v: &T) -> String {
    audit_hash(&canonical_json(v))
}

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn open(path: &Path) -> SqliteResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // F18 — register sqlite-vec as a SQLite auto-extension before
        // opening any connection. The hook is process-global and
        // applies to every Connection::open that follows; vec0 vtab
        // calls in v18 migration succeed because of this.
        register_sqlite_vec_once();
        let conn = Connection::open(path)?;
        // WAL for concurrent reads with one writer — only matters if
        // we ever add a read replica, but cheap and safer than the
        // rollback journal default.
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        init(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ── Messages ────────────────────────────────────────────────────

    pub fn insert_message(&self, m: &Message) -> SqliteResult<()> {
        let to_json = serde_json::to_string(&m.to).unwrap_or_else(|_| "[]".into());
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO messages
             (id, channel, from_, content, timestamp, to_, thread_id, pinned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                m.id, m.channel, m.from, m.content, m.timestamp as i64,
                to_json, m.thread_id, m.pinned as i64
            ],
        )?;
        Ok(())
    }

    pub fn set_message_pinned(&self, id: &str, pinned: bool) -> SqliteResult<()> {
        self.conn.lock().execute(
            "UPDATE messages SET pinned = ?1 WHERE id = ?2",
            params![pinned as i64, id],
        )?;
        Ok(())
    }

    /// Force a WAL checkpoint — flushes the wal file's pending
    /// frames into the main sqlite db so a subsequent restart can
    /// read the latest state. Called from the SIGTERM/SIGINT
    /// handler in `main()` BEFORE the tokio runtime drops the
    /// Store. Per ops dispatch 1779063832 + state-loss incident:
    /// without an explicit checkpoint, a graceful shutdown leaves
    /// the WAL un-merged and the next boot rehydrates a stale
    /// snapshot (decision keys, memory rows, routing rules,
    /// peer_watchers state all rolled back to the prior
    /// checkpoint, which can be hours/days old under WAL+`synchronous=NORMAL`).
    ///
    /// `PRAGMA wal_checkpoint(TRUNCATE)` is the strongest variant —
    /// merges all frames + truncates the wal file to zero. Slightly
    /// slower than PASSIVE, but the restart path needs the
    /// guarantee. Bridge shutdown is a low-frequency event, the
    /// extra ms is irrelevant.
    pub fn checkpoint_wal_on_shutdown(&self) -> SqliteResult<()> {
        let conn = self.conn.lock();
        // wal_checkpoint returns a row with (busy, log, checkpointed)
        // — we don't care about the values, only success.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Drop messages from a channel that fall outside the in-memory
    /// retention window (the oldest beyond `keep` rows). Mirrors the
    /// in-memory drain so the DB doesn't grow unbounded.
    pub fn prune_messages(&self, channel: &str, keep: usize) -> SqliteResult<()> {
        self.conn.lock().execute(
            "DELETE FROM messages WHERE channel = ?1 AND id NOT IN (
                SELECT id FROM messages WHERE channel = ?1
                ORDER BY timestamp DESC LIMIT ?2
            )",
            params![channel, keep as i64],
        )?;
        Ok(())
    }

    pub fn clear_messages(&self, channel: &str) -> SqliteResult<()> {
        self.conn
            .lock()
            .execute("DELETE FROM messages WHERE channel = ?1", params![channel])?;
        Ok(())
    }

    pub fn load_messages(&self, per_channel_cap: usize) -> SqliteResult<Vec<Message>> {
        let conn = self.conn.lock();
        // Use a window function to keep only the latest N per channel —
        // honours HISTORY_LIMIT even if the DB has more rows from a
        // previous run with a higher cap. Pinned rows are kept on top
        // of the per-channel window so a pinned doc never falls off
        // the cap.
        let mut stmt = conn.prepare(
            "SELECT id, channel, from_, content, timestamp,
                    COALESCE(to_, '[]') AS to_,
                    COALESCE(thread_id, '') AS thread_id,
                    COALESCE(pinned, 0) AS pinned FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY channel ORDER BY pinned DESC, timestamp DESC
                ) AS rn FROM messages
            ) WHERE rn <= ?1 ORDER BY channel, timestamp",
        )?;
        let rows = stmt.query_map(params![per_channel_cap as i64], |r| {
            let to_json: String = r.get(5).unwrap_or_else(|_| "[]".into());
            let to: Vec<String> = serde_json::from_str(&to_json).unwrap_or_default();
            Ok(Message {
                id: r.get(0)?,
                channel: r.get(1)?,
                from: r.get(2)?,
                content: r.get(3)?,
                timestamp: r.get::<_, i64>(4)? as u64,
                to,
                thread_id: r.get(6).unwrap_or_default(),
                pinned: r.get::<_, i64>(7).unwrap_or(0) != 0,
            })
        })?;
        rows.collect()
    }

    /// Hard-delete every row tagged to a channel — used by the
    /// channel-cap evictor in server.rs so the DB doesn't keep
    /// rows for an evicted channel that the in-memory map dropped.
    pub fn drop_channel(&self, channel: &str) -> SqliteResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM messages WHERE channel = ?1", params![channel])?;
        conn.execute("DELETE FROM findings WHERE channel = ?1", params![channel])?;
        conn.execute(
            "DELETE FROM artifacts WHERE channel = ?1",
            params![channel],
        )?;
        Ok(())
    }

    // ── Findings ────────────────────────────────────────────────────

    pub fn upsert_finding(&self, f: &Finding) -> SqliteResult<()> {
        let blocks = serde_json::to_string(&f.blocks).unwrap_or_else(|_| "[]".into());
        let deps = serde_json::to_string(&f.depends_on).unwrap_or_else(|_| "[]".into());
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO findings
             (id, channel, from_, severity, title, detail, endpoint,
              status, created_at, updated_at, note, blocks_, depends_on_)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                f.id,
                f.channel,
                f.from,
                f.severity,
                f.title,
                f.detail,
                f.endpoint,
                f.status,
                f.created_at as i64,
                f.updated_at as i64,
                f.note,
                blocks,
                deps,
            ],
        )?;
        Ok(())
    }

    pub fn delete_finding(&self, channel: &str, id: &str) -> SqliteResult<()> {
        self.conn.lock().execute(
            "DELETE FROM findings WHERE channel = ?1 AND id = ?2",
            params![channel, id],
        )?;
        Ok(())
    }

    pub fn prune_findings(&self, channel: &str, keep: usize) -> SqliteResult<()> {
        self.conn.lock().execute(
            "DELETE FROM findings WHERE channel = ?1 AND id NOT IN (
                SELECT id FROM findings WHERE channel = ?1
                ORDER BY created_at DESC LIMIT ?2
            )",
            params![channel, keep as i64],
        )?;
        Ok(())
    }

    pub fn load_findings(&self, per_channel_cap: usize) -> SqliteResult<Vec<Finding>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, channel, from_, severity, title, detail, endpoint,
                    status, created_at, updated_at, note,
                    COALESCE(blocks_, '[]') AS blocks_,
                    COALESCE(depends_on_, '[]') AS depends_on_
             FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY channel ORDER BY created_at DESC
                ) AS rn FROM findings
             ) WHERE rn <= ?1 ORDER BY channel, created_at",
        )?;
        let rows = stmt.query_map(params![per_channel_cap as i64], |r| {
            let blocks_json: String = r.get(11).unwrap_or_else(|_| "[]".into());
            let deps_json: String = r.get(12).unwrap_or_else(|_| "[]".into());
            Ok(Finding {
                id: r.get(0)?,
                channel: r.get(1)?,
                from: r.get(2)?,
                severity: r.get(3)?,
                title: r.get(4)?,
                detail: r.get(5)?,
                endpoint: r.get(6)?,
                status: r.get(7)?,
                created_at: r.get::<_, i64>(8)? as u64,
                updated_at: r.get::<_, i64>(9)? as u64,
                note: r.get(10)?,
                blocks: serde_json::from_str(&blocks_json).unwrap_or_default(),
                depends_on: serde_json::from_str(&deps_json).unwrap_or_default(),
            })
        })?;
        rows.collect()
    }

    // ── Channel topics ──────────────────────────────────────────────

    pub fn upsert_topic(&self, t: &ChannelTopic) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO channel_topics
             (name, topic, updated_by, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![t.name, t.topic, t.updated_by, t.updated_at as i64],
        )?;
        Ok(())
    }

    pub fn load_topics(&self) -> SqliteResult<Vec<ChannelTopic>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT name, topic, updated_by, updated_at FROM channel_topics",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ChannelTopic {
                name: r.get(0)?,
                topic: r.get(1)?,
                updated_by: r.get(2)?,
                updated_at: r.get::<_, i64>(3)? as u64,
            })
        })?;
        rows.collect()
    }

    // ── Tasks ───────────────────────────────────────────────────────

    pub fn upsert_task(&self, t: &Task) -> SqliteResult<()> {
        let blocks = serde_json::to_string(&t.blocks).unwrap_or_else(|_| "[]".into());
        let deps = serde_json::to_string(&t.depends_on).unwrap_or_else(|_| "[]".into());
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO tasks
             (id, channel, from_, title, description, owner, status,
              created_at, updated_at, note, blocks_, depends_on_)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                t.id, t.channel, t.from, t.title, t.description,
                t.owner, t.status,
                t.created_at as i64, t.updated_at as i64, t.note,
                blocks, deps,
            ],
        )?;
        Ok(())
    }

    pub fn delete_task(&self, channel: &str, id: &str) -> SqliteResult<()> {
        self.conn.lock().execute(
            "DELETE FROM tasks WHERE channel = ?1 AND id = ?2",
            params![channel, id],
        )?;
        Ok(())
    }

    pub fn load_tasks(&self) -> SqliteResult<Vec<Task>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, channel, from_, title, description, owner, status,
                    created_at, updated_at, note,
                    COALESCE(blocks_, '[]'), COALESCE(depends_on_, '[]')
             FROM tasks ORDER BY channel, created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            let blocks_json: String = r.get(10).unwrap_or_else(|_| "[]".into());
            let deps_json: String = r.get(11).unwrap_or_else(|_| "[]".into());
            Ok(Task {
                id: r.get(0)?,
                channel: r.get(1)?,
                from: r.get(2)?,
                title: r.get(3)?,
                description: r.get(4)?,
                owner: r.get(5)?,
                status: r.get(6)?,
                created_at: r.get::<_, i64>(7)? as u64,
                updated_at: r.get::<_, i64>(8)? as u64,
                note: r.get(9)?,
                blocks: serde_json::from_str(&blocks_json).unwrap_or_default(),
                depends_on: serde_json::from_str(&deps_json).unwrap_or_default(),
            })
        })?;
        rows.collect()
    }

    // ── Shared memory (KV) ──────────────────────────────────────────

    /// At server boot post auth-bundle finding `0919a7db`: rewrite
    /// any memory row whose `updated_by` isn't in the known
    /// identity set to ownerless (`updated_by = ''`). Includes the
    /// pre-auth-bundle placeholders `"unknown"` and `"anonymous"`
    /// — those came from the X-Bridge-From fallback and don't
    /// correspond to real registry entities.
    ///
    /// Per finding `9fe0e927` (paledo restart 19:22:58 hit this
    /// boot path with an `SqliteFailure` that pentest traced to
    /// FTS5 shadow-table inconsistency from a prior partial migration):
    ///
    /// - Wrap the whole op in `BEGIN IMMEDIATE` / `COMMIT` so a
    ///   trigger-side failure rolls the whole UPDATE back instead
    ///   of leaving the memory table half-migrated.
    /// - Before the UPDATE runs, fire
    ///   `INSERT INTO memory_fts(memory_fts) VALUES('rebuild')` to
    ///   regenerate the FTS5 shadow content from the live memory
    ///   table. This is a no-op when FTS is already coherent and a
    ///   self-repair when it isn't — the underlying cause of the
    ///   migration's `disk I/O error` on paledo.
    ///
    /// `known` is the union of registry identities + memory admins
    /// at boot. Empty string and `NULL` are already treated as
    /// ownerless by the column type (TEXT NOT NULL DEFAULT '') so
    /// only existing non-matching strings need rewriting.
    ///
    /// Returns the number of rows whose ownership was reset.
    pub fn orphan_unmapped_memory_owners(
        &self,
        known: &std::collections::HashSet<String>,
    ) -> SqliteResult<usize> {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN IMMEDIATE;")?;

        // Defensive FTS rebuild. The trigger `memory_fts_update`
        // attempts a DELETE of OLD.rowid from the FTS shadow table;
        // if the shadow row is missing (partial prior migration,
        // direct SQL edits, etc.), the DELETE fails with a generic
        // `disk I/O error` masking the real cause. Rebuilding the
        // index here re-syncs it to the content table before our
        // UPDATE walks the rows. Cheap on a coherent DB.
        if let Err(e) = conn.execute_batch(
            "INSERT INTO memory_fts(memory_fts) VALUES('rebuild');",
        ) {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(e);
        }

        let result: SqliteResult<usize> = if known.is_empty() {
            conn.execute(
                "UPDATE memory SET updated_by = '' WHERE updated_by != ''",
                [],
            )
        } else {
            // Build the IN-clause dynamically — rusqlite expects
            // param count to match SQL placeholders.
            let names: Vec<String> = known.iter().cloned().collect();
            let placeholders: String = std::iter::repeat("?")
                .take(names.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "UPDATE memory SET updated_by = '' \
                 WHERE updated_by != '' AND updated_by NOT IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            stmt.execute(rusqlite::params_from_iter(names.iter()))
        };

        match result {
            Ok(n) => {
                conn.execute_batch("COMMIT;")?;
                Ok(n)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }

    /// Per ops 1779046844 Item 7 (root-cause cleanup of identity-
    /// spoofed findings): rewrite the `from_` column on any finding
    /// whose author isn't in the known identity set to a clearly-
    /// flagged orphan name (`[orphan-<prior>]`). Mirrors
    /// `orphan_unmapped_memory_owners` but uses a wrapping name
    /// rather than emptying the column — findings need an attributed
    /// author so the audit trail stays coherent; flagging makes the
    /// orphan status visible to anyone reading list_findings.
    ///
    /// Run-once safe: a second call sees the already-`[orphan-…]`-
    /// prefixed values and (provided they're not in `known`)
    /// double-wraps them. Callers should only invoke when the
    /// registry is well-defined (enforce mode); in permissive mode
    /// every name looks unknown and we'd torch the whole table.
    /// `server::main` enforces this precondition before calling.
    ///
    /// Returns the number of rows renamed.
    pub fn orphan_unmapped_finding_authors(
        &self,
        known: &std::collections::HashSet<String>,
    ) -> SqliteResult<usize> {
        let conn = self.conn.lock();
        if known.is_empty() {
            // Defensive: caller should never invoke us in this
            // state, but we still refuse to torch every author
            // string. Return 0 with no rewrite.
            return Ok(0);
        }
        let names: Vec<String> = known.iter().cloned().collect();
        let placeholders: String = std::iter::repeat("?")
            .take(names.len())
            .collect::<Vec<_>>()
            .join(",");
        // Skip rows already flagged so a repeated boot doesn't
        // double-wrap (e.g. `[orphan-[orphan-foo]]`).
        let sql = format!(
            "UPDATE findings SET from_ = '[orphan-' || from_ || ']' \
             WHERE from_ NOT IN ({placeholders}) \
               AND from_ NOT LIKE '[orphan-%'"
        );
        let mut stmt = conn.prepare(&sql)?;
        let n = stmt.execute(rusqlite::params_from_iter(names.iter()))?;
        Ok(n)
    }

    // ── Pull requests (F22) ────────────────────────────────────────

    pub fn upsert_pull_request(&self, p: &crate::PullRequest) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO pull_requests
             (id, repo, number, title, state, author, base_branch, head_branch,
              url, linked_findings, linked_decisions, linked_goal_id, body,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(repo, number) DO UPDATE SET
                title = excluded.title,
                state = excluded.state,
                base_branch = excluded.base_branch,
                head_branch = excluded.head_branch,
                url = excluded.url,
                body = excluded.body,
                updated_at = excluded.updated_at",
            params![
                p.id, p.repo, p.number, p.title, p.state, p.author,
                p.base_branch, p.head_branch, p.url,
                p.linked_findings, p.linked_decisions, p.linked_goal_id,
                p.body, p.created_at as i64, p.updated_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_pull_requests(
        &self,
        state_filter: Option<&str>,
        repo_filter: Option<&str>,
    ) -> SqliteResult<Vec<crate::PullRequest>> {
        let conn = self.conn.lock();
        let mut sql = String::from(
            "SELECT id, repo, number, title, state, author, base_branch,
                    head_branch, url, linked_findings, linked_decisions,
                    linked_goal_id, body, created_at, updated_at
             FROM pull_requests WHERE 1=1",
        );
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(s) = state_filter {
            sql.push_str(" AND state = ?");
            bound.push(Box::new(s.to_string()));
        }
        if let Some(r) = repo_filter {
            sql.push_str(" AND repo = ?");
            bound.push(Box::new(r.to_string()));
        }
        sql.push_str(" ORDER BY updated_at DESC");
        let mut stmt = conn.prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(refs.as_slice(), |r| {
            Ok(crate::PullRequest {
                id: r.get(0)?, repo: r.get(1)?, number: r.get(2)?,
                title: r.get(3)?, state: r.get(4)?, author: r.get(5)?,
                base_branch: r.get(6)?, head_branch: r.get(7)?, url: r.get(8)?,
                linked_findings: r.get(9)?, linked_decisions: r.get(10)?,
                linked_goal_id: r.get(11)?, body: r.get(12)?,
                created_at: r.get::<_, i64>(13)? as u64,
                updated_at: r.get::<_, i64>(14)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn get_pull_request_by_repo_number(
        &self,
        repo: &str,
        number: i64,
    ) -> SqliteResult<Option<crate::PullRequest>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, repo, number, title, state, author, base_branch,
                    head_branch, url, linked_findings, linked_decisions,
                    linked_goal_id, body, created_at, updated_at
             FROM pull_requests WHERE repo = ?1 AND number = ?2",
        )?;
        let mut rows = stmt.query(params![repo, number])?;
        if let Some(r) = rows.next()? {
            Ok(Some(crate::PullRequest {
                id: r.get(0)?, repo: r.get(1)?, number: r.get(2)?,
                title: r.get(3)?, state: r.get(4)?, author: r.get(5)?,
                base_branch: r.get(6)?, head_branch: r.get(7)?, url: r.get(8)?,
                linked_findings: r.get(9)?, linked_decisions: r.get(10)?,
                linked_goal_id: r.get(11)?, body: r.get(12)?,
                created_at: r.get::<_, i64>(13)? as u64,
                updated_at: r.get::<_, i64>(14)? as u64,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_pull_request_links(
        &self,
        id: &str,
        linked_findings: &str,
        linked_decisions: &str,
        linked_goal_id: &str,
        now: u64,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE pull_requests
             SET linked_findings = ?1,
                 linked_decisions = ?2,
                 linked_goal_id = ?3,
                 updated_at = ?4
             WHERE id = ?5",
            params![linked_findings, linked_decisions, linked_goal_id, now as i64, id],
        )?;
        Ok(n)
    }

    // ── Peer recovery config (F23) ─────────────────────────────────

    pub fn upsert_peer_recovery_config(&self, c: &crate::PeerRecoveryConfig) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO peer_recovery_config
             (peer, routine_url, created_by, created_at, last_fired_at, fire_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                c.peer, c.routine_url, c.created_by,
                c.created_at as i64, c.last_fired_at as i64, c.fire_count as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_peer_recovery_configs(&self) -> SqliteResult<Vec<crate::PeerRecoveryConfig>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT peer, routine_url, created_by, created_at, last_fired_at, fire_count
             FROM peer_recovery_config ORDER BY peer",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::PeerRecoveryConfig {
                peer: r.get(0)?, routine_url: r.get(1)?, created_by: r.get(2)?,
                created_at: r.get::<_, i64>(3)? as u64,
                last_fired_at: r.get::<_, i64>(4)? as u64,
                fire_count: r.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn mark_recovery_fired(&self, peer: &str, now: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE peer_recovery_config
             SET last_fired_at = ?1, fire_count = fire_count + 1
             WHERE peer = ?2",
            params![now as i64, peer],
        )?;
        Ok(n)
    }

    pub fn delete_peer_recovery_config(&self, peer: &str) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "DELETE FROM peer_recovery_config WHERE peer = ?1",
            params![peer],
        )?;
        Ok(n)
    }

    // ── Plans (F21) ────────────────────────────────────────────────

    pub fn insert_plan(&self, p: &crate::Plan) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO plans
             (id, channel, title, description, steps_json, status,
              owner, created_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                p.id, p.channel, p.title, p.description, p.steps_json,
                p.status, p.owner, p.created_by,
                p.created_at as i64, p.updated_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get_plan(&self, id: &str) -> SqliteResult<Option<crate::Plan>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, channel, title, description, steps_json, status,
                    owner, created_by, created_at, updated_at
             FROM plans WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(crate::Plan {
                id: r.get(0)?, channel: r.get(1)?, title: r.get(2)?,
                description: r.get(3)?, steps_json: r.get(4)?,
                status: r.get(5)?, owner: r.get(6)?, created_by: r.get(7)?,
                created_at: r.get::<_, i64>(8)? as u64,
                updated_at: r.get::<_, i64>(9)? as u64,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_plans(&self) -> SqliteResult<Vec<crate::Plan>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, channel, title, description, steps_json, status,
                    owner, created_by, created_at, updated_at
             FROM plans ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::Plan {
                id: r.get(0)?, channel: r.get(1)?, title: r.get(2)?,
                description: r.get(3)?, steps_json: r.get(4)?,
                status: r.get(5)?, owner: r.get(6)?, created_by: r.get(7)?,
                created_at: r.get::<_, i64>(8)? as u64,
                updated_at: r.get::<_, i64>(9)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Replace the steps_json + bump updated_at. Used by
    /// plan_advance after walking + validating the step transition.
    pub fn write_plan_steps(&self, id: &str, steps_json: &str, now: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE plans SET steps_json = ?1, updated_at = ?2 WHERE id = ?3",
            params![steps_json, now as i64, id],
        )?;
        Ok(n)
    }

    pub fn set_plan_status(&self, id: &str, status: &str, now: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE plans SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, now as i64, id],
        )?;
        Ok(n)
    }

    pub fn delete_plan(&self, id: &str) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "DELETE FROM plans WHERE id = ?1",
            params![id],
        )?;
        Ok(n)
    }

    // ── Goals (F20) ────────────────────────────────────────────────

    pub fn insert_goal(&self, g: &crate::Goal) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO goals
             (id, channel, name, description, target_metric, target_value,
              current_value, comparator, created_by, deadline, status,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                g.id, g.channel, g.name, g.description, g.target_metric,
                g.target_value, g.current_value, g.comparator, g.created_by,
                g.deadline as i64, g.status, g.created_at as i64, g.updated_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_goals(&self) -> SqliteResult<Vec<crate::Goal>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, channel, name, description, target_metric, target_value,
                    current_value, comparator, created_by, deadline, status,
                    created_at, updated_at
             FROM goals ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::Goal {
                id: r.get(0)?, channel: r.get(1)?, name: r.get(2)?,
                description: r.get(3)?, target_metric: r.get(4)?,
                target_value: r.get(5)?, current_value: r.get(6)?,
                comparator: r.get(7)?, created_by: r.get(8)?,
                deadline: r.get::<_, i64>(9)? as u64,
                status: r.get(10)?,
                created_at: r.get::<_, i64>(11)? as u64,
                updated_at: r.get::<_, i64>(12)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn get_goal(&self, id: &str) -> SqliteResult<Option<crate::Goal>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, channel, name, description, target_metric, target_value,
                    current_value, comparator, created_by, deadline, status,
                    created_at, updated_at
             FROM goals WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(crate::Goal {
                id: r.get(0)?, channel: r.get(1)?, name: r.get(2)?,
                description: r.get(3)?, target_metric: r.get(4)?,
                target_value: r.get(5)?, current_value: r.get(6)?,
                comparator: r.get(7)?, created_by: r.get(8)?,
                deadline: r.get::<_, i64>(9)? as u64,
                status: r.get(10)?,
                created_at: r.get::<_, i64>(11)? as u64,
                updated_at: r.get::<_, i64>(12)? as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Scanner-side update: refresh `current_value` + flip `status`
    /// to 'met' when the comparator passes (transition-edge), or
    /// 'missed' when the deadline passes without met. Returns the
    /// pre/post status pair so the caller can fire `goal_achieved`
    /// trigger only on the pending→met edge.
    pub fn update_goal_progress(
        &self,
        id: &str,
        new_current: i64,
        comparator: &str,
        target: i64,
        deadline: u64,
        now: u64,
    ) -> SqliteResult<(String, String)> {
        let conn = self.conn.lock();
        let prior: String = conn.query_row(
            "SELECT status FROM goals WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        let met = match comparator {
            ">=" => new_current >= target,
            "<=" => new_current <= target,
            "==" => new_current == target,
            _ => false,
        };
        let new_status: String = if prior == "pending" {
            if met {
                "met".into()
            } else if deadline != 0 && now > deadline {
                "missed".into()
            } else {
                "pending".into()
            }
        } else {
            prior.clone()
        };
        conn.execute(
            "UPDATE goals SET current_value = ?1, status = ?2, updated_at = ?3
             WHERE id = ?4",
            params![new_current, &new_status, now as i64, id],
        )?;
        Ok((prior, new_status))
    }

    pub fn cancel_goal(&self, id: &str, now: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE goals SET status = 'cancelled', updated_at = ?1
             WHERE id = ?2 AND status = 'pending'",
            params![now as i64, id],
        )?;
        Ok(n)
    }

    pub fn delete_goal(&self, id: &str) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "DELETE FROM goals WHERE id = ?1",
            params![id],
        )?;
        Ok(n)
    }

    // ── Tasks (F29 additions) ──────────────────────────────────────

    /// Atomic claim of an unowned task — pattern-atomic-status-flip.
    /// UPDATE WHERE owner='' AND status='todo' ensures concurrent
    /// callers race fairly: exactly one rows_affected=1, the rest
    /// rows_affected=0. Caller maps 0 → 403/409 and 1 → success.
    /// Also bumps `claim_count` for observability.
    pub fn claim_task(&self, task_id: &str, owner: &str, now: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE tasks SET owner = ?1, updated_at = ?2,
                              claim_count = claim_count + 1
             WHERE id = ?3 AND owner = '' AND status = 'todo'",
            params![owner, now as i64, task_id],
        )?;
        Ok(n)
    }

    /// Submit a plan for `task_id`. Sets plan_status='pending' +
    /// plan_text. Caller must be task owner (handler enforces);
    /// store stays generic. Refuses if task isn't in `todo`/`open`
    /// status (no plan submission on in-flight/completed tasks).
    pub fn submit_plan(
        &self,
        task_id: &str,
        plan: &str,
        now: u64,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE tasks SET plan_status = 'pending', plan_text = ?1,
                              plan_decided_at = 0, plan_reviewer = '',
                              updated_at = ?2
             WHERE id = ?3 AND status IN ('todo', 'open')
               AND plan_status IN ('none', 'rejected')",
            params![plan, now as i64, task_id],
        )?;
        Ok(n)
    }

    /// Approve a pending plan. Reviewer recorded for audit; status
    /// flip enables todo → in_progress transition.
    pub fn approve_plan(
        &self,
        task_id: &str,
        reviewer: &str,
        now: u64,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE tasks SET plan_status = 'approved', plan_reviewer = ?1,
                              plan_decided_at = ?2, updated_at = ?2
             WHERE id = ?3 AND plan_status = 'pending'",
            params![reviewer, now as i64, task_id],
        )?;
        Ok(n)
    }

    /// Reject a pending plan. Sets plan_status='rejected', task
    /// remains in todo; owner can re-submit via submit_plan (the
    /// submit query allows 'rejected' → 'pending' transition).
    pub fn reject_plan(
        &self,
        task_id: &str,
        reviewer: &str,
        reason: &str,
        now: u64,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE tasks SET plan_status = 'rejected', plan_reviewer = ?1,
                              plan_decided_at = ?2, note = ?3,
                              updated_at = ?2
             WHERE id = ?4 AND plan_status = 'pending'",
            params![reviewer, now as i64, reason, task_id],
        )?;
        Ok(n)
    }

    /// Complete a task atomically: status='done' + completed_at + note.
    /// Refuses transition if plan_status='pending' (can't complete a
    /// task whose plan hasn't been resolved). Returns rows-touched
    /// for 404 / 409 semantics at the handler.
    pub fn complete_task(
        &self,
        task_id: &str,
        outcome: &str,
        now: u64,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE tasks SET status = 'done', completed_at = ?1,
                              note = ?2, updated_at = ?1
             WHERE id = ?3 AND status != 'done' AND status != 'cancelled'
               AND plan_status != 'pending'",
            params![now as i64, outcome, task_id],
        )?;
        Ok(n)
    }

    /// All tasks ready to progress — depends_on entries are all in
    /// the `done` or `fixed` set. Used by the dep-resolution scanner
    /// to emit `task_ready` triggers.
    ///
    /// Implementation: in-memory scan since dependency lists are
    /// JSON arrays (not relationally normalised). For the typical
    /// bridge scale (~hundreds of tasks max) this is fine; a
    /// proper join would require splitting depends_on into a
    /// task_deps table — deferred to F29.1 if scan cost surfaces.
    pub fn tasks_ready_to_unblock(
        &self,
    ) -> SqliteResult<Vec<(crate::Task, Vec<String>)>> {
        let all = self.load_tasks()?;
        let done_ids: std::collections::HashSet<String> = all
            .iter()
            .filter(|t| t.status == "done" || t.status == "fixed")
            .map(|t| t.id.clone())
            .collect();
        let mut out = Vec::new();
        for t in &all {
            // Only consider tasks that haven't started + have deps.
            if !(t.status == "todo" || t.status == "open") || t.depends_on.is_empty() {
                continue;
            }
            let unmet: Vec<String> = t
                .depends_on
                .iter()
                .filter(|d| !done_ids.contains(*d))
                .cloned()
                .collect();
            if unmet.is_empty() {
                out.push((t.clone(), Vec::<String>::new()));
            }
        }
        Ok(out)
    }

    // ── Peer watchers (F26) ────────────────────────────────────────

    /// Insert a freshly-spawned watcher row. Replaces any prior row
    /// for the same peer (last spawn wins) — the spawn handler is
    /// expected to have already killed/cleaned any stale process
    /// for that peer before calling here.
    pub fn insert_peer_watcher(&self, w: &crate::PeerWatcher) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO peer_watchers
             (peer, channel, pid, spawned_at, last_seen, ttl_secs,
              spawned_by, status, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                w.peer,
                w.channel,
                w.pid as i64,
                w.spawned_at as i64,
                w.last_seen as i64,
                w.ttl_secs as i64,
                w.spawned_by,
                w.status,
                w.session_id,
            ],
        )?;
        Ok(())
    }

    pub fn get_peer_watcher(&self, peer: &str) -> SqliteResult<Option<crate::PeerWatcher>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT peer, channel, pid, spawned_at, last_seen, ttl_secs,
                    spawned_by, status, session_id
             FROM peer_watchers WHERE peer = ?1",
        )?;
        let mut rows = stmt.query(params![peer])?;
        if let Some(r) = rows.next()? {
            Ok(Some(crate::PeerWatcher {
                peer: r.get(0)?,
                channel: r.get(1)?,
                pid: r.get::<_, i64>(2)? as i32,
                spawned_at: r.get::<_, i64>(3)? as u64,
                last_seen: r.get::<_, i64>(4)? as u64,
                ttl_secs: r.get::<_, i64>(5)? as u64,
                spawned_by: r.get(6)?,
                status: r.get(7)?,
                session_id: r.get(8)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_peer_watchers(&self) -> SqliteResult<Vec<crate::PeerWatcher>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT peer, channel, pid, spawned_at, last_seen, ttl_secs,
                    spawned_by, status, session_id
             FROM peer_watchers ORDER BY spawned_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::PeerWatcher {
                peer: r.get(0)?,
                channel: r.get(1)?,
                pid: r.get::<_, i64>(2)? as i32,
                spawned_at: r.get::<_, i64>(3)? as u64,
                last_seen: r.get::<_, i64>(4)? as u64,
                ttl_secs: r.get::<_, i64>(5)? as u64,
                spawned_by: r.get(6)?,
                status: r.get(7)?,
                session_id: r.get(8)?,
            })
        })?;
        rows.collect()
    }

    pub fn set_peer_watcher_status(&self, peer: &str, status: &str) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE peer_watchers SET status = ?1 WHERE peer = ?2",
            params![status, peer],
        )?;
        Ok(n)
    }

    pub fn touch_peer_watcher_last_seen(&self, peer: &str, now: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE peer_watchers SET last_seen = ?1 WHERE peer = ?2",
            params![now as i64, peer],
        )?;
        Ok(n)
    }

    pub fn delete_peer_watcher(&self, peer: &str) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "DELETE FROM peer_watchers WHERE peer = ?1",
            params![peer],
        )?;
        Ok(n)
    }

    // ── Routing rules (F17) ─────────────────────────────────────────

    /// Insert a new routing rule. Filter + action_params should be
    /// pre-validated by the handler (per Q2 ops decision —
    /// fail-at-insert on bad filter syntax).
    pub fn insert_routing_rule(&self, r: &crate::RoutingRule) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO routing_rules
             (id, name, trigger_type, trigger_filter, action_type,
              action_params, enabled, priority, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                r.id,
                r.name,
                r.trigger_type,
                r.trigger_filter,
                r.action_type,
                r.action_params,
                r.enabled as i64,
                r.priority,
                r.created_by,
                r.created_at as i64,
            ],
        )?;
        Ok(())
    }

    /// All enabled rules for a trigger_type, priority DESC. Hot
    /// path on the scanner side — the partial index
    /// `routing_rules_enabled_prio` covers this exact query.
    pub fn rules_for_trigger(
        &self,
        trigger_type: &str,
    ) -> SqliteResult<Vec<crate::RoutingRule>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, trigger_type, trigger_filter, action_type,
                    action_params, enabled, priority, created_by, created_at
             FROM routing_rules
             WHERE enabled = 1 AND trigger_type = ?1
             ORDER BY priority DESC",
        )?;
        let rows = stmt.query_map(params![trigger_type], |r| {
            Ok(crate::RoutingRule {
                id: r.get(0)?,
                name: r.get(1)?,
                trigger_type: r.get(2)?,
                trigger_filter: r.get(3)?,
                action_type: r.get(4)?,
                action_params: r.get(5)?,
                enabled: r.get::<_, i64>(6)? != 0,
                priority: r.get(7)?,
                created_by: r.get(8)?,
                created_at: r.get::<_, i64>(9)? as u64,
            })
        })?;
        rows.collect()
    }

    /// List all rules (any trigger, any enabled state) with optional
    /// filters. Powers `GET /routing-rules`.
    pub fn list_routing_rules(
        &self,
        trigger_filter: Option<&str>,
        enabled_filter: Option<bool>,
    ) -> SqliteResult<Vec<crate::RoutingRule>> {
        let conn = self.conn.lock();
        // Compose SQL + params dynamically; the optional filters
        // make a prepared-statement approach awkward without
        // a query builder.
        let mut sql = String::from(
            "SELECT id, name, trigger_type, trigger_filter, action_type,
                    action_params, enabled, priority, created_by, created_at
             FROM routing_rules WHERE 1=1",
        );
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(t) = trigger_filter {
            sql.push_str(" AND trigger_type = ?");
            bound.push(Box::new(t.to_string()));
        }
        if let Some(e) = enabled_filter {
            sql.push_str(" AND enabled = ?");
            bound.push(Box::new(e as i64));
        }
        sql.push_str(" ORDER BY priority DESC, created_at ASC");
        let mut stmt = conn.prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(refs.as_slice(), |r| {
            Ok(crate::RoutingRule {
                id: r.get(0)?,
                name: r.get(1)?,
                trigger_type: r.get(2)?,
                trigger_filter: r.get(3)?,
                action_type: r.get(4)?,
                action_params: r.get(5)?,
                enabled: r.get::<_, i64>(6)? != 0,
                priority: r.get(7)?,
                created_by: r.get(8)?,
                created_at: r.get::<_, i64>(9)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Toggle `enabled` for a rule. Used by both the operator
    /// PATCH endpoint and the quarantine path (3-trips-in-5-min).
    /// Returns rows-touched for 404 semantics at the handler.
    pub fn set_routing_rule_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE routing_rules SET enabled = ?1 WHERE id = ?2",
            params![enabled as i64, id],
        )?;
        Ok(n)
    }

    /// Update any combination of (name, trigger_filter,
    /// action_params, priority) on an existing rule. Other
    /// columns (trigger_type, action_type, created_*) are
    /// immutable post-insert — to change those, delete + recreate.
    pub fn update_routing_rule(
        &self,
        id: &str,
        name: Option<&str>,
        trigger_filter: Option<&str>,
        action_params: Option<&str>,
        priority: Option<i64>,
    ) -> SqliteResult<usize> {
        // Build the SET clause incrementally so untouched columns
        // keep their values.
        let mut sets = Vec::new();
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(v) = name {
            sets.push("name = ?");
            bound.push(Box::new(v.to_string()));
        }
        if let Some(v) = trigger_filter {
            sets.push("trigger_filter = ?");
            bound.push(Box::new(v.to_string()));
        }
        if let Some(v) = action_params {
            sets.push("action_params = ?");
            bound.push(Box::new(v.to_string()));
        }
        if let Some(v) = priority {
            sets.push("priority = ?");
            bound.push(Box::new(v));
        }
        if sets.is_empty() {
            return Ok(0);
        }
        let sql = format!("UPDATE routing_rules SET {} WHERE id = ?", sets.join(", "));
        bound.push(Box::new(id.to_string()));
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        let n = stmt.execute(refs.as_slice())?;
        Ok(n)
    }

    /// Read a single rule by id — used by the ownership-enforce
    /// path on update/delete so we can compare `created_by` against
    /// the authed identity without round-tripping the full list.
    /// Returns Ok(None) on missing id (caller maps to 404).
    pub fn get_routing_rule(&self, id: &str) -> SqliteResult<Option<crate::RoutingRule>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, trigger_type, trigger_filter, action_type,
                    action_params, enabled, priority, created_by, created_at
             FROM routing_rules WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(crate::RoutingRule {
                id: r.get(0)?,
                name: r.get(1)?,
                trigger_type: r.get(2)?,
                trigger_filter: r.get(3)?,
                action_type: r.get(4)?,
                action_params: r.get(5)?,
                enabled: r.get::<_, i64>(6)? != 0,
                priority: r.get(7)?,
                created_by: r.get(8)?,
                created_at: r.get::<_, i64>(9)? as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Mirror of `orphan_unmapped_memory_owners` for the
    /// `routing_rules` table. Per 0f4543 Phase 1 review forward
    /// note 2 (msg 1779049950): rules created during a permissive
    /// window where the authoring identity isn't in the post-flip
    /// registry+admins set get their `created_by` rewritten to
    /// empty so they're treated as ownerless (first authenticated
    /// re-claim wins). Enforce-mode-only at the caller; empty
    /// `known` set is a defensive no-op.
    ///
    /// Returns rows-touched.
    pub fn orphan_unmapped_rule_owners(
        &self,
        known: &std::collections::HashSet<String>,
    ) -> SqliteResult<usize> {
        let conn = self.conn.lock();
        if known.is_empty() {
            return Ok(0);
        }
        let names: Vec<String> = known.iter().cloned().collect();
        let placeholders: String = std::iter::repeat("?")
            .take(names.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "UPDATE routing_rules SET created_by = '' \
             WHERE created_by != '' AND created_by NOT IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql)?;
        let n = stmt.execute(rusqlite::params_from_iter(names.iter()))?;
        Ok(n)
    }

    pub fn delete_routing_rule(&self, id: &str) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "DELETE FROM routing_rules WHERE id = ?1",
            params![id],
        )?;
        Ok(n)
    }

    pub fn memory_set(&self, m: &MemoryEntry) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO memory
             (channel, key_, value_, updated_by, updated_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                m.channel, m.key, m.value, m.updated_by,
                m.updated_at as i64, m.expires_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn memory_delete(&self, channel: &str, key: &str) -> SqliteResult<()> {
        self.conn.lock().execute(
            "DELETE FROM memory WHERE channel = ?1 AND key_ = ?2",
            params![channel, key],
        )?;
        Ok(())
    }

    pub fn load_memory(&self) -> SqliteResult<Vec<MemoryEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT channel, key_, value_, updated_by, updated_at, expires_at
             FROM memory ORDER BY channel, key_",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(MemoryEntry {
                channel: r.get(0)?,
                key: r.get(1)?,
                value: r.get(2)?,
                updated_by: r.get(3)?,
                updated_at: r.get::<_, i64>(4)? as u64,
                expires_at: r.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect()
    }

    // ── Dispatches ──────────────────────────────────────────────────

    /// Insert a dispatch row. Called from `send()` when the outbound
    /// message has a non-empty `to:` list. `to_` is comma-joined at
    /// the call site so this stays a scalar column.
    pub fn insert_dispatch(&self, d: &crate::Dispatch) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO dispatches
             (id, message_id, from_, to_, channel, sent_at, ack_at,
              ack_eta_secs, completed_at, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                d.id,
                d.message_id,
                d.from,
                d.to,
                d.channel,
                d.sent_at as i64,
                d.ack_at as i64,
                d.ack_eta_secs as i64,
                d.completed_at as i64,
                d.outcome,
            ],
        )?;
        Ok(())
    }

    /// Mark a dispatch as acked. Identified by its `message_id` (the
    /// reference clients have — internal `id` is server-generated and
    /// not surfaced). Returns the number of rows touched so callers
    /// can 404 when the id is unknown vs a no-op repeat ack.
    pub fn ack_dispatch(
        &self,
        message_id: &str,
        ack_at: u64,
        eta_secs: u64,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE dispatches SET ack_at = ?1, ack_eta_secs = ?2
             WHERE message_id = ?3 AND ack_at = 0",
            params![ack_at as i64, eta_secs as i64, message_id],
        )?;
        Ok(n)
    }

    /// Mark a dispatch as completed. Like `ack_dispatch`, returns
    /// rows-touched for 404 semantics. Setting `completed_at`
    /// implicitly closes the dispatch even if it was never acked —
    /// some peers just ship and report done.
    ///
    /// Per finding `85bdd17a` (0f4543's hypothesis #2, msg
    /// 1779048382): when a peer calls `complete_dispatch` without
    /// a prior `ack_dispatch`, the row is closed but `ack_at`
    /// stays 0. The escalation scanner historically filtered on
    /// `WHERE ack_at = 0` alone and re-pinged completed dispatches.
    /// Two layers of defense land here:
    ///
    ///   1. The COMPLETE write back-fills `ack_at = completed_at`
    ///      when ack_at was 0 — restores the invariant "ack_at != 0
    ///      ⇒ dispatch was engaged at least once".
    ///   2. The scanner query (`open_dispatches_older_than`) also
    ///      filters `AND completed_at = 0`.
    pub fn complete_dispatch(
        &self,
        message_id: &str,
        completed_at: u64,
        outcome: &str,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE dispatches SET
                completed_at = ?1,
                outcome      = ?2,
                ack_at       = CASE WHEN ack_at = 0 THEN ?1 ELSE ack_at END
             WHERE message_id = ?3 AND completed_at = 0",
            params![completed_at as i64, outcome, message_id],
        )?;
        Ok(n)
    }

    /// Open dispatches addressed to a given peer. The `to_` column
    /// is comma-joined, so we use `LIKE '%name%'` then double-check
    /// in Rust for exact membership — avoids substring false-
    /// positives where one peer name is a prefix of another.
    /// Result is newest-first so a fresh dispatch shows up before a
    /// week-old stalemate in a peer-health view.
    ///
    /// Filters on both `ack_at = 0` AND `completed_at = 0` so a
    /// completed-without-prior-ack dispatch doesn't surface as
    /// "pending" in peer-health (same bug pattern as the scanner
    /// query — finding `85bdd17a`).
    pub fn open_dispatches_for_peer(
        &self,
        peer: &str,
        limit: usize,
    ) -> SqliteResult<Vec<crate::Dispatch>> {
        let conn = self.conn.lock();
        let pattern = format!("%{peer}%");
        let mut stmt = conn.prepare(
            "SELECT id, message_id, from_, to_, channel, sent_at,
                    ack_at, ack_eta_secs, completed_at, outcome
             FROM dispatches
             WHERE ack_at = 0
               AND completed_at = 0
               AND to_ LIKE ?1
             ORDER BY sent_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |r| {
            Ok(crate::Dispatch {
                id: r.get(0)?,
                message_id: r.get(1)?,
                from: r.get(2)?,
                to: r.get(3)?,
                channel: r.get(4)?,
                sent_at: r.get::<_, i64>(5)? as u64,
                ack_at: r.get::<_, i64>(6)? as u64,
                ack_eta_secs: r.get::<_, i64>(7)? as u64,
                completed_at: r.get::<_, i64>(8)? as u64,
                outcome: r.get(9)?,
            })
        })?;
        let all: Vec<crate::Dispatch> = rows.collect::<SqliteResult<_>>()?;
        // Exact-membership filter on the comma-joined `to_`.
        Ok(all
            .into_iter()
            .filter(|d| d.to.split(',').any(|n| n.trim() == peer))
            .collect())
    }

    /// Cheap count of every open dispatch in the table (neither
    /// acked nor completed). Used by `/metrics` and the Prometheus
    /// exporter. Same `85bdd17a` defensive filter — both columns
    /// have to be zero for a dispatch to count as "pending".
    pub fn count_open_dispatches(&self) -> SqliteResult<usize> {
        let n: i64 = self.conn.lock().query_row(
            "SELECT COUNT(*) FROM dispatches WHERE ack_at = 0 AND completed_at = 0",
            [],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Open dispatches older than `cutoff` (unix-secs). "Open"
    /// means BOTH `ack_at = 0` AND `completed_at = 0` — per
    /// finding `85bdd17a`, a dispatch closed via
    /// `complete_dispatch` without a prior `ack_dispatch` left
    /// `ack_at = 0` and the scanner re-pinged it. The
    /// `complete_dispatch` SQL now back-fills `ack_at` defensively,
    /// but this query filters on both columns regardless — a
    /// scanner shouldn't trust a single-column invariant.
    pub fn open_dispatches_older_than(
        &self,
        cutoff: u64,
        limit: usize,
    ) -> SqliteResult<Vec<crate::Dispatch>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, message_id, from_, to_, channel, sent_at,
                    ack_at, ack_eta_secs, completed_at, outcome
             FROM dispatches
             WHERE ack_at = 0
               AND completed_at = 0
               AND sent_at < ?1
             ORDER BY sent_at ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cutoff as i64, limit as i64], |r| {
            Ok(crate::Dispatch {
                id: r.get(0)?,
                message_id: r.get(1)?,
                from: r.get(2)?,
                to: r.get(3)?,
                channel: r.get(4)?,
                sent_at: r.get::<_, i64>(5)? as u64,
                ack_at: r.get::<_, i64>(6)? as u64,
                ack_eta_secs: r.get::<_, i64>(7)? as u64,
                completed_at: r.get::<_, i64>(8)? as u64,
                outcome: r.get(9)?,
            })
        })?;
        rows.collect()
    }

    // ── Peer status history ─────────────────────────────────────────

    /// Insert one row. Caller is responsible for diffing against the
    /// last row for this peer — `Store` does not enforce the
    /// "transition-only writes" policy. That choice lives at the
    /// presence handler, where the prior state is in hand without an
    /// extra read.
    pub fn insert_peer_status(
        &self,
        id: &str,
        peer: &str,
        status: &crate::PeerStatus,
        recorded_at: u64,
    ) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO peer_status_history
             (id, peer, state, reason, since, blocked_by, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                peer,
                status.state,
                status.reason,
                status.since as i64,
                status.blocked_by,
                recorded_at as i64,
            ],
        )?;
        Ok(())
    }

    /// Drop history rows older than `cutoff` (unix-seconds). Returns
    /// the number deleted so callers can log the prune size — used
    /// by the `PeerHistoryPruneScanner` in `automation.rs`.
    pub fn prune_peer_history(&self, cutoff: u64) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "DELETE FROM peer_status_history WHERE recorded_at < ?1",
            params![cutoff as i64],
        )?;
        Ok(n)
    }

    // ── Audit log (append-only) ─────────────────────────────────────

    /// Append one audit entry. Cheap (single INSERT, no read);
    /// callers should batch with their own transaction when wrapping
    /// a multi-step write op.
    ///
    /// The `before`/`after` hashes are the call site's
    /// responsibility — `Store` is the storage layer, not the
    /// serialization authority. Use `audit_hash(serde_json::to_vec)`
    /// over the table row at each point if you need the standard
    /// "row before write" → "row after write" pair; pass `""` for
    /// the `before` side of an INSERT that didn't have a prior row.
    pub fn audit(&self, entry: &AuditEntry) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT INTO audit_log
             (id, at, actor, op, target_type, target_id,
              before_hash, after_hash, result)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.id,
                entry.at as i64,
                entry.actor,
                entry.op,
                entry.target_type,
                entry.target_id,
                entry.before_hash,
                entry.after_hash,
                entry.result,
            ],
        )?;
        Ok(())
    }

    /// Read entries for a target back out — used by the
    /// `/findings/{channel}/{id}/lifecycle` and audit endpoints
    /// (Group C/D follow-ups). Newest first; cap is the caller's
    /// responsibility because audit views are paginated.
    pub fn audit_for_target(
        &self,
        target_type: &str,
        target_id: &str,
        limit: usize,
    ) -> SqliteResult<Vec<AuditEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, at, actor, op, target_type, target_id,
                    before_hash, after_hash, result
             FROM audit_log
             WHERE target_type = ?1 AND target_id = ?2
             ORDER BY at DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![target_type, target_id, limit as i64],
            |r| {
                Ok(AuditEntry {
                    id: r.get(0)?,
                    at: r.get::<_, i64>(1)? as u64,
                    actor: r.get(2)?,
                    op: r.get(3)?,
                    target_type: r.get(4)?,
                    target_id: r.get(5)?,
                    before_hash: r.get(6)?,
                    after_hash: r.get(7)?,
                    result: r.get(8)?,
                })
            },
        )?;
        rows.collect()
    }

    // ── Artifacts ───────────────────────────────────────────────────

    pub fn insert_artifact(&self, art: &Artifact, bytes: &[u8]) -> SqliteResult<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO artifacts
             (id, channel, from_, filename, mime, size_bytes, bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                art.id,
                art.channel,
                art.from,
                art.filename,
                art.mime,
                art.size as i64,
                bytes,
                art.created_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn delete_artifact(&self, id: &str) -> SqliteResult<()> {
        self.conn
            .lock()
            .execute("DELETE FROM artifacts WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn load_artifacts(
        &self,
        global_cap: usize,
    ) -> SqliteResult<Vec<(Artifact, Vec<u8>)>> {
        let conn = self.conn.lock();
        // Globally cap to the newest N by created_at — mirrors the
        // in-memory ARTIFACT_LIMIT LRU eviction policy.
        let mut stmt = conn.prepare(
            "SELECT id, channel, from_, filename, mime, size_bytes, bytes, created_at
             FROM artifacts ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![global_cap as i64], |r| {
            let art = Artifact {
                id: r.get(0)?,
                channel: r.get(1)?,
                from: r.get(2)?,
                filename: r.get(3)?,
                mime: r.get(4)?,
                size: r.get::<_, i64>(5)? as usize,
                created_at: r.get::<_, i64>(7)? as u64,
            };
            let bytes: Vec<u8> = r.get(6)?;
            Ok((art, bytes))
        })?;
        rows.collect()
    }

    // ── F18: embeddings ────────────────────────────────────────────

    /// Insert or replace an embedding for an entity. Vector must be
    /// exactly 384 dims (the migration-declared width). On re-embed of
    /// the same (entity_type, entity_id), the old vec0 row is deleted
    /// first so dim/cosine math stays clean.
    pub fn upsert_embedding(
        &self,
        entity_type: &str,
        entity_id: &str,
        channel: &str,
        content_hash: &str,
        vector: &[f32],
    ) -> SqliteResult<()> {
        if vector.len() != 384 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::ConstraintViolation,
                    extended_code: 1,
                },
                Some(format!("embedding must be 384 dims, got {}", vector.len())),
            ));
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        // Resolve existing rowid (if any) so we can DELETE the vec0
        // row before inserting the new one. vec0 has no UPSERT.
        let existing: Option<i64> = tx
            .query_row(
                "SELECT rowid FROM embeddings_meta
                 WHERE entity_type = ?1 AND entity_id = ?2",
                params![entity_type, entity_id],
                |r| r.get(0),
            )
            .ok();
        if let Some(rowid) = existing {
            tx.execute(
                "DELETE FROM embeddings_vec WHERE rowid = ?1",
                params![rowid],
            )?;
            tx.execute(
                "DELETE FROM embeddings_meta WHERE rowid = ?1",
                params![rowid],
            )?;
        }
        // vec0 takes a JSON array literal OR a blob of f32 le-bytes.
        // Bytes are the canonical fast path.
        let bytes = vec_to_bytes(vector);
        tx.execute(
            "INSERT INTO embeddings_vec (embedding) VALUES (?1)",
            params![bytes],
        )?;
        let rowid = tx.last_insert_rowid();
        let now = crate::now_secs() as i64;
        tx.execute(
            "INSERT INTO embeddings_meta
             (rowid, entity_type, entity_id, channel, content_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![rowid, entity_type, entity_id, channel, content_hash, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// k-NN semantic search using cosine distance. Returns up to `k`
    /// hits ordered by distance ascending (closer = more similar).
    /// `entity_type_filter` is optional; `channel_filter` is optional
    /// (empty string matches the broadcast/no-channel entries too).
    pub fn semantic_search(
        &self,
        query: &[f32],
        k: usize,
        entity_type_filter: Option<&str>,
        channel_filter: Option<&str>,
    ) -> SqliteResult<Vec<SemanticHit>> {
        if query.len() != 384 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::ConstraintViolation,
                    extended_code: 1,
                },
                Some(format!("query embedding must be 384 dims, got {}", query.len())),
            ));
        }
        let conn = self.conn.lock();
        let bytes = vec_to_bytes(query);
        // Generous over-fetch: vec0 doesn't support WHERE pushdown
        // into the MATCH operator, so we filter post-knn. 4× the
        // requested k bounds tail latency while making it unlikely
        // we run out of matches after the filter.
        let knn_k = (k * 4).max(20) as i64;
        let mut stmt = conn.prepare(
            "SELECT v.rowid, v.distance, m.entity_type, m.entity_id, m.channel
             FROM embeddings_vec v
             JOIN embeddings_meta m ON m.rowid = v.rowid
             WHERE v.embedding MATCH ?1 AND k = ?2
             ORDER BY v.distance ASC",
        )?;
        let rows = stmt.query_map(params![bytes, knn_k], |r| {
            Ok(SemanticHit {
                rowid: r.get::<_, i64>(0)?,
                distance: r.get::<_, f32>(1)?,
                entity_type: r.get(2)?,
                entity_id: r.get(3)?,
                channel: r.get(4)?,
            })
        })?;
        let mut out = Vec::with_capacity(k);
        for hit in rows {
            let hit = hit?;
            if let Some(et) = entity_type_filter {
                if hit.entity_type != et {
                    continue;
                }
            }
            if let Some(ch) = channel_filter {
                if !ch.is_empty() && hit.channel != ch {
                    continue;
                }
            }
            out.push(hit);
            if out.len() >= k {
                break;
            }
        }
        Ok(out)
    }

    /// Delete the embedding row for an entity (called on memory_delete
    /// / task delete / finding delete). No-op if absent.
    pub fn delete_embedding(&self, entity_type: &str, entity_id: &str) -> SqliteResult<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        if let Ok(rowid) = tx.query_row(
            "SELECT rowid FROM embeddings_meta
             WHERE entity_type = ?1 AND entity_id = ?2",
            params![entity_type, entity_id],
            |r| r.get::<_, i64>(0),
        ) {
            tx.execute("DELETE FROM embeddings_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute("DELETE FROM embeddings_meta WHERE rowid = ?1", params![rowid])?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Result row for [`Store::semantic_search`]. `distance` is cosine
/// distance ∈ [0, 2] (0 = identical direction, 1 = orthogonal, 2 =
/// opposite). Lower is better.
#[derive(Debug, Clone)]
pub struct SemanticHit {
    pub rowid: i64,
    pub distance: f32,
    pub entity_type: String,
    pub entity_id: String,
    pub channel: String,
}

/// Pack a [`Vec<f32>`] into the little-endian byte buffer vec0 expects.
fn vec_to_bytes(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// One numbered migration. `up` runs as a single sqlite batch — if
/// it fails partway, the version is NOT recorded, so a retry on the
/// next boot re-runs the same SQL. Migrations are therefore expected
/// to be idempotent enough that a partial run + a re-run leave the
/// db in a consistent state (typical pattern: `CREATE TABLE IF NOT
/// EXISTS`, `CREATE INDEX IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN`
/// guarded by a column-existence probe).
struct Migration {
    version: u32,
    name: &'static str,
    up: &'static str,
}

/// Master migration list. Append-only — never edit the SQL of a
/// migration that has shipped; add a new one instead. Version
/// numbers are dense and strictly increasing; gaps will panic the
/// runner to catch accidental reordering during code review.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "v1_initial_schema",
        // Captures the schema as it shipped before the migration
        // runner existed — messages/findings/artifacts/topics/tasks/
        // memory plus the columns previously added via best-effort
        // ALTERs (to_, thread_id, pinned, blocks_, depends_on_).
        // Idempotent so existing pre-runner DBs are recorded at v1.
        up: r#"
            CREATE TABLE IF NOT EXISTS messages (
                id        TEXT PRIMARY KEY,
                channel   TEXT NOT NULL,
                from_     TEXT NOT NULL,
                content   TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                to_       TEXT NOT NULL DEFAULT '[]',
                thread_id TEXT NOT NULL DEFAULT '',
                pinned    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS messages_channel_ts
                ON messages (channel, timestamp);

            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                channel     TEXT NOT NULL,
                from_       TEXT NOT NULL,
                severity    TEXT NOT NULL,
                title       TEXT NOT NULL,
                detail      TEXT NOT NULL,
                endpoint    TEXT NOT NULL DEFAULT '',
                status      TEXT NOT NULL DEFAULT 'open',
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                note        TEXT NOT NULL DEFAULT '',
                blocks_     TEXT NOT NULL DEFAULT '[]',
                depends_on_ TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS findings_channel_ts
                ON findings (channel, created_at);

            CREATE TABLE IF NOT EXISTS artifacts (
                id         TEXT PRIMARY KEY,
                channel    TEXT NOT NULL,
                from_      TEXT NOT NULL,
                filename   TEXT NOT NULL,
                mime       TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                bytes      BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS artifacts_channel_ts
                ON artifacts (channel, created_at);

            CREATE TABLE IF NOT EXISTS channel_topics (
                name       TEXT PRIMARY KEY,
                topic      TEXT NOT NULL DEFAULT '',
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id           TEXT PRIMARY KEY,
                channel      TEXT NOT NULL,
                from_        TEXT NOT NULL,
                title        TEXT NOT NULL,
                description  TEXT NOT NULL DEFAULT '',
                owner        TEXT NOT NULL DEFAULT '',
                status       TEXT NOT NULL DEFAULT 'todo',
                created_at   INTEGER NOT NULL,
                updated_at   INTEGER NOT NULL,
                note         TEXT NOT NULL DEFAULT '',
                blocks_      TEXT NOT NULL DEFAULT '[]',
                depends_on_  TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS tasks_channel_owner
                ON tasks (channel, owner, status);

            CREATE TABLE IF NOT EXISTS memory (
                channel    TEXT NOT NULL,
                key_       TEXT NOT NULL,
                value_     TEXT NOT NULL,
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (channel, key_)
            );
        "#,
    },
    Migration {
        version: 2,
        name: "v2_audit_log",
        // Landed first among Group A so every subsequent migration's
        // effects (and every runtime write op once Group D wires the
        // hook) can themselves be audited. Hash columns truncated to
        // 16 hex chars = 8 sha256 bytes — collision-resistant for
        // forensic joins, too short to reverse a known payload from.
        up: r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id           TEXT PRIMARY KEY,
                at           INTEGER NOT NULL,
                actor        TEXT NOT NULL,
                op           TEXT NOT NULL,
                target_type  TEXT NOT NULL,
                target_id    TEXT NOT NULL,
                before_hash  TEXT NOT NULL DEFAULT '',
                after_hash   TEXT NOT NULL DEFAULT '',
                result       TEXT NOT NULL DEFAULT 'ok'
            );
            CREATE INDEX IF NOT EXISTS audit_log_at        ON audit_log (at);
            CREATE INDEX IF NOT EXISTS audit_log_target    ON audit_log (target_type, target_id);
            CREATE INDEX IF NOT EXISTS audit_log_actor_op  ON audit_log (actor, op);
        "#,
    },
    Migration {
        version: 3,
        name: "v3_dispatches",
        // Tracks `send_message` calls with non-empty `to:` as
        // first-class units. `to_` stays comma-joined here so the
        // table remains scalar; the server unpacks for API responses.
        // Partial index over open rows keeps the auto-escalation
        // scanner (Group B) fast even with a large history.
        up: r#"
            CREATE TABLE IF NOT EXISTS dispatches (
                id            TEXT PRIMARY KEY,
                message_id    TEXT NOT NULL,
                from_         TEXT NOT NULL,
                to_           TEXT NOT NULL,
                channel       TEXT NOT NULL,
                sent_at       INTEGER NOT NULL,
                ack_at        INTEGER NOT NULL DEFAULT 0,
                ack_eta_secs  INTEGER NOT NULL DEFAULT 0,
                completed_at  INTEGER NOT NULL DEFAULT 0,
                outcome       TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS dispatches_message ON dispatches (message_id);
            CREATE INDEX IF NOT EXISTS dispatches_pending
                ON dispatches (sent_at) WHERE ack_at = 0;
            CREATE INDEX IF NOT EXISTS dispatches_open
                ON dispatches (sent_at) WHERE completed_at = 0;
        "#,
    },
    Migration {
        version: 4,
        name: "v4_peer_status_history",
        // Append-only audit trail of peer status transitions. Server
        // writes only on diff vs the most recent row for that peer —
        // never on every heartbeat. Lets `/resume/{name}` and
        // postmortem queries answer "what was X doing at time T" even
        // after the peer disconnected and live state was evicted.
        up: r#"
            CREATE TABLE IF NOT EXISTS peer_status_history (
                id          TEXT PRIMARY KEY,
                peer        TEXT NOT NULL,
                state       TEXT NOT NULL,
                reason      TEXT NOT NULL DEFAULT '',
                since       INTEGER NOT NULL,
                blocked_by  TEXT NOT NULL DEFAULT '',
                recorded_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS peer_status_history_peer_at
                ON peer_status_history (peer, recorded_at);
        "#,
    },
    Migration {
        version: 5,
        name: "v5_memory_history",
        // Versioned memory: keep the last N rows per (channel, key).
        // Old rows are dropped at write time by the server, not by a
        // trigger here, so the cap is policy and not schema.
        up: r#"
            CREATE TABLE IF NOT EXISTS memory_history (
                channel  TEXT NOT NULL,
                key_     TEXT NOT NULL,
                version  INTEGER NOT NULL,
                value_   TEXT NOT NULL,
                set_by   TEXT NOT NULL,
                set_at   INTEGER NOT NULL,
                PRIMARY KEY (channel, key_, version)
            );
            CREATE INDEX IF NOT EXISTS memory_history_set_at
                ON memory_history (channel, key_, set_at);
        "#,
    },
    Migration {
        version: 6,
        name: "v6_coverage",
        up: r#"
            CREATE TABLE IF NOT EXISTS coverage (
                role         TEXT NOT NULL,
                surface_type TEXT NOT NULL,
                current_     INTEGER NOT NULL,
                total_       INTEGER NOT NULL,
                breakdown    TEXT NOT NULL DEFAULT '',
                updated_by   TEXT NOT NULL,
                updated_at   INTEGER NOT NULL,
                PRIMARY KEY (role, surface_type)
            );
        "#,
    },
    Migration {
        version: 7,
        name: "v7_decisions",
        // First-class decisions table. FTS index added in a
        // separate migration (v9) so a build without FTS5 compiled
        // in can still get the base table.
        up: r#"
            CREATE TABLE IF NOT EXISTS decisions (
                id            TEXT PRIMARY KEY,
                decision_text TEXT NOT NULL,
                reason        TEXT NOT NULL,
                alternatives  TEXT NOT NULL DEFAULT '',
                scope         TEXT NOT NULL DEFAULT '',
                decided_by    TEXT NOT NULL,
                applies_to    TEXT NOT NULL DEFAULT '',
                decided_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS decisions_decided_at
                ON decisions (decided_at);
        "#,
    },
    Migration {
        version: 8,
        name: "v8_finding_transitions_and_mirrors",
        up: r#"
            CREATE TABLE IF NOT EXISTS finding_transitions (
                finding_id      TEXT NOT NULL,
                from_status     TEXT NOT NULL,
                to_status       TEXT NOT NULL,
                transitioned_by TEXT NOT NULL,
                at              INTEGER NOT NULL,
                note            TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (finding_id, at)
            );

            CREATE TABLE IF NOT EXISTS mirror_links (
                source_channel TEXT NOT NULL,
                source_key     TEXT NOT NULL,
                target_channel TEXT NOT NULL,
                target_key     TEXT NOT NULL,
                created_at     INTEGER NOT NULL,
                PRIMARY KEY (source_channel, source_key, target_channel, target_key)
            );
            CREATE INDEX IF NOT EXISTS mirror_links_source
                ON mirror_links (source_channel, source_key);
        "#,
    },
    Migration {
        version: 9,
        name: "v9_memory_soft_delete_and_fts",
        // Adds `archived_at` to memory (0 = active, otherwise the
        // archival timestamp). Existing reads filter on it, so no
        // peer sees archived rows unless they hit
        // `/memory/{channel}/archived` explicitly.
        //
        // memory_fts is content-rowid mode joined to the memory
        // table by ROWID. Triggers keep it in sync AND skip archived
        // rows so a search can't surface tombstones. The
        // `external content` shape means the FTS table doesn't
        // duplicate the value column on disk.
        up: r#"
            ALTER TABLE memory ADD COLUMN archived_at INTEGER NOT NULL DEFAULT 0;
            CREATE INDEX IF NOT EXISTS memory_active
                ON memory (channel) WHERE archived_at = 0;

            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                channel UNINDEXED,
                key_,
                value_,
                content='memory',
                content_rowid='rowid'
            );

            -- Drop any pre-existing triggers so the migration is
            -- replayable against a partial run.
            DROP TRIGGER IF EXISTS memory_fts_insert;
            DROP TRIGGER IF EXISTS memory_fts_delete;
            DROP TRIGGER IF EXISTS memory_fts_update;

            CREATE TRIGGER memory_fts_insert AFTER INSERT ON memory
                WHEN NEW.archived_at = 0
                BEGIN
                    INSERT INTO memory_fts(rowid, channel, key_, value_)
                    VALUES (NEW.rowid, NEW.channel, NEW.key_, NEW.value_);
                END;

            CREATE TRIGGER memory_fts_delete AFTER DELETE ON memory
                BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, channel, key_, value_)
                    VALUES('delete', OLD.rowid, OLD.channel, OLD.key_, OLD.value_);
                END;

            -- Treat an archive-flip as a delete from the index; a
            -- restore (archived_at: nonzero → 0) re-inserts. Keeps
            -- archived content out of search without splitting the
            -- table.
            CREATE TRIGGER memory_fts_update AFTER UPDATE ON memory
                BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, channel, key_, value_)
                    VALUES('delete', OLD.rowid, OLD.channel, OLD.key_, OLD.value_);
                    INSERT INTO memory_fts(rowid, channel, key_, value_)
                    SELECT NEW.rowid, NEW.channel, NEW.key_, NEW.value_
                    WHERE NEW.archived_at = 0;
                END;

            -- Backfill: index everything currently active. Safe to
            -- run after the triggers because we INSERT OR IGNORE
            -- the rowid in case a partial run already populated.
            INSERT INTO memory_fts(rowid, channel, key_, value_)
                SELECT rowid, channel, key_, value_
                FROM memory
                WHERE archived_at = 0
                  AND rowid NOT IN (SELECT rowid FROM memory_fts);
        "#,
    },
    Migration {
        version: 10,
        name: "v10_extra_indexes",
        // Hot-path indexes for queries the new endpoints in Group C
        // will hit: thread reconstruction, findings triage filters.
        up: r#"
            CREATE INDEX IF NOT EXISTS messages_thread
                ON messages (thread_id, timestamp) WHERE thread_id != '';
            CREATE INDEX IF NOT EXISTS findings_status_sev
                ON findings (channel, status, severity);
        "#,
    },
    Migration {
        version: 11,
        name: "v11_routing_rules",
        // F17 — Smart routing rules. Schema per
        // `bridge-features-roadmap-v2` F17 plus `created_by` so
        // ownership matches the pattern established by finding
        // `0919a7db` (memory_set ownership). Action params + filter
        // are JSON blobs validated at insert time per Q2 op decision
        // (`fail at insert on unknown filter syntax`).
        //
        // Index orders by (enabled, priority DESC, trigger_type) so
        // the eval engine's hot path can stream-walk matching rules
        // without a sort.
        up: r#"
            CREATE TABLE IF NOT EXISTS routing_rules (
                id             TEXT PRIMARY KEY,
                name           TEXT NOT NULL,
                trigger_type   TEXT NOT NULL,
                trigger_filter TEXT NOT NULL DEFAULT '{}',
                action_type    TEXT NOT NULL,
                action_params  TEXT NOT NULL DEFAULT '{}',
                enabled        INTEGER NOT NULL DEFAULT 1,
                priority       INTEGER NOT NULL DEFAULT 50,
                created_by     TEXT NOT NULL DEFAULT '',
                created_at     INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS routing_rules_enabled_prio
                ON routing_rules (enabled, priority DESC, trigger_type);
        "#,
    },
    Migration {
        version: 12,
        name: "v12_peer_watchers",
        // F26 — Background watcher per-peer state. Server-side
        // spawn record: PID + spawned_at + status + TTL. The
        // bridge tokio task hosts the child process; this table
        // is the durable handle so a bridge restart can re-adopt
        // running children (detached process_group means they
        // survive the bridge crash/restart).
        //
        // `spawned_by` matches the auth bundle's `created_by`
        // ownership pattern — only the spawner or BRIDGE_MEMORY_ADMINS
        // can stop the watcher.
        up: r#"
            CREATE TABLE IF NOT EXISTS peer_watchers (
                peer        TEXT PRIMARY KEY,
                channel     TEXT NOT NULL,
                pid         INTEGER NOT NULL,
                spawned_at  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                ttl_secs    INTEGER NOT NULL DEFAULT 3600,
                spawned_by  TEXT NOT NULL DEFAULT '',
                status      TEXT NOT NULL DEFAULT 'running',
                session_id  TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS peer_watchers_status
                ON peer_watchers (status);
        "#,
    },
    Migration {
        version: 13,
        name: "v13_task_plan_status",
        // F29 — Agent-Teams task coordination columns.
        // plan_status: 'none' (default, free transitions) | 'pending'
        // (awaiting approve_plan, blocks todo→in_progress) |
        // 'approved' (allowed to advance) | 'rejected' (terminal).
        // completed_at: filled by complete_task → fires task_completed
        // routing trigger via fire_routing_actions.
        // claim_count: observability for orphan reclaim cycles.
        up: r#"
            ALTER TABLE tasks ADD COLUMN plan_status TEXT NOT NULL DEFAULT 'none';
            ALTER TABLE tasks ADD COLUMN plan_text TEXT NOT NULL DEFAULT '';
            ALTER TABLE tasks ADD COLUMN plan_reviewer TEXT NOT NULL DEFAULT '';
            ALTER TABLE tasks ADD COLUMN plan_decided_at INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE tasks ADD COLUMN completed_at INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE tasks ADD COLUMN claim_count INTEGER NOT NULL DEFAULT 0;
            CREATE INDEX IF NOT EXISTS tasks_plan_status
                ON tasks (channel, plan_status);
        "#,
    },
    Migration {
        version: 14,
        name: "v14_goals",
        // F20 — Operator-set targets. target_metric is a closed
        // string vocab: 'peers_active' | 'findings_open' |
        // 'tasks_active' | 'dispatches_pending' | 'sla_met_pct'.
        // current_value updated by GoalScanner every 60s.
        // status: 'pending' | 'met' | 'missed' | 'cancelled'.
        // Routing trigger `goal_achieved` fires when current crosses
        // target (transition-edge, not every tick at target).
        up: r#"
            CREATE TABLE IF NOT EXISTS goals (
                id            TEXT PRIMARY KEY,
                channel       TEXT NOT NULL DEFAULT '',
                name          TEXT NOT NULL,
                description   TEXT NOT NULL DEFAULT '',
                target_metric TEXT NOT NULL,
                target_value  INTEGER NOT NULL,
                current_value INTEGER NOT NULL DEFAULT 0,
                comparator    TEXT NOT NULL DEFAULT '>=',
                created_by    TEXT NOT NULL DEFAULT '',
                deadline      INTEGER NOT NULL DEFAULT 0,
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS goals_status
                ON goals (status);
        "#,
    },
    Migration {
        version: 15,
        name: "v15_plans",
        // F21 — Plan = an ordered tree of steps with intra-plan
        // dependencies. Distinct from `tasks` because plans express
        // "multi-step work for ONE owner" while tasks are unit-of-
        // work claimable across peers. steps_json is a JSON array
        // of {id, title, depends_on, status} — opaque to sqlite,
        // walked Rust-side at plan_advance + render time.
        up: r#"
            CREATE TABLE IF NOT EXISTS plans (
                id          TEXT PRIMARY KEY,
                channel     TEXT NOT NULL DEFAULT '',
                title       TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                steps_json  TEXT NOT NULL DEFAULT '[]',
                status      TEXT NOT NULL DEFAULT 'active',
                owner       TEXT NOT NULL DEFAULT '',
                created_by  TEXT NOT NULL DEFAULT '',
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS plans_status
                ON plans (status);
        "#,
    },
    Migration {
        version: 16,
        name: "v16_peer_recovery_config",
        // F23 — Per-peer recovery webhook config. When a peer drops
        // off /peers (>5min no heartbeat) AND has pending unread
        // dispatches, the PeerRecoveryScanner POSTs the routine URL
        // configured here with {peer, dispatches, channel}.
        // last_fired_at de-dups so the scanner doesn't re-fire on
        // every tick during the drop window.
        up: r#"
            CREATE TABLE IF NOT EXISTS peer_recovery_config (
                peer           TEXT PRIMARY KEY,
                routine_url    TEXT NOT NULL,
                created_by     TEXT NOT NULL DEFAULT '',
                created_at     INTEGER NOT NULL,
                last_fired_at  INTEGER NOT NULL DEFAULT 0,
                fire_count     INTEGER NOT NULL DEFAULT 0
            );
        "#,
    },
    Migration {
        version: 17,
        name: "v17_pull_requests",
        // F22 — PR management. Webhook receivers + manual link tools
        // both write here. linked_* are JSON arrays opaque to sqlite
        // (walked Rust-side on render). UNIQUE(repo, number) so
        // GitHub `synchronize` deliveries upsert cleanly.
        up: r#"
            CREATE TABLE IF NOT EXISTS pull_requests (
                id                TEXT PRIMARY KEY,
                repo              TEXT NOT NULL,
                number            INTEGER NOT NULL,
                title             TEXT NOT NULL DEFAULT '',
                state             TEXT NOT NULL DEFAULT 'open',
                author            TEXT NOT NULL DEFAULT '',
                base_branch       TEXT NOT NULL DEFAULT '',
                head_branch       TEXT NOT NULL DEFAULT '',
                url               TEXT NOT NULL DEFAULT '',
                linked_findings   TEXT NOT NULL DEFAULT '[]',
                linked_decisions  TEXT NOT NULL DEFAULT '[]',
                linked_goal_id    TEXT NOT NULL DEFAULT '',
                body              TEXT NOT NULL DEFAULT '',
                created_at        INTEGER NOT NULL,
                updated_at        INTEGER NOT NULL,
                UNIQUE (repo, number)
            );
            CREATE INDEX IF NOT EXISTS pull_requests_state
                ON pull_requests (state);
        "#,
    },
    Migration {
        version: 18,
        name: "v18_embeddings_vec0",
        // F18 — semantic search. vec0 vtab stores the actual floats
        // (384 dims = MiniLM / fastembed-default). `embeddings_meta`
        // joins back to the entity (memory_key / message id /
        // finding id / task id) and the channel for scoped queries.
        // rowid is shared between the two tables — vec0 assigns it,
        // we mirror it into meta. ON DELETE CASCADE on the meta row
        // is enough; vec0 rows are explicitly DELETEd when meta goes.
        //
        // Default-feature builds without the `embeddings` Cargo
        // feature still create this schema: search just returns
        // empty results until an embedder is wired in.
        up: r#"
            CREATE VIRTUAL TABLE IF NOT EXISTS embeddings_vec
                USING vec0(embedding float[384]);
            CREATE TABLE IF NOT EXISTS embeddings_meta (
                rowid         INTEGER PRIMARY KEY,
                entity_type   TEXT NOT NULL,
                entity_id     TEXT NOT NULL,
                channel       TEXT NOT NULL DEFAULT '',
                content_hash  TEXT NOT NULL DEFAULT '',
                created_at    INTEGER NOT NULL,
                UNIQUE (entity_type, entity_id)
            );
            CREATE INDEX IF NOT EXISTS embeddings_meta_entity
                ON embeddings_meta (entity_type, channel);
        "#,
    },
];

/// Best-effort column adds for pre-runner DBs. `CREATE TABLE IF
/// NOT EXISTS` in v1 is a no-op against an existing table, so a DB
/// created by the previous code (which used these ad-hoc ALTERs on
/// every boot) would otherwise be missing the columns `to_`,
/// `thread_id`, `pinned`, `blocks_`, `depends_on_`. Each ALTER
/// fails with "duplicate column name" on a fresh/already-migrated
/// DB; the error is swallowed since the absence of the error means
/// nothing — the column either was added now, or already existed.
fn pre_runner_compat(conn: &Connection) {
    let stmts = [
        "ALTER TABLE messages ADD COLUMN to_ TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE messages ADD COLUMN thread_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE messages ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN blocks_ TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE findings ADD COLUMN depends_on_ TEXT NOT NULL DEFAULT '[]'",
    ];
    for s in stmts {
        match conn.execute(s, []) {
            Ok(_) => tracing::info!(stmt = s, "pre-runner compat ALTER applied"),
            Err(e) => tracing::debug!(stmt = s, error = %e, "pre-runner compat ALTER skipped"),
        }
    }
}

/// Run every pending migration in version order under one
/// transaction per migration. Records success in `schema_version`;
/// a failure leaves the row unrecorded so the next boot retries.
fn run_migrations(conn: &Connection) -> SqliteResult<()> {
    pre_runner_compat(conn);
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            name       TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        );",
    )?;

    // Density check: catch accidental gaps or reorderings during
    // review. Panic is appropriate here — a misaligned migration
    // list is a programmer error, not a runtime condition.
    for (idx, m) in MIGRATIONS.iter().enumerate() {
        let expected = (idx + 1) as u32;
        assert_eq!(
            m.version, expected,
            "migration list out of order: position {idx} declares version {} but should be {expected}",
            m.version
        );
    }

    let mut applied = std::collections::BTreeSet::new();
    {
        let mut stmt = conn.prepare("SELECT version FROM schema_version")?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        for v in rows {
            applied.insert(v? as u32);
        }
    }

    // Downgrade detection (finding `752cc548`, pentest 0f4543
    // 1779042815): if the DB has an applied migration newer than
    // the highest version this binary knows about, then either
    // (a) the operator is running an older binary against a
    // newer DB, or (b) someone hand-edited schema_version. Either
    // way the binary lacks the structural assumptions of the
    // newer schema — running it would either skip invariants or
    // panic on first SQL hit. Refuse to start so the operator
    // notices before silent data loss.
    let highest_known = MIGRATIONS.iter().map(|m| m.version).max().unwrap_or(0);
    let highest_applied = applied.iter().copied().max().unwrap_or(0);
    if highest_applied > highest_known {
        let msg = format!(
            "schema_version has v{highest_applied} applied but this binary only knows up to v{highest_known}. \
             Refusing to start — running an older binary against a newer DB would skip migration \
             invariants. See finding 752cc548. To force re-migrate from scratch, delete the schema_version \
             row(s) > v{highest_known} AND verify no later-schema tables are in use, then restart."
        );
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::SchemaChanged,
                extended_code: 1,
            },
            Some(msg),
        ));
    }

    let now = crate::now_secs() as i64;
    for m in MIGRATIONS {
        if applied.contains(&m.version) {
            continue;
        }
        // execute_batch implicitly runs in autocommit; wrap in an
        // explicit transaction so a multi-statement migration is
        // atomic. BEGIN IMMEDIATE so we grab the write lock up-front
        // and don't fail late on a contended db.
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        match conn.execute_batch(m.up) {
            Ok(()) => {
                conn.execute(
                    "INSERT INTO schema_version (version, name, applied_at) VALUES (?1, ?2, ?3)",
                    params![m.version as i64, m.name, now],
                )?;
                conn.execute_batch("COMMIT;")?;
                tracing::info!(version = m.version, name = m.name, "migration applied");
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                tracing::error!(
                    version = m.version,
                    name = m.name,
                    error = %e,
                    "migration failed; will retry on next boot"
                );
                return Err(e);
            }
        }
    }
    Ok(())
}

fn init(conn: &Connection) -> SqliteResult<()> {
    run_migrations(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::now_secs;

    fn temp_store() -> Store {
        let p = std::env::temp_dir().join(format!(
            "bridge-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        Store::open(&p).expect("open temp db")
    }

    #[test]
    fn embeddings_round_trip_and_search() {
        let s = temp_store();
        let mk_vec = |seed: u8| -> Vec<f32> {
            (0..384).map(|i| ((i as u8).wrapping_add(seed) as f32) / 255.0).collect()
        };
        s.upsert_embedding("memory", "c1/alpha", "c1", "h1", &mk_vec(1)).unwrap();
        s.upsert_embedding("memory", "c1/beta", "c1", "h2", &mk_vec(2)).unwrap();
        s.upsert_embedding("memory", "c1/gamma", "c1", "h3", &mk_vec(60)).unwrap();
        // Query near alpha — alpha should rank first.
        let hits = s.semantic_search(&mk_vec(1), 3, Some("memory"), Some("c1")).unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].entity_id, "c1/alpha");
        // Wrong-length input rejected.
        let bad = vec![0.0; 100];
        assert!(s.semantic_search(&bad, 3, None, None).is_err());
        assert!(s.upsert_embedding("memory", "c1/x", "c1", "h", &bad).is_err());
        // Delete drops the row.
        s.delete_embedding("memory", "c1/alpha").unwrap();
        let hits2 = s.semantic_search(&mk_vec(1), 5, Some("memory"), Some("c1")).unwrap();
        assert!(hits2.iter().all(|h| h.entity_id != "c1/alpha"));
        // Channel filter excludes mismatches.
        s.upsert_embedding("memory", "c2/delta", "c2", "h4", &mk_vec(2)).unwrap();
        let hits3 = s.semantic_search(&mk_vec(2), 10, Some("memory"), Some("c2")).unwrap();
        assert!(hits3.iter().all(|h| h.channel == "c2"));
    }

    #[test]
    fn round_trip_message() {
        let s = temp_store();
        let m = Message {
            id: "m1".into(),
            channel: "c1".into(),
            from: "alice".into(),
            content: "hi".into(),
            timestamp: now_secs(),
            to: Vec::new(),
            thread_id: String::new(),
            pinned: false,
        };
        s.insert_message(&m).unwrap();
        let loaded = s.load_messages(100).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].content, "hi");
        s.clear_messages("c1").unwrap();
        assert!(s.load_messages(100).unwrap().is_empty());
    }

    #[test]
    fn round_trip_finding() {
        let s = temp_store();
        let f = Finding {
            id: "f1".into(),
            channel: "c1".into(),
            from: "bob".into(),
            severity: "high".into(),
            title: "SQLi".into(),
            detail: "x".into(),
            endpoint: "POST /login".into(),
            status: "open".into(),
            created_at: now_secs(),
            updated_at: now_secs(),
            note: "".into(),
            blocks: Vec::new(),
            depends_on: Vec::new(),
        };
        s.upsert_finding(&f).unwrap();
        let loaded = s.load_findings(100).unwrap();
        assert_eq!(loaded.len(), 1);
        // Update
        let mut updated = f.clone();
        updated.status = "fixed".into();
        updated.note = "shipped".into();
        s.upsert_finding(&updated).unwrap();
        let loaded = s.load_findings(100).unwrap();
        assert_eq!(loaded[0].status, "fixed");
        assert_eq!(loaded[0].note, "shipped");
        // Delete
        s.delete_finding("c1", "f1").unwrap();
        assert!(s.load_findings(100).unwrap().is_empty());
    }

    #[test]
    fn round_trip_artifact() {
        let s = temp_store();
        let a = Artifact {
            id: "a1".into(),
            channel: "c1".into(),
            from: "alice".into(),
            filename: "poc.txt".into(),
            mime: "text/plain".into(),
            size: 5,
            created_at: now_secs(),
        };
        s.insert_artifact(&a, b"hello").unwrap();
        let loaded = s.load_artifacts(100).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, b"hello");
        s.delete_artifact("a1").unwrap();
        assert!(s.load_artifacts(100).unwrap().is_empty());
    }

    #[test]
    fn migrations_recorded_and_idempotent() {
        // Cold open writes one schema_version row per migration.
        let s = temp_store();
        let count: i64 = s
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count as usize, MIGRATIONS.len());

        // Re-opening the same file (via init on the same conn) must
        // not re-apply or error — the `applied` set skips already-
        // versioned migrations.
        run_migrations(&s.conn.lock()).expect("re-run is a no-op");
        let count2: i64 = s
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, count2);
    }

    #[test]
    fn migration_runner_refuses_downgrade() {
        // Cold-open a store at the current schema, then forge a
        // schema_version row at version > MIGRATIONS.max() to
        // simulate someone restarting with an older binary against
        // a newer DB.
        let s = temp_store();
        let max_known = MIGRATIONS.iter().map(|m| m.version).max().unwrap();
        let future = max_known + 1;
        s.conn
            .lock()
            .execute(
                "INSERT INTO schema_version (version, name, applied_at) VALUES (?1, 'forged', 0)",
                rusqlite::params![future as i64],
            )
            .unwrap();
        // Re-run migrations on the same connection — should refuse.
        let r = run_migrations(&s.conn.lock());
        assert!(r.is_err(), "downgrade must refuse to start");
        // Error message contains the diagnostic hint per finding
        // 752cc548 so an operator hitting this knows what to do.
        let msg = format!("{}", r.unwrap_err());
        assert!(msg.contains("752cc548"), "error names finding id: {msg}");
        assert!(msg.contains(&format!("v{future}")), "error names applied version: {msg}");
    }

    #[test]
    fn memory_fts_indexes_active_rows_and_skips_archived() {
        let s = temp_store();
        // Two active rows, one we'll archive after insert.
        s.conn
            .lock()
            .execute(
                "INSERT INTO memory (channel, key_, value_, updated_at)
                 VALUES ('c1', 'alpha', 'hello world', 0)",
                [],
            )
            .unwrap();
        s.conn
            .lock()
            .execute(
                "INSERT INTO memory (channel, key_, value_, updated_at)
                 VALUES ('c1', 'beta', 'goodbye galaxy', 0)",
                [],
            )
            .unwrap();
        // FTS reflects both rows.
        let n: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM memory_fts WHERE memory_fts MATCH ?",
                ["hello OR goodbye"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
        // Archive `alpha` — update trigger drops it from the index.
        s.conn
            .lock()
            .execute(
                "UPDATE memory SET archived_at = 1 WHERE key_ = 'alpha'",
                [],
            )
            .unwrap();
        let m: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM memory_fts WHERE memory_fts MATCH ?",
                ["hello"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(m, 0, "archived row must be invisible to FTS");
        // The base table still has it (soft-delete, not hard).
        let live: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM memory WHERE key_ = 'alpha'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(live, 1);
    }

    #[test]
    fn orphan_unmapped_memory_owners_rewrites_unknowns() {
        let s = temp_store();
        let conn = s.conn.lock();
        // Three rows: alice-owned (registry identity), unknown
        // (legacy placeholder), and a stranger not in any registry.
        conn.execute(
            "INSERT INTO memory (channel, key_, value_, updated_by, updated_at)
             VALUES ('c1', 'alpha', 'v1', 'alice', 0),
                    ('c1', 'beta',  'v2', 'unknown', 0),
                    ('c1', 'gamma', 'v3', 'mallory', 0),
                    ('c1', 'delta', 'v4', '', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        // Known identity set = { alice, ops-admin }. Mallory and
        // unknown both get orphaned; alice's row stays; the
        // already-empty delta row stays empty (untouched).
        let mut known = std::collections::HashSet::new();
        known.insert("alice".to_string());
        known.insert("ops-admin".to_string());
        let n = s.orphan_unmapped_memory_owners(&known).unwrap();
        assert_eq!(n, 2, "exactly mallory + unknown should be orphaned");
        // Verify per-row outcomes.
        let mut state: Vec<(String, String)> = Vec::new();
        let conn = s.conn.lock();
        let mut stmt = conn
            .prepare("SELECT key_, updated_by FROM memory ORDER BY key_")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap();
        for r in rows {
            state.push(r.unwrap());
        }
        assert_eq!(state[0], ("alpha".into(), "alice".into()));
        assert_eq!(state[1], ("beta".into(), "".into()));
        assert_eq!(state[2], ("delta".into(), "".into()));
        assert_eq!(state[3], ("gamma".into(), "".into()));
    }

    #[test]
    fn orphan_unmapped_finding_authors_rewrites_strangers_only() {
        let s = temp_store();
        let now = crate::now_secs();
        for (id, author) in [
            ("f1", "alice"),
            ("f2", "saas"),
            ("f3", "saas"),
            ("f4", "saas"),
            ("f5", "[orphan-mallory]"),
        ] {
            s.conn
                .lock()
                .execute(
                    "INSERT INTO findings (id, channel, from_, severity, title, detail, created_at, updated_at) \
                     VALUES (?1, 'c1', ?2, 'low', 't', 'd', ?3, ?3)",
                    rusqlite::params![id, author, now as i64],
                )
                .unwrap();
        }
        let mut known = std::collections::HashSet::new();
        known.insert("alice".to_string());
        let n = s.orphan_unmapped_finding_authors(&known).unwrap();
        // 3 saas rows renamed; alice stays; already-orphan-prefixed
        // row left alone (no double-wrap).
        assert_eq!(n, 3);
        let rows: Vec<(String, String)> = {
            let conn = s.conn.lock();
            let mut stmt = conn
                .prepare("SELECT id, from_ FROM findings ORDER BY id")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(rows[0], ("f1".into(), "alice".into()));
        assert_eq!(rows[1], ("f2".into(), "[orphan-saas]".into()));
        assert_eq!(rows[2], ("f3".into(), "[orphan-saas]".into()));
        assert_eq!(rows[3], ("f4".into(), "[orphan-saas]".into()));
        assert_eq!(rows[4], ("f5".into(), "[orphan-mallory]".into()));
        // Second call is a no-op — already-orphan-prefixed rows
        // are filtered out by the `NOT LIKE '[orphan-%'` guard.
        let n2 = s.orphan_unmapped_finding_authors(&known).unwrap();
        assert_eq!(n2, 0, "second call must be idempotent");
    }

    #[test]
    fn orphan_finding_authors_refuses_empty_known_set() {
        let s = temp_store();
        s.conn
            .lock()
            .execute(
                "INSERT INTO findings (id, channel, from_, severity, title, detail, created_at, updated_at) \
                 VALUES ('f1', 'c1', 'real', 'low', 't', 'd', 0, 0)",
                [],
            )
            .unwrap();
        let known = std::collections::HashSet::new();
        let n = s.orphan_unmapped_finding_authors(&known).unwrap();
        assert_eq!(n, 0, "empty known must not torch every author");
        let author: String = s
            .conn
            .lock()
            .query_row("SELECT from_ FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(author, "real");
    }

    #[test]
    fn orphan_migration_runs_under_transaction_with_fts_rebuild() {
        // Re-runs of orphan_unmapped_memory_owners on the same DB
        // must be idempotent — second call sees an already-clean
        // table and orphans nothing. Confirms the TX commit-path
        // is wired correctly (otherwise the BEGIN IMMEDIATE would
        // leave a stale write lock and the second call would
        // either deadlock or duplicate work).
        let s = temp_store();
        s.conn
            .lock()
            .execute(
                "INSERT INTO memory (channel, key_, value_, updated_by, updated_at)
                 VALUES ('c1', 'a', 'v', 'alice', 0),
                        ('c1', 'b', 'v', 'unknown', 0),
                        ('c1', 'c', 'v', 'anonymous', 0)",
                [],
            )
            .unwrap();
        let mut known = std::collections::HashSet::new();
        known.insert("alice".to_string());
        let n1 = s.orphan_unmapped_memory_owners(&known).unwrap();
        assert_eq!(n1, 2, "first pass clears unknown + anonymous");
        let n2 = s.orphan_unmapped_memory_owners(&known).unwrap();
        assert_eq!(n2, 0, "second pass is idempotent");
        // memory_fts is still queryable post-rebuild — confirms
        // the trigger plumbing wasn't broken by the migration.
        let q: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM memory_fts WHERE memory_fts MATCH ?",
                ["v"],
                |r| r.get(0),
            )
            .unwrap();
        assert!(q >= 1, "FTS index remains queryable post-orphan-migration");
    }

    #[test]
    fn orphan_with_empty_known_set_clears_every_named_owner() {
        let s = temp_store();
        s.conn
            .lock()
            .execute(
                "INSERT INTO memory (channel, key_, value_, updated_by, updated_at)
                 VALUES ('c1', 'a', 'v', 'alice', 0),
                        ('c1', 'b', 'v', 'bob',   0),
                        ('c1', 'c', 'v', '',      0)",
                [],
            )
            .unwrap();
        let known = std::collections::HashSet::new();
        let n = s.orphan_unmapped_memory_owners(&known).unwrap();
        // Two rows had non-empty owners and get rewritten; the
        // empty one was already ownerless.
        assert_eq!(n, 2);
    }

    #[test]
    fn checkpoint_wal_on_shutdown_is_callable_and_idempotent() {
        // The actual file-level WAL flush is sqlite's responsibility;
        // we only assert the call shape doesn't error AND can be
        // invoked repeatedly (defensive — a SIGTERM might fire
        // twice if systemd is impatient).
        let s = temp_store();
        // Write something so there's wal content to checkpoint.
        s.conn
            .lock()
            .execute(
                "INSERT INTO memory (channel, key_, value_, updated_at) VALUES ('c1','k','v',0)",
                [],
            )
            .unwrap();
        s.checkpoint_wal_on_shutdown().expect("first checkpoint");
        s.checkpoint_wal_on_shutdown().expect("second checkpoint idempotent");
    }

    #[test]
    fn f21_plan_crud_and_status_roundtrip() {
        let s = temp_store();
        let now = crate::now_secs();
        let steps = vec![
            crate::PlanStep { id: "a".into(), title: "A".into(), depends_on: vec![], status: "todo".into() },
            crate::PlanStep { id: "b".into(), title: "B".into(), depends_on: vec!["a".into()], status: "todo".into() },
        ];
        let p = crate::Plan {
            id: "p1".into(), channel: "c1".into(), title: "ship F21".into(),
            description: "".into(),
            steps_json: serde_json::to_string(&steps).unwrap(),
            status: "active".into(), owner: "alice".into(), created_by: "ops".into(),
            created_at: now, updated_at: now,
        };
        s.insert_plan(&p).unwrap();
        let got = s.get_plan("p1").unwrap().expect("present");
        assert_eq!(got.title, "ship F21");
        assert_eq!(got.owner, "alice");
        let parsed: Vec<crate::PlanStep> = serde_json::from_str(&got.steps_json).unwrap();
        assert_eq!(parsed.len(), 2);
        // Mutate steps via write_plan_steps.
        let mut updated = parsed.clone();
        updated[0].status = "done".into();
        let new_json = serde_json::to_string(&updated).unwrap();
        let n = s.write_plan_steps("p1", &new_json, now + 1).unwrap();
        assert_eq!(n, 1);
        let after = s.get_plan("p1").unwrap().unwrap();
        let after_steps: Vec<crate::PlanStep> = serde_json::from_str(&after.steps_json).unwrap();
        assert_eq!(after_steps[0].status, "done");
        // set_plan_status closes the plan.
        s.set_plan_status("p1", "done", now + 2).unwrap();
        assert_eq!(s.get_plan("p1").unwrap().unwrap().status, "done");
        // list returns 1.
        assert_eq!(s.list_plans().unwrap().len(), 1);
    }

    #[test]
    fn f20_goal_progress_transitions_to_met_and_stays() {
        let s = temp_store();
        let now = crate::now_secs();
        let g = crate::Goal {
            id: "g1".into(), channel: "c1".into(), name: "5 peers".into(),
            description: String::new(), target_metric: "peers_active".into(),
            target_value: 5, current_value: 0, comparator: ">=".into(),
            created_by: "ops".into(), deadline: 0, status: "pending".into(),
            created_at: now, updated_at: now,
        };
        s.insert_goal(&g).unwrap();
        // 3 peers → still pending.
        let (prior, new) = s.update_goal_progress("g1", 3, ">=", 5, 0, now).unwrap();
        assert_eq!(prior, "pending"); assert_eq!(new, "pending");
        // 5 peers → met.
        let (prior, new) = s.update_goal_progress("g1", 5, ">=", 5, 0, now + 1).unwrap();
        assert_eq!(prior, "pending"); assert_eq!(new, "met");
        // 3 peers again → stays met (no rollback once met, by design).
        let (prior, new) = s.update_goal_progress("g1", 3, ">=", 5, 0, now + 2).unwrap();
        assert_eq!(prior, "met"); assert_eq!(new, "met");
    }

    #[test]
    fn f20_goal_misses_deadline() {
        let s = temp_store();
        let g = crate::Goal {
            id: "g2".into(), channel: "".into(), name: "x".into(),
            description: String::new(), target_metric: "findings_open".into(),
            target_value: 0, current_value: 10, comparator: "<=".into(),
            created_by: "ops".into(), deadline: 100, status: "pending".into(),
            created_at: 0, updated_at: 0,
        };
        s.insert_goal(&g).unwrap();
        // now > deadline + not met → status flips to 'missed'.
        let (prior, new) = s.update_goal_progress("g2", 10, "<=", 0, 100, 200).unwrap();
        assert_eq!(prior, "pending"); assert_eq!(new, "missed");
    }

    #[test]
    fn f29_task_lifecycle_full_path() {
        // F29 — claim → submit_plan → approve_plan → complete_task
        // chain. Verifies status-transition guards + atomic UPDATE
        // semantics fire correctly on each step.
        let s = temp_store();
        let now = crate::now_secs();
        let t = crate::Task {
            id: "t1".into(),
            channel: "c1".into(),
            from: "alice".into(),
            title: "fix the thing".into(),
            description: String::new(),
            owner: String::new(),
            status: "todo".into(),
            created_at: now,
            updated_at: now,
            note: String::new(),
            blocks: Vec::new(),
            depends_on: Vec::new(),
        };
        s.upsert_task(&t).unwrap();
        // Claim: first wins.
        assert_eq!(s.claim_task("t1", "bob", now).unwrap(), 1);
        assert_eq!(s.claim_task("t1", "carol", now).unwrap(), 0);
        // Submit plan: allowed (status=todo, plan_status=none).
        assert_eq!(s.submit_plan("t1", "step 1; step 2", now).unwrap(), 1);
        // Approve: flips status.
        assert_eq!(s.approve_plan("t1", "ops", now + 1).unwrap(), 1);
        // Approve a second time → 0 (no longer pending).
        assert_eq!(s.approve_plan("t1", "ops", now + 2).unwrap(), 0);
        // Complete: now allowed (plan approved).
        assert_eq!(s.complete_task("t1", "shipped", now + 10).unwrap(), 1);
        // Re-complete is a no-op.
        assert_eq!(s.complete_task("t1", "again", now + 11).unwrap(), 0);
    }

    #[test]
    fn f29_complete_refuses_while_plan_pending() {
        let s = temp_store();
        let now = crate::now_secs();
        let t = crate::Task {
            id: "t2".into(),
            channel: "c1".into(),
            from: "alice".into(),
            title: "x".into(),
            description: String::new(),
            owner: "bob".into(),
            status: "todo".into(),
            created_at: now,
            updated_at: now,
            note: String::new(),
            blocks: Vec::new(),
            depends_on: Vec::new(),
        };
        s.upsert_task(&t).unwrap();
        // Submit plan (still pending), then try to complete.
        s.submit_plan("t2", "draft", now).unwrap();
        let n = s.complete_task("t2", "ship anyway", now + 1).unwrap();
        assert_eq!(n, 0, "complete must refuse while plan pending");
        // After reject (plan back to non-pending), complete still
        // refuses because status moved... wait, reject doesn't move
        // status. So complete should now SUCCEED.
        s.reject_plan("t2", "ops", "needs more detail", now + 2).unwrap();
        let n = s.complete_task("t2", "shipped", now + 3).unwrap();
        assert_eq!(n, 1, "complete allowed after plan rejected (status guard)");
    }

    #[test]
    fn f29_tasks_ready_to_unblock_resolves_dependencies() {
        let s = temp_store();
        let now = crate::now_secs();
        let mk = |id: &str, status: &str, deps: Vec<String>| crate::Task {
            id: id.into(),
            channel: "c1".into(),
            from: "alice".into(),
            title: id.into(),
            description: String::new(),
            owner: String::new(),
            status: status.into(),
            created_at: now,
            updated_at: now,
            note: String::new(),
            blocks: Vec::new(),
            depends_on: deps,
        };
        s.upsert_task(&mk("a", "done", vec![])).unwrap();
        s.upsert_task(&mk("b", "done", vec![])).unwrap();
        s.upsert_task(&mk("c", "todo", vec!["a".into(), "b".into()])).unwrap();
        s.upsert_task(&mk("d", "todo", vec!["a".into(), "missing".into()])).unwrap();
        s.upsert_task(&mk("e", "in_progress", vec!["a".into()])).unwrap();
        let ready = s.tasks_ready_to_unblock().unwrap();
        let ids: Vec<String> = ready.iter().map(|(t, _)| t.id.clone()).collect();
        // c is ready (all deps done); d has unmet "missing"; e is
        // already in_progress so not a candidate.
        assert_eq!(ids, vec!["c".to_string()]);
    }

    #[test]
    fn peer_watcher_crud_round_trips() {
        let s = temp_store();
        let now = crate::now_secs();
        let w = crate::PeerWatcher {
            peer: "alice".into(),
            channel: "general".into(),
            pid: 4242,
            spawned_at: now,
            last_seen: now,
            ttl_secs: 3600,
            spawned_by: "ops".into(),
            status: "running".into(),
            session_id: "sess-abc".into(),
        };
        s.insert_peer_watcher(&w).unwrap();
        let got = s.get_peer_watcher("alice").unwrap().expect("present");
        assert_eq!(got.pid, 4242);
        assert_eq!(got.spawned_by, "ops");
        assert_eq!(got.session_id, "sess-abc");
        // touch_last_seen advances the column.
        let later = now + 100;
        let n = s.touch_peer_watcher_last_seen("alice", later).unwrap();
        assert_eq!(n, 1);
        assert_eq!(s.get_peer_watcher("alice").unwrap().unwrap().last_seen, later);
        // Status flip works for the crash path.
        s.set_peer_watcher_status("alice", "crashed").unwrap();
        assert_eq!(s.get_peer_watcher("alice").unwrap().unwrap().status, "crashed");
        // Re-insert replaces (last spawn wins).
        let mut w2 = w.clone();
        w2.pid = 9999;
        w2.status = "running".into();
        s.insert_peer_watcher(&w2).unwrap();
        assert_eq!(s.get_peer_watcher("alice").unwrap().unwrap().pid, 9999);
        assert_eq!(s.get_peer_watcher("alice").unwrap().unwrap().status, "running");
        // list returns 1.
        assert_eq!(s.list_peer_watchers().unwrap().len(), 1);
        // Delete.
        s.delete_peer_watcher("alice").unwrap();
        assert!(s.get_peer_watcher("alice").unwrap().is_none());
    }

    #[test]
    fn orphan_unmapped_rule_owners_rewrites_strangers() {
        // F17 Phase 2 — mirror of orphan_unmapped_memory_owners
        // for routing_rules per 0f4543 Phase 1 forward note 2.
        let s = temp_store();
        for (id, by) in [
            ("r1", "alice"),
            ("r2", "saas-legacy"),
            ("r3", "another-stranger"),
            ("r4", ""),
        ] {
            s.conn
                .lock()
                .execute(
                    "INSERT INTO routing_rules
                     (id, name, trigger_type, trigger_filter, action_type,
                      action_params, enabled, priority, created_by, created_at)
                     VALUES (?1, ?1, 'finding_created', '{}', 'auto_message',
                             '{}', 1, 50, ?2, 0)",
                    rusqlite::params![id, by],
                )
                .unwrap();
        }
        let mut known = std::collections::HashSet::new();
        known.insert("alice".to_string());
        let n = s.orphan_unmapped_rule_owners(&known).unwrap();
        // r2 + r3 renamed; r1 stays; r4 was already empty (untouched).
        assert_eq!(n, 2);
        let rows: Vec<(String, String)> = {
            let conn = s.conn.lock();
            let mut stmt = conn
                .prepare("SELECT id, created_by FROM routing_rules ORDER BY id")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(rows[0], ("r1".into(), "alice".into()));
        assert_eq!(rows[1], ("r2".into(), "".into()));
        assert_eq!(rows[2], ("r3".into(), "".into()));
        assert_eq!(rows[3], ("r4".into(), "".into()));
        // Empty known is a defensive no-op.
        let empty = std::collections::HashSet::new();
        let n2 = s.orphan_unmapped_rule_owners(&empty).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn get_routing_rule_round_trips() {
        let s = temp_store();
        s.conn
            .lock()
            .execute(
                "INSERT INTO routing_rules
                 (id, name, trigger_type, trigger_filter, action_type,
                  action_params, enabled, priority, created_by, created_at)
                 VALUES ('r1', 'alpha', 'finding_created', '{\"severity\":\"high\"}',
                         'auto_message', '{\"template\":\"hi\"}', 1, 80, 'alice', 0)",
                [],
            )
            .unwrap();
        let r = s.get_routing_rule("r1").unwrap().expect("present");
        assert_eq!(r.name, "alpha");
        assert_eq!(r.priority, 80);
        assert_eq!(r.created_by, "alice");
        assert!(r.enabled);
        // Missing id → None.
        assert!(s.get_routing_rule("does-not-exist").unwrap().is_none());
    }

    #[test]
    fn dispatch_round_trip_ack_complete_and_scan() {
        let s = temp_store();
        let now = crate::now_secs();
        let mk = |id: &str, message_id: &str, sent_at: u64| crate::Dispatch {
            id: id.into(),
            message_id: message_id.into(),
            from: "alice".into(),
            to: "bob".into(),
            channel: "c1".into(),
            sent_at,
            ack_at: 0,
            ack_eta_secs: 0,
            completed_at: 0,
            outcome: String::new(),
        };
        // Three dispatches: two old enough to be stale, one fresh.
        s.insert_dispatch(&mk("d1", "m1", now - 2000)).unwrap();
        s.insert_dispatch(&mk("d2", "m2", now - 1500)).unwrap();
        s.insert_dispatch(&mk("d3", "m3", now - 100)).unwrap();
        // The scanner-query view: open + older than `now-1000`.
        let stale = s.open_dispatches_older_than(now - 1000, 10).unwrap();
        assert_eq!(stale.len(), 2);
        // Ordered by sent_at ASC, so oldest first.
        assert_eq!(stale[0].message_id, "m1");
        assert_eq!(stale[1].message_id, "m2");
        // Ack the older one — it falls out of the open set.
        let n = s.ack_dispatch("m1", now, 300).unwrap();
        assert_eq!(n, 1);
        let stale = s.open_dispatches_older_than(now - 1000, 10).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].message_id, "m2");
        // Re-acking the same row is a no-op (1 row UPDATEd → 0
        // because the WHERE ack_at=0 no longer matches).
        let n = s.ack_dispatch("m1", now, 300).unwrap();
        assert_eq!(n, 0);
        // Completing without prior ack still flips the row closed.
        let n = s.complete_dispatch("m3", now, "shipped").unwrap();
        assert_eq!(n, 1);
        // The non-existent id returns 0 — server uses this for 404.
        let n = s.complete_dispatch("never-existed", now, "").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn complete_without_prior_ack_falls_out_of_scanner_query() {
        // Finding 85bdd17a — completed-via-direct-complete dispatches
        // (no prior ack) must NOT re-surface in the SLA scanner query,
        // otherwise the escalation scanner re-pings them.
        let s = temp_store();
        let now = crate::now_secs();
        let mk = |id: &str, message_id: &str, sent_at: u64| crate::Dispatch {
            id: id.into(),
            message_id: message_id.into(),
            from: "alice".into(),
            to: "bob".into(),
            channel: "c1".into(),
            sent_at,
            ack_at: 0,
            ack_eta_secs: 0,
            completed_at: 0,
            outcome: String::new(),
        };
        s.insert_dispatch(&mk("d1", "m1", now - 2000)).unwrap();
        // Pre-fix sanity: the open scan picks it up while it's still
        // open + past the cutoff.
        let stale = s.open_dispatches_older_than(now - 1000, 10).unwrap();
        assert_eq!(stale.len(), 1);
        // Close directly via complete_dispatch — no prior ack.
        let n = s.complete_dispatch("m1", now, "shipped-direct").unwrap();
        assert_eq!(n, 1);
        // The defensive completed_at-filter must drop it from the scan,
        // AND the row's ack_at must be backfilled (closes the
        // "ack_at = 0 implies engaged-never" gap).
        let stale = s.open_dispatches_older_than(now - 1000, 10).unwrap();
        assert!(
            stale.is_empty(),
            "completed-without-ack must not be a scanner candidate; got {stale:?}"
        );
        let ack_at: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT ack_at FROM dispatches WHERE message_id = 'm1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(ack_at > 0, "complete_dispatch must back-fill ack_at when ack_at was 0");
        // Open-count also drops to 0.
        let pending = s.count_open_dispatches().unwrap();
        assert_eq!(pending, 0);
        // Same drop on the per-peer view (peer_health consumer).
        let peer_view = s.open_dispatches_for_peer("bob", 10).unwrap();
        assert!(peer_view.is_empty());
    }

    #[test]
    fn peer_history_prune_drops_old_rows_only() {
        let s = temp_store();
        let now = crate::now_secs();
        let status = crate::PeerStatus {
            state: "working".into(),
            reason: String::new(),
            since: now,
            blocked_by: String::new(),
        };
        // 3 rows: two old (now-1000, now-500), one fresh (now).
        s.insert_peer_status("h1", "alice", &status, now - 1000).unwrap();
        s.insert_peer_status("h2", "alice", &status, now - 500).unwrap();
        s.insert_peer_status("h3", "alice", &status, now).unwrap();
        let deleted = s.prune_peer_history(now - 400).unwrap();
        assert_eq!(deleted, 2);
        let remaining: i64 = s
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM peer_status_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn audit_hash_is_deterministic_and_truncated() {
        let h1 = audit_hash(b"hello world");
        let h2 = audit_hash(b"hello world");
        let h3 = audit_hash(b"hello world!");
        assert_eq!(h1, h2, "same input must hash identically");
        assert_ne!(h1, h3, "one-byte diff must change the hash");
        // 32 hex chars = 16 bytes = 128-bit per pentest review
        // 1779038688. Bump from 64 → 128 done in tandem with the
        // wire-up to forensic auditing of mutation paths.
        assert_eq!(h1.len(), 32);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        use serde_json::json;
        // Two structurally identical maps with reversed insertion
        // order must serialize to the SAME bytes — the whole point
        // of the canonical form. serde_json::to_vec alone does not
        // give this guarantee (preserves-order feature is the
        // default since 1.0.x).
        let a = json!({"z": 1, "a": {"y": 2, "b": 3}});
        let b = json!({"a": {"b": 3, "y": 2}, "z": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        // And the hash of those equals the hash of either.
        assert_eq!(audit_hash_struct(&a), audit_hash_struct(&b));
        // Different content still hashes differently.
        let c = json!({"z": 1, "a": {"y": 99, "b": 3}});
        assert_ne!(audit_hash_struct(&a), audit_hash_struct(&c));
    }

    #[test]
    fn audit_round_trip_writes_and_filters_by_target() {
        let s = temp_store();
        let now = crate::now_secs();
        let entries = [
            AuditEntry {
                id: "a1".into(),
                at: now,
                actor: "alice".into(),
                op: "create".into(),
                target_type: "finding".into(),
                target_id: "f1".into(),
                before_hash: String::new(),
                after_hash: audit_hash(b"after"),
                result: "ok".into(),
            },
            AuditEntry {
                id: "a2".into(),
                at: now + 1,
                actor: "bob".into(),
                op: "triage".into(),
                target_type: "finding".into(),
                target_id: "f1".into(),
                before_hash: audit_hash(b"before"),
                after_hash: audit_hash(b"after2"),
                result: "ok".into(),
            },
            AuditEntry {
                id: "a3".into(),
                at: now + 2,
                actor: "carol".into(),
                op: "create".into(),
                target_type: "task".into(),
                target_id: "t1".into(),
                before_hash: String::new(),
                after_hash: audit_hash(b"t"),
                result: "ok".into(),
            },
        ];
        for e in &entries {
            s.audit(e).unwrap();
        }
        // Filter by target — only the two finding/f1 rows come back,
        // newest first.
        let rows = s.audit_for_target("finding", "f1", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "a2");
        assert_eq!(rows[1].id, "a1");
    }

    #[test]
    fn prune_keeps_newest() {
        let s = temp_store();
        for i in 0..10 {
            let m = Message {
                id: format!("m{i}"),
                channel: "c1".into(),
                from: "alice".into(),
                content: format!("msg {i}"),
                timestamp: 1000 + i as u64,
                to: Vec::new(),
                thread_id: String::new(),
                pinned: false,
            };
            s.insert_message(&m).unwrap();
        }
        s.prune_messages("c1", 3).unwrap();
        let loaded = s.load_messages(100).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].content, "msg 7");
        assert_eq!(loaded[2].content, "msg 9");
    }
}
