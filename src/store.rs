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
use std::sync::Arc;

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
        // Build the IN-clause dynamically — rusqlite expects param
        // count to match the SQL placeholders. For an empty known
        // set the IN-clause collapses to "WHERE updated_by != ''",
        // which is the correct effect: rewrite every non-empty
        // owner string.
        let conn = self.conn.lock();
        if known.is_empty() {
            let n = conn.execute(
                "UPDATE memory SET updated_by = '' WHERE updated_by != ''",
                [],
            )?;
            return Ok(n);
        }
        // Two passes — first orphan anything that was the literal
        // historical sentinel strings; then orphan anything whose
        // owner isn't in the known set. Both can run as a single
        // UPDATE with a NOT IN, but rusqlite's parameter binding
        // for slice expansion isn't a one-liner here, so we walk.
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
        let n = stmt.execute(rusqlite::params_from_iter(names.iter()))?;
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
    pub fn complete_dispatch(
        &self,
        message_id: &str,
        completed_at: u64,
        outcome: &str,
    ) -> SqliteResult<usize> {
        let n = self.conn.lock().execute(
            "UPDATE dispatches SET completed_at = ?1, outcome = ?2
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
             WHERE ack_at = 0 AND to_ LIKE ?1
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

    /// Cheap count of every open (unacked) dispatch in the table.
    /// Used by `/metrics` and the Prometheus exporter — the partial
    /// index `dispatches_pending` makes this an index-only scan.
    pub fn count_open_dispatches(&self) -> SqliteResult<usize> {
        let n: i64 = self.conn.lock().query_row(
            "SELECT COUNT(*) FROM dispatches WHERE ack_at = 0",
            [],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// All open (unacked) dispatches older than `cutoff` (unix-secs).
    /// Used by `DispatchEscalationScanner` to find work to ping on.
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
             WHERE ack_at = 0 AND sent_at < ?1
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
