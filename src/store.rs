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

use crate::{Artifact, ChannelTopic, Finding, MemoryEntry, Message, Task};

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

fn init(conn: &Connection) -> SqliteResult<()> {
    // Best-effort column add for existing DBs. Fails harmlessly on
    // "duplicate column name" when run against a DB that already has
    // the column; we ignore the error rather than gating on schema
    // version, since adding nullable/defaulted columns is the only
    // migration we've needed so far.
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN to_ TEXT NOT NULL DEFAULT '[]'", []);
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN thread_id TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE findings ADD COLUMN blocks_ TEXT NOT NULL DEFAULT '[]'", []);
    let _ = conn.execute("ALTER TABLE findings ADD COLUMN depends_on_ TEXT NOT NULL DEFAULT '[]'", []);

    // `from_` not `from` because `FROM` is a SQL keyword and quoting
    // it across drivers is annoying.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id        TEXT PRIMARY KEY,
            channel   TEXT NOT NULL,
            from_     TEXT NOT NULL,
            content   TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            to_       TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS messages_channel_ts
            ON messages (channel, timestamp);
        -- Idempotent column add for DBs created before to_ existed.
        -- SQLite ALTER ADD COLUMN is a no-op on existing column;
        -- the error from a second run is swallowed at the batch level.

        CREATE TABLE IF NOT EXISTS findings (
            id         TEXT PRIMARY KEY,
            channel    TEXT NOT NULL,
            from_      TEXT NOT NULL,
            severity   TEXT NOT NULL,
            title      TEXT NOT NULL,
            detail     TEXT NOT NULL,
            endpoint   TEXT NOT NULL DEFAULT '',
            status     TEXT NOT NULL DEFAULT 'open',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            note       TEXT NOT NULL DEFAULT ''
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

        -- Shared memory: channel-scoped KV store. Composite primary
        -- key (channel, key) so two channels can use the same key
        -- name independently. `expires_at = 0` means no expiry.
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
    )
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
    fn prune_keeps_newest() {
        let s = temp_store();
        for i in 0..10 {
            let m = Message {
                id: format!("m{i}"),
                channel: "c1".into(),
                from: "alice".into(),
                content: format!("msg {i}"),
                timestamp: 1000 + i as u64,
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
