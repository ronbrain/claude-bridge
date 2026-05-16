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

use crate::{Artifact, Finding, Message};

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
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO messages (id, channel, from_, content, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![m.id, m.channel, m.from, m.content, m.timestamp as i64],
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
        // previous run with a higher cap.
        let mut stmt = conn.prepare(
            "SELECT id, channel, from_, content, timestamp FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY channel ORDER BY timestamp DESC
                ) AS rn FROM messages
            ) WHERE rn <= ?1 ORDER BY channel, timestamp",
        )?;
        let rows = stmt.query_map(params![per_channel_cap as i64], |r| {
            Ok(Message {
                id: r.get(0)?,
                channel: r.get(1)?,
                from: r.get(2)?,
                content: r.get(3)?,
                timestamp: r.get::<_, i64>(4)? as u64,
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
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO findings
             (id, channel, from_, severity, title, detail, endpoint,
              status, created_at, updated_at, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                    status, created_at, updated_at, note
             FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY channel ORDER BY created_at DESC
                ) AS rn FROM findings
             ) WHERE rn <= ?1 ORDER BY channel, created_at",
        )?;
        let rows = stmt.query_map(params![per_channel_cap as i64], |r| {
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
    // `from_` not `from` because `FROM` is a SQL keyword and quoting
    // it across drivers is annoying.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id        TEXT PRIMARY KEY,
            channel   TEXT NOT NULL,
            from_     TEXT NOT NULL,
            content   TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS messages_channel_ts
            ON messages (channel, timestamp);

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
