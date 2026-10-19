use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rusqlite::{params, Connection};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY,
    hostname     TEXT NOT NULL DEFAULT '',
    username     TEXT NOT NULL DEFAULT '',
    peer         TEXT NOT NULL,
    keyfp        TEXT NOT NULL DEFAULT '',
    connected_at INTEGER NOT NULL,
    closed_at    INTEGER
);
CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER NOT NULL,
    session_id  INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    finished_at INTEGER,
    status      INTEGER,
    PRIMARY KEY (session_id, id)
);
CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id, id);
"#;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    pub fn open_session(&self, id: u64, peer: &str, now: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, peer, connected_at) VALUES (?1, ?2, ?3)",
            params![id as i64, peer, now as i64],
        )?;
        Ok(())
    }

    pub fn identify_session(&self, id: u64, hostname: &str, username: &str, keyfp: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET hostname=?2, username=?3, keyfp=?4 WHERE id=?1",
            params![id as i64, hostname, username, keyfp],
        )?;
        Ok(())
    }

    pub fn close_session(&self, id: u64, now: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE sessions SET closed_at=?2 WHERE id=?1", params![id as i64, now as i64])?;
        Ok(())
    }

    pub fn open_task(&self, session: u64, task: u64, kind: &str, now: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO tasks (id, session_id, kind, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![task as i64, session as i64, kind, now as i64],
        )?;
        Ok(())
    }

    pub fn finish_task(&self, session: u64, task: u64, status: i32, now: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE tasks SET finished_at=?3, status=?4 WHERE session_id=?1 AND id=?2",
            params![session as i64, task as i64, now as i64, status],
        )?;
        Ok(())
    }

    pub fn audit(&self, actor: &str, action: &str, detail: &str, now: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit (ts, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now as i64, actor, action, detail],
        )?;
        Ok(())
    }
}
