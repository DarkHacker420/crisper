use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crisper_proto::{msg::Task, MsgType, SessionKeys};
use tokio::sync::mpsc;
use x25519_dalek::StaticSecret;

#[derive(Clone, Default)]
pub struct SessionInfo {
    pub hostname: String,
    pub username: String,
    pub keyfp: String,
    pub peer: String,
    pub connected_at: u64,
}

pub enum Outbound {
    Task(Task),
    Send(MsgType, Vec<u8>),
    Ping(u64),
    Kill,
    SetKeys(SessionKeys),
}

pub struct SessionHandle {
    pub id: u64,
    pub info: Mutex<SessionInfo>,
    pub tx: mpsc::Sender<Outbound>,
    pub next_tx: Arc<AtomicU32>,
    pub secret: StaticSecret,
}

impl SessionHandle {
    pub fn submit(&self, task: Task) -> bool {
        self.tx.try_send(Outbound::Task(task)).is_ok()
    }

    pub fn send(&self, typ: MsgType, body: Vec<u8>) -> bool {
        self.tx.try_send(Outbound::Send(typ, body)).is_ok()
    }

    pub fn ping(&self, ts: u64) -> bool {
        self.tx.try_send(Outbound::Ping(ts)).is_ok()
    }

    pub fn kill(&self) -> bool {
        self.tx.try_send(Outbound::Kill).is_ok()
    }

    pub fn next_seq(&self) -> u32 {
        self.next_tx.fetch_add(1, Ordering::SeqCst)
    }

    pub fn describe(&self) -> String {
        let info = self.info.lock().unwrap();
        format!("{} {}@{}/{} [{}]", self.id, info.username, info.hostname, info.keyfp, info.peer)
    }
}
