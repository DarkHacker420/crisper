use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::ProtoError;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Checkin {
    pub hostname: String,
    pub username: String,
    pub domain: String,
    pub pid: u32,
    pub ppid: u32,
    pub path: String,
    pub integrity: String,
    pub arch: String,
    pub os_build: String,
    pub uptime: u64,
    pub sid: String,
    pub modules: Vec<String>,
    pub keyfp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: u64,
    pub kind: String,
    #[serde(with = "serde_bytes")]
    pub args: Vec<u8>,
    pub deadline: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub id: u64,
    pub status: i32,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub done: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ping {
    pub ts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pong {
    pub ts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rekey {
    pub public: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChunk {
    pub xfer: u32,
    pub offset: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileAck {
    pub xfer: u32,
    pub next: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEnd {
    pub xfer: u32,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: u16,
    pub message: String,
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|e| ProtoError::Codec(e.to_string()))?;
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    ciborium::de::from_reader(bytes).map_err(|e| ProtoError::Codec(e.to_string()))
}
