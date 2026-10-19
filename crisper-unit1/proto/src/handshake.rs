use rand::RngCore;
use x25519_dalek::PublicKey;

use crate::crypto::KEY_LEN;
use crate::ProtoError;

pub const MAGIC: [u8; 4] = *b"CRSP";
pub const VERSION: u16 = 1;
pub const HELLO_LEN: usize = 4 + 2 + KEY_LEN + 16;
pub const ACK_LEN: usize = KEY_LEN + 16 + 12 + 32;

#[derive(Clone, Debug)]
pub struct Hello {
    pub version: u16,
    pub public: PublicKey,
    pub nonce: [u8; 16],
}

impl Hello {
    pub fn new(public: PublicKey) -> Self {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self { version: VERSION, public, nonce }
    }

    pub fn encode(&self) -> [u8; HELLO_LEN] {
        let mut out = [0u8; HELLO_LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        out[6..38].copy_from_slice(self.public.as_bytes());
        out[38..54].copy_from_slice(&self.nonce);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < HELLO_LEN {
            return Err(ProtoError::Short { need: HELLO_LEN, have: buf.len() });
        }
        if buf[..4] != MAGIC {
            return Err(ProtoError::Handshake("bad magic"));
        }
        let version = u16::from_be_bytes([buf[4], buf[5]]);
        if version != VERSION {
            return Err(ProtoError::Handshake("version mismatch"));
        }
        let mut pk = [0u8; KEY_LEN];
        pk.copy_from_slice(&buf[6..38]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&buf[38..54]);
        Ok(Self { version, public: PublicKey::from(pk), nonce })
    }
}

#[derive(Clone, Debug)]
pub struct HelloAck {
    pub public: [u8; KEY_LEN],
    pub nonce: [u8; 16],
    pub gcm_nonce: [u8; 12],
    pub mac: [u8; 32],
}

impl HelloAck {
    pub fn encode(&self) -> [u8; ACK_LEN] {
        let mut out = [0u8; ACK_LEN];
        out[..32].copy_from_slice(&self.public);
        out[32..48].copy_from_slice(&self.nonce);
        out[48..60].copy_from_slice(&self.gcm_nonce);
        out[60..92].copy_from_slice(&self.mac);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < ACK_LEN {
            return Err(ProtoError::Short { need: ACK_LEN, have: buf.len() });
        }
        let mut public = [0u8; KEY_LEN];
        public.copy_from_slice(&buf[..32]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&buf[32..48]);
        let mut gcm_nonce = [0u8; 12];
        gcm_nonce.copy_from_slice(&buf[48..60]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[60..92]);
        Ok(Self { public, nonce, gcm_nonce, mac })
    }
}

pub fn transcript(hello: &[u8; HELLO_LEN], ack: &HelloAck) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_LEN + ACK_LEN);
    out.extend_from_slice(hello);
    out.extend_from_slice(&ack.public);
    out.extend_from_slice(&ack.nonce);
    out.extend_from_slice(&ack.gcm_nonce);
    out
}

pub fn salt(client_nonce: &[u8; 16], server_nonce: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(client_nonce);
    out[16..].copy_from_slice(server_nonce);
    out
}

pub fn info(gcm_nonce: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(b"crisper-v1");
    out.extend_from_slice(gcm_nonce);
    out
}

pub fn rekey_salt(client_pub: &[u8; 32], server_pub: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(client_pub);
    out[32..].copy_from_slice(server_pub);
    out
}
