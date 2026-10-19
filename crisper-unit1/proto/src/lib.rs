pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod msg;

pub use crypto::{derive_keys, hmac_sha256, hmac_verify, Ephemeral, SessionKeys};
pub use frame::{Frame, MsgType, ReplayWindow, HEADER_LEN, MAX_BODY, TAG_LEN};
pub use handshake::{Hello, HelloAck, ACK_LEN, HELLO_LEN, MAGIC, VERSION};

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("body too large")]
    BodyTooLarge,
    #[error("short buffer: need {need}, have {have}")]
    Short { need: usize, have: usize },
    #[error("unknown message type {0:#04x}")]
    UnknownType(u8),
    #[error("authentication failed")]
    Auth,
    #[error("sequence rejected: {0}")]
    Sequence(u32),
    #[error("handshake rejected: {0}")]
    Handshake(&'static str),
    #[error("codec: {0}")]
    Codec(String),
    #[error("crypto")]
    Crypto,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, handshake};

    #[test]
    fn frame_roundtrip() {
        let key = [7u8; 32];
        let body = b"the bench is warm".to_vec();
        let bytes = Frame::encode(&key, 42, MsgType::Task, 0, &body).unwrap();
        let (frame, used) = Frame::decode(&key, &bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(frame.seq, 42);
        assert_eq!(frame.body, body);
    }

    #[test]
    fn tamper_rejected() {
        let key = [3u8; 32];
        let mut bytes = Frame::encode(&key, 1, MsgType::Ping, 0, b"x").unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(Frame::decode(&key, &bytes), Err(ProtoError::Auth)));
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        for seq in 0..100u32 {
            w.accept(seq).unwrap();
        }
        assert!(w.accept(50).is_err());
        w.accept(1200).unwrap();
        assert!(w.accept(100).is_err());
        w.accept(1199).unwrap();
    }

    #[test]
    fn handshake_roundtrip() {
        let client = crypto::Ephemeral::generate();
        let server = crypto::Ephemeral::generate();
        let hello = Hello::new(client.public);
        let hb = hello.encode();
        let parsed = Hello::decode(&hb).unwrap();

        let mut ack = HelloAck {
            public: server.public.to_bytes(),
            nonce: [9u8; 16],
            gcm_nonce: [4u8; 12],
            mac: [0u8; 32],
        };
        let psk = b"0123456789abcdef";
        let tag = hmac_sha256(psk, &handshake::transcript(&hb, &ack));
        ack.mac.copy_from_slice(&tag);
        assert!(hmac_verify(psk, &handshake::transcript(&hb, &ack), &ack.mac));

        let s1 = client.diffie_hellman(&server.public);
        let s2 = server.diffie_hellman(&parsed.public);
        assert_eq!(s1, s2);

        let k1 = derive_keys(&s1, &handshake::salt(&hello.nonce, &ack.nonce), &handshake::info(&ack.gcm_nonce)).unwrap();
        let k2 = derive_keys(&s2, &handshake::salt(&parsed.nonce, &ack.nonce), &handshake::info(&ack.gcm_nonce)).unwrap();
        assert_eq!(k1.c2s, k2.c2s);
        assert_eq!(k1.s2c, k2.s2c);
    }
}
