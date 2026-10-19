use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::ProtoError;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
const SPLIT_LEN: usize = KEY_LEN * 3;

#[derive(Clone)]
pub struct SessionKeys {
    pub c2s: [u8; KEY_LEN],
    pub s2c: [u8; KEY_LEN],
    pub mac: [u8; KEY_LEN],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
        self.mac.zeroize();
    }
}

pub struct Ephemeral {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl Ephemeral {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; KEY_LEN] {
        self.secret.diffie_hellman(peer).to_bytes()
    }

    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

pub fn derive_keys(shared: &[u8; KEY_LEN], salt: &[u8], info: &[u8]) -> Result<SessionKeys, ProtoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = [0u8; SPLIT_LEN];
    hk.expand(info, &mut okm).map_err(|_| ProtoError::Crypto)?;
    let mut keys = SessionKeys { c2s: [0; KEY_LEN], s2c: [0; KEY_LEN], mac: [0; KEY_LEN] };
    keys.c2s.copy_from_slice(&okm[..32]);
    keys.s2c.copy_from_slice(&okm[32..64]);
    keys.mac.copy_from_slice(&okm[64..96]);
    okm.zeroize();
    Ok(keys)
}

fn nonce_for(seq: u32) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&seq.to_be_bytes());
    n
}

pub fn seal(key: &[u8; KEY_LEN], seq: u32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_for(seq);
    cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| ProtoError::Crypto)
}

pub fn open(key: &[u8; KEY_LEN], seq: u32, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_for(seq);
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| ProtoError::Auth)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let expect = hmac_sha256(key, data);
    expect.ct_eq(tag).into()
}
