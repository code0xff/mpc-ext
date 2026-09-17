//! Encryption at rest.
//!
//! Shares and session state are sealed here before reaching the database. The sealing key is
//! injected from an environment variable or a KMS and never lives in the repo or the database
//! (`docs/server.md`).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use rand::RngCore;

use crate::Error;

/// Sealed bytes. Never holds plaintext.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The ciphertext.
    pub ciphertext: Vec<u8>,
    /// A nonce used by this record only. Reusing one breaks AES-GCM.
    pub nonce: Vec<u8>,
}

/// The key used to seal data at rest.
#[derive(Clone)]
pub struct SealingKey {
    cipher: Aes256Gcm,
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey([redacted])")
    }
}

impl SealingKey {
    /// Builds one from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Reads it from `MPC_SERVER_SEALING_KEY`, 64 hex characters.
    pub fn from_env() -> Result<Self, Error> {
        let raw = std::env::var("MPC_SERVER_SEALING_KEY")
            .map_err(|_| Error::Config("MPC_SERVER_SEALING_KEY is not set".into()))?;
        let bytes = hex_decode(&raw).ok_or_else(|| {
            Error::Config("MPC_SERVER_SEALING_KEY must be 64 hex characters".into())
        })?;
        Ok(Self::new(&bytes))
    }

    /// Seals a plaintext.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed, Error> {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce_bytes.into(), plaintext)
            .map_err(|_| Error::Crypto("sealing failed"))?;
        Ok(Sealed {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Unseals. Fails if authentication does not check out.
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, Error> {
        let nonce: [u8; 12] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("the nonce length is wrong"))?;
        self.cipher
            .decrypt(&nonce.into(), sealed.ciphertext.as_slice())
            .map_err(|_| Error::Crypto("unsealing failed"))
    }
}

fn hex_decode(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(value.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// Panicking is how a test asserts. Production code keeps these lints.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens() {
        let key = SealingKey::new(&[7u8; 32]);
        let sealed = key.seal(b"share bytes").expect("it should seal");

        assert_ne!(sealed.ciphertext, b"share bytes");
        assert_eq!(key.open(&sealed).expect("it should unseal"), b"share bytes");
    }

    #[test]
    fn uses_a_fresh_nonce_each_time() {
        let key = SealingKey::new(&[7u8; 32]);

        let first = key.seal(b"same plaintext").expect("it should seal");
        let second = key.seal(b"same plaintext").expect("it should seal");

        assert_ne!(first.nonce, second.nonce, "a nonce must never be reused");
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn rejects_a_tampered_ciphertext() {
        let key = SealingKey::new(&[7u8; 32]);
        let mut sealed = key.seal(b"share bytes").expect("it should seal");

        sealed.ciphertext[0] ^= 0xFF;

        assert!(
            key.open(&sealed).is_err(),
            "a tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn rejects_the_wrong_key() {
        let sealed = SealingKey::new(&[7u8; 32])
            .seal(b"share bytes")
            .expect("it should seal");

        assert!(SealingKey::new(&[8u8; 32]).open(&sealed).is_err());
    }
}
