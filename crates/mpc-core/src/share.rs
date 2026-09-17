//! Key shares and the identifiers around them.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A protocol participant, with `0 <= id < TOTAL_PARTIES`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct PartyId(pub u8);

/// The joint public key, SEC1 compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 33]);

/// The secret share held by one participant.
///
/// - `Debug` redacts the contents, so an accidental log line leaks nothing.
/// - Zeroized on drop.
/// - Never written to disk in the clear; storage is always encrypted (`docs/security.md`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    #[zeroize(skip)]
    party: PartyId,
    secret: Vec<u8>,
}

impl KeyShare {
    /// Wraps the share bytes produced by the upstream backend.
    pub fn new(party: PartyId, secret: Vec<u8>) -> Self {
        Self { party, secret }
    }

    /// Which participant holds this share.
    pub fn party(&self) -> PartyId {
        self.party
    }

    /// Access to the secret bytes. Callers must discard them immediately after use.
    pub fn expose_secret(&self) -> &[u8] {
        &self.secret
    }
}

impl core::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyShare")
            .field("party", &self.party)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secret() {
        let share = KeyShare::new(PartyId(0), b"super-secret-material".to_vec());
        let rendered = format!("{share:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(
            !rendered.contains("super-secret"),
            "Debug output leaked the secret"
        );
    }
}
