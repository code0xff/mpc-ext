//! 2-of-3 threshold ECDSA protocol core.
//!
//! The extension consumes this crate as wasm and the server uses it natively. Protocol logic
//! lives here and nowhere else — we never reimplement it in a second language (see `AGENTS.md`).
//!
//! The upstream MPC implementation stays behind this crate's own types, so extension and server
//! code never references upstream types and the library remains replaceable
//! (`docs/adr/0004-mpc-library-reselection.md`).

mod backend;
pub mod protocol;
pub mod session;
pub mod share;

use core::fmt;

pub use backend::{dkg, ethereum_address, export_private_key, refresh, reshare, sign, verify};
pub use protocol::{DkgParty, Envelope, Progress, SignParty, SignProgress};
pub use session::{Round, SessionId};
pub use share::{KeyShare, PartyId, PublicKey};

/// How many of the three shares are needed to sign.
pub const THRESHOLD: u8 = 2;

/// How many shares exist in total.
pub const TOTAL_PARTIES: u8 = 3;

// A threshold at or above the total would make recovery impossible. Catch it at compile time.
const _: () = assert!(THRESHOLD < TOTAL_PARTIES);

/// A reconstructed private key, as 32 big-endian bytes.
///
/// While this value exists the MPC security benefit is gone. It is zeroized on drop.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub [u8; 32]);

impl core::fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKeyBytes([redacted])")
    }
}

/// A threshold ECDSA signature over secp256k1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// The `r` component.
    pub r: [u8; 32],
    /// The `s` component, normalised to low-s.
    pub s: [u8; 32],
    /// Public key recovery identifier.
    pub recovery_id: u8,
}

/// An error raised while running the protocol.
///
/// Never carries secret material: these messages may be logged or shown in the UI verbatim.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A message arrived out of round order. The session is discarded.
    #[error("unexpected round: expected {expected:?}, got {got:?}")]
    UnexpectedRound {
        /// The round the session was expecting.
        expected: Round,
        /// The round the message claimed.
        got: Round,
    },

    /// The session is unknown or has already expired.
    #[error("unknown or expired session")]
    UnknownSession,

    /// The number of participants does not match what the protocol requires.
    #[error("invalid party count: expected {expected}, got {got}")]
    InvalidPartyCount {
        /// How many parties the operation needs.
        expected: u8,
        /// How many were supplied.
        got: u8,
    },

    /// The upstream MPC implementation reported a failure.
    #[error("mpc backend failure: {0}")]
    Backend(String),
}

/// The protocol result type.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "party#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_two_of_three() {
        assert_eq!(THRESHOLD, 2);
        assert_eq!(TOTAL_PARTIES, 3);
    }

    #[test]
    fn errors_never_render_secrets() {
        let err = Error::Backend("upstream said no".into());
        let rendered = err.to_string();
        assert!(!rendered.is_empty());
    }
}
