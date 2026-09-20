//! The server that stores share C and takes part in DKG and signing.
//!
//! It is not a vault, it is a **second factor**: if the extension is compromised and the server
//! refuses, no signature is produced (`docs/adr/0005-share-placement.md`).

pub mod api;
pub mod auth;
pub mod auth_page;
pub mod crypto;
pub mod passkey;
pub mod recovery;
pub mod reshare;
pub mod store;

/// A server error.
///
/// Never carries secrets: these messages may reach the client verbatim.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration is missing or invalid.
    #[error("configuration error: {0}")]
    Config(String),

    /// Sealing or unsealing failed.
    #[error("crypto error: {0}")]
    Crypto(&'static str),

    /// A storage failure.
    #[error("storage error")]
    Storage(#[from] sqlx::Error),

    /// A migration failure.
    #[error("migration error")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// The requested session is unknown or has expired.
    #[error("unknown or expired session")]
    UnknownSession,

    /// The request device proof is missing or invalid.
    #[error("authentication failed")]
    Authentication,

    /// Too many requests for this wallet in a short time.
    #[error("too many requests")]
    RateLimited,

    /// The protocol run failed.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<mpc_core::Error> for Error {
    fn from(value: mpc_core::Error) -> Self {
        Error::Protocol(value.to_string())
    }
}
