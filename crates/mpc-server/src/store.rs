//! SQLite storage.
//!
//! Shares and session state are **encrypted by the application** before they are stored. A
//! leaked database file is useless without the sealing key — which is exactly why the two must
//! not be backed up to the same place (`docs/server.md`).

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::FromRow;
use sqlx::SqlitePool;

use crate::crypto::Sealed;
use crate::Error;

/// The server-side state for one browser-origin WebAuthn ceremony.
#[derive(Clone, Debug)]
pub struct BrowserCeremony {
    pub session_id: String,
    pub wallet_id: String,
    pub kind: String,
    pub purpose: String,
    pub operation_id: Option<String>,
    pub digest: Option<String>,
    pub challenge_id: Option<String>,
    pub options: Option<String>,
    pub expires_at: String,
    pub claimed_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancelled_at: Option<String>,
}

#[derive(Debug, FromRow)]
struct BrowserCeremonyRow {
    session_id: String,
    wallet_id: String,
    kind: String,
    purpose: String,
    operation_id: Option<String>,
    digest: Option<String>,
    challenge_id: Option<String>,
    options: Option<String>,
    expires_at: String,
    claimed_at: Option<String>,
    completed_at: Option<String>,
    cancelled_at: Option<String>,
}

impl From<BrowserCeremonyRow> for BrowserCeremony {
    fn from(row: BrowserCeremonyRow) -> Self {
        Self {
            session_id: row.session_id,
            wallet_id: row.wallet_id,
            kind: row.kind,
            purpose: row.purpose,
            operation_id: row.operation_id,
            digest: row.digest,
            challenge_id: row.challenge_id,
            options: row.options,
            expires_at: row.expires_at,
            claimed_at: row.claimed_at,
            completed_at: row.completed_at,
            cancelled_at: row.cancelled_at,
        }
    }
}

/// A handle to the store.
#[derive(Clone, Debug)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Opens the database and applies migrations.
    pub async fn open(url: &str) -> Result<Self, Error> {
        let options: SqliteConnectOptions =
            url.parse::<SqliteConnectOptions>()?.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Stores a one-time WebAuthn challenge.
    pub async fn put_passkey_challenge(
        &self,
        challenge_id: &str,
        wallet_id: &str,
        purpose: &str,
        challenge: &[u8],
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        self.put_passkey_challenge_with_binding(
            challenge_id,
            wallet_id,
            purpose,
            challenge,
            &[],
            ttl_seconds,
        )
        .await
    }

    /// Stores a one-time WebAuthn challenge and its immutable operation binding.
    pub async fn put_passkey_challenge_with_binding(
        &self,
        challenge_id: &str,
        wallet_id: &str,
        purpose: &str,
        challenge: &[u8],
        binding: &[u8],
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::seconds(ttl_seconds);
        sqlx::query(
            "INSERT INTO passkey_challenges
             (challenge_id, wallet_id, purpose, challenge, binding, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(challenge_id)
        .bind(wallet_id)
        .bind(purpose)
        .bind(challenge)
        .bind(binding)
        .bind(format_time(expires))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Creates a short-lived browser handoff. The raw handoff token is never persisted.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_browser_ceremony(
        &self,
        session_id: &str,
        handoff_hash: &[u8],
        wallet_id: &str,
        kind: &str,
        purpose: &str,
        operation_id: Option<&str>,
        digest: Option<&str>,
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let expires =
            format_time(time::OffsetDateTime::now_utc() + time::Duration::seconds(ttl_seconds));
        sqlx::query(
            "INSERT INTO browser_ceremonies
             (session_id, handoff_hash, wallet_id, kind, purpose, operation_id, digest, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(handoff_hash)
        .bind(wallet_id)
        .bind(kind)
        .bind(purpose)
        .bind(operation_id)
        .bind(digest)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Claims a browser handoff exactly once and returns its scoped session.
    pub async fn claim_browser_ceremony(
        &self,
        handoff_hash: &[u8],
    ) -> Result<Option<BrowserCeremony>, Error> {
        let now = timestamp();
        let row = sqlx::query_as::<_, BrowserCeremonyRow>(
            "UPDATE browser_ceremonies SET claimed_at = ?
             WHERE handoff_hash = ? AND claimed_at IS NULL AND cancelled_at IS NULL
               AND completed_at IS NULL AND expires_at >= ?
             RETURNING session_id, wallet_id, kind, purpose, operation_id, digest,
                       challenge_id, options, expires_at, claimed_at, completed_at, cancelled_at",
        )
        .bind(&now)
        .bind(handoff_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(BrowserCeremony::from))
    }

    /// Loads a claimed browser ceremony, rejecting expired or cancelled sessions.
    pub async fn browser_ceremony(
        &self,
        session_id: &str,
    ) -> Result<Option<BrowserCeremony>, Error> {
        let row = sqlx::query_as::<_, BrowserCeremonyRow>(
            "SELECT session_id, wallet_id, kind, purpose, operation_id, digest,
                    challenge_id, options, expires_at, claimed_at, completed_at, cancelled_at
             FROM browser_ceremonies
             WHERE session_id = ? AND expires_at >= ? AND cancelled_at IS NULL",
        )
        .bind(session_id)
        .bind(timestamp())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(BrowserCeremony::from))
    }

    /// Stores the one-time WebAuthn challenge and options for a browser session.
    pub async fn set_browser_challenge(
        &self,
        session_id: &str,
        challenge_id: &str,
        options: &str,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE browser_ceremonies SET challenge_id = ?, options = ?
             WHERE session_id = ? AND claimed_at IS NOT NULL AND challenge_id IS NULL
               AND completed_at IS NULL AND cancelled_at IS NULL AND expires_at >= ?",
        )
        .bind(challenge_id)
        .bind(options)
        .bind(session_id)
        .bind(timestamp())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Marks a browser ceremony complete after the WebAuthn verification has succeeded.
    pub async fn complete_browser_ceremony(&self, session_id: &str) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE browser_ceremonies SET completed_at = ?
             WHERE session_id = ? AND claimed_at IS NOT NULL AND completed_at IS NULL
               AND cancelled_at IS NULL AND expires_at >= ?",
        )
        .bind(timestamp())
        .bind(session_id)
        .bind(timestamp())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Removes expired browser sessions.
    pub async fn sweep_browser_ceremonies(&self) -> Result<u64, Error> {
        let result = sqlx::query("DELETE FROM browser_ceremonies WHERE expires_at < ?")
            .bind(timestamp())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Consumes a valid, unexpired challenge exactly once.
    pub async fn take_passkey_challenge(
        &self,
        challenge_id: &str,
        wallet_id: &str,
        purpose: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .take_passkey_challenge_with_binding(challenge_id, wallet_id, purpose)
            .await?
            .map(|(challenge, _binding)| challenge))
    }

    /// Consumes a valid challenge and returns its state plus immutable operation binding.
    pub async fn take_passkey_challenge_with_binding(
        &self,
        challenge_id: &str,
        wallet_id: &str,
        purpose: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let now = format_time(time::OffsetDateTime::now_utc());
        let mut tx = self.pool.begin().await?;
        // Claiming and returning the row is one SQLite write operation. This prevents two
        // concurrent finish requests from both observing an unused challenge.
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "UPDATE passkey_challenges SET used_at = ?
             WHERE challenge_id = ? AND wallet_id = ? AND purpose = ?
               AND used_at IS NULL AND expires_at >= ?
             RETURNING challenge, binding",
        )
        .bind(&now)
        .bind(challenge_id)
        .bind(wallet_id)
        .bind(purpose)
        .bind(&now)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Stores the serialized WebAuthn credential for a wallet.
    pub async fn put_passkey_credential(
        &self,
        wallet_id: &str,
        credential: &[u8],
        sign_count: u32,
    ) -> Result<(), Error> {
        let now = timestamp();
        sqlx::query(
            "INSERT INTO passkey_credentials (wallet_id, credential, sign_count, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(wallet_id)
        .bind(credential)
        .bind(i64::from(sign_count))
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Updates credential state after a successful assertion.
    pub async fn update_passkey_credential(
        &self,
        wallet_id: &str,
        credential: &[u8],
        sign_count: u32,
    ) -> Result<(), Error> {
        let now = timestamp();
        sqlx::query(
            "UPDATE passkey_credentials
             SET credential = ?, sign_count = ?, updated_at = ?
             WHERE wallet_id = ?",
        )
        .bind(credential)
        .bind(i64::from(sign_count))
        .bind(&now)
        .bind(wallet_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Loads a wallet's serialized passkey credential and sign counter.
    pub async fn passkey_credential(
        &self,
        wallet_id: &str,
    ) -> Result<Option<(Vec<u8>, u32)>, Error> {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT credential, sign_count FROM passkey_credentials WHERE wallet_id = ?",
        )
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(credential, count)| {
            u32::try_from(count)
                .map(|count| (credential, count))
                .map_err(|_| {
                    Error::Storage(sqlx::Error::Protocol("invalid passkey counter".into()))
                })
        })
        .transpose()
    }

    /// Stores a short-lived, one-use authorization produced by a verified passkey assertion.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_passkey_authorization(
        &self,
        wallet_id: &str,
        purpose: &str,
        operation_id: &str,
        digest: &str,
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::seconds(ttl_seconds);
        sqlx::query(
            "INSERT INTO passkey_authorizations
             (authorization_id, wallet_id, purpose, operation_id, digest, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(wallet_id)
        .bind(purpose)
        .bind(operation_id)
        .bind(digest)
        .bind(format_time(now))
        .bind(format_time(expires))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consumes the authorization for one exact signing operation.
    pub async fn consume_passkey_authorization(
        &self,
        wallet_id: &str,
        purpose: &str,
        operation_id: &str,
        digest: &str,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE passkey_authorizations SET consumed_at = ?
             WHERE wallet_id = ? AND purpose = ? AND operation_id = ? AND digest = ?
               AND consumed_at IS NULL AND expires_at >= ?",
        )
        .bind(timestamp())
        .bind(wallet_id)
        .bind(purpose)
        .bind(operation_id)
        .bind(digest)
        .bind(timestamp())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Registers or replaces the public device key for a wallet.
    pub async fn register_device_key(
        &self,
        wallet_id: &str,
        public_key: &[u8],
    ) -> Result<(), Error> {
        let now = timestamp();
        sqlx::query(
            "INSERT INTO device_keys (wallet_id, public_key, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(wallet_id) DO UPDATE SET public_key = excluded.public_key,
                                                   updated_at = excluded.updated_at",
        )
        .bind(wallet_id)
        .bind(public_key)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Reads the registered device public key.
    pub async fn device_key(&self, wallet_id: &str) -> Result<Option<Vec<u8>>, Error> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT public_key FROM device_keys WHERE wallet_id = ?")
                .bind(wallet_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(key,)| key))
    }

    /// Atomically reserves a nonce until its expiry. Returns false on replay.
    pub async fn reserve_device_nonce(
        &self,
        wallet_id: &str,
        nonce: &str,
        ttl_seconds: i64,
    ) -> Result<bool, Error> {
        let now = timestamp();
        let expires =
            format_time(time::OffsetDateTime::now_utc() + time::Duration::seconds(ttl_seconds));
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM used_device_nonces WHERE expires_at < ?")
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO used_device_nonces (wallet_id, nonce, expires_at)
             VALUES (?, ?, ?)",
        )
        .bind(wallet_id)
        .bind(nonce)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Commits the DKG result in a single transaction.
    ///
    /// Deleting the session and storing the share have to happen atomically, or a half-finished
    /// state survives.
    pub async fn finish_dkg(
        &self,
        session_id: &str,
        wallet_id: &str,
        share: &Sealed,
        public_key: &[u8],
    ) -> Result<(), Error> {
        let now = timestamp();
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM dkg_sessions WHERE session_id = ?")
            .bind(session_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO key_shares
               (wallet_id, ciphertext, nonce, public_key, format_version, created_at)
             VALUES (?, ?, ?, ?, 1, ?)",
        )
        .bind(wallet_id)
        .bind(&share.ciphertext)
        .bind(&share.nonce)
        .bind(public_key)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at) VALUES (?, 'dkg.completed', ?)",
        )
        .bind(wallet_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Stores the state of an in-flight DKG session.
    pub async fn put_session(
        &self,
        session_id: &str,
        wallet_id: &str,
        round: i64,
        state: &Sealed,
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::seconds(ttl_seconds);
        sqlx::query(
            "INSERT INTO dkg_sessions (session_id, wallet_id, round, state, nonce, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET round = excluded.round,
                                                   state = excluded.state,
                                                   nonce = excluded.nonce",
        )
        .bind(session_id)
        .bind(wallet_id)
        .bind(round)
        .bind(&state.ciphertext)
        .bind(&state.nonce)
        .bind(format_time(now))
        .bind(format_time(expires))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Reads session state that has not expired.
    pub async fn take_session(&self, session_id: &str) -> Result<Option<(i64, Sealed)>, Error> {
        let row: Option<(i64, Vec<u8>, Vec<u8>, String)> = sqlx::query_as(
            "SELECT round, state, nonce, expires_at FROM dkg_sessions WHERE session_id = ?",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((round, ciphertext, nonce, expires_at)) = row else {
            return Ok(None);
        };

        // Treat an expired session as absent, and clean it up.
        if expires_at.as_str() < format_time(time::OffsetDateTime::now_utc()).as_str() {
            sqlx::query("DELETE FROM dkg_sessions WHERE session_id = ?")
                .bind(session_id)
                .execute(&self.pool)
                .await?;
            return Ok(None);
        }

        Ok(Some((round, Sealed { ciphertext, nonce })))
    }

    /// Loads the sealed share for a wallet.
    pub async fn key_share(&self, wallet_id: &str) -> Result<Option<Sealed>, Error> {
        let row: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT ciphertext, nonce FROM key_shares WHERE wallet_id = ?")
                .bind(wallet_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(ciphertext, nonce)| Sealed { ciphertext, nonce }))
    }

    /// Stores the state of an in-flight signing session.
    pub async fn put_sign_session(
        &self,
        sign_id: &str,
        wallet_id: &str,
        round: i64,
        state: &Sealed,
        digest: &[u8],
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::seconds(ttl_seconds);
        sqlx::query(
            "INSERT INTO sign_sessions
               (sign_id, wallet_id, round, state, nonce, digest, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(sign_id) DO UPDATE SET round = excluded.round,
                                                state = excluded.state,
                                                nonce = excluded.nonce",
        )
        .bind(sign_id)
        .bind(wallet_id)
        .bind(round)
        .bind(&state.ciphertext)
        .bind(&state.nonce)
        .bind(digest)
        .bind(format_time(now))
        .bind(format_time(expires))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Reads signing session state that has not expired.
    pub async fn take_sign_session(&self, sign_id: &str) -> Result<Option<Sealed>, Error> {
        let row: Option<(Vec<u8>, Vec<u8>, String)> =
            sqlx::query_as("SELECT state, nonce, expires_at FROM sign_sessions WHERE sign_id = ?")
                .bind(sign_id)
                .fetch_optional(&self.pool)
                .await?;

        let Some((ciphertext, nonce, expires_at)) = row else {
            return Ok(None);
        };

        if expires_at.as_str() < format_time(time::OffsetDateTime::now_utc()).as_str() {
            sqlx::query("DELETE FROM sign_sessions WHERE sign_id = ?")
                .bind(sign_id)
                .execute(&self.pool)
                .await?;
            return Ok(None);
        }

        Ok(Some(Sealed { ciphertext, nonce }))
    }

    /// Closes a signing session and records the outcome.
    ///
    /// The audit log keeps the digest only, never the signature or any secret.
    pub async fn finish_sign(&self, sign_id: &str, wallet_id: &str) -> Result<(), Error> {
        let now = timestamp();
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM sign_sessions WHERE sign_id = ?")
            .bind(sign_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, detail, created_at)
             VALUES (?, 'sign.completed', ?, ?)",
        )
        .bind(wallet_id)
        .bind(sign_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Reads a wallet's public key. Never returns the share itself.
    pub async fn public_key(&self, wallet_id: &str) -> Result<Option<Vec<u8>>, Error> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT public_key FROM key_shares WHERE wallet_id = ?")
                .bind(wallet_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(pk,)| pk))
    }

    /// Sweeps expired sessions of both kinds.
    pub async fn sweep_expired(&self) -> Result<u64, Error> {
        let now = format_time(time::OffsetDateTime::now_utc());
        let dkg = sqlx::query("DELETE FROM dkg_sessions WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        let signing = sqlx::query("DELETE FROM sign_sessions WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(dkg.rows_affected() + signing.rows_affected())
    }
}

fn format_time(value: time::OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

fn timestamp() -> String {
    format_time(time::OffsetDateTime::now_utc())
}
