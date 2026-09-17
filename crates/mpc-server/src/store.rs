//! SQLite storage.
//!
//! Shares and session state are **encrypted by the application** before they are stored. A
//! leaked database file is useless without the sealing key — which is exactly why the two must
//! not be backed up to the same place (`docs/server.md`).

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use crate::crypto::Sealed;
use crate::Error;

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
