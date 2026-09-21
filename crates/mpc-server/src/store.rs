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
/// A recovery request as stored. `status` is one of `awaiting_assertion`, `cooling`, `completed`,
/// `cancelled` or `expired`.
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryRequest {
    pub request_id: String,
    pub wallet_id: String,
    pub status: String,
    pub new_device_key: Vec<u8>,
    pub created_unix: i64,
    /// When the request lapses, or the last moment a cooling request can be completed.
    pub expires_unix: i64,
    /// When the cooling-off period ends. `None` until the passkey assertion has been verified.
    pub ready_unix: Option<i64>,
}

/// The result of starting a request's cooling-off period.
#[derive(Debug, PartialEq, Eq)]
pub enum CoolingStart {
    /// The period began and ends at this unix time.
    Started { ready_unix: i64 },
    /// The request is not waiting for an assertion (unknown, lapsed, or already past that step).
    NotAwaiting,
    /// Another request for this wallet is already cooling.
    AnotherCooling,
}

/// The result of completing a recovery.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryCompletion {
    /// The device key was replaced.
    Done,
    /// The cooling-off period has not ended yet.
    NotReady { ready_unix: i64 },
    /// The request is unknown, cancelled, lapsed or already used.
    Gone,
}

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
        let store = Self { pool };
        // Credentials stored before the user handle column existed cannot be found by handle until
        // it is filled in. It is cheap and does nothing once every row has one.
        let filled = store.backfill_user_handles().await?;
        if filled > 0 {
            tracing::info!(filled, "indexed passkey user handles");
        }
        Ok(store)
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
            "INSERT INTO passkey_credentials
               (wallet_id, credential, sign_count, created_at, updated_at, user_handle)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(wallet_id)
        .bind(credential)
        .bind(i64::from(sign_count))
        .bind(&now)
        .bind(&now)
        .bind(user_handle_of(credential))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Finds the wallet a passkey belongs to from its user handle.
    ///
    /// A usernameless assertion carries the handle and nothing else that names the wallet.
    pub async fn wallet_for_user_handle(
        &self,
        user_handle: &[u8],
    ) -> Result<Option<String>, Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT wallet_id FROM passkey_credentials WHERE user_handle = ?")
                .bind(user_handle)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(wallet_id,)| wallet_id))
    }

    /// Fills in the user handle of credentials stored before the column existed.
    ///
    /// Returns how many rows it filled. A credential whose blob has no readable handle is left
    /// alone: it could never have completed a usernameless assertion anyway.
    pub async fn backfill_user_handles(&self) -> Result<u64, Error> {
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT wallet_id, credential FROM passkey_credentials WHERE user_handle IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut filled = 0;
        for (wallet_id, credential) in rows {
            let Some(handle) = user_handle_of(&credential) else {
                continue;
            };
            let updated = sqlx::query(
                "UPDATE passkey_credentials SET user_handle = ?
                 WHERE wallet_id = ? AND user_handle IS NULL",
            )
            .bind(handle)
            .bind(&wallet_id)
            .execute(&self.pool)
            .await?;
            filled += updated.rows_affected();
        }
        Ok(filled)
    }

    /// Opens a management session and returns nothing secret: the caller keeps the token, and only
    /// its hash is stored. Sessions are short, and a wallet may have several.
    pub async fn open_manage_session(
        &self,
        session_hash: &[u8],
        wallet_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = unix_now();
        // Expired sessions are useless, so clear them while here.
        sqlx::query("DELETE FROM manage_sessions WHERE expires_unix < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO manage_sessions (session_hash, wallet_id, expires_unix) VALUES (?, ?, ?)",
        )
        .bind(session_hash)
        .bind(wallet_id)
        .bind(now + ttl_seconds)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The wallet a live management session belongs to.
    pub async fn manage_session_wallet(
        &self,
        session_hash: &[u8],
    ) -> Result<Option<String>, Error> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT wallet_id FROM manage_sessions WHERE session_hash = ? AND expires_unix >= ?",
        )
        .bind(session_hash)
        .bind(unix_now())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(wallet_id,)| wallet_id))
    }

    /// How many challenges for the management page are live. The page asks for one without any
    /// proof, so the count is capped to keep the table from being filled.
    ///
    /// These are the challenges with no wallet: every other challenge is made for a wallet whose
    /// device key has already authenticated the request.
    pub async fn live_manage_challenges(&self) -> Result<i64, Error> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM passkey_challenges
             WHERE wallet_id = '' AND used_at IS NULL AND expires_at >= ?",
        )
        .bind(timestamp())
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
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

    /// Registers a wallet's first device key. Returns `false`, changing nothing, when the wallet
    /// already has one.
    ///
    /// This must never overwrite. Replacing a key is a recovery, which needs a passkey assertion
    /// and a cooling-off wait (`docs/adr/0008-recovery-start-and-device-key-replacement.md`).
    pub async fn register_device_key(
        &self,
        wallet_id: &str,
        public_key: &[u8],
    ) -> Result<bool, Error> {
        let now = timestamp();
        let result = sqlx::query(
            "INSERT INTO device_keys (wallet_id, public_key, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(wallet_id) DO NOTHING",
        )
        .bind(wallet_id)
        .bind(public_key)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Records a recovery request, unless the wallet has made too many lately.
    ///
    /// Returns `false` when it is over the limit. The request only asks for a passkey assertion;
    /// it changes nothing by itself.
    pub async fn create_recovery_request(
        &self,
        request_id: &str,
        wallet_id: &str,
        new_device_key: &[u8],
        ttl_seconds: i64,
        max_per_hour: i64,
    ) -> Result<bool, Error> {
        let now = unix_now();
        let mut tx = self.pool.begin().await?;
        let (recent,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM recovery_requests WHERE wallet_id = ? AND created_unix >= ?",
        )
        .bind(wallet_id)
        .bind(now - 3600)
        .fetch_one(&mut *tx)
        .await?;
        if recent >= max_per_hour {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO recovery_requests
               (request_id, wallet_id, status, created_at, new_device_key, created_unix, expires_unix)
             VALUES (?, ?, 'awaiting_assertion', ?, ?, ?, ?)",
        )
        .bind(request_id)
        .bind(wallet_id)
        .bind(timestamp())
        .bind(new_device_key)
        .bind(now)
        .bind(now + ttl_seconds)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at) VALUES (?, 'recovery.requested', ?)",
        )
        .bind(wallet_id)
        .bind(timestamp())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Reads a recovery request belonging to `wallet_id`.
    pub async fn recovery_request(
        &self,
        request_id: &str,
        wallet_id: &str,
    ) -> Result<Option<RecoveryRequest>, Error> {
        Ok(sqlx::query_as::<_, RecoveryRequest>(
            "SELECT request_id, wallet_id, status, new_device_key, created_unix, expires_unix,
                    ready_unix
             FROM recovery_requests
             WHERE request_id = ? AND wallet_id = ? AND new_device_key IS NOT NULL",
        )
        .bind(request_id)
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Moves a request whose passkey assertion has been verified into its cooling-off period.
    pub async fn start_recovery_cooling(
        &self,
        request_id: &str,
        wallet_id: &str,
        cooling_seconds: i64,
        complete_window_seconds: i64,
    ) -> Result<CoolingStart, Error> {
        let now = unix_now();
        let ready = now + cooling_seconds;
        let mut tx = self.pool.begin().await?;

        // A cooling request nobody completed in time must not block the next one.
        sqlx::query(
            "UPDATE recovery_requests SET status = 'expired'
             WHERE wallet_id = ? AND status = 'cooling' AND expires_unix < ?",
        )
        .bind(wallet_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        let updated = sqlx::query(
            "UPDATE recovery_requests
             SET status = 'cooling', approved_at = ?, ready_unix = ?, expires_unix = ?
             WHERE request_id = ? AND wallet_id = ? AND status = 'awaiting_assertion'
               AND expires_unix >= ?",
        )
        .bind(timestamp())
        .bind(ready)
        .bind(ready + complete_window_seconds)
        .bind(request_id)
        .bind(wallet_id)
        .bind(now)
        .execute(&mut *tx)
        .await;
        let updated = match updated {
            Ok(result) => result,
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                return Ok(CoolingStart::AnotherCooling);
            }
            Err(other) => return Err(other.into()),
        };
        if updated.rows_affected() != 1 {
            return Ok(CoolingStart::NotAwaiting);
        }
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at) VALUES (?, 'recovery.cooling', ?)",
        )
        .bind(wallet_id)
        .bind(timestamp())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(CoolingStart::Started { ready_unix: ready })
    }

    /// Replaces the wallet's device key with the request's, once the cooling-off period is over.
    ///
    /// Everything happens in one transaction: the key swap, the request's own end, and the end of
    /// every other request the wallet still had open.
    pub async fn complete_recovery(
        &self,
        request_id: &str,
        wallet_id: &str,
    ) -> Result<RecoveryCompletion, Error> {
        let now = unix_now();
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, Option<i64>, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT status, ready_unix, expires_unix, new_device_key FROM recovery_requests
             WHERE request_id = ? AND wallet_id = ? AND new_device_key IS NOT NULL",
        )
        .bind(request_id)
        .bind(wallet_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((status, ready, expires, new_key)) = row else {
            return Ok(RecoveryCompletion::Gone);
        };
        let Some(ready) = ready else {
            return Ok(RecoveryCompletion::Gone);
        };
        if status != "cooling" || expires < now {
            return Ok(RecoveryCompletion::Gone);
        }
        if ready > now {
            return Ok(RecoveryCompletion::NotReady { ready_unix: ready });
        }

        sqlx::query(
            "INSERT INTO device_keys (wallet_id, public_key, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(wallet_id) DO UPDATE SET public_key = excluded.public_key,
                                                   updated_at = excluded.updated_at",
        )
        .bind(wallet_id)
        .bind(&new_key)
        .bind(timestamp())
        .bind(timestamp())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE recovery_requests SET status = 'completed', completed_at = ?
             WHERE request_id = ?",
        )
        .bind(timestamp())
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE recovery_requests SET status = 'cancelled', cancelled_at = ?
             WHERE wallet_id = ? AND request_id != ?
               AND status IN ('awaiting_assertion', 'cooling')",
        )
        .bind(timestamp())
        .bind(wallet_id)
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at)
             VALUES (?, 'recovery.completed', ?)",
        )
        .bind(wallet_id)
        .bind(timestamp())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(RecoveryCompletion::Done)
    }

    /// Cancels a request that has not finished. Returns `false` when there was nothing to cancel.
    pub async fn cancel_recovery(&self, request_id: &str, wallet_id: &str) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE recovery_requests SET status = 'cancelled', cancelled_at = ?
             WHERE request_id = ? AND wallet_id = ?
               AND status IN ('awaiting_assertion', 'cooling')",
        )
        .bind(timestamp())
        .bind(request_id)
        .bind(wallet_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at) VALUES (?, 'recovery.cancelled', ?)",
        )
        .bind(wallet_id)
        .bind(timestamp())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Recoveries that have passed their passkey assertion and are still in play, oldest first.
    pub async fn live_recoveries(&self, wallet_id: &str) -> Result<Vec<RecoveryRequest>, Error> {
        Ok(sqlx::query_as::<_, RecoveryRequest>(
            "SELECT request_id, wallet_id, status, new_device_key, created_unix, expires_unix,
                    ready_unix
             FROM recovery_requests
             WHERE wallet_id = ? AND status = 'cooling' AND expires_unix >= ?
               AND new_device_key IS NOT NULL
             ORDER BY created_unix",
        )
        .bind(wallet_id)
        .bind(unix_now())
        .fetch_all(&self.pool)
        .await?)
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

    /// Stores the state of an in-flight reshare session.
    pub async fn put_reshare_session(
        &self,
        reshare_id: &str,
        wallet_id: &str,
        round: i64,
        state: &Sealed,
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::seconds(ttl_seconds);
        sqlx::query(
            "INSERT INTO reshare_sessions
               (reshare_id, wallet_id, round, state, nonce, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(reshare_id) DO UPDATE SET round = excluded.round,
                                                   state = excluded.state,
                                                   nonce = excluded.nonce",
        )
        .bind(reshare_id)
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

    /// Reads a reshare session that has not expired. A session belonging to another wallet reads
    /// as absent.
    pub async fn take_reshare_session(
        &self,
        reshare_id: &str,
        wallet_id: &str,
    ) -> Result<Option<Sealed>, Error> {
        let row: Option<(Vec<u8>, Vec<u8>, String)> = sqlx::query_as(
            "SELECT state, nonce, expires_at FROM reshare_sessions
             WHERE reshare_id = ? AND wallet_id = ?",
        )
        .bind(reshare_id)
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((ciphertext, nonce, expires_at)) = row else {
            return Ok(None);
        };
        if expires_at.as_str() < timestamp().as_str() {
            sqlx::query("DELETE FROM reshare_sessions WHERE reshare_id = ?")
                .bind(reshare_id)
                .execute(&self.pool)
                .await?;
            return Ok(None);
        }
        Ok(Some(Sealed { ciphertext, nonce }))
    }

    /// Stages the finished reshare's share and drops its session, in one transaction.
    ///
    /// The live share is untouched until [`Self::commit_reshare`]. A wallet keeps at most one
    /// staged share, so a newer reshare replaces an older one.
    pub async fn stage_reshare(
        &self,
        reshare_id: &str,
        wallet_id: &str,
        share: &Sealed,
        ttl_seconds: i64,
    ) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::seconds(ttl_seconds);
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM reshare_sessions WHERE reshare_id = ?")
            .bind(reshare_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO pending_reshares
               (wallet_id, reshare_id, ciphertext, nonce, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(wallet_id) DO UPDATE SET reshare_id = excluded.reshare_id,
                                                  ciphertext = excluded.ciphertext,
                                                  nonce = excluded.nonce,
                                                  created_at = excluded.created_at,
                                                  expires_at = excluded.expires_at",
        )
        .bind(wallet_id)
        .bind(reshare_id)
        .bind(&share.ciphertext)
        .bind(&share.nonce)
        .bind(format_time(now))
        .bind(format_time(expires))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at) VALUES (?, 'reshare.staged', ?)",
        )
        .bind(wallet_id)
        .bind(format_time(now))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Swaps the staged share in for the live one and deletes the old share.
    ///
    /// Returns `false` when nothing matching is staged, or when it has expired. The public key
    /// is untouched: the reshare already refused to change it.
    pub async fn commit_reshare(&self, reshare_id: &str, wallet_id: &str) -> Result<bool, Error> {
        let now = timestamp();
        let mut tx = self.pool.begin().await?;

        let staged: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT ciphertext, nonce FROM pending_reshares
             WHERE wallet_id = ? AND reshare_id = ? AND expires_at >= ?",
        )
        .bind(wallet_id)
        .bind(reshare_id)
        .bind(&now)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((ciphertext, nonce)) = staged else {
            return Ok(false);
        };

        let updated = sqlx::query(
            "UPDATE key_shares SET ciphertext = ?, nonce = ?, refreshed_at = ?
             WHERE wallet_id = ?",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&now)
        .bind(wallet_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Ok(false);
        }

        sqlx::query("DELETE FROM pending_reshares WHERE wallet_id = ?")
            .bind(wallet_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at)
             VALUES (?, 'reshare.committed', ?)",
        )
        .bind(wallet_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Drops a reshare's session and its staged share, leaving the live share as it was.
    pub async fn abort_reshare(&self, reshare_id: &str, wallet_id: &str) -> Result<(), Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM reshare_sessions WHERE reshare_id = ? AND wallet_id = ?")
            .bind(reshare_id)
            .bind(wallet_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pending_reshares WHERE reshare_id = ? AND wallet_id = ?")
            .bind(reshare_id)
            .bind(wallet_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (wallet_id, event, created_at) VALUES (?, 'reshare.aborted', ?)",
        )
        .bind(wallet_id)
        .bind(timestamp())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
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

    /// Sweeps expired sessions and staged reshares.
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
        let reshare = sqlx::query("DELETE FROM reshare_sessions WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        let staged = sqlx::query("DELETE FROM pending_reshares WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(dkg.rows_affected()
            + signing.rows_affected()
            + reshare.rows_affected()
            + staged.rows_affected())
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

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Reads the passkey's user handle out of a stored credential blob, if it has one.
fn user_handle_of(credential: &[u8]) -> Option<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct Blob {
        user_id: Vec<u8>,
    }
    serde_json::from_slice::<Blob>(credential)
        .ok()
        .map(|blob| blob.user_id)
        .filter(|handle| !handle.is_empty())
}
