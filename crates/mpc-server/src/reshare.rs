//! Distributed reshare after a device loss (`docs/adr/0007-distributed-reshare.md`).
//!
//! The server plays one of the two surviving parties. It contributes its Lagrange-weighted
//! share, receives a fresh one, and never sends its old share anywhere. The fresh share is
//! staged beside the live one and only replaces it on an explicit commit, so a reshare that stops
//! halfway leaves the previous share valid.
//!
//! Every endpoint needs the device key. Starting one also consumes a `recovery` passkey grant
//! bound to this exact reshare, because it ends by replacing the server's share.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mpc_core::{DkgParty, Envelope, KeyShare, PartyId, Progress, PublicKey, ReshareRole};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::api::{
    hex, parse_hex32, ApiError, AppState, WireEnvelope, SERVER_PARTY, SESSION_TTL_SECONDS,
};
use crate::auth::authenticate;
use crate::Error;

/// How long a finished reshare waits for its commit. The user has to save a new recovery file in
/// between, so this is longer than a session.
const STAGED_TTL_SECONDS: i64 = 1800;

/// The party that holds the survivor share besides the server: the recovery share, B.
const RECOVERY_PARTY: PartyId = PartyId(1);

/// The passkey purpose that authorizes a reshare. It is the same policy as recovery signing.
const PURPOSE: &str = "recovery";

/// The digest a passkey grant is bound to for one reshare.
///
/// It ties the assertion to the wallet's public key and to this reshare id, so a grant obtained
/// for one wallet or one session cannot start another.
pub fn grant_digest(public_key: &[u8], reshare_id: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mpc-ext reshare v1");
    hasher.update(public_key);
    hasher.update(reshare_id);
    hex(&hasher.finalize())
}

/// A request to open a reshare session.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StartReshare {
    /// The wallet identifier.
    pub wallet_id: String,
    /// A unique id for this reshare, 64 hex characters. Never reuse one.
    pub reshare_id: String,
}

/// The response to opening a reshare session.
#[derive(Debug, Serialize, ToSchema)]
pub struct StartedReshare {
    /// The round 1 envelopes the server sends.
    pub envelopes: Vec<WireEnvelope>,
}

/// A request to advance a reshare round.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AdvanceReshare {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The reshare id, 64 hex characters.
    pub reshare_id: String,
    /// The envelopes being delivered to the server.
    pub envelopes: Vec<WireEnvelope>,
}

/// The response to advancing a reshare round.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AdvancedReshare {
    /// Still running. Deliver the envelopes and call again.
    InProgress {
        /// The envelopes the server sends.
        envelopes: Vec<WireEnvelope>,
    },
    /// The reshare finished and the new share is staged. It takes effect on commit.
    Staged {
        /// The SEC1 compressed public key, hex-encoded. It equals the wallet's existing key.
        public_key: String,
    },
}

/// A request to commit or abort a reshare.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FinishReshare {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The reshare id, 64 hex characters.
    pub reshare_id: String,
}

fn to_public_key(bytes: &[u8]) -> Result<PublicKey, Error> {
    let key: [u8; 33] = bytes
        .try_into()
        .map_err(|_| Error::Protocol("the stored public key is malformed".into()))?;
    Ok(PublicKey(key))
}

/// Opens a reshare session and returns the server's round 1 envelopes.
#[utoipa::path(
    post,
    path = "/v1/reshare/session",
    request_body = StartReshare,
    responses(
        (status = 200, description = "session opened", body = StartedReshare),
        (status = 401, description = "missing device proof or passkey grant"),
        (status = 404, description = "no key for this wallet"),
    ),
)]
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StartReshare>,
) -> Result<Json<StartedReshare>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/reshare/session",
        &request.wallet_id,
        &request,
    )
    .await?;
    let reshare_id = parse_hex32(&request.reshare_id, "reshare_id")?;

    let public_key = state
        .store
        .public_key(&request.wallet_id)
        .await?
        .ok_or(Error::UnknownSession)?;
    let digest = grant_digest(&public_key, &reshare_id);
    if !state
        .store
        .consume_passkey_authorization(&request.wallet_id, PURPOSE, &request.reshare_id, &digest)
        .await?
    {
        return Err(Error::Authentication.into());
    }

    let sealed = state
        .store
        .key_share(&request.wallet_id)
        .await?
        .ok_or(Error::UnknownSession)?;
    let share = KeyShare::new(SERVER_PARTY, state.sealing.open(&sealed)?);

    let role = ReshareRole::Survivor {
        share: &share,
        survivors: [RECOVERY_PARTY, SERVER_PARTY],
    };
    let (party, envelopes) = DkgParty::start_reshare(
        SERVER_PARTY,
        &reshare_id,
        &role,
        &to_public_key(&public_key)?,
    )?;

    let sealed = state.sealing.seal(&party.to_bytes()?)?;
    state
        .store
        .put_reshare_session(
            &request.reshare_id,
            &request.wallet_id,
            1,
            &sealed,
            SESSION_TTL_SECONDS,
        )
        .await?;

    Ok(Json(StartedReshare {
        envelopes: envelopes.into_iter().map(WireEnvelope::from).collect(),
    }))
}

/// Advances the reshare by one round. The last round stages the new share.
#[utoipa::path(
    post,
    path = "/v1/reshare/round",
    request_body = AdvanceReshare,
    responses(
        (status = 200, description = "round advanced, or new share staged", body = AdvancedReshare),
        (status = 404, description = "unknown or expired session"),
    ),
)]
pub async fn advance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AdvanceReshare>,
) -> Result<Json<AdvancedReshare>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/reshare/round",
        &request.wallet_id,
        &request,
    )
    .await?;
    let sealed = state
        .store
        .take_reshare_session(&request.reshare_id, &request.wallet_id)
        .await?
        .ok_or(Error::UnknownSession)?;
    let mut party = DkgParty::from_bytes(&state.sealing.open(&sealed)?)?;

    let inbox: Vec<Envelope> = request
        .envelopes
        .into_iter()
        .map(Envelope::try_from)
        .collect::<Result<_, _>>()?;

    let progress = match party.advance(&inbox) {
        Ok(progress) => progress,
        Err(error) => {
            // A failed round cannot be resumed. Drop the session so it cannot be retried.
            state
                .store
                .abort_reshare(&request.reshare_id, &request.wallet_id)
                .await?;
            return Err(error.into());
        }
    };

    match progress {
        Progress::Send(outgoing) => {
            let sealed = state.sealing.seal(&party.to_bytes()?)?;
            state
                .store
                .put_reshare_session(
                    &request.reshare_id,
                    &request.wallet_id,
                    i64::from(outgoing.first().map_or(0, |e| e.round)),
                    &sealed,
                    SESSION_TTL_SECONDS,
                )
                .await?;
            Ok(Json(AdvancedReshare::InProgress {
                envelopes: outgoing.into_iter().map(WireEnvelope::from).collect(),
            }))
        }
        Progress::Done { share, public_key } => {
            let sealed = state.sealing.seal(share.expose_secret())?;
            state
                .store
                .stage_reshare(
                    &request.reshare_id,
                    &request.wallet_id,
                    &sealed,
                    STAGED_TTL_SECONDS,
                )
                .await?;
            Ok(Json(AdvancedReshare::Staged {
                public_key: hex(&public_key.0),
            }))
        }
    }
}

/// Makes the staged share the live one and deletes the old share.
///
/// Call it only after the user has saved the new recovery file. Until then an abort, or a
/// timeout, leaves the previous share in place.
#[utoipa::path(
    post,
    path = "/v1/reshare/commit",
    request_body = FinishReshare,
    responses(
        (status = 204, description = "the new share is live"),
        (status = 404, description = "nothing staged, or it expired"),
    ),
)]
pub async fn commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FinishReshare>,
) -> Result<StatusCode, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/reshare/commit",
        &request.wallet_id,
        &request,
    )
    .await?;
    parse_hex32(&request.reshare_id, "reshare_id")?;
    if state
        .store
        .commit_reshare(&request.reshare_id, &request.wallet_id)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(Error::UnknownSession.into())
    }
}

/// Abandons a reshare. The previous share stays live.
#[utoipa::path(
    post,
    path = "/v1/reshare/abort",
    request_body = FinishReshare,
    responses((status = 204, description = "the reshare was dropped")),
)]
pub async fn abort(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FinishReshare>,
) -> Result<StatusCode, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/reshare/abort",
        &request.wallet_id,
        &request,
    )
    .await?;
    parse_hex32(&request.reshare_id, "reshare_id")?;
    state
        .store
        .abort_reshare(&request.reshare_id, &request.wallet_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::grant_digest;

    /// The extension computes the same digest in TypeScript ().
    /// Both sides test against this vector, so a change to either one fails in CI.
    #[test]
    fn grant_digest_matches_the_extension_vector() {
        let mut public_key = vec![0x02];
        public_key.extend([0xaa; 32]);
        assert_eq!(
            grant_digest(&public_key, &[0xe1; 32]),
            "7b145ea52b0d958bfd5ebdd538e7a90ac9a6d4f4876a19c58aef96ca69069531"
        );
    }

    #[test]
    fn grant_digest_binds_the_wallet_key_and_the_reshare_id() {
        let key_a = [0x02; 33];
        let key_b = [0x03; 33];
        let id = [0x11; 32];
        assert_ne!(grant_digest(&key_a, &id), grant_digest(&key_b, &id));
        assert_ne!(grant_digest(&key_a, &id), grant_digest(&key_a, &[0x12; 32]));
    }
}
