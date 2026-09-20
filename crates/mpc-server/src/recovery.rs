//! Starting a recovery and replacing the device key
//! (`docs/adr/0008-recovery-start-and-device-key-replacement.md`).
//!
//! A new install has no device key the server accepts, so nothing that needs one can start a
//! recovery. Instead a request names the key that wants to take over, and the only things that let
//! it succeed are a passkey assertion bound to that exact key and then a cooling-off wait, during
//! which the wallet's current device can object.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::api::{hex, parse_hex32, ApiError, AppState};
use crate::auth::{authenticate, authenticate_with_key, SignedJson};
use crate::passkey::{hash_handoff, validate_wallet_id, HANDOFF_TTL_SECONDS};
use crate::store::{CoolingStart, RecoveryCompletion, RecoveryRequest};
use crate::Error;

/// How long a request waits for its passkey assertion before it lapses.
pub const REQUEST_TTL_SECONDS: i64 = 900;
/// How long after the cooling-off period ends a request can still be completed.
pub const COMPLETE_WINDOW_SECONDS: i64 = 72 * 3600;
/// How many requests a wallet may open per hour.
pub const MAX_REQUESTS_PER_HOUR: i64 = 5;
/// The default cooling-off period, 24 hours.
pub const DEFAULT_COOLING_SECONDS: i64 = 24 * 3600;

/// The passkey purpose that authorizes a recovery. It is shared with resharing and with signing
/// under a recovered wallet, and told apart by the operation id and digest.
const PURPOSE: &str = "recovery";

/// Recovery settings.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// How long a verified request waits before it can replace the device key.
    pub cooling_seconds: i64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            cooling_seconds: DEFAULT_COOLING_SECONDS,
        }
    }
}

impl RecoveryConfig {
    /// Reads `MPC_SERVER_RECOVERY_COOLING_SECONDS`, defaulting to 24 hours.
    pub fn from_env() -> Result<Self, Error> {
        match std::env::var("MPC_SERVER_RECOVERY_COOLING_SECONDS") {
            Err(_) => Ok(Self::default()),
            Ok(value) => {
                let cooling_seconds: i64 = value.parse().map_err(|_| {
                    Error::Config("MPC_SERVER_RECOVERY_COOLING_SECONDS is not a number".into())
                })?;
                if cooling_seconds < 0 {
                    return Err(Error::Config(
                        "MPC_SERVER_RECOVERY_COOLING_SECONDS must not be negative".into(),
                    ));
                }
                Ok(Self { cooling_seconds })
            }
        }
    }
}

/// The digest a recovery's passkey assertion is bound to:
/// SHA-256("mpc-ext recovery v1" || wallet id || 0x00 || new device key || request id).
///
/// It ties the assertion to this wallet, this request and, above all, the key that would take
/// over, so an approval for one key cannot be spent on another. The extension needs no copy of
/// this: the server builds it and the browser ceremony carries it.
pub fn assertion_digest(wallet_id: &str, new_device_key: &[u8], request_id: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mpc-ext recovery v1");
    hasher.update(wallet_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(new_device_key);
    hasher.update(request_id);
    hex(&hasher.finalize())
}

/// A short, human-comparable fingerprint of a device key, for showing what is being approved.
pub fn key_fingerprint(public_key: &[u8]) -> String {
    hex(&Sha256::digest(public_key)[..4])
}

/// A request to start a recovery. It carries no device proof: the install asking has none yet.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RequestRecovery {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The new install's public device key: 65 bytes, uncompressed SEC1, as lowercase hex.
    pub device_public_key: String,
}

/// The response to a recovery request.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryRequested {
    /// Identifies this request in every later call, 64 hex characters.
    pub request_id: String,
    /// The browser ceremony for the passkey assertion.
    pub ceremony_id: String,
    /// The one-use token that starts that ceremony. Submit it in a form body, never in a URL.
    pub handoff_token: String,
}

/// A call about one request, signed with the new device key.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RecoveryCall {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The request, 64 hex characters.
    pub request_id: String,
}

/// Where a recovery request stands.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum RecoveryState {
    /// Waiting for the passkey assertion.
    AwaitingAssertion,
    /// The assertion was verified. It can be completed once `ready_at` (unix seconds) has passed.
    Cooling {
        /// When the cooling-off period ends, in unix seconds.
        ready_at: i64,
    },
    /// The cooling-off period is over: call `complete`.
    Ready,
    /// The device key was replaced.
    Completed,
    /// Cancelled before it finished.
    Cancelled,
    /// Lapsed before it finished.
    Expired,
}

/// A request to list what is waiting on a wallet.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ListRecoveries {
    /// The wallet identifier.
    pub wallet_id: String,
}

/// One recovery waiting on a wallet.
#[derive(Debug, Serialize, ToSchema)]
pub struct PendingRecovery {
    /// The request id.
    pub request_id: String,
    /// When it was made, in unix seconds.
    pub requested_at: i64,
    /// When the cooling-off period ends, in unix seconds.
    pub ready_at: i64,
    /// A short fingerprint of the key that would take over, to compare with the requester's.
    pub key_fingerprint: String,
}

/// The recoveries waiting on a wallet.
#[derive(Debug, Serialize, ToSchema)]
pub struct PendingRecoveries {
    /// Recoveries past their passkey assertion and not yet completed or cancelled.
    pub pending: Vec<PendingRecovery>,
}

fn parse_device_key(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = crate::api::decode_hex(value)
        .ok_or_else(|| Error::Protocol("device_public_key is not valid hex".into()))?;
    if bytes.len() != 65 || bytes.first() != Some(&0x04) {
        return Err(Error::Protocol(
            "device_public_key must be an uncompressed P-256 key".into(),
        ));
    }
    // A key that is not a point on the curve could never verify anything.
    VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|_| Error::Protocol("device_public_key is not a valid P-256 key".into()))?;
    Ok(bytes)
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Reads the state a request is in, as of now.
fn state_of(request: &RecoveryRequest) -> RecoveryState {
    let now = now_unix();
    match request.status.as_str() {
        "awaiting_assertion" if request.expires_unix >= now => RecoveryState::AwaitingAssertion,
        "cooling" if request.expires_unix >= now => match request.ready_unix {
            Some(ready) if ready <= now => RecoveryState::Ready,
            Some(ready_at) => RecoveryState::Cooling { ready_at },
            None => RecoveryState::Expired,
        },
        "completed" => RecoveryState::Completed,
        "cancelled" => RecoveryState::Cancelled,
        _ => RecoveryState::Expired,
    }
}

/// Starts a recovery and opens the passkey ceremony that has to approve it.
///
/// Nothing changes yet. The request only asks for an assertion bound to the new device key.
#[utoipa::path(
    post,
    path = "/v1/recovery/request",
    request_body = RequestRecovery,
    responses(
        (status = 200, description = "request recorded", body = RecoveryRequested),
        (status = 404, description = "no such wallet, or it has no passkey"),
        (status = 429, description = "too many requests for this wallet"),
    ),
)]
pub async fn request(
    State(state): State<AppState>,
    Json(request): Json<RequestRecovery>,
) -> Result<Json<RecoveryRequested>, ApiError> {
    validate_wallet_id(&request.wallet_id)?;
    let device_key = parse_device_key(&request.device_public_key)?;

    // Without a wallet and a passkey there is nothing to recover, and nothing that could approve
    // it. Both cases answer the same, so this does not tell a stranger which wallet ids exist.
    if state.store.public_key(&request.wallet_id).await?.is_none()
        || state
            .store
            .passkey_credential(&request.wallet_id)
            .await?
            .is_none()
    {
        return Err(Error::UnknownSession.into());
    }

    let request_id_bytes: [u8; 32] = rand::random();
    let request_id = hex(&request_id_bytes);
    if !state
        .store
        .create_recovery_request(
            &request_id,
            &request.wallet_id,
            &device_key,
            REQUEST_TTL_SECONDS,
            MAX_REQUESTS_PER_HOUR,
        )
        .await?
    {
        return Err(Error::RateLimited.into());
    }

    let ceremony_id = uuid::Uuid::new_v4().to_string();
    let handoff_token = uuid::Uuid::new_v4().to_string();
    state
        .store
        .put_browser_ceremony(
            &ceremony_id,
            &hash_handoff(&handoff_token),
            &request.wallet_id,
            "assert",
            PURPOSE,
            Some(&request_id),
            Some(&assertion_digest(
                &request.wallet_id,
                &device_key,
                &request_id_bytes,
            )),
            HANDOFF_TTL_SECONDS,
        )
        .await?;

    Ok(Json(RecoveryRequested {
        request_id,
        ceremony_id,
        handoff_token,
    }))
}

/// Loads a request and checks the call was signed with the key it names.
async fn authenticated_request(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    call: &RecoveryCall,
    raw: &str,
) -> Result<RecoveryRequest, Error> {
    validate_wallet_id(&call.wallet_id).map_err(|_| Error::Authentication)?;
    parse_hex32(&call.request_id, "request_id").map_err(|_| Error::Authentication)?;
    let request = state
        .store
        .recovery_request(&call.request_id, &call.wallet_id)
        .await?
        .ok_or(Error::Authentication)?;
    authenticate_with_key(
        &state.store,
        headers,
        "POST",
        path,
        &call.wallet_id,
        raw,
        &request.new_device_key,
    )
    .await?;
    Ok(request)
}

/// Reports where a request stands, and starts its cooling-off period once the passkey assertion
/// for it has been verified. Signed with the new device key.
#[utoipa::path(
    post,
    path = "/v1/recovery/status",
    request_body = RecoveryCall,
    responses(
        (status = 200, description = "the request's state", body = RecoveryState),
        (status = 401, description = "missing or invalid device proof"),
    ),
)]
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson { value: call, raw }: SignedJson<RecoveryCall>,
) -> Result<Json<RecoveryState>, ApiError> {
    let mut request =
        authenticated_request(&state, &headers, "/v1/recovery/status", &call, &raw).await?;

    if state_of(&request).is_awaiting() {
        let request_id = parse_hex32(&call.request_id, "request_id")?;
        let digest = assertion_digest(&call.wallet_id, &request.new_device_key, &request_id);
        // The assertion is consumed by whoever asks first, and only once.
        if state
            .store
            .consume_passkey_authorization(&call.wallet_id, PURPOSE, &call.request_id, &digest)
            .await?
        {
            match state
                .store
                .start_recovery_cooling(
                    &call.request_id,
                    &call.wallet_id,
                    state.recovery.cooling_seconds,
                    COMPLETE_WINDOW_SECONDS,
                )
                .await?
            {
                CoolingStart::Started { .. } => {}
                CoolingStart::AnotherCooling => {
                    return Err(Error::Protocol(
                        "another recovery for this wallet is already waiting; cancel it first"
                            .into(),
                    )
                    .into());
                }
                CoolingStart::NotAwaiting => {}
            }
            request = state
                .store
                .recovery_request(&call.request_id, &call.wallet_id)
                .await?
                .ok_or(Error::Authentication)?;
        }
    }
    Ok(Json(state_of(&request)))
}

/// Replaces the wallet's device key with this request's, once the cooling-off period is over.
/// Signed with the new device key.
#[utoipa::path(
    post,
    path = "/v1/recovery/complete",
    request_body = RecoveryCall,
    responses(
        (status = 204, description = "the device key was replaced"),
        (status = 400, description = "the cooling-off period has not ended"),
        (status = 404, description = "unknown, cancelled or lapsed request"),
    ),
)]
pub async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson { value: call, raw }: SignedJson<RecoveryCall>,
) -> Result<StatusCode, ApiError> {
    authenticated_request(&state, &headers, "/v1/recovery/complete", &call, &raw).await?;
    match state
        .store
        .complete_recovery(&call.request_id, &call.wallet_id)
        .await?
    {
        RecoveryCompletion::Done => Ok(StatusCode::NO_CONTENT),
        RecoveryCompletion::NotReady { .. } => {
            Err(Error::Protocol("the cooling-off period has not ended yet".into()).into())
        }
        RecoveryCompletion::Gone => Err(Error::UnknownSession.into()),
    }
}

/// Lists the recoveries waiting on a wallet. Signed with the wallet's current device key, so it
/// is how an existing install learns that someone asked to replace it.
#[utoipa::path(
    post,
    path = "/v1/recovery/pending",
    request_body = ListRecoveries,
    responses((status = 200, description = "recoveries waiting", body = PendingRecoveries)),
)]
pub async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson { value: call, raw }: SignedJson<ListRecoveries>,
) -> Result<Json<PendingRecoveries>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/recovery/pending",
        &call.wallet_id,
        &raw,
    )
    .await?;
    let pending = state
        .store
        .live_recoveries(&call.wallet_id)
        .await?
        .into_iter()
        .filter_map(|request| {
            Some(PendingRecovery {
                key_fingerprint: key_fingerprint(&request.new_device_key),
                requested_at: request.created_unix,
                ready_at: request.ready_unix?,
                request_id: request.request_id,
            })
        })
        .collect();
    Ok(Json(PendingRecoveries { pending }))
}

/// Cancels a recovery. Either the wallet's current device key or the request's own key may sign,
/// so the existing install can object, and the requester can withdraw.
#[utoipa::path(
    post,
    path = "/v1/recovery/cancel",
    request_body = RecoveryCall,
    responses(
        (status = 204, description = "cancelled"),
        (status = 404, description = "nothing to cancel"),
    ),
)]
pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson { value: call, raw }: SignedJson<RecoveryCall>,
) -> Result<StatusCode, ApiError> {
    validate_wallet_id(&call.wallet_id).map_err(|_| Error::Authentication)?;
    parse_hex32(&call.request_id, "request_id").map_err(|_| Error::Authentication)?;
    let request = state
        .store
        .recovery_request(&call.request_id, &call.wallet_id)
        .await?
        .ok_or(Error::Authentication)?;

    // A failed proof reserves no nonce, so trying the second key after the first is safe.
    let by_current = authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/recovery/cancel",
        &call.wallet_id,
        &raw,
    )
    .await;
    if by_current.is_err() {
        authenticate_with_key(
            &state.store,
            &headers,
            "POST",
            "/v1/recovery/cancel",
            &call.wallet_id,
            &raw,
            &request.new_device_key,
        )
        .await?;
    }

    if state
        .store
        .cancel_recovery(&call.request_id, &call.wallet_id)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(Error::UnknownSession.into())
    }
}

impl RecoveryState {
    fn is_awaiting(&self) -> bool {
        matches!(self, RecoveryState::AwaitingAssertion)
    }
}

#[cfg(test)]
mod tests {
    use super::{assertion_digest, key_fingerprint};

    /// The digest is what a passkey approval is bound to, so each input has to change it.
    #[test]
    fn assertion_digest_binds_wallet_key_and_request() {
        let key = [0x04u8; 65];
        let request_id = [0xe1u8; 32];
        assert_eq!(
            assertion_digest("wallet-1", &key, &request_id).len(),
            64,
            "the digest is 32 bytes as hex"
        );
        assert_ne!(
            assertion_digest("wallet-1", &key, &request_id),
            assertion_digest("wallet-2", &key, &request_id),
            "the wallet must be bound"
        );
        let mut other_key = key;
        other_key[64] = 0x05;
        assert_ne!(
            assertion_digest("wallet-1", &key, &request_id),
            assertion_digest("wallet-1", &other_key, &request_id),
            "the new device key must be bound"
        );
        assert_ne!(
            assertion_digest("wallet-1", &key, &request_id),
            assertion_digest("wallet-1", &key, &[0xe2; 32]),
            "the request must be bound"
        );
        // Moving the boundary between the wallet id and the key must not give the same input.
        assert_ne!(
            assertion_digest("wallet-1", &key, &request_id),
            assertion_digest("wallet-1\u{4}", &key[1..], &request_id),
            "the wallet id and the key must not run together"
        );
    }

    #[test]
    fn fingerprint_is_short_and_stable() {
        assert_eq!(key_fingerprint(&[1, 2, 3]).len(), 8);
        assert_eq!(key_fingerprint(&[1, 2, 3]), key_fingerprint(&[1, 2, 3]));
        assert_ne!(key_fingerprint(&[1, 2, 3]), key_fingerprint(&[1, 2, 4]));
    }
}
