//! The HTTP API and its OpenAPI spec.
//!
//! Every public endpoint is documented with `utoipa`; we do not ship undocumented public
//! endpoints (`docs/server.md`).
//!
//! Device-key authentication and server-side WebAuthn ceremonies are implemented here.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mpc_core::{DkgParty, Envelope, KeyShare, PartyId, Progress, SignParty, SignProgress};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::auth::{authenticate, SignedJson};
use crate::auth_page;
use crate::crypto::SealingKey;
use crate::passkey::{self, PasskeyConfig};
use crate::passkey::{
    AssertFinishRequest, AssertFinishResponse, AssertOptionsRequest, AssertOptionsResponse,
    CeremonyStatusRequest, CeremonyStatusResponse, HandoffRequest, HandoffResponse,
    PasskeyRegistered, PasskeyRegisteredRequest, RegisterFinishRequest, RegisterOptionsRequest,
    RegisterOptionsResponse,
};
use crate::store::Store;
use crate::Error;

/// The party the server drives, which holds share C.
pub(crate) const SERVER_PARTY: PartyId = PartyId(2);

/// How long a DKG session stays valid. Generous, but not unbounded.
pub(crate) const SESSION_TTL_SECONDS: i64 = 600;

/// State shared by the handlers.
#[derive(Clone, Debug)]
pub struct AppState {
    /// The store.
    pub store: Store,
    /// The key used to seal data at rest.
    pub sealing: SealingKey,
    /// Fixed relying-party configuration for the server-origin ceremony.
    pub passkey: PasskeyConfig,
    /// How long a recovery waits before it can replace the device key.
    pub recovery: crate::recovery::RecoveryConfig,
}

/// A device public-key registration request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterDeviceKey {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The raw SEC1 public key, encoded as lowercase hex.
    pub public_key: String,
}

/// Registers a wallet's first device key. Signing endpoints verify requests with this key.
///
/// A wallet that already has one is refused: replacing a key needs a recovery.
#[utoipa::path(
    post,
    path = "/v1/device-key",
    request_body = RegisterDeviceKey,
    responses((status = 204, description = "device key registered"), (status = 400, description = "malformed request")),
)]
async fn register_device_key(
    State(state): State<AppState>,
    Json(request): Json<RegisterDeviceKey>,
) -> Result<StatusCode, ApiError> {
    if request.wallet_id.is_empty() || request.wallet_id.len() > 128 {
        return Err(Error::Protocol("wallet_id is malformed".into()).into());
    }
    let public_key = decode_hex(&request.public_key)
        .ok_or_else(|| Error::Protocol("public_key is not valid hex".into()))?;
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(Error::Protocol("public_key must be an uncompressed P-256 key".into()).into());
    }
    if !state
        .store
        .register_device_key(&request.wallet_id, &public_key)
        .await?
    {
        return Err(Error::Protocol(
            "this wallet already has a device key; replace it through a recovery".into(),
        )
        .into());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The health-check response.
#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// Always `"ok"`.
    pub status: &'static str,
    /// This build's threshold configuration, for example `"2-of-3"`.
    pub threshold: String,
}

/// A single envelope. The body travels base64-encoded.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct WireEnvelope {
    /// The protocol round number.
    pub round: u8,
    /// The sending party, 0-based.
    pub from: u8,
    /// The recipient. Omitted means broadcast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<u8>,
    /// The base64-encoded body.
    pub payload: String,
}

impl From<Envelope> for WireEnvelope {
    fn from(value: Envelope) -> Self {
        use base64::Engine;
        Self {
            round: value.round,
            from: value.from.0,
            to: value.to.map(|p| p.0),
            payload: base64::engine::general_purpose::STANDARD.encode(&value.payload),
        }
    }
}

impl TryFrom<WireEnvelope> for Envelope {
    type Error = Error;

    fn try_from(value: WireEnvelope) -> Result<Self, Self::Error> {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&value.payload)
            .map_err(|_| Error::Protocol("payload is not valid base64".into()))?;
        Ok(Envelope {
            round: value.round,
            from: PartyId(value.from),
            to: value.to.map(PartyId),
            payload,
        })
    }
}

/// A request to open a DKG session.
#[derive(Debug, Deserialize, ToSchema)]
pub struct StartDkg {
    /// The wallet identifier, generated by the client.
    pub wallet_id: String,
    /// The session id shared by every party, 64 hex characters.
    pub session_id: String,
}

/// The response to opening a DKG session.
#[derive(Debug, Serialize, ToSchema)]
pub struct StartedDkg {
    /// The round 1 envelopes the server sends.
    pub envelopes: Vec<WireEnvelope>,
}

/// A request to advance a DKG round.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AdvanceDkg {
    /// The session id, 64 hex characters.
    pub session_id: String,
    /// The wallet identifier.
    pub wallet_id: String,
    /// The envelopes being delivered to the server.
    pub envelopes: Vec<WireEnvelope>,
}

/// The response to advancing a DKG round.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AdvancedDkg {
    /// Still running. Deliver the envelopes and call again.
    InProgress {
        /// The envelopes the server sends.
        envelopes: Vec<WireEnvelope>,
    },
    /// The DKG finished and the server stored share C.
    Completed {
        /// The SEC1 compressed public key, hex-encoded.
        public_key: String,
    },
}

/// Returns the server's status.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses((status = 200, description = "the server is healthy", body = Health)),
)]
async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        threshold: format!("{}-of-{}", mpc_core::THRESHOLD, mpc_core::TOTAL_PARTIES),
    })
}

/// Opens a DKG session and returns the server's round 1 envelopes.
#[utoipa::path(
    post,
    path = "/v1/dkg/session",
    request_body = StartDkg,
    responses(
        (status = 200, description = "session opened", body = StartedDkg),
        (status = 400, description = "malformed request"),
    ),
)]
async fn start_dkg(
    State(state): State<AppState>,
    Json(request): Json<StartDkg>,
) -> Result<Json<StartedDkg>, ApiError> {
    let session_id = parse_session_id(&request.session_id)?;
    let (party, envelopes) = DkgParty::start(SERVER_PARTY, &session_id)?;

    let sealed = state
        .sealing
        .seal(&serialize_party(&party)?)
        .map_err(ApiError::from)?;
    state
        .store
        .put_session(
            &request.session_id,
            &request.wallet_id,
            1,
            &sealed,
            SESSION_TTL_SECONDS,
        )
        .await?;

    Ok(Json(StartedDkg {
        envelopes: envelopes.into_iter().map(WireEnvelope::from).collect(),
    }))
}

/// Advances to the next round using the envelopes supplied.
#[utoipa::path(
    post,
    path = "/v1/dkg/round",
    request_body = AdvanceDkg,
    responses(
        (status = 200, description = "round advanced, or DKG complete", body = AdvancedDkg),
        (status = 404, description = "unknown or expired session"),
    ),
)]
async fn advance_dkg(
    State(state): State<AppState>,
    Json(request): Json<AdvanceDkg>,
) -> Result<Json<AdvancedDkg>, ApiError> {
    let (_, sealed) = state
        .store
        .take_session(&request.session_id)
        .await?
        .ok_or(Error::UnknownSession)?;

    let mut party = deserialize_party(&state.sealing.open(&sealed)?)?;

    let inbox: Vec<Envelope> = request
        .envelopes
        .into_iter()
        .map(Envelope::try_from)
        .collect::<Result<_, _>>()?;

    match party.advance(&inbox)? {
        Progress::Send(outgoing) => {
            let sealed = state.sealing.seal(&serialize_party(&party)?)?;
            state
                .store
                .put_session(
                    &request.session_id,
                    &request.wallet_id,
                    i64::from(outgoing.first().map_or(0, |e| e.round)),
                    &sealed,
                    SESSION_TTL_SECONDS,
                )
                .await?;
            Ok(Json(AdvancedDkg::InProgress {
                envelopes: outgoing.into_iter().map(WireEnvelope::from).collect(),
            }))
        }
        Progress::Done { share, public_key } => {
            let sealed = state.sealing.seal(share.expose_secret())?;
            state
                .store
                .finish_dkg(
                    &request.session_id,
                    &request.wallet_id,
                    &sealed,
                    &public_key.0,
                )
                .await?;
            Ok(Json(AdvancedDkg::Completed {
                public_key: hex(&public_key.0),
            }))
        }
    }
}

/// A request to open a signing session.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StartSign {
    /// The wallet identifier.
    pub wallet_id: String,
    /// A unique id for this signature, 64 hex characters. Never reuse one.
    pub sign_id: String,
    /// The 32-byte digest being signed, hex-encoded.
    pub digest: String,
    /// Which party the client is driving (0 for the extension share, 1 for the recovery file).
    pub counterparty: u8,
}

/// The response to opening a signing session.
#[derive(Debug, Serialize, ToSchema)]
pub struct StartedSign {
    /// The round 1 envelopes the server sends.
    pub envelopes: Vec<WireEnvelope>,
}

/// A request to advance a signing round.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AdvanceSign {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The signature id, 64 hex characters.
    pub sign_id: String,
    /// The envelopes being delivered to the server.
    pub envelopes: Vec<WireEnvelope>,
}

/// The response to advancing a signing round.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AdvancedSign {
    /// Still running. Deliver the envelopes and call again.
    InProgress {
        /// The envelopes the server sends.
        envelopes: Vec<WireEnvelope>,
    },
    /// Signing finished. The signature is returned as 65 hex-encoded bytes (r || s || v).
    Completed {
        /// The signature, hex-encoded.
        signature: String,
    },
}

/// Opens a signing session and returns the server's round 1 envelopes.
///
/// The server is a second factor, so this is where policy belongs: rate limits, anomaly
/// blocking and user confirmation all hang off this endpoint once authentication exists
/// (`docs/server.md`).
#[utoipa::path(
    post,
    path = "/v1/sign/session",
    request_body = StartSign,
    responses(
        (status = 200, description = "session opened", body = StartedSign),
        (status = 404, description = "no key for this wallet"),
    ),
)]
async fn start_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<StartSign>,
) -> Result<Json<StartedSign>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/sign/session",
        &request.wallet_id,
        &raw,
    )
    .await?;
    let sign_id = parse_hex32(&request.sign_id, "sign_id")?;
    let digest = parse_hex32(&request.digest, "digest")?;
    // Driving the recovery share (party 1) is a recovery operation and needs its own assertion.
    // A `sign` grant must not open it, so the two policies stay separately enforceable.
    let purpose = match request.counterparty {
        0 => "sign",
        1 => "recovery",
        _ => return Err(Error::Protocol("counterparty must be 0 or 1".into()).into()),
    };
    if !state
        .store
        .consume_passkey_authorization(
            &request.wallet_id,
            purpose,
            &request.sign_id,
            &request.digest,
        )
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

    let (party, envelopes) =
        SignParty::start(&share, PartyId(request.counterparty), &sign_id, &digest)?;

    let sealed = state.sealing.seal(&party.to_bytes()?)?;
    state
        .store
        .put_sign_session(
            &request.sign_id,
            &request.wallet_id,
            1,
            &sealed,
            &digest,
            SESSION_TTL_SECONDS,
        )
        .await?;

    Ok(Json(StartedSign {
        envelopes: envelopes.into_iter().map(WireEnvelope::from).collect(),
    }))
}

/// Advances the signing protocol by one round.
#[utoipa::path(
    post,
    path = "/v1/sign/round",
    request_body = AdvanceSign,
    responses(
        (status = 200, description = "round advanced, or signing complete", body = AdvancedSign),
        (status = 404, description = "unknown or expired session"),
    ),
)]
async fn advance_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<AdvanceSign>,
) -> Result<Json<AdvancedSign>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/sign/round",
        &request.wallet_id,
        &raw,
    )
    .await?;
    let sealed = state
        .store
        .take_sign_session(&request.sign_id)
        .await?
        .ok_or(Error::UnknownSession)?;
    let mut party = SignParty::from_bytes(&state.sealing.open(&sealed)?)?;

    let inbox: Vec<Envelope> = request
        .envelopes
        .into_iter()
        .map(Envelope::try_from)
        .collect::<Result<_, _>>()?;

    match party.advance(&inbox)? {
        SignProgress::Send(outgoing) => {
            let round = i64::from(outgoing.first().map_or(0, |e| e.round));
            let sealed = state.sealing.seal(&party.to_bytes()?)?;
            state
                .store
                .put_sign_session(
                    &request.sign_id,
                    &request.wallet_id,
                    round,
                    &sealed,
                    &[],
                    SESSION_TTL_SECONDS,
                )
                .await?;
            Ok(Json(AdvancedSign::InProgress {
                envelopes: outgoing.into_iter().map(WireEnvelope::from).collect(),
            }))
        }
        SignProgress::Done(signature) => {
            state
                .store
                .finish_sign(&request.sign_id, &request.wallet_id)
                .await?;
            let mut bytes = Vec::with_capacity(65);
            bytes.extend_from_slice(&signature.r);
            bytes.extend_from_slice(&signature.s);
            bytes.push(signature.recovery_id);
            Ok(Json(AdvancedSign::Completed {
                signature: hex(&bytes),
            }))
        }
    }
}

/// The root of the OpenAPI spec.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        health,
        register_device_key,
        start_dkg,
        advance_dkg,
        start_sign,
        advance_sign,
        crate::reshare::start,
        crate::reshare::advance,
        crate::reshare::commit,
        crate::reshare::abort,
        crate::recovery::request,
        crate::recovery::status,
        crate::recovery::complete,
        crate::recovery::pending,
        crate::recovery::cancel,
        passkey::register_options,
        passkey::register_finish,
        passkey::assert_options,
        passkey::assert_finish,
        passkey::handoff,
        passkey::ceremony_status,
        passkey::registered
    ),
    components(schemas(
        Health,
        RegisterDeviceKey,
        StartDkg,
        StartedDkg,
        AdvanceDkg,
        AdvancedDkg,
        StartSign,
        StartedSign,
        AdvanceSign,
        AdvancedSign,
        crate::reshare::StartReshare,
        crate::reshare::StartedReshare,
        crate::reshare::AdvanceReshare,
        crate::reshare::AdvancedReshare,
        crate::reshare::FinishReshare,
        crate::recovery::RequestRecovery,
        crate::recovery::RecoveryRequested,
        crate::recovery::RecoveryCall,
        crate::recovery::RecoveryState,
        crate::recovery::ListRecoveries,
        crate::recovery::PendingRecovery,
        crate::recovery::PendingRecoveries,
        WireEnvelope,
        RegisterOptionsRequest,
        RegisterOptionsResponse,
        RegisterFinishRequest,
        AssertOptionsRequest,
        AssertOptionsResponse,
        AssertFinishRequest,
        AssertFinishResponse,
        HandoffRequest,
        HandoffResponse,
        CeremonyStatusRequest,
        CeremonyStatusResponse,
        PasskeyRegisteredRequest,
        PasskeyRegistered,
    )),
    info(
        title = "mpc-ext server",
        description = "Holds one share of a 2-of-3 MPC key, joins signing, and verifies server-origin WebAuthn passkey ceremonies.",
    )
)]
pub struct ApiDoc;

/// Builds the router. Swagger UI lives at `/docs`, the spec at `/openapi.json`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/device-key", post(register_device_key))
        .route("/v1/dkg/session", post(start_dkg))
        .route("/v1/dkg/round", post(advance_dkg))
        .route("/v1/sign/session", post(start_sign))
        .route("/v1/sign/round", post(advance_sign))
        .route("/v1/reshare/session", post(crate::reshare::start))
        .route("/v1/reshare/round", post(crate::reshare::advance))
        .route("/v1/reshare/commit", post(crate::reshare::commit))
        .route("/v1/reshare/abort", post(crate::reshare::abort))
        .route("/v1/recovery/request", post(crate::recovery::request))
        .route("/v1/recovery/status", post(crate::recovery::status))
        .route("/v1/recovery/complete", post(crate::recovery::complete))
        .route("/v1/recovery/pending", post(crate::recovery::pending))
        .route("/v1/recovery/cancel", post(crate::recovery::cancel))
        .route(
            "/v1/passkeys/register/options",
            post(passkey::register_options),
        )
        .route(
            "/v1/passkeys/register/finish",
            post(passkey::register_finish),
        )
        .route("/v1/passkeys/assert/options", post(passkey::assert_options))
        .route("/v1/passkeys/assert/finish", post(passkey::assert_finish))
        .route("/v1/passkeys/handoff", post(passkey::handoff))
        .route(
            "/v1/passkeys/ceremony/status",
            post(passkey::ceremony_status),
        )
        .route("/v1/passkeys/registered", post(passkey::registered))
        .route("/auth", get(auth_page::page))
        .route("/auth.js", get(auth_page::script))
        .route("/auth/handoff", post(auth_page::handoff))
        .route("/auth/session", get(auth_page::options))
        .route("/auth/session/finish", post(auth_page::finish))
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .with_state(state)
}

/// An error on its way out over HTTP. Never exposes internal state.
#[derive(Debug)]
pub struct ApiError(Error);

impl From<Error> for ApiError {
    fn from(value: Error) -> Self {
        Self(value)
    }
}

impl From<mpc_core::Error> for ApiError {
    fn from(value: mpc_core::Error) -> Self {
        Self(Error::from(value))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            Error::UnknownSession => StatusCode::NOT_FOUND,
            Error::Authentication => StatusCode::UNAUTHORIZED,
            Error::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Error::Protocol(_) => StatusCode::BAD_REQUEST,
            Error::Config(_) | Error::Crypto(_) | Error::Storage(_) | Error::Migration(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        // Storage and crypto failures keep their details to themselves.
        let message = match &self.0 {
            Error::Storage(_) | Error::Migration(_) | Error::Crypto(_) => {
                "internal error".to_string()
            }
            other => other.to_string(),
        };
        tracing::warn!(error = %self.0, "request failed");
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn parse_session_id(value: &str) -> Result<[u8; 32], Error> {
    parse_hex32(value, "session_id")
}

/// Parses a 32-byte hex value, naming the field in any error.
pub(crate) fn parse_hex32(value: &str, field: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 {
        return Err(Error::Protocol(format!(
            "{field} must be 64 hex characters"
        )));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = value
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| Error::Protocol(format!("{field} is malformed")))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| Error::Protocol(format!("{field} is not hex")))?;
    }
    Ok(out)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Serialization used to hold party state between rounds.
fn serialize_party(party: &DkgParty) -> Result<Vec<u8>, Error> {
    party
        .to_bytes()
        .map_err(|e| Error::Protocol(format!("session state encode: {e}")))
}

fn deserialize_party(bytes: &[u8]) -> Result<DkgParty, Error> {
    DkgParty::from_bytes(bytes).map_err(|e| Error::Protocol(format!("session state decode: {e}")))
}
