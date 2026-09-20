//! Server-side WebAuthn passkey ceremonies.
//!
//! The server-origin page owns the browser ceremony. This module owns the relying-party
//! configuration, durable ceremony state, credential verification, and operation binding. No
//! challenge or credential is placed in a URL.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::auth::{
    AuthenticationVerificationOptions, DiscoverableCredentialRequestOptions,
    SignatureCounterEnforcement,
};
use webauthn_rp::request::register::{
    CoseAlgorithmIdentifier, CoseAlgorithmIdentifiers, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialUserEntity, RegistrationServerState, UserHandle64,
};
use webauthn_rp::request::{AsciiDomain, DomainOrigin, RpId};
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::{
    AuthenticatedCredential, DiscoverableAuthentication64, DiscoverableAuthenticationServerState,
    Registration,
};

use crate::api::{ApiError, AppState};
use crate::auth::{authenticate, SignedJson};
use crate::Error;

const CEREMONY_TTL_SECONDS: i64 = 300;
const USER_HANDLE_LEN: usize = 64;
const MAX_CREDENTIAL_JSON_BYTES: usize = 128 * 1024;
const MAX_OPERATION_ID_LEN: usize = 256;
const MAX_PURPOSE_LEN: usize = 32;
pub(crate) const HANDOFF_TTL_SECONDS: i64 = 300;
const AUTHORIZATION_TTL_SECONDS: i64 = 300;

/// A fixed relying-party configuration. It is loaded at startup and never derived from a request
/// Host header.
#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    /// The WebAuthn RP ID.
    pub rp_id: String,
    /// The exact server origin accepted in clientDataJSON.
    pub origin: String,
}

impl PasskeyConfig {
    /// Validates and constructs a passkey configuration.
    pub fn new(rp_id: impl Into<String>, origin: impl Into<String>) -> Result<Self, Error> {
        let rp_id = rp_id.into();
        let origin = origin.into();
        AsciiDomain::try_from(rp_id.clone())
            .map_err(|_| Error::Config("MPC_SERVER_RP_ID is not a valid ASCII domain".into()))?;
        DomainOrigin::try_from(origin.as_str())
            .map_err(|_| Error::Config("MPC_SERVER_ORIGIN is not a valid origin".into()))?;
        if !(origin.starts_with("https://") || origin.starts_with("http://localhost")) {
            return Err(Error::Config(
                "MPC_SERVER_ORIGIN must use HTTPS except for localhost".into(),
            ));
        }
        Ok(Self { rp_id, origin })
    }

    /// Loads fixed configuration from process configuration, with a documented local default.
    pub fn from_env() -> Result<Self, Error> {
        let rp_id = std::env::var("MPC_SERVER_RP_ID").unwrap_or_else(|_| "localhost".into());
        let origin =
            std::env::var("MPC_SERVER_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());
        Self::new(rp_id, origin)
    }

    fn rp_id(&self) -> Result<RpId, Error> {
        AsciiDomain::try_from(self.rp_id.clone())
            .map(RpId::Domain)
            .map_err(|_| Error::Config("the configured RP ID is invalid".into()))
    }

    fn origin(&self) -> Result<DomainOrigin<'_, '_>, Error> {
        DomainOrigin::try_from(self.origin.as_str())
            .map_err(|_| Error::Config("the configured origin is invalid".into()))
    }
}

/// Starts a registration ceremony for a wallet identified by its device key.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RegisterOptionsRequest {
    /// The wallet identifier.
    pub wallet_id: String,
}

/// A browser registration ceremony's public options.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterOptionsResponse {
    /// Opaque server-side ceremony identifier. It is submitted in the next request body.
    pub challenge_id: String,
    /// The options passed to `navigator.credentials.create`.
    #[schema(value_type = Object)]
    pub options: Value,
}

/// Completes a registration ceremony.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RegisterFinishRequest {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The opaque challenge identifier returned by the options endpoint.
    pub challenge_id: String,
    /// The browser's `PublicKeyCredential` JSON object.
    #[schema(value_type = Object)]
    pub credential: Value,
}

/// Starts an assertion ceremony bound to one exact operation.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AssertOptionsRequest {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The policy operation, currently `sign` or `recovery`.
    pub purpose: String,
    /// Application-generated operation identifier.
    pub operation_id: String,
    /// The exact 32-byte operation digest, encoded as lowercase or uppercase hex.
    pub digest: String,
}

/// A browser assertion ceremony's public options.
#[derive(Debug, Serialize, ToSchema)]
pub struct AssertOptionsResponse {
    /// Opaque server-side ceremony identifier. It is submitted in the next request body.
    pub challenge_id: String,
    /// The options passed to `navigator.credentials.get`.
    #[schema(value_type = Object)]
    pub options: Value,
}

/// Completes an assertion ceremony.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AssertFinishRequest {
    /// The wallet identifier.
    pub wallet_id: String,
    /// The opaque challenge identifier returned by the options endpoint.
    pub challenge_id: String,
    /// Must exactly match the values bound when options were requested.
    pub purpose: String,
    /// Must exactly match the values bound when options were requested.
    pub operation_id: String,
    /// Must exactly match the values bound when options were requested.
    pub digest: String,
    /// The browser's `PublicKeyCredential` JSON object.
    #[schema(value_type = Object)]
    pub credential: Value,
}

/// The result of a verified assertion.
#[derive(Debug, Serialize, ToSchema)]
pub struct AssertFinishResponse {
    /// Always true on a successful response.
    pub verified: bool,
    /// Echoes the already validated policy purpose.
    pub purpose: String,
    /// Echoes the already validated operation identifier.
    pub operation_id: String,
}

/// Starts a server-origin browser ceremony after device-key authentication.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct HandoffRequest {
    pub wallet_id: String,
    /// `register`, `sign`, or `recovery`.
    pub purpose: String,
    pub operation_id: Option<String>,
    pub digest: Option<String>,
}

/// A one-use token delivered to the extension and then submitted in an HTML form body.
#[derive(Debug, Serialize, ToSchema)]
pub struct HandoffResponse {
    pub ceremony_id: String,
    pub handoff_token: String,
}

/// A device-authenticated, non-secret view of a browser ceremony.
#[derive(Debug, Serialize, ToSchema)]
pub struct CeremonyStatusResponse {
    pub ceremony_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CeremonyStatusRequest {
    pub wallet_id: String,
    pub ceremony_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AssertionBinding {
    purpose: String,
    operation_id: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredCredential {
    id: Vec<u8>,
    user_id: Vec<u8>,
    static_state: Vec<u8>,
    dynamic_state: [u8; 7],
}

type StoredPublicKey = CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>;
type StoredStaticState = StaticState<StoredPublicKey>;

pub(crate) fn hash_handoff(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn validate_handoff_request(request: &HandoffRequest) -> Result<(), ApiError> {
    validate_wallet_id(&request.wallet_id)?;
    match request.purpose.as_str() {
        "register" => {
            if request.operation_id.is_some() || request.digest.is_some() {
                return Err(
                    Error::Protocol("registration handoff has unexpected binding".into()).into(),
                );
            }
        }
        "sign" | "recovery" => {
            let operation_id = request
                .operation_id
                .as_deref()
                .ok_or_else(|| Error::Protocol("operation_id is required".into()))?;
            let digest = request
                .digest
                .as_deref()
                .ok_or_else(|| Error::Protocol("digest is required".into()))?;
            validate_operation_id(operation_id)?;
            validate_digest(digest)?;
        }
        _ => return Err(Error::Protocol("purpose is not allowed".into()).into()),
    }
    Ok(())
}

/// Creates the one-use browser handoff after verifying device possession.
#[utoipa::path(
    post,
    path = "/v1/passkeys/handoff",
    request_body = HandoffRequest,
    responses((status = 200, description = "browser ceremony handoff", body = HandoffResponse))
)]
pub async fn handoff(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<HandoffRequest>,
) -> Result<Json<HandoffResponse>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/passkeys/handoff",
        &request.wallet_id,
        &raw,
    )
    .await?;
    validate_handoff_request(&request)?;
    if request.purpose == "register"
        && state
            .store
            .passkey_credential(&request.wallet_id)
            .await?
            .is_some()
    {
        return Err(Error::Protocol("a passkey is already registered".into()).into());
    }
    if request.purpose != "register"
        && state
            .store
            .passkey_credential(&request.wallet_id)
            .await?
            .is_none()
    {
        return Err(Error::Authentication.into());
    }
    let ceremony_id = uuid::Uuid::new_v4().to_string();
    let handoff_token = uuid::Uuid::new_v4().to_string();
    state
        .store
        .put_browser_ceremony(
            &ceremony_id,
            &hash_handoff(&handoff_token),
            &request.wallet_id,
            if request.purpose == "register" {
                "register"
            } else {
                "assert"
            },
            &request.purpose,
            request.operation_id.as_deref(),
            request.digest.as_deref(),
            HANDOFF_TTL_SECONDS,
        )
        .await?;
    Ok(Json(HandoffResponse {
        ceremony_id,
        handoff_token,
    }))
}

/// Returns browser ceremony progress to the extension without exposing credential state.
#[utoipa::path(
    post,
    path = "/v1/passkeys/ceremony/status",
    request_body = CeremonyStatusRequest,
    responses((status = 200, description = "browser ceremony status", body = CeremonyStatusResponse))
)]
pub async fn ceremony_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<CeremonyStatusRequest>,
) -> Result<Json<CeremonyStatusResponse>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/passkeys/ceremony/status",
        &request.wallet_id,
        &raw,
    )
    .await?;
    validate_wallet_id(&request.wallet_id)?;
    if request.ceremony_id.is_empty() || request.ceremony_id.len() > 64 {
        return Err(Error::Protocol("ceremony_id is malformed".into()).into());
    }
    let ceremony = state
        .store
        .browser_ceremony(&request.ceremony_id)
        .await?
        .filter(|ceremony| ceremony.wallet_id == request.wallet_id)
        .ok_or(Error::UnknownSession)?;
    let status = if ceremony.completed_at.is_some() {
        "completed"
    } else if ceremony.claimed_at.is_some() {
        "inProgress"
    } else {
        "waitingForBrowser"
    };
    Ok(Json(CeremonyStatusResponse {
        ceremony_id: request.ceremony_id,
        status: status.into(),
    }))
}

/// Creates registration options for an already authenticated wallet.
pub async fn registration_options(
    state: &AppState,
    wallet_id: &str,
) -> Result<RegisterOptionsResponse, Error> {
    if state.store.passkey_credential(wallet_id).await?.is_some() {
        return Err(Error::Protocol("a passkey is already registered".into()));
    }
    let rp_id = state.passkey.rp_id()?;
    let user_handle = UserHandle64::new();
    let user = PublicKeyCredentialUserEntity::from(&user_handle);
    let mut options = PublicKeyCredentialCreationOptions::passkey(&rp_id, user, Vec::new());
    // Assertions are verified against P-256 keys only (`verify_assertion`), so offer nothing else.
    // The library's default list starts with EdDSA, and an authenticator that supports it picks it
    // first: registration then succeeds and every later assertion is refused, stranding the user.
    options.pub_key_cred_params = CoseAlgorithmIdentifiers::ALL
        .remove(CoseAlgorithmIdentifier::Eddsa)
        .remove(CoseAlgorithmIdentifier::Es384)
        .remove(CoseAlgorithmIdentifier::Rs256);
    let (server_state, client_state) = options
        .start_ceremony()
        .map_err(|_| Error::Protocol("passkey ceremony could not start".into()))?;
    let server_state = server_state
        .encode()
        .map_err(|_| Error::Protocol("passkey ceremony state could not be stored".into()))?;
    let options = serde_json::to_value(&client_state)
        .map_err(|_| Error::Protocol("passkey options could not be encoded".into()))?;
    let challenge_id = uuid::Uuid::new_v4().to_string();
    state
        .store
        .put_passkey_challenge_with_binding(
            &challenge_id,
            wallet_id,
            "register",
            &server_state,
            b"register",
            CEREMONY_TTL_SECONDS,
        )
        .await?;
    Ok(RegisterOptionsResponse {
        challenge_id,
        options,
    })
}

/// Verifies and stores a registration response without deciding how the caller authenticated.
pub async fn verify_registration(
    state: &AppState,
    wallet_id: &str,
    challenge_id: &str,
    credential: &Value,
) -> Result<(), Error> {
    let credential_json = serde_json::to_vec(credential)
        .map_err(|_| Error::Protocol("credential is malformed".into()))?;
    if credential_json.len() > MAX_CREDENTIAL_JSON_BYTES {
        return Err(Error::Protocol("credential is too large".into()));
    }
    if state.store.passkey_credential(wallet_id).await?.is_some() {
        return Err(Error::Protocol("a passkey is already registered".into()));
    }
    let Some((server_state, binding)) = state
        .store
        .take_passkey_challenge_with_binding(challenge_id, wallet_id, "register")
        .await?
    else {
        return Err(Error::Authentication);
    };
    if binding != b"register" {
        return Err(Error::Authentication);
    }
    let server_state = RegistrationServerState::<USER_HANDLE_LEN>::decode(&server_state)
        .map_err(|_| Error::Protocol("passkey ceremony state is invalid".into()))?;
    let registration = Registration::from_json_relaxed(&credential_json)
        .map_err(|_| Error::Protocol("passkey credential is invalid".into()))?;
    let rp_id = state.passkey.rp_id()?;
    let origin = state.passkey.origin()?;
    let allowed_origins = [origin];
    let verification_options = webauthn_rp::request::register::RegistrationVerificationOptions::<
        DomainOrigin<'_, '_>,
        DomainOrigin<'_, '_>,
    > {
        allowed_origins: allowed_origins.as_slice(),
        client_data_json_relaxed: false,
        ..Default::default()
    };
    let credential = server_state
        .verify(&rp_id, &registration, &verification_options)
        .map_err(|_| Error::Protocol("passkey registration verification failed".into()))?;
    if !credential.dynamic_state().user_verified {
        return Err(Error::Authentication);
    }
    // Defence in depth for the list offered above: never store a key the assertion path would
    // refuse, because the wallet could then never be authorized again.
    if !matches!(
        credential.static_state().credential_public_key,
        webauthn_rp::response::register::UncompressedPubKey::P256(_)
    ) {
        return Err(Error::Protocol("only P-256 passkeys are supported".into()));
    }
    let stored = StoredCredential::from_registered(&credential)?;
    let encoded = serde_json::to_vec(&stored)
        .map_err(|_| Error::Protocol("passkey credential could not be stored".into()))?;
    state
        .store
        .put_passkey_credential(wallet_id, &encoded, credential.dynamic_state().sign_count)
        .await
        .map_err(|error| match error {
            Error::Storage(sqlx::Error::Database(database_error))
                if database_error.is_unique_violation() =>
            {
                Error::Protocol("a passkey is already registered".into())
            }
            other => other,
        })
}

/// Creates an assertion ceremony for an already authenticated wallet.
pub async fn assertion_options(
    state: &AppState,
    request: &AssertOptionsRequest,
) -> Result<AssertOptionsResponse, Error> {
    if state
        .store
        .passkey_credential(&request.wallet_id)
        .await?
        .is_none()
    {
        return Err(Error::Authentication);
    }
    let rp_id = state.passkey.rp_id()?;
    let options = DiscoverableCredentialRequestOptions::passkey(&rp_id);
    let (server_state, client_state) = options
        .start_ceremony()
        .map_err(|_| Error::Protocol("passkey ceremony could not start".into()))?;
    let server_state = server_state
        .encode()
        .map_err(|_| Error::Protocol("passkey ceremony state could not be stored".into()))?;
    let options = serde_json::to_value(&client_state)
        .map_err(|_| Error::Protocol("passkey options could not be encoded".into()))?;
    let binding = serde_json::to_vec(&AssertionBinding {
        purpose: request.purpose.clone(),
        operation_id: request.operation_id.clone(),
        digest: request.digest.clone(),
    })
    .map_err(|_| Error::Protocol("assertion binding could not be encoded".into()))?;
    let challenge_id = uuid::Uuid::new_v4().to_string();
    state
        .store
        .put_passkey_challenge_with_binding(
            &challenge_id,
            &request.wallet_id,
            "assert",
            &server_state,
            &binding,
            CEREMONY_TTL_SECONDS,
        )
        .await?;
    Ok(AssertOptionsResponse {
        challenge_id,
        options,
    })
}

/// Verifies one assertion and updates the stored authenticator state.
pub async fn verify_assertion(
    state: &AppState,
    request: &AssertFinishRequest,
) -> Result<(), Error> {
    let credential_json = serde_json::to_vec(&request.credential)
        .map_err(|_| Error::Protocol("credential is malformed".into()))?;
    if credential_json.len() > MAX_CREDENTIAL_JSON_BYTES {
        return Err(Error::Protocol("credential is too large".into()));
    }
    let Some((server_state, binding)) = state
        .store
        .take_passkey_challenge_with_binding(&request.challenge_id, &request.wallet_id, "assert")
        .await?
    else {
        tracing::warn!("passkey assertion has no live challenge for this wallet");
        return Err(Error::Authentication);
    };
    let expected_binding = serde_json::to_vec(&AssertionBinding {
        purpose: request.purpose.clone(),
        operation_id: request.operation_id.clone(),
        digest: request.digest.clone(),
    })
    .map_err(|_| Error::Authentication)?;
    if binding != expected_binding {
        tracing::warn!("passkey assertion does not match the operation it was issued for");
        return Err(Error::Authentication);
    }
    let server_state = DiscoverableAuthenticationServerState::decode(&server_state)
        .map_err(|_| Error::Protocol("passkey ceremony state is invalid".into()))?;
    let authentication = DiscoverableAuthentication64::from_json_relaxed(&credential_json)
        .map_err(|_| Error::Protocol("passkey credential is invalid".into()))?;
    let (credential_bytes, database_sign_count) = state
        .store
        .passkey_credential(&request.wallet_id)
        .await?
        .ok_or(Error::Authentication)?;
    let mut stored = StoredCredential::from_json(&credential_bytes)?;
    let rp_id = state.passkey.rp_id()?;
    let origin = state.passkey.origin()?;
    let allowed_origins = [origin];
    let verification_options =
        AuthenticationVerificationOptions::<DomainOrigin<'_, '_>, DomainOrigin<'_, '_>> {
            allowed_origins: allowed_origins.as_slice(),
            update_uv: true,
            sig_counter_enforcement: SignatureCounterEnforcement::Fail,
            client_data_json_relaxed: false,
            ..Default::default()
        };
    let user_handle = stored.user_handle()?;
    let id = authentication.raw_id();
    let id_bytes = id.encode().map_err(|_| Error::Authentication)?;
    if id_bytes != stored.id.as_slice() {
        tracing::warn!("passkey assertion is for a different credential than the registered one");
        return Err(Error::Authentication);
    }
    let static_state = stored.static_state()?;
    if !matches!(
        static_state.credential_public_key,
        CompressedPubKey::P256(_)
    ) {
        tracing::warn!("the registered passkey is not a P-256 key");
        return Err(Error::Authentication);
    }
    let dynamic_state = stored.dynamic_state()?;
    if dynamic_state.sign_count != database_sign_count {
        tracing::warn!("stored passkey counter and its database copy disagree");
        return Err(Error::Authentication);
    }
    let mut credential =
        AuthenticatedCredential::new(id, &user_handle, static_state, dynamic_state).map_err(
            |error| {
                tracing::warn!(?error, "the stored passkey could not be reassembled");
                Error::Authentication
            },
        )?;
    server_state
        .verify(
            &rp_id,
            &authentication,
            &mut credential,
            &verification_options,
        )
        .map_err(|error| {
            // Only the kind of failure, never the credential. Every rejection reaches the client
            // as the same "authentication failed", so this is the one place an operator can see why.
            tracing::warn!(?error, "passkey assertion failed verification");
            Error::Authentication
        })?;
    if !credential.dynamic_state().user_verified {
        tracing::warn!("the assertion did not carry user verification");
        return Err(Error::Authentication);
    }
    stored.dynamic_state = credential
        .dynamic_state()
        .encode()
        .map_err(|_| Error::Authentication)?;
    let encoded = serde_json::to_vec(&stored)
        .map_err(|_| Error::Protocol("passkey credential could not be stored".into()))?;
    state
        .store
        .update_passkey_credential(
            &request.wallet_id,
            &encoded,
            credential.dynamic_state().sign_count,
        )
        .await?;
    state
        .store
        .put_passkey_authorization(
            &request.wallet_id,
            &request.purpose,
            &request.operation_id,
            &request.digest,
            AUTHORIZATION_TTL_SECONDS,
        )
        .await
}

/// Starts a passkey registration ceremony.
#[utoipa::path(
    post,
    path = "/v1/passkeys/register/options",
    request_body = RegisterOptionsRequest,
    responses((status = 200, description = "registration options", body = RegisterOptionsResponse))
)]
pub async fn register_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<RegisterOptionsRequest>,
) -> Result<Json<RegisterOptionsResponse>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/passkeys/register/options",
        &request.wallet_id,
        &raw,
    )
    .await?;
    validate_wallet_id(&request.wallet_id)?;
    // One code path for the options, so the algorithms offered cannot drift between callers.
    Ok(Json(
        registration_options(&state, &request.wallet_id).await?,
    ))
}

/// Verifies and stores a new passkey credential.
#[utoipa::path(
    post,
    path = "/v1/passkeys/register/finish",
    request_body = RegisterFinishRequest,
    responses((status = 204, description = "passkey registered"))
)]
pub async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<RegisterFinishRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/passkeys/register/finish",
        &request.wallet_id,
        &raw,
    )
    .await?;
    validate_wallet_id(&request.wallet_id)?;
    if request.challenge_id.len() > 64 || request.challenge_id.is_empty() {
        return Err(Error::Protocol("challenge_id is malformed".into()).into());
    }
    let credential_json = serde_json::to_vec(&request.credential)
        .map_err(|_| Error::Protocol("credential is malformed".into()))?;
    if credential_json.len() > MAX_CREDENTIAL_JSON_BYTES {
        return Err(Error::Protocol("credential is too large".into()).into());
    }
    if state
        .store
        .passkey_credential(&request.wallet_id)
        .await?
        .is_some()
    {
        return Err(Error::Protocol("a passkey is already registered".into()).into());
    }

    let Some((server_state, binding)) = state
        .store
        .take_passkey_challenge_with_binding(&request.challenge_id, &request.wallet_id, "register")
        .await?
    else {
        return Err(Error::Authentication.into());
    };
    if binding != b"register" {
        return Err(Error::Authentication.into());
    }
    let server_state = RegistrationServerState::<USER_HANDLE_LEN>::decode(&server_state)
        .map_err(|_| Error::Protocol("passkey ceremony state is invalid".into()))?;
    let registration = Registration::from_json_relaxed(&credential_json)
        .map_err(|_| Error::Protocol("passkey credential is invalid".into()))?;
    let rp_id = state.passkey.rp_id()?;
    let origin = state.passkey.origin()?;
    let allowed_origins = [origin];
    let verification_options = webauthn_rp::request::register::RegistrationVerificationOptions::<
        DomainOrigin<'_, '_>,
        DomainOrigin<'_, '_>,
    > {
        allowed_origins: allowed_origins.as_slice(),
        client_data_json_relaxed: false,
        ..Default::default()
    };
    let credential = server_state
        .verify(&rp_id, &registration, &verification_options)
        .map_err(|_| Error::Protocol("passkey registration verification failed".into()))?;
    if !credential.dynamic_state().user_verified {
        return Err(Error::Authentication.into());
    }
    let stored = StoredCredential::from_registered(&credential)?;
    let encoded = serde_json::to_vec(&stored)
        .map_err(|_| Error::Protocol("passkey credential could not be stored".into()))?;
    state
        .store
        .put_passkey_credential(
            &request.wallet_id,
            &encoded,
            credential.dynamic_state().sign_count,
        )
        .await
        .map_err(|error| match error {
            Error::Storage(sqlx::Error::Database(database_error))
                if database_error.is_unique_violation() =>
            {
                Error::Protocol("a passkey is already registered".into())
            }
            other => other,
        })?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Starts a passkey assertion bound to one exact operation.
#[utoipa::path(
    post,
    path = "/v1/passkeys/assert/options",
    request_body = AssertOptionsRequest,
    responses((status = 200, description = "assertion options", body = AssertOptionsResponse))
)]
pub async fn assert_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<AssertOptionsRequest>,
) -> Result<Json<AssertOptionsResponse>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/passkeys/assert/options",
        &request.wallet_id,
        &raw,
    )
    .await?;
    validate_assertion_binding(&request)?;
    if state
        .store
        .passkey_credential(&request.wallet_id)
        .await?
        .is_none()
    {
        return Err(Error::Authentication.into());
    }
    let rp_id = state.passkey.rp_id()?;
    let options = DiscoverableCredentialRequestOptions::passkey(&rp_id);
    let (server_state, client_state) = options
        .start_ceremony()
        .map_err(|_| Error::Protocol("passkey ceremony could not start".into()))?;
    let server_state = server_state
        .encode()
        .map_err(|_| Error::Protocol("passkey ceremony state could not be stored".into()))?;
    let options = serde_json::to_value(&client_state)
        .map_err(|_| Error::Protocol("passkey options could not be encoded".into()))?;
    let binding = serde_json::to_vec(&AssertionBinding {
        purpose: request.purpose.clone(),
        operation_id: request.operation_id.clone(),
        digest: request.digest.clone(),
    })
    .map_err(|_| Error::Protocol("assertion binding could not be encoded".into()))?;
    let challenge_id = uuid::Uuid::new_v4().to_string();
    state
        .store
        .put_passkey_challenge_with_binding(
            &challenge_id,
            &request.wallet_id,
            "assert",
            &server_state,
            &binding,
            CEREMONY_TTL_SECONDS,
        )
        .await?;
    Ok(Json(AssertOptionsResponse {
        challenge_id,
        options,
    }))
}

/// Verifies one passkey assertion and consumes its operation binding.
#[utoipa::path(
    post,
    path = "/v1/passkeys/assert/finish",
    request_body = AssertFinishRequest,
    responses((status = 200, description = "assertion verified", body = AssertFinishResponse))
)]
pub async fn assert_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedJson {
        value: request,
        raw,
    }: SignedJson<AssertFinishRequest>,
) -> Result<Json<AssertFinishResponse>, ApiError> {
    authenticate(
        &state.store,
        &headers,
        "POST",
        "/v1/passkeys/assert/finish",
        &request.wallet_id,
        &raw,
    )
    .await?;
    validate_assertion_finish(&request)?;
    verify_assertion(&state, &request).await?;
    Ok(Json(AssertFinishResponse {
        verified: true,
        purpose: request.purpose,
        operation_id: request.operation_id,
    }))
}

impl StoredCredential {
    fn from_registered(
        credential: &webauthn_rp::RegisteredCredential<'_, USER_HANDLE_LEN>,
    ) -> Result<Self, Error> {
        let (id, _transports, user_id, static_state, dynamic_state, _metadata) =
            credential.as_parts();
        let static_state = static_state
            .encode()
            .map_err(|_| Error::Protocol("passkey credential state is invalid".into()))?;
        let id = id
            .encode()
            .map_err(|_| Error::Protocol("passkey credential id is invalid".into()))?
            .to_vec();
        Ok(Self {
            id,
            user_id: user_id.as_ref().to_vec(),
            static_state,
            dynamic_state: dynamic_state
                .encode()
                .map_err(|_| Error::Protocol("passkey credential state is invalid".into()))?,
        })
    }

    fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::Protocol("passkey credential state is invalid".into()))
    }

    fn user_handle(&self) -> Result<UserHandle64, Error> {
        let bytes: [u8; USER_HANDLE_LEN] = self
            .user_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::Authentication)?;
        UserHandle64::decode(bytes).map_err(|_| Error::Authentication)
    }

    fn static_state(&self) -> Result<StoredStaticState, Error> {
        StoredStaticState::decode(self.static_state.as_slice()).map_err(|_| Error::Authentication)
    }

    fn dynamic_state(&self) -> Result<DynamicState, Error> {
        DynamicState::decode(self.dynamic_state).map_err(|_| Error::Authentication)
    }
}

pub(crate) fn validate_wallet_id(wallet_id: &str) -> Result<(), ApiError> {
    if wallet_id.is_empty() || wallet_id.len() > 128 {
        return Err(Error::Protocol("wallet_id is malformed".into()).into());
    }
    Ok(())
}

fn validate_assertion_binding(request: &AssertOptionsRequest) -> Result<(), ApiError> {
    validate_wallet_id(&request.wallet_id)?;
    validate_purpose(&request.purpose)?;
    validate_operation_id(&request.operation_id)?;
    validate_digest(&request.digest)
}

fn validate_assertion_finish(request: &AssertFinishRequest) -> Result<(), ApiError> {
    validate_wallet_id(&request.wallet_id)?;
    if request.challenge_id.is_empty() || request.challenge_id.len() > 64 {
        return Err(Error::Protocol("challenge_id is malformed".into()).into());
    }
    validate_purpose(&request.purpose)?;
    validate_operation_id(&request.operation_id)?;
    validate_digest(&request.digest)
}

fn validate_purpose(purpose: &str) -> Result<(), ApiError> {
    if purpose.len() > MAX_PURPOSE_LEN || !matches!(purpose, "sign" | "recovery") {
        return Err(Error::Protocol("purpose is not allowed".into()).into());
    }
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), ApiError> {
    if operation_id.is_empty()
        || operation_id.len() > MAX_OPERATION_ID_LEN
        || !operation_id.is_ascii()
    {
        return Err(Error::Protocol("operation_id is malformed".into()).into());
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), ApiError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Protocol("digest is malformed".into()).into());
    }
    Ok(())
}
