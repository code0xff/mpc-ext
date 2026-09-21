//! Seeing and cancelling a recovery with the passkey alone
//! (`docs/adr/0009-managing-recoveries-with-the-passkey.md`).
//!
//! A recovery waits before it can replace a wallet's device key, and the wait only helps if the
//! owner can object. The extension can, but it may be the thing that was lost. This page, on the
//! server's own origin, lets the owner do it from any browser with nothing but their passkey.
//!
//! The wallet is identified by the passkey itself, so there is no wallet id to type or to guess.
//! One verified assertion opens a five minute session, and a cancel inside it needs the session
//! cookie and the page's own origin.

use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::api::{hex, ApiError, AppState};
use crate::auth_page::{json_response, security_headers};
use crate::passkey::{self, AssertOptionsResponse};
use crate::recovery::key_fingerprint;
use crate::Error;

const SESSION_COOKIE: &str = "mpc_manage_session";
const SESSION_TTL_SECONDS: i64 = 300;

/// How many challenges may be live at once. The page asks for one without any proof, so without a
/// cap anyone could fill the table.
const MAX_LIVE_CHALLENGES: i64 = 200;

/// The management page.
pub async fn page() -> Response {
    security_headers(Html(include_str!("../static/manage.html")).into_response())
}

/// The management page's script, a separate file so the CSP can forbid inline script.
pub async fn script() -> Response {
    let mut response = Response::new(include_str!("../static/manage.js").into());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    security_headers(response)
}

/// A passkey assertion answering a challenge from `/manage/challenge`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ManageFinish {
    /// The challenge the assertion answers.
    pub challenge_id: String,
    /// The browser's WebAuthn assertion, as JSON.
    #[schema(value_type = Object)]
    pub credential: Value,
}

/// A recovery waiting on the wallet.
#[derive(Debug, Serialize, ToSchema)]
pub struct WaitingRecovery {
    /// The request id.
    pub request_id: String,
    /// When it was asked, in unix seconds.
    pub requested_at: i64,
    /// When the new device could take over, in unix seconds.
    pub ready_at: i64,
    /// A short fingerprint of the requesting device's key.
    pub key_fingerprint: String,
}

/// The recoveries waiting on the wallet whose passkey was just used.
#[derive(Debug, Serialize, ToSchema)]
pub struct ManageView {
    /// Recoveries past their passkey approval and not yet completed or cancelled.
    pub recoveries: Vec<WaitingRecovery>,
}

/// Which recovery to cancel.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ManageCancel {
    /// The request id.
    pub request_id: String,
}

/// Starts a passkey assertion for the management page. No proof is needed, and none is useful:
/// the challenge names no wallet.
#[utoipa::path(
    get,
    path = "/manage/challenge",
    responses(
        (status = 200, description = "assertion options", body = AssertOptionsResponse),
        (status = 429, description = "too many challenges are waiting"),
    ),
)]
pub async fn challenge(State(state): State<AppState>) -> Result<Response, ApiError> {
    if state.store.live_manage_challenges().await? >= MAX_LIVE_CHALLENGES {
        return Err(Error::RateLimited.into());
    }
    Ok(json_response(&passkey::manage_options(&state).await?))
}

/// Verifies the assertion, opens a five minute session, and lists what is waiting.
///
/// A passkey that no wallet has and a bad signature both answer `401`, so this cannot be used to
/// ask which passkeys exist.
#[utoipa::path(
    post,
    path = "/manage/session",
    request_body = ManageFinish,
    responses(
        (status = 200, description = "session opened", body = ManageView),
        (status = 401, description = "the assertion did not verify"),
    ),
)]
pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManageFinish>,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
    let wallet_id =
        passkey::verify_manage_assertion(&state, &request.challenge_id, &request.credential)
            .await?;

    let mut token = [0u8; 32];
    rand::rng().fill_bytes(&mut token);
    let token = hex(&token);
    state
        .store
        .open_manage_session(&session_hash(&token), &wallet_id, SESSION_TTL_SECONDS)
        .await?;

    let mut response = json_response(&view(&state, &wallet_id).await?);
    let mut cookie = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/manage; Max-Age={SESSION_TTL_SECONDS}"
    );
    if state.passkey.origin.starts_with("https://") {
        cookie.push_str("; Secure");
    }
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| Error::Authentication)?,
    );
    Ok(response)
}

/// Cancels a recovery on the session's wallet. Needs the session cookie and the page's origin.
#[utoipa::path(
    post,
    path = "/manage/cancel",
    request_body = ManageCancel,
    responses(
        (status = 200, description = "cancelled; what is still waiting", body = ManageView),
        (status = 401, description = "no live session, or a foreign origin"),
        (status = 404, description = "nothing to cancel"),
    ),
)]
pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManageCancel>,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
    let wallet_id = session_wallet(&state, &headers).await?;
    if !state
        .store
        .cancel_recovery(&request.request_id, &wallet_id)
        .await?
    {
        return Err(Error::UnknownSession.into());
    }
    Ok(json_response(&view(&state, &wallet_id).await?))
}

/// A cancel changes state, and a cookie alone would let another site cause one. The page sends its
/// own origin, so a request from anywhere else is refused.
fn require_origin(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin != Some(state.passkey.origin.as_str()) {
        tracing::warn!("management request from an unexpected origin");
        return Err(Error::Authentication);
    }
    Ok(())
}

async fn session_wallet(state: &AppState, headers: &HeaderMap) -> Result<String, Error> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                (name == SESSION_COOKIE).then_some(value)
            })
        })
        .filter(|token| !token.is_empty() && token.len() <= 128 && token.is_ascii())
        .ok_or(Error::Authentication)?;
    state
        .store
        .manage_session_wallet(&session_hash(token))
        .await?
        .ok_or(Error::Authentication)
}

fn session_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

async fn view(state: &AppState, wallet_id: &str) -> Result<ManageView, Error> {
    let recoveries = state
        .store
        .live_recoveries(wallet_id)
        .await?
        .into_iter()
        .filter_map(|request| {
            Some(WaitingRecovery {
                key_fingerprint: key_fingerprint(&request.new_device_key),
                requested_at: request.created_unix,
                ready_at: request.ready_unix?,
                request_id: request.request_id,
            })
        })
        .collect();
    Ok(ManageView { recoveries })
}
