//! Server-origin WebAuthn ceremony delivery.
//!
//! The extension receives a one-use handoff token over an authenticated JSON response. It submits
//! that token in a form body to this module; the token is exchanged for an HttpOnly cookie and is
//! never placed in a URL. The browser page then talks only to this server origin.

use axum::extract::{Form, Json, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{ApiError, AppState};
use crate::passkey::{self, AssertFinishRequest, AssertOptionsRequest};
use crate::Error;

const SESSION_COOKIE: &str = "mpc_auth_session";

#[derive(Debug, Deserialize)]
pub struct HandoffForm {
    pub handoff_token: String,
}

#[derive(Debug, Serialize)]
struct BrowserOptions {
    kind: String,
    purpose: String,
    options: Value,
}

#[derive(Debug, Serialize)]
struct BrowserFinishResponse {
    verified: bool,
}

/// Serves the no-cache server-origin ceremony page.
pub async fn page() -> Response {
    security_headers(Html(include_str!("../static/auth.html")).into_response())
}

/// Serves the browser ceremony JavaScript as a separate CSP-allowed resource.
pub async fn script() -> Response {
    let mut response = Response::new(include_str!("../static/auth.js").into());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    security_headers(response)
}

/// Exchanges the one-use form-body handoff token for a scoped browser session cookie.
pub async fn handoff(
    State(state): State<AppState>,
    Form(form): Form<HandoffForm>,
) -> Result<Response, ApiError> {
    if form.handoff_token.is_empty() || form.handoff_token.len() > 128 {
        return Err(Error::Authentication.into());
    }
    let hash = passkey_hash(&form.handoff_token);
    let ceremony = state
        .store
        .claim_browser_ceremony(&hash)
        .await?
        .ok_or(Error::Authentication)?;
    let mut response = Redirect::to("/auth").into_response();
    let mut cookie = format!(
        "{SESSION_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/auth; Max-Age=300",
        ceremony.session_id
    );
    if state.passkey.origin.starts_with("https://") {
        cookie.push_str("; Secure");
    }
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| Error::Authentication)?,
    );
    Ok(security_headers(response))
}

/// Returns the browser ceremony options associated with the HttpOnly session cookie.
pub async fn options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session_id = session_cookie(&headers)?;
    let ceremony = state
        .store
        .browser_ceremony(&session_id)
        .await?
        .ok_or(Error::Authentication)?;
    if ceremony.claimed_at.is_none()
        || ceremony.completed_at.is_some()
        || ceremony.cancelled_at.is_some()
    {
        return Err(Error::Authentication.into());
    }

    if let (Some(challenge_id), Some(options)) =
        (ceremony.challenge_id.clone(), ceremony.options.clone())
    {
        let _ = challenge_id;
        return Ok(json_response(&BrowserOptions {
            kind: ceremony.kind,
            purpose: ceremony.purpose,
            options: serde_json::from_str(&options)
                .map_err(|_| Error::Protocol("browser options are invalid".into()))?,
        }));
    }

    let (challenge_id, options) = if ceremony.kind == "register" {
        let result = passkey::registration_options(&state, &ceremony.wallet_id).await?;
        (result.challenge_id, result.options)
    } else {
        let operation_id = ceremony.operation_id.clone().ok_or(Error::Authentication)?;
        let digest = ceremony.digest.clone().ok_or(Error::Authentication)?;
        let result = passkey::assertion_options(
            &state,
            &AssertOptionsRequest {
                wallet_id: ceremony.wallet_id.clone(),
                purpose: ceremony.purpose.clone(),
                operation_id,
                digest,
            },
        )
        .await?;
        (result.challenge_id, result.options)
    };
    let serialized = serde_json::to_string(&options)
        .map_err(|_| Error::Protocol("browser options could not be encoded".into()))?;
    if !state
        .store
        .set_browser_challenge(&session_id, &challenge_id, &serialized)
        .await?
    {
        let retry = state
            .store
            .browser_ceremony(&session_id)
            .await?
            .ok_or(Error::Authentication)?;
        let serialized = retry.options.ok_or(Error::Authentication)?;
        return Ok(json_response(&BrowserOptions {
            kind: retry.kind,
            purpose: retry.purpose,
            options: serde_json::from_str(&serialized)
                .map_err(|_| Error::Protocol("browser options are invalid".into()))?,
        }));
    }
    Ok(json_response(&BrowserOptions {
        kind: ceremony.kind,
        purpose: ceremony.purpose,
        options,
    }))
}

/// Accepts only the browser's WebAuthn response JSON body and verifies it server-side.
pub async fn finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(credential): Json<Value>,
) -> Result<Response, ApiError> {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        != Some(state.passkey.origin.as_str())
    {
        tracing::warn!("browser ceremony finished from an unexpected origin");
        return Err(Error::Authentication.into());
    }
    let session_id = session_cookie(&headers)?;
    let ceremony = state
        .store
        .browser_ceremony(&session_id)
        .await?
        .ok_or_else(|| {
            tracing::warn!("browser ceremony session is unknown or expired");
            Error::Authentication
        })?;
    let challenge_id = ceremony.challenge_id.ok_or_else(|| {
        tracing::warn!("browser ceremony finished before it was given a challenge");
        Error::Authentication
    })?;
    if ceremony.kind == "register" {
        passkey::verify_registration(&state, &ceremony.wallet_id, &challenge_id, &credential)
            .await?;
    } else {
        let request = AssertFinishRequest {
            wallet_id: ceremony.wallet_id.clone(),
            challenge_id,
            purpose: ceremony.purpose,
            operation_id: ceremony.operation_id.ok_or(Error::Authentication)?,
            digest: ceremony.digest.ok_or(Error::Authentication)?,
            credential,
        };
        passkey::verify_assertion(&state, &request).await?;
    }
    if !state.store.complete_browser_ceremony(&session_id).await? {
        tracing::warn!("browser ceremony was already completed or has expired");
        return Err(Error::Authentication.into());
    }
    Ok(json_response(&BrowserFinishResponse { verified: true }))
}

fn passkey_hash(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn session_cookie(headers: &HeaderMap) -> Result<String, ApiError> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Authentication)?;
    let value = cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == SESSION_COOKIE).then_some(value)
    });
    let value = value.ok_or(Error::Authentication)?;
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(Error::Authentication.into());
    }
    Ok(value.to_owned())
}

fn json_response<T: Serialize>(value: &T) -> Response {
    security_headers(Json(value).into_response())
}

fn security_headers(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'",
        ),
    );
    response
}
