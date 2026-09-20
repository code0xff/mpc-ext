//! Device-key request authentication.

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{header, HeaderMap};
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::de::DeserializeOwned;

use crate::api::ApiError;
use crate::{store::Store, Error};

const MAX_CLOCK_SKEW_MS: i64 = 300_000;
const NONCE_TTL_SECONDS: i64 = 600;

/// A JSON request body together with the exact text that arrived.
///
/// The device proof covers those bytes. Verifying against a re-serialization of the parsed value
/// instead would let the two sides disagree over key order, escaping or how an absent field is
/// written, and a `register` handoff was once rejected for a single `null`.
pub struct SignedJson<T> {
    /// The parsed body.
    pub value: T,
    /// The body exactly as it was received.
    pub raw: String,
}

impl<T> core::fmt::Debug for SignedJson<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Bodies can carry protocol messages, so never print them.
        f.debug_struct("SignedJson")
            .field("raw_len", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl<S, T> FromRequest<S> for SignedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                let essence = value.split(';').next().unwrap_or("").trim();
                essence == "application/json" || essence.ends_with("+json")
            });
        if !is_json {
            return Err(Error::Protocol("the request body must be JSON".into()).into());
        }
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(|_| Error::Protocol("the request body could not be read".into()))?;
        let raw = String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::Protocol("the request body is not UTF-8".into()))?;
        let value = serde_json::from_str(&raw)
            .map_err(|_| Error::Protocol("the request body is malformed".into()))?;
        Ok(Self { value, raw })
    }
}

/// Verifies and consumes the device proof attached to a request, against the wallet's current
/// device key.
///
/// `raw` is the body exactly as received. Use [`SignedJson`] to obtain it.
pub async fn authenticate(
    store: &Store,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    wallet_id: &str,
    raw: &str,
) -> Result<(), Error> {
    let public_key = store
        .device_key(wallet_id)
        .await?
        .ok_or(Error::Authentication)?;
    authenticate_with_key(store, headers, method, path, wallet_id, raw, &public_key).await
}

/// Verifies and consumes a device proof against a specific public key.
///
/// A recovery is signed with the key that is waiting to replace the wallet's current one, so the
/// key cannot always be looked up from the wallet.
pub async fn authenticate_with_key(
    store: &Store,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    wallet_id: &str,
    raw: &str,
    public_key: &[u8],
) -> Result<(), Error> {
    let timestamp = header_i64(headers, "x-device-timestamp")?;
    let nonce = header(headers, "x-device-nonce")?;
    let signature_b64 = header(headers, "x-device-signature")?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let now = i64::try_from(now).map_err(|_| Error::Authentication)?;
    if (now - timestamp).abs() > MAX_CLOCK_SKEW_MS || nonce.is_empty() || nonce.len() > 128 {
        return Err(Error::Authentication);
    }

    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| Error::Authentication)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.as_bytes())
        .map_err(|_| Error::Authentication)?;
    let signature = Signature::from_slice(&signature).map_err(|_| Error::Authentication)?;
    let message = format!("{method}\n{path}\n{timestamp}\n{nonce}\n{raw}");
    key.verify(message.as_bytes(), &signature)
        .map_err(|_| Error::Authentication)?;

    if !store
        .reserve_device_nonce(wallet_id, nonce, NONCE_TTL_SECONDS)
        .await?
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Error> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Authentication)
}

fn header_i64(headers: &HeaderMap, name: &str) -> Result<i64, Error> {
    header(headers, name)?
        .parse()
        .map_err(|_| Error::Authentication)
}
