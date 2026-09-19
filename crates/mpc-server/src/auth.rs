//! Device-key request authentication.

use axum::http::HeaderMap;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Serialize;

use crate::{store::Store, Error};

const MAX_CLOCK_SKEW_MS: i64 = 300_000;
const NONCE_TTL_SECONDS: i64 = 600;

/// Verifies and consumes the device proof attached to a request.
pub async fn authenticate<T: Serialize>(
    store: &Store,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    wallet_id: &str,
    body: &T,
) -> Result<(), Error> {
    let timestamp = header_i64(headers, "x-device-timestamp")?;
    let nonce = header(headers, "x-device-nonce")?;
    let signature_b64 = header(headers, "x-device-signature")?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let now = i64::try_from(now).map_err(|_| Error::Authentication)?;
    if (now - timestamp).abs() > MAX_CLOCK_SKEW_MS || nonce.is_empty() || nonce.len() > 128 {
        return Err(Error::Authentication);
    }

    let public_key = store
        .device_key(wallet_id)
        .await?
        .ok_or(Error::Authentication)?;
    let key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| Error::Authentication)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.as_bytes())
        .map_err(|_| Error::Authentication)?;
    let signature = Signature::from_slice(&signature).map_err(|_| Error::Authentication)?;
    let serialized = serde_json::to_string(body).map_err(|_| Error::Authentication)?;
    let message = format!("{method}\n{path}\n{timestamp}\n{nonce}\n{serialized}");
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
