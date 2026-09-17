//! wasm bindings for `mpc-core`.
//!
//! This layer only converts types. Protocol logic never lives here. Shares stay inside wasm
//! memory, and all that crosses into JS is opaque bytes.

use mpc_core::{THRESHOLD, TOTAL_PARTIES};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

/// Reports this build's threshold configuration as `"2-of-3"`.
///
/// The extension UI also uses it as a health check that wasm loaded.
#[wasm_bindgen]
pub fn threshold_config() -> String {
    format!("{THRESHOLD}-of-{TOTAL_PARTIES}")
}

fn to_js(err: mpc_core::Error) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn session_from(bytes: &[u8]) -> Result<[u8; 32], JsValue> {
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str("session id must be 32 bytes"))
}

/// The result of a DKG. Shares are opaque bytes and must be encrypted before storage.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Keyset {
    shares: Vec<Vec<u8>>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl Keyset {
    /// How many shares there are.
    #[wasm_bindgen(getter)]
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// The bytes of share `index`.
    pub fn share(&self, index: usize) -> Result<Vec<u8>, JsValue> {
        self.shares
            .get(index)
            .cloned()
            .ok_or_else(|| JsValue::from_str("share index out of range"))
    }

    /// The SEC1 compressed public key, 33 bytes.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// Three-party distributed key generation.
#[wasm_bindgen]
pub fn dkg(session_id: &[u8]) -> Result<Keyset, JsValue> {
    let session = session_from(session_id)?;
    let (shares, public_key) = mpc_core::dkg(&session).map_err(to_js)?;
    Ok(Keyset {
        shares: shares.iter().map(|s| s.expose_secret().to_vec()).collect(),
        public_key: public_key.0.to_vec(),
    })
}

/// Signs with two shares. Returns 65 bytes: r || s || v.
#[wasm_bindgen]
pub fn sign(
    share_a: &[u8],
    party_a: u8,
    share_b: &[u8],
    party_b: u8,
    sign_id: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sign_id = session_from(sign_id)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| JsValue::from_str("digest must be 32 bytes"))?;

    let a = mpc_core::KeyShare::new(mpc_core::PartyId(party_a), share_a.to_vec());
    let b = mpc_core::KeyShare::new(mpc_core::PartyId(party_b), share_b.to_vec());

    let signature = mpc_core::sign(&[&a, &b], &sign_id, &digest).map_err(to_js)?;

    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&signature.r);
    out.extend_from_slice(&signature.s);
    out.push(signature.recovery_id);
    Ok(out)
}

/// Regenerates all three shares. The public key is preserved.
#[wasm_bindgen]
pub fn refresh(keyset: &Keyset, session_id: &[u8]) -> Result<Keyset, JsValue> {
    let session = session_from(session_id)?;
    let shares: Vec<mpc_core::KeyShare> = keyset
        .shares
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            mpc_core::KeyShare::new(
                mpc_core::PartyId(u8::try_from(i).unwrap_or(u8::MAX)),
                bytes.clone(),
            )
        })
        .collect();

    let refreshed = mpc_core::refresh(&shares, &session).map_err(to_js)?;
    Ok(Keyset {
        shares: refreshed
            .iter()
            .map(|s| s.expose_secret().to_vec())
            .collect(),
        public_key: keyset.public_key.clone(),
    })
}

/// Checks a signature against a public key.
#[wasm_bindgen]
pub fn verify(public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let pk: [u8; 33] = public_key
        .try_into()
        .map_err(|_| JsValue::from_str("public key must be 33 bytes"))?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| JsValue::from_str("digest must be 32 bytes"))?;
    if signature.len() != 65 {
        return Err(JsValue::from_str("signature must be 65 bytes"));
    }

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..64]);

    mpc_core::verify(
        &mpc_core::PublicKey(pk),
        &digest,
        &mpc_core::Signature {
            r,
            s,
            recovery_id: signature[64],
        },
    )
    .map_err(to_js)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_two_of_three() {
        assert_eq!(threshold_config(), "2-of-3");
    }
}
