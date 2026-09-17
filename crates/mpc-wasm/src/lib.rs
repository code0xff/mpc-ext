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

/// An envelope shaped for the wire.
///
/// Payloads reach 100 KB, and encoding those as a JSON array of numbers costs several times
/// the bytes and a great deal of parse time on both sides. Base64 keeps them compact and means
/// the extension can forward what it receives to the server untouched.
#[derive(serde::Serialize, serde::Deserialize)]
struct WireEnvelope {
    round: u8,
    from: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<u8>,
    payload: String,
}

fn envelopes_to_json(envelopes: &[mpc_core::Envelope]) -> Result<String, JsValue> {
    let wire: Vec<WireEnvelope> = envelopes
        .iter()
        .map(|envelope| WireEnvelope {
            round: envelope.round,
            from: envelope.from.0,
            to: envelope.to.map(|party| party.0),
            payload: base64_encode(&envelope.payload),
        })
        .collect();
    serde_json::to_string(&wire).map_err(|e| JsValue::from_str(&format!("encode: {e}")))
}

fn envelopes_from_json(json: &str) -> Result<Vec<mpc_core::Envelope>, JsValue> {
    let wire: Vec<WireEnvelope> =
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&format!("decode: {e}")))?;
    wire.into_iter()
        .map(|envelope| {
            Ok(mpc_core::Envelope {
                round: envelope.round,
                from: mpc_core::PartyId(envelope.from),
                to: envelope.to.map(mpc_core::PartyId),
                payload: base64_decode(&envelope.payload)?,
            })
        })
        .collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(value: &str) -> Result<Vec<u8>, JsValue> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| JsValue::from_str("payload is not valid base64"))
}

/// One party in a distributed key generation.
///
/// The extension drives parties 0 and 1; the server drives party 2. Hand the envelopes from
/// [`Self::outgoing`] to the other side, then feed what comes back into [`Self::advance`].
#[wasm_bindgen]
#[derive(Debug)]
pub struct DkgSession {
    inner: Option<mpc_core::DkgParty>,
    outgoing: String,
    share: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl DkgSession {
    /// Starts a party and produces its round 1 envelopes.
    #[wasm_bindgen(constructor)]
    pub fn new(party: u8, session_id: &[u8]) -> Result<DkgSession, JsValue> {
        let session = session_from(session_id)?;
        let (inner, outgoing) =
            mpc_core::DkgParty::start(mpc_core::PartyId(party), &session).map_err(to_js)?;
        Ok(Self {
            inner: Some(inner),
            outgoing: envelopes_to_json(&outgoing)?,
            share: None,
            public_key: None,
        })
    }

    /// The envelopes this party wants to send, as JSON.
    #[wasm_bindgen(getter)]
    pub fn outgoing(&self) -> String {
        self.outgoing.clone()
    }

    /// True once the protocol has finished.
    #[wasm_bindgen(getter)]
    pub fn finished(&self) -> bool {
        self.share.is_some()
    }

    /// This party's share. Empty until the protocol finishes.
    #[wasm_bindgen(getter)]
    pub fn share(&self) -> Vec<u8> {
        self.share.clone().unwrap_or_default()
    }

    /// The joint public key. Empty until the protocol finishes.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone().unwrap_or_default()
    }

    /// Consumes a JSON array of envelopes and advances one round.
    pub fn advance(&mut self, inbox: &str) -> Result<(), JsValue> {
        let inbox = envelopes_from_json(inbox)?;
        let party = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("this session has already finished"))?;

        match party.advance(&inbox).map_err(to_js)? {
            mpc_core::Progress::Send(outgoing) => {
                self.outgoing = envelopes_to_json(&outgoing)?;
            }
            mpc_core::Progress::Done { share, public_key } => {
                self.share = Some(share.expose_secret().to_vec());
                self.public_key = Some(public_key.0.to_vec());
                self.outgoing = "[]".into();
                self.inner = None;
            }
        }
        Ok(())
    }
}

/// One party in a threshold signature.
///
/// Used for both the everyday path (extension share plus the server) and the offline fallback
/// (extension share plus the recovery file).
#[wasm_bindgen]
#[derive(Debug)]
pub struct SignSession {
    inner: Option<mpc_core::SignParty>,
    outgoing: String,
    signature: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl SignSession {
    /// Starts a signing party and produces its round 1 envelopes.
    #[wasm_bindgen(constructor)]
    pub fn new(
        share: &[u8],
        party: u8,
        counterparty: u8,
        sign_id: &[u8],
        digest: &[u8],
    ) -> Result<SignSession, JsValue> {
        let sign_id = session_from(sign_id)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| JsValue::from_str("digest must be 32 bytes"))?;

        let share = mpc_core::KeyShare::new(mpc_core::PartyId(party), share.to_vec());
        let (inner, outgoing) =
            mpc_core::SignParty::start(&share, mpc_core::PartyId(counterparty), &sign_id, &digest)
                .map_err(to_js)?;

        Ok(Self {
            inner: Some(inner),
            outgoing: envelopes_to_json(&outgoing)?,
            signature: None,
        })
    }

    /// The envelopes this party wants to send, as JSON.
    #[wasm_bindgen(getter)]
    pub fn outgoing(&self) -> String {
        self.outgoing.clone()
    }

    /// True once a signature is available.
    #[wasm_bindgen(getter)]
    pub fn finished(&self) -> bool {
        self.signature.is_some()
    }

    /// The signature as 65 bytes (r || s || v). Empty until finished.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone().unwrap_or_default()
    }

    /// Consumes a JSON array of envelopes and advances one round.
    pub fn advance(&mut self, inbox: &str) -> Result<(), JsValue> {
        let inbox = envelopes_from_json(inbox)?;
        let party = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("this session has already finished"))?;

        match party.advance(&inbox).map_err(to_js)? {
            mpc_core::SignProgress::Send(outgoing) => {
                self.outgoing = envelopes_to_json(&outgoing)?;
            }
            mpc_core::SignProgress::Done(signature) => {
                let mut bytes = Vec::with_capacity(65);
                bytes.extend_from_slice(&signature.r);
                bytes.extend_from_slice(&signature.s);
                bytes.push(signature.recovery_id);
                self.signature = Some(bytes);
                self.outgoing = "[]".into();
                self.inner = None;
            }
        }
        Ok(())
    }
}
