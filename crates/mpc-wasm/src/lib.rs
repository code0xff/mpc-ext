//! `mpc-core`의 wasm 바인딩.
//!
//! 이 계층은 타입 변환과 시간 측정만 담당한다. 프로토콜 로직을 여기에 두지 않는다.
//! 셰어는 wasm 메모리 안에 머물며, JS로 넘어가는 것은 불투명한 바이트뿐이다.

use mpc_core::{THRESHOLD, TOTAL_PARTIES};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

/// 이 빌드가 사용하는 임계 설정을 `"2-of-3"` 형태로 반환한다.
///
/// 확장 UI가 wasm 로딩 성공 여부를 확인하는 헬스체크로도 쓴다.
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

/// DKG 결과. 셰어는 불투명한 바이트이며, 저장 전에 반드시 암호화해야 한다.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Keyset {
    shares: Vec<Vec<u8>>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl Keyset {
    /// 셰어 개수.
    #[wasm_bindgen(getter)]
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// `index`번째 셰어의 바이트.
    pub fn share(&self, index: usize) -> Result<Vec<u8>, JsValue> {
        self.shares
            .get(index)
            .cloned()
            .ok_or_else(|| JsValue::from_str("share index out of range"))
    }

    /// SEC1 압축 공개키 (33바이트).
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// 3파티 분산 키 생성.
#[wasm_bindgen]
pub fn dkg(session_id: &[u8]) -> Result<Keyset, JsValue> {
    let session = session_from(session_id)?;
    let (shares, public_key) = mpc_core::dkg(&session).map_err(to_js)?;
    Ok(Keyset {
        shares: shares.iter().map(|s| s.expose_secret().to_vec()).collect(),
        public_key: public_key.0.to_vec(),
    })
}

/// 두 셰어로 서명한다. 65바이트(r‖s‖v)를 반환한다.
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

/// 세 셰어를 모두 재생성한다. 공개키는 유지된다.
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

/// 서명이 공개키에 대해 유효한지 검증한다.
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
