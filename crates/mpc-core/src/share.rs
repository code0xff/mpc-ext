//! 키 셰어와 관련 식별자.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 프로토콜 참여자 식별자. `0 <= id < TOTAL_PARTIES`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct PartyId(pub u8);

/// 공동 공개키 (SEC1 압축 인코딩).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 33]);

/// 한 참여자가 보유하는 비밀 셰어.
///
/// - `Debug`는 내용을 가린다. 로그에 실수로 찍히더라도 비밀이 새지 않는다.
/// - `Drop` 시 zeroize된다.
/// - 평문으로 디스크에 쓰지 않는다. 저장은 항상 암호화 후 (`docs/security.md`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    #[zeroize(skip)]
    party: PartyId,
    secret: Vec<u8>,
}

impl KeyShare {
    /// 업스트림 백엔드가 만든 셰어 바이트를 감싼다.
    pub fn new(party: PartyId, secret: Vec<u8>) -> Self {
        Self { party, secret }
    }

    /// 이 셰어를 보유한 참여자.
    pub fn party(&self) -> PartyId {
        self.party
    }

    /// 비밀 바이트에 대한 접근. 호출부는 사용 후 즉시 폐기해야 한다.
    pub fn expose_secret(&self) -> &[u8] {
        &self.secret
    }
}

impl core::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyShare")
            .field("party", &self.party)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secret() {
        let share = KeyShare::new(PartyId(0), b"super-secret-material".to_vec());
        let rendered = format!("{share:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(
            !rendered.contains("super-secret"),
            "Debug 출력에 비밀이 노출되었다"
        );
    }
}
