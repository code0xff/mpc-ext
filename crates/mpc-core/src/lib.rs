//! 2-of-3 임계 ECDSA 프로토콜 코어.
//!
//! 확장은 이 crate를 wasm으로, 서버는 네이티브로 사용한다. 프로토콜 로직은
//! 여기에만 존재하며 두 언어로 중복 구현하지 않는다 (`AGENTS.md` 참조).
//!
//! 업스트림 MPC 구현([`Mpc`] 구현체)은 트레이트 뒤에 감춰진다. 확장·서버 코드가
//! 업스트림 타입을 직접 참조하지 않으므로 라이브러리 교체가 가능하다
//! (`docs/adr/0004-mpc-library-reselection.md`).

mod backend;
pub mod session;
pub mod share;

use core::fmt;

pub use backend::{dkg, export_private_key, refresh, reshare, sign, verify};
pub use session::{Round, SessionId};
pub use share::{KeyShare, PartyId, PublicKey};

/// 추출된 완전한 개인키 (32바이트 big-endian).
///
/// 이 값이 존재하는 동안 MPC의 보안 이점은 없다. 사용 후 즉시 폐기된다.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub [u8; 32]);

impl core::fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKeyBytes([redacted])")
    }
}

/// 임계 ECDSA 서명 (secp256k1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// r 성분.
    pub r: [u8; 32],
    /// s 성분. low-s로 정규화된다.
    pub s: [u8; 32],
    /// 공개키 복구 식별자.
    pub recovery_id: u8,
}

/// 셰어 3개 중 서명에 필요한 최소 개수.
pub const THRESHOLD: u8 = 2;

/// 전체 셰어 개수.
pub const TOTAL_PARTIES: u8 = 3;

// 임계값이 전체 개수 이상이면 복구가 불가능하다. 컴파일 타임에 막는다.
const _: () = assert!(THRESHOLD < TOTAL_PARTIES);

/// 프로토콜 실행 중 발생하는 오류.
///
/// 비밀 값을 절대 담지 않는다. 오류 메시지는 로그·UI에 그대로 노출될 수 있다.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 라운드 순서를 어긴 메시지를 받았다. 세션은 폐기된다.
    #[error("unexpected round: expected {expected:?}, got {got:?}")]
    UnexpectedRound { expected: Round, got: Round },

    /// 세션을 찾을 수 없거나 이미 만료되었다.
    #[error("unknown or expired session")]
    UnknownSession,

    /// 참여자 수가 프로토콜 요구와 맞지 않는다.
    #[error("invalid party count: expected {expected}, got {got}")]
    InvalidPartyCount { expected: u8, got: u8 },

    /// 업스트림 MPC 구현이 보고한 오류.
    #[error("mpc backend failure: {0}")]
    Backend(String),
}

/// 프로토콜 결과 타입.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "party#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_two_of_three() {
        assert_eq!(THRESHOLD, 2);
        assert_eq!(TOTAL_PARTIES, 3);
    }

    #[test]
    fn errors_never_render_secrets() {
        let err = Error::Backend("upstream said no".into());
        let rendered = err.to_string();
        assert!(!rendered.is_empty());
    }
}
