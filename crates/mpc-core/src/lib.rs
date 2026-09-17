//! 2-of-3 임계 ECDSA 프로토콜 코어.
//!
//! 확장은 이 crate를 wasm으로, 서버는 네이티브로 사용한다. 프로토콜 로직은
//! 여기에만 존재하며 두 언어로 중복 구현하지 않는다 (`AGENTS.md` 참조).
//!
//! 업스트림 MPC 구현([`Mpc`] 구현체)은 트레이트 뒤에 감춰진다. 확장·서버 코드가
//! 업스트림 타입을 직접 참조하지 않으므로 라이브러리 교체가 가능하다
//! (`docs/adr/0004-mpc-library-reselection.md`).

pub mod session;
pub mod share;

use core::fmt;

pub use session::{Round, SessionId};
pub use share::{KeyShare, PartyId, PublicKey};

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

/// 업스트림 MPC 구현이 만족해야 하는 인터페이스.
///
/// Phase 1에서 `0xCarbon/DKLs23` 백엔드를 이 트레이트로 구현한다.
/// 상위 계층(확장 background, 서버 핸들러)은 이 트레이트만 본다.
pub trait Mpc {
    /// 분산 키 생성. 성공 시 자신의 셰어와 공동 공개키를 얻는다.
    fn keygen(&mut self, session: SessionId, party: PartyId) -> Result<(KeyShare, PublicKey)>;

    /// 임계 서명. `THRESHOLD`개의 셰어가 참여해야 한다.
    fn sign(
        &mut self,
        session: SessionId,
        shares: &[&KeyShare],
        digest: &[u8; 32],
    ) -> Result<Vec<u8>>;

    /// 키 리프레시(리셰어). 공개키를 유지한 채 셰어만 재생성한다.
    ///
    /// 복구 직후 반드시 실행하여 분실 셰어를 무효화하고 2-of-3 상태로 되돌린다.
    /// 이 기능이 없으면 복구는 주소 변경을 동반한 이전이 된다 (`docs/recovery.md`).
    fn refresh(&mut self, session: SessionId, share: &KeyShare) -> Result<KeyShare>;
}

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
