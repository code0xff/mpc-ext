//! 2-of-3 프로토콜 통합 테스트.
//!
//! 모든 파티를 한 프로세스에서 실행한다. 실제 배포의 파티 분리는 Phase 3에서
//! 붙지만, 라운드별 메시지 경로는 동일하므로 프로토콜 성질은 여기서 검증된다.

// 테스트에서 panic은 단언 수단이다. 프로덕션 코드에는 이 lint가 그대로 적용된다.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use mpc_core::{
    dkg, refresh, sign, verify, KeyShare, PartyId, Signature, THRESHOLD, TOTAL_PARTIES,
};

/// 테스트 픽스처용 더미 세션 ID. 실제 값은 매 세션 무작위로 생성된다.
fn session_id(tag: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = tag;
    id[31] = 0xA5;
    id
}

fn digest(tag: u8) -> [u8; 32] {
    let mut d = [0x11u8; 32];
    d[0] = tag;
    d
}

/// 셰어 목록에서 특정 파티의 셰어를 찾는다.
fn share_of(shares: &[KeyShare], party: u8) -> &KeyShare {
    shares
        .iter()
        .find(|s| s.party() == PartyId(party))
        .expect("파티의 셰어가 있어야 한다")
}

fn sign_with(shares: &[KeyShare], a: u8, b: u8, msg: &[u8; 32]) -> Signature {
    sign(
        &[share_of(shares, a), share_of(shares, b)],
        &session_id(0xEE),
        msg,
    )
    .expect("두 셰어로 서명할 수 있어야 한다")
}

#[test]
fn dkg_produces_three_shares_under_one_public_key() {
    let (shares, public_key) = dkg(&session_id(1)).expect("DKG가 성공해야 한다");

    assert_eq!(shares.len(), TOTAL_PARTIES as usize);
    let mut parties: Vec<u8> = shares.iter().map(|s| s.party().0).collect();
    parties.sort_unstable();
    assert_eq!(parties, vec![0, 1, 2], "파티 식별자가 0,1,2여야 한다");

    // SEC1 압축 인코딩의 첫 바이트는 0x02 또는 0x03이다.
    assert!(matches!(public_key.0[0], 0x02 | 0x03));
}

#[test]
fn any_two_of_three_shares_can_sign() {
    let (shares, public_key) = dkg(&session_id(2)).expect("DKG가 성공해야 한다");
    let msg = digest(0x42);

    // 평시 경로(확장의 A+B)와 복구 경로(A+C, B+C)가 모두 동작해야 한다.
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let signature = sign_with(&shares, a, b, &msg);
        assert!(
            verify(&public_key, &msg, &signature).expect("검증이 실행되어야 한다"),
            "셰어 {a}+{b} 조합의 서명이 공개키로 검증되어야 한다"
        );
    }
}

#[test]
fn a_single_share_cannot_sign() {
    let (shares, _) = dkg(&session_id(3)).expect("DKG가 성공해야 한다");

    let result = sign(&[share_of(&shares, 0)], &session_id(0xEE), &digest(1));

    assert!(
        matches!(
            result,
            Err(mpc_core::Error::InvalidPartyCount { expected, got })
                if expected == THRESHOLD && got == 1
        ),
        "셰어 하나로는 서명할 수 없어야 한다"
    );
}

#[test]
fn refresh_preserves_the_public_key() {
    let (shares, public_key) = dkg(&session_id(4)).expect("DKG가 성공해야 한다");
    let refreshed = refresh(&shares, &session_id(0x40)).expect("리프레시가 성공해야 한다");

    assert_eq!(refreshed.len(), TOTAL_PARTIES as usize);

    // 공개키가 유지되어야 복구가 '이전'이 아닌 '복구'가 된다 (docs/recovery.md).
    let msg = digest(0x77);
    let signature = sign_with(&refreshed, 0, 1, &msg);
    assert!(
        verify(&public_key, &msg, &signature).expect("검증이 실행되어야 한다"),
        "리프레시 후에도 같은 공개키로 검증되어야 한다"
    );
}

#[test]
fn refresh_invalidates_the_old_shares() {
    let (shares, public_key) = dkg(&session_id(5)).expect("DKG가 성공해야 한다");
    let refreshed = refresh(&shares, &session_id(0x50)).expect("리프레시가 성공해야 한다");
    let msg = digest(2);

    // 복구의 핵심 보안 성질: 옛 셰어와 새 셰어를 섞어서는 유효한 서명을 만들 수
    // 없어야 한다. 그래야 분실한 셰어가 실제로 무효가 된다 (docs/recovery.md).
    let mixed = sign(
        &[share_of(&shares, 0), share_of(&refreshed, 1)],
        &session_id(0xEE),
        &msg,
    );

    let verified = match mixed {
        // 프로토콜이 중단되는 것이 정상 경로다.
        Err(_) => false,
        // 서명이 나오더라도 원래 공개키로 검증되어서는 안 된다.
        Ok(signature) => verify(&public_key, &msg, &signature).unwrap_or(false),
    };

    assert!(
        !verified,
        "옛 셰어와 새 셰어를 섞은 서명이 유효해서는 안 된다"
    );
}
