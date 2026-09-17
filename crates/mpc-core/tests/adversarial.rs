//! 잘못되거나 악의적인 입력에 대한 방어 테스트.
//!
//! 프로토콜 라운드 내부의 메시지 조작은 업스트림이 자체 테스트로 다룬다
//! (`refresh_complete_phase4_aborts_on_tampered_enc_proof` 등). 여기서는
//! **`mpc-core`의 경계**에 들어오는 입력을 다룬다 — 확장 background와 서버
//! 핸들러가 실제로 넘기게 될 값들이다.

// 테스트에서 panic은 단언 수단이다. 프로덕션 코드에는 이 lint가 그대로 적용된다.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use mpc_core::{dkg, export_private_key, refresh, reshare, sign, verify, Error, KeyShare, PartyId};

fn session_id(tag: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = tag;
    id[31] = 0x5A;
    id
}

fn digest(tag: u8) -> [u8; 32] {
    let mut d = [0x22u8; 32];
    d[0] = tag;
    d
}

fn share_of(shares: &[KeyShare], party: u8) -> &KeyShare {
    shares
        .iter()
        .find(|s| s.party() == PartyId(party))
        .expect("파티의 셰어가 있어야 한다")
}

#[test]
fn rejects_a_share_with_corrupted_bytes() {
    let (shares, _) = dkg(&session_id(10)).expect("DKG가 성공해야 한다");

    let mut corrupted = share_of(&shares, 0).expose_secret().to_vec();
    corrupted[8] ^= 0xFF;
    let corrupted = KeyShare::new(PartyId(0), corrupted);

    let result = sign(
        &[&corrupted, share_of(&shares, 1)],
        &session_id(0xEE),
        &digest(1),
    );

    assert!(result.is_err(), "손상된 셰어로는 서명이 만들어지면 안 된다");
}

#[test]
fn rejects_shares_from_different_keysets() {
    // 공격자가 자기 지갑의 셰어를 섞어 넣는 상황.
    let (first, public_key) = dkg(&session_id(11)).expect("DKG가 성공해야 한다");
    let (second, _) = dkg(&session_id(12)).expect("DKG가 성공해야 한다");
    let msg = digest(2);

    let result = sign(
        &[share_of(&first, 0), share_of(&second, 1)],
        &session_id(0xEE),
        &msg,
    );

    let verified = match result {
        Err(_) => false,
        Ok(signature) => verify(&public_key, &msg, &signature).unwrap_or(false),
    };

    assert!(
        !verified,
        "서로 다른 키셋의 셰어를 섞은 서명이 유효해서는 안 된다"
    );
}

#[test]
fn rejects_the_same_share_used_twice() {
    // 셰어 하나를 두 번 넣어 임계값을 속이려는 시도.
    let (shares, _) = dkg(&session_id(13)).expect("DKG가 성공해야 한다");
    let only_one = share_of(&shares, 0);

    let result = sign(&[only_one, only_one], &session_id(0xEE), &digest(3));

    assert!(
        result.is_err(),
        "같은 셰어를 두 번 써서 임계값을 채울 수 없어야 한다"
    );
}

#[test]
fn refresh_requires_every_party() {
    let (shares, _) = dkg(&session_id(14)).expect("DKG가 성공해야 한다");
    let partial = vec![share_of(&shares, 0).clone(), share_of(&shares, 1).clone()];

    let result = refresh(&partial, &session_id(0x60));

    assert!(
        matches!(result, Err(Error::InvalidPartyCount { got: 2, .. })),
        "리프레시는 파티 전원을 요구해야 한다"
    );
}

#[test]
fn export_requires_the_threshold() {
    let (shares, _) = dkg(&session_id(15)).expect("DKG가 성공해야 한다");

    let result = export_private_key(&[share_of(&shares, 0)]);

    assert!(
        matches!(result, Err(Error::InvalidPartyCount { got: 1, .. })),
        "셰어 하나로는 개인키를 추출할 수 없어야 한다"
    );
}

#[test]
fn export_rejects_a_duplicated_share() {
    let (shares, _) = dkg(&session_id(16)).expect("DKG가 성공해야 한다");
    let only_one = share_of(&shares, 0);

    let result = export_private_key(&[only_one, only_one]);

    assert!(
        result.is_err(),
        "같은 셰어를 두 번 넣어 개인키를 복원할 수 없어야 한다"
    );
}

#[test]
fn exported_key_matches_the_public_key() {
    let (shares, public_key) = dkg(&session_id(17)).expect("DKG가 성공해야 한다");

    // 어떤 2셰어 조합으로 추출하든 같은 개인키가 나와야 하고,
    // 그 개인키의 공개키가 키셋의 공개키와 같아야 한다.
    let from_ab = export_private_key(&[share_of(&shares, 0), share_of(&shares, 1)])
        .expect("추출이 성공해야 한다");
    let from_bc = export_private_key(&[share_of(&shares, 1), share_of(&shares, 2)])
        .expect("추출이 성공해야 한다");

    assert_eq!(
        from_ab.0, from_bc.0,
        "조합에 따라 개인키가 달라서는 안 된다"
    );

    let signing_key =
        k256::ecdsa::SigningKey::from_slice(&from_ab.0).expect("유효한 개인키여야 한다");
    let derived = signing_key.verifying_key().to_sec1_bytes();

    assert_eq!(
        derived.as_ref(),
        &public_key.0[..],
        "추출한 개인키의 공개키가 키셋의 공개키와 같아야 한다"
    );
}

#[test]
fn reshare_preserves_the_public_key_and_invalidates_old_shares() {
    let (shares, public_key) = dkg(&session_id(18)).expect("DKG가 성공해야 한다");

    // 셰어 하나를 잃은 상황: 남은 둘로 새 셋을 발급한다.
    let (fresh, fresh_public_key) = reshare(
        &[share_of(&shares, 0), share_of(&shares, 1)],
        &session_id(0x70),
    )
    .expect("리셰어가 성공해야 한다");

    assert_eq!(fresh.len(), 3, "다시 셰어 3개가 되어야 한다");
    assert_eq!(
        fresh_public_key.0, public_key.0,
        "리셰어는 주소를 바꾸지 않아야 한다"
    );

    // 새 셰어로 서명이 되고, 원래 공개키로 검증된다.
    let msg = digest(4);
    let signature = sign(
        &[share_of(&fresh, 0), share_of(&fresh, 2)],
        &session_id(0xEE),
        &msg,
    )
    .expect("새 셰어로 서명할 수 있어야 한다");
    assert!(verify(&public_key, &msg, &signature).expect("검증이 실행되어야 한다"));

    // 분실을 가정한 옛 셰어는 새 셰어와 섞이지 않아야 한다.
    let mixed = sign(
        &[share_of(&shares, 2), share_of(&fresh, 0)],
        &session_id(0xEE),
        &msg,
    );
    let verified = match mixed {
        Err(_) => false,
        Ok(signature) => verify(&public_key, &msg, &signature).unwrap_or(false),
    };
    assert!(!verified, "옛 셰어가 새 셋에서 계속 통하면 안 된다");
}
