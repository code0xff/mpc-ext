//! 파티별 세션이 봉투를 주고받아 실제로 맞물리는지 검증한다.
//!
//! 이 경로가 Phase 3의 확장 ↔ 서버 배치에서 쓰인다. 전송 방법과 무관하게
//! 프로토콜이 성립하는지 먼저 확인한다.

// 테스트에서 panic은 단언 수단이다. 프로덕션 코드에는 이 lint가 그대로 적용된다.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use mpc_core::{protocol, sign, verify, DkgParty, Envelope, PartyId, Progress, TOTAL_PARTIES};

fn session_id(tag: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = tag;
    id[31] = 0xC3;
    id
}

#[test]
fn distributed_dkg_matches_the_local_harness_shape() {
    let (shares, public_key) = protocol::run_locally(&session_id(1)).expect("DKG가 성공해야 한다");

    assert_eq!(shares.len(), TOTAL_PARTIES as usize);
    assert!(matches!(public_key.0[0], 0x02 | 0x03));

    // 봉투를 거쳐 만들어진 셰어도 임의의 두 개로 서명할 수 있어야 한다.
    let digest = [0x31u8; 32];
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let signature = sign(&[&shares[a], &shares[b]], &session_id(0xEE), &digest)
            .expect("두 셰어로 서명할 수 있어야 한다");
        assert!(
            verify(&public_key, &digest, &signature).expect("검증이 실행되어야 한다"),
            "셰어 {a}+{b}의 서명이 검증되어야 한다"
        );
    }
}

#[test]
fn envelopes_survive_serialization() {
    // 실제 배치에서는 봉투가 네트워크를 건너간다. 직렬화를 거쳐도 동작해야 한다.
    let (mut party, outgoing) = DkgParty::start(PartyId(0), &session_id(2)).expect("시작해야 한다");

    let round_trip: Vec<Envelope> = outgoing
        .iter()
        .map(|envelope| {
            let bytes = serde_json::to_vec(envelope).expect("직렬화되어야 한다");
            serde_json::from_slice(&bytes).expect("역직렬화되어야 한다")
        })
        .collect();

    assert_eq!(round_trip.len(), (TOTAL_PARTIES - 1) as usize);
    for envelope in &round_trip {
        assert_eq!(envelope.round, 1);
        assert_eq!(envelope.from, PartyId(0));
        assert!(envelope.to.is_some(), "라운드 1은 p2p여야 한다");
    }

    // 자기 자신에게 온 봉투가 아니면 거부해야 한다.
    let misrouted = Envelope {
        round: 1,
        from: PartyId(1),
        to: Some(PartyId(2)),
        payload: vec![0; 8],
    };
    assert!(
        party.advance(&[misrouted]).is_err(),
        "다른 파티 앞으로 온 봉투를 받아들이면 안 된다"
    );
}

#[test]
fn rejects_out_of_order_rounds() {
    let (mut party, _) = DkgParty::start(PartyId(0), &session_id(3)).expect("시작해야 한다");

    let from_the_future = Envelope {
        round: 3,
        from: PartyId(1),
        to: Some(PartyId(0)),
        payload: vec![0; 8],
    };

    assert!(
        matches!(
            party.advance(&[from_the_future]),
            Err(mpc_core::Error::UnexpectedRound { .. })
        ),
        "라운드 순서를 어긴 봉투는 거부해야 한다"
    );
}

#[test]
fn dkg_fails_without_every_party() {
    let (mut party, _) = DkgParty::start(PartyId(0), &session_id(4)).expect("시작해야 한다");

    // 세 파티 중 하나의 조각만 도착한 상태로 진행하면 실패해야 한다.
    let (_, from_one) = DkgParty::start(PartyId(1), &session_id(4)).expect("시작해야 한다");
    let addressed: Vec<Envelope> = from_one
        .into_iter()
        .filter(|e| e.to == Some(PartyId(0)))
        .collect();

    let result = party.advance(&addressed);

    assert!(
        matches!(result, Err(mpc_core::Error::InvalidPartyCount { .. })),
        "파티가 모자라면 DKG가 진행되면 안 된다"
    );
}

#[test]
fn progress_reports_the_expected_shape() {
    let (mut party, outgoing) = DkgParty::start(PartyId(0), &session_id(5)).expect("시작해야 한다");
    assert_eq!(party.party(), PartyId(0));
    assert_eq!(outgoing.len(), (TOTAL_PARTIES - 1) as usize);

    // 다른 두 파티의 라운드 1 조각을 모아 넣으면 라운드 2 메시지가 나와야 한다.
    let mut inbox = Vec::new();
    for other in [PartyId(1), PartyId(2)] {
        let (_, sent) = DkgParty::start(other, &session_id(5)).expect("시작해야 한다");
        inbox.extend(sent.into_iter().filter(|e| e.to == Some(PartyId(0))));
    }

    match party.advance(&inbox).expect("라운드 2로 넘어가야 한다") {
        Progress::Send(messages) => {
            assert!(
                messages.iter().any(|m| m.to.is_none()),
                "라운드 2에는 브로드캐스트가 있어야 한다"
            );
            assert!(
                messages.iter().any(|m| m.to.is_some()),
                "라운드 2에는 p2p 메시지도 있어야 한다"
            );
            assert!(messages.iter().all(|m| m.round == 2));
        }
        Progress::Done { .. } => panic!("라운드 2에서 끝나면 안 된다"),
    }
}
