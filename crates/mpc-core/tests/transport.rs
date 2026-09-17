//! Checks that the per-party sessions actually mesh by exchanging envelopes.
//!
//! This is the path the split extension/server deployment uses. Here we establish that the
//! protocol holds regardless of how the envelopes travel.

// Panicking is how a test asserts. Production code keeps these lints.
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
    let (shares, public_key) = protocol::run_locally(&session_id(1)).expect("DKG should succeed");

    assert_eq!(shares.len(), TOTAL_PARTIES as usize);
    assert!(matches!(public_key.0[0], 0x02 | 0x03));

    // Shares produced through envelopes must still sign with any two of them.
    let digest = [0x31u8; 32];
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let signature = sign(&[&shares[a], &shares[b]], &session_id(0xEE), &digest)
            .expect("two shares should be able to sign");
        assert!(
            verify(&public_key, &digest, &signature).expect("verification should run"),
            "the signature from shares {a}+{b} should verify"
        );
    }
}

#[test]
fn envelopes_survive_serialization() {
    // In the real deployment envelopes cross a network, so they must survive a round trip.
    let (mut party, outgoing) =
        DkgParty::start(PartyId(0), &session_id(2)).expect("the party should start");

    let round_trip: Vec<Envelope> = outgoing
        .iter()
        .map(|envelope| {
            let bytes = serde_json::to_vec(envelope).expect("it should serialize");
            serde_json::from_slice(&bytes).expect("it should deserialize")
        })
        .collect();

    assert_eq!(round_trip.len(), (TOTAL_PARTIES - 1) as usize);
    for envelope in &round_trip {
        assert_eq!(envelope.round, 1);
        assert_eq!(envelope.from, PartyId(0));
        assert!(envelope.to.is_some(), "round 1 is point to point");
    }

    // An envelope addressed to somebody else must be rejected.
    let misrouted = Envelope {
        round: 1,
        from: PartyId(1),
        to: Some(PartyId(2)),
        payload: vec![0; 8],
    };
    assert!(
        party.advance(&[misrouted]).is_err(),
        "an envelope addressed to another party must not be accepted"
    );
}

#[test]
fn rejects_out_of_order_rounds() {
    let (mut party, _) =
        DkgParty::start(PartyId(0), &session_id(3)).expect("the party should start");

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
        "an envelope from the wrong round must be rejected"
    );
}

#[test]
fn dkg_fails_without_every_party() {
    let (mut party, _) =
        DkgParty::start(PartyId(0), &session_id(4)).expect("the party should start");

    // Advancing with only one of the two peers' fragments must fail.
    let (_, from_one) =
        DkgParty::start(PartyId(1), &session_id(4)).expect("the party should start");
    let addressed: Vec<Envelope> = from_one
        .into_iter()
        .filter(|e| e.to == Some(PartyId(0)))
        .collect();

    let result = party.advance(&addressed);

    assert!(
        matches!(result, Err(mpc_core::Error::InvalidPartyCount { .. })),
        "DKG must not advance with parties missing"
    );
}

#[test]
fn progress_reports_the_expected_shape() {
    let (mut party, outgoing) =
        DkgParty::start(PartyId(0), &session_id(5)).expect("the party should start");
    assert_eq!(party.party(), PartyId(0));
    assert_eq!(outgoing.len(), (TOTAL_PARTIES - 1) as usize);

    // Feeding in both peers' round 1 fragments should produce round 2 messages.
    let mut inbox = Vec::new();
    for other in [PartyId(1), PartyId(2)] {
        let (_, sent) = DkgParty::start(other, &session_id(5)).expect("the party should start");
        inbox.extend(sent.into_iter().filter(|e| e.to == Some(PartyId(0))));
    }

    match party.advance(&inbox).expect("it should advance to round 2") {
        Progress::Send(messages) => {
            assert!(
                messages.iter().any(|m| m.to.is_none()),
                "round 2 should contain a broadcast"
            );
            assert!(
                messages.iter().any(|m| m.to.is_some()),
                "round 2 should also contain point-to-point messages"
            );
            assert!(messages.iter().all(|m| m.round == 2));
        }
        Progress::Done { .. } => panic!("the protocol must not finish at round 2"),
    }
}
