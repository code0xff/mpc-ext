//! 2-of-3 protocol integration tests.
//!
//! Every party runs in one process. The split deployment is exercised in `transport.rs`, but the
//! per-round message flow is the same, so the protocol properties are established here.

// Panicking is how a test asserts. Production code keeps these lints.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use mpc_core::{
    dkg, refresh, sign, verify, KeyShare, PartyId, Signature, THRESHOLD, TOTAL_PARTIES,
};

/// A dummy session id for fixtures. Real ones are random per session.
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

/// Finds a particular party's share in a list.
fn share_of(shares: &[KeyShare], party: u8) -> &KeyShare {
    shares
        .iter()
        .find(|s| s.party() == PartyId(party))
        .expect("the party should have a share")
}

fn sign_with(shares: &[KeyShare], a: u8, b: u8, msg: &[u8; 32]) -> Signature {
    sign(
        &[share_of(shares, a), share_of(shares, b)],
        &session_id(0xEE),
        msg,
    )
    .expect("two shares should be able to sign")
}

#[test]
fn dkg_produces_three_shares_under_one_public_key() {
    let (shares, public_key) = dkg(&session_id(1)).expect("DKG should succeed");

    assert_eq!(shares.len(), TOTAL_PARTIES as usize);
    let mut parties: Vec<u8> = shares.iter().map(|s| s.party().0).collect();
    parties.sort_unstable();
    assert_eq!(parties, vec![0, 1, 2], "party ids should be 0, 1 and 2");

    // The first byte of a SEC1 compressed encoding is 0x02 or 0x03.
    assert!(matches!(public_key.0[0], 0x02 | 0x03));
}

#[test]
fn any_two_of_three_shares_can_sign() {
    let (shares, public_key) = dkg(&session_id(2)).expect("DKG should succeed");
    let msg = digest(0x42);

    // Every pairing has to work: everyday (A+C), server outage (A+B) and device loss (B+C).
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let signature = sign_with(&shares, a, b, &msg);
        assert!(
            verify(&public_key, &msg, &signature).expect("verification should run"),
            "the signature from shares {a}+{b} should verify against the public key"
        );
    }
}

#[test]
fn a_single_share_cannot_sign() {
    let (shares, _) = dkg(&session_id(3)).expect("DKG should succeed");

    let result = sign(&[share_of(&shares, 0)], &session_id(0xEE), &digest(1));

    assert!(
        matches!(
            result,
            Err(mpc_core::Error::InvalidPartyCount { expected, got })
                if expected == THRESHOLD && got == 1
        ),
        "a single share must not be able to sign"
    );
}

#[test]
fn refresh_preserves_the_public_key() {
    let (shares, public_key) = dkg(&session_id(4)).expect("DKG should succeed");
    let refreshed = refresh(&shares, &session_id(0x40)).expect("refresh should succeed");

    assert_eq!(refreshed.len(), TOTAL_PARTIES as usize);

    // Keeping the public key is what makes this a recovery rather than a migration
    // (docs/recovery.md).
    let msg = digest(0x77);
    let signature = sign_with(&refreshed, 0, 1, &msg);
    assert!(
        verify(&public_key, &msg, &signature).expect("verification should run"),
        "the signature should still verify against the same public key after a refresh"
    );
}

#[test]
fn refresh_invalidates_the_old_shares() {
    let (shares, public_key) = dkg(&session_id(5)).expect("DKG should succeed");
    let refreshed = refresh(&shares, &session_id(0x50)).expect("refresh should succeed");
    let msg = digest(2);

    // The security property recovery depends on: mixing an old share with a new one must not
    // produce a valid signature, otherwise the lost share is not really invalidated
    // (docs/recovery.md).
    let mixed = sign(
        &[share_of(&shares, 0), share_of(&refreshed, 1)],
        &session_id(0xEE),
        &msg,
    );

    let verified = match mixed {
        // Aborting is the expected path.
        Err(_) => false,
        // Even if a signature comes out, it must not verify against the original public key.
        Ok(signature) => verify(&public_key, &msg, &signature).unwrap_or(false),
    };

    assert!(
        !verified,
        "a signature mixing old and new shares must never be valid"
    );
}
