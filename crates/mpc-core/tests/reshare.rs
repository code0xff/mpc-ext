//! Distributed reshare (ADR-0007): two survivors and a joiner end with three fresh shares for
//! the same key, without any survivor's share being reconstructed in one place.

// Panicking is how a test asserts. Production code keeps these lints.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use mpc_core::{
    dkg, export_private_key, export_private_key_for, reshare_locally, sign, verify, DkgParty,
    KeyShare, PartyId, PublicKey, ReshareRole,
};

fn session_id(tag: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = tag;
    id[31] = 0x7E;
    id
}

fn digest(tag: u8) -> [u8; 32] {
    let mut d = [0x33u8; 32];
    d[0] = tag;
    d
}

fn share_of(shares: &[KeyShare], party: u8) -> &KeyShare {
    shares
        .iter()
        .find(|s| s.party() == PartyId(party))
        .expect("the party should have a share")
}

fn sign_and_verify(a: &KeyShare, b: &KeyShare, public_key: &PublicKey, tag: u8) -> bool {
    let d = digest(tag);
    match sign(&[a, b], &session_id(100 + tag), &d) {
        Ok(signature) => verify(public_key, &d, &signature).unwrap_or(false),
        Err(_) => false,
    }
}

#[test]
fn reshare_after_losing_a_keeps_the_key_and_gives_every_pair_a_working_share() {
    let (old, public_key) = dkg(&session_id(1)).expect("DKG should succeed");

    // Party 0 (A) is lost. B and C survive.
    let (fresh, new_public_key) = reshare_locally(
        [share_of(&old, 1), share_of(&old, 2)],
        &public_key,
        &session_id(2),
    )
    .expect("reshare should succeed");

    assert_eq!(new_public_key, public_key, "the address must not change");
    assert_eq!(fresh.len(), 3);
    assert!(sign_and_verify(
        share_of(&fresh, 0),
        share_of(&fresh, 2),
        &public_key,
        1
    ));
    assert!(sign_and_verify(
        share_of(&fresh, 0),
        share_of(&fresh, 1),
        &public_key,
        2
    ));
    assert!(sign_and_verify(
        share_of(&fresh, 1),
        share_of(&fresh, 2),
        &public_key,
        3
    ));
}

#[test]
fn reshare_preserves_the_underlying_secret() {
    let (old, public_key) = dkg(&session_id(3)).expect("DKG should succeed");
    let (fresh, _) = reshare_locally(
        [share_of(&old, 1), share_of(&old, 2)],
        &public_key,
        &session_id(4),
    )
    .expect("reshare should succeed");

    let before = export_private_key(&[share_of(&old, 0), share_of(&old, 1)])
        .expect("old shares should export");
    let after = export_private_key_for(&[share_of(&fresh, 0), share_of(&fresh, 1)], &public_key)
        .expect("new shares should export");

    assert_eq!(
        before.0, after.0,
        "the secret must be the same before and after"
    );
}

#[test]
fn new_shares_do_not_combine_with_the_lost_share() {
    let (old, public_key) = dkg(&session_id(5)).expect("DKG should succeed");
    let (fresh, _) = reshare_locally(
        [share_of(&old, 1), share_of(&old, 2)],
        &public_key,
        &session_id(6),
    )
    .expect("reshare should succeed");

    // The lost A against every fresh share: a different polynomial, so it must not sign.
    assert!(!sign_and_verify(
        share_of(&old, 0),
        share_of(&fresh, 1),
        &public_key,
        4
    ));
    assert!(!sign_and_verify(
        share_of(&old, 0),
        share_of(&fresh, 2),
        &public_key,
        5
    ));
    let exported = export_private_key_for(&[share_of(&old, 0), share_of(&fresh, 1)], &public_key);
    assert!(exported.is_err(), "mixing epochs must not export a key");
}

#[test]
fn old_shares_still_sign_together_so_they_must_be_destroyed() {
    // A reshare cannot revoke shares that still exist. This documents why the server deletes its
    // old share on commit and why the user has to destroy the old recovery file.
    let (old, public_key) = dkg(&session_id(7)).expect("DKG should succeed");
    let (_fresh, _) = reshare_locally(
        [share_of(&old, 1), share_of(&old, 2)],
        &public_key,
        &session_id(8),
    )
    .expect("reshare should succeed");

    assert!(sign_and_verify(
        share_of(&old, 0),
        share_of(&old, 1),
        &public_key,
        6
    ));
    assert!(sign_and_verify(
        share_of(&old, 1),
        share_of(&old, 2),
        &public_key,
        7
    ));
}

#[test]
fn reshare_works_for_any_survivor_pair() {
    let (old, public_key) = dkg(&session_id(9)).expect("DKG should succeed");

    // A server migration: A and B survive and a new party takes the third slot.
    let (fresh, new_public_key) = reshare_locally(
        [share_of(&old, 0), share_of(&old, 1)],
        &public_key,
        &session_id(10),
    )
    .expect("reshare should succeed");

    assert_eq!(new_public_key, public_key);
    assert!(sign_and_verify(
        share_of(&fresh, 0),
        share_of(&fresh, 2),
        &public_key,
        8
    ));
    assert!(sign_and_verify(
        share_of(&fresh, 1),
        share_of(&fresh, 2),
        &public_key,
        9
    ));
}

#[test]
fn reshare_refuses_to_change_the_public_key() {
    let (old, _) = dkg(&session_id(11)).expect("DKG should succeed");
    let (_, other_public_key) = dkg(&session_id(12)).expect("DKG should succeed");

    let result = reshare_locally(
        [share_of(&old, 1), share_of(&old, 2)],
        &other_public_key,
        &session_id(13),
    );

    assert!(
        result.is_err(),
        "a reshare that lands on another key must abort"
    );
}

#[test]
fn reshare_rejects_bad_roles() {
    let (old, public_key) = dkg(&session_id(14)).expect("DKG should succeed");
    let b = share_of(&old, 1);

    // The same party twice.
    let duplicated = ReshareRole::Survivor {
        share: b,
        survivors: [PartyId(1), PartyId(1)],
    };
    assert!(
        DkgParty::start_reshare(PartyId(1), &session_id(15), &duplicated, &public_key).is_err()
    );

    // A party that is not one of the survivors.
    let outsider = ReshareRole::Survivor {
        share: b,
        survivors: [PartyId(0), PartyId(2)],
    };
    assert!(DkgParty::start_reshare(PartyId(1), &session_id(16), &outsider, &public_key).is_err());

    // A share that belongs to another party.
    let wrong_party = ReshareRole::Survivor {
        share: b,
        survivors: [PartyId(1), PartyId(2)],
    };
    assert!(
        DkgParty::start_reshare(PartyId(2), &session_id(17), &wrong_party, &public_key).is_err()
    );

    // A survivor outside the party range.
    let out_of_range = ReshareRole::Survivor {
        share: b,
        survivors: [PartyId(1), PartyId(9)],
    };
    assert!(
        DkgParty::start_reshare(PartyId(1), &session_id(18), &out_of_range, &public_key).is_err()
    );
}
