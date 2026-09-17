//! Defences against malformed or malicious input.
//!
//! Tampering with messages inside a protocol round is covered by upstream's own tests (see
//! `refresh_complete_phase4_aborts_on_tampered_enc_proof` and friends). What we test here is the
//! input that crosses **`mpc-core`'s boundary** - exactly what the extension background worker
//! and the server handlers will hand it.

// Panicking is how a test asserts. Production code keeps these lints.
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
        .expect("the party should have a share")
}

#[test]
fn rejects_a_share_with_corrupted_bytes() {
    let (shares, _) = dkg(&session_id(10)).expect("DKG should succeed");

    let mut corrupted = share_of(&shares, 0).expose_secret().to_vec();
    corrupted[8] ^= 0xFF;
    let corrupted = KeyShare::new(PartyId(0), corrupted);

    let result = sign(
        &[&corrupted, share_of(&shares, 1)],
        &session_id(0xEE),
        &digest(1),
    );

    assert!(
        result.is_err(),
        "a corrupted share must not produce a signature"
    );
}

#[test]
fn rejects_shares_from_different_keysets() {
    // An attacker mixing in a share from their own wallet.
    let (first, public_key) = dkg(&session_id(11)).expect("DKG should succeed");
    let (second, _) = dkg(&session_id(12)).expect("DKG should succeed");
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
        "a signature mixing shares from different keysets must never be valid"
    );
}

#[test]
fn rejects_the_same_share_used_twice() {
    // Passing one share twice to fake meeting the threshold.
    let (shares, _) = dkg(&session_id(13)).expect("DKG should succeed");
    let only_one = share_of(&shares, 0);

    let result = sign(&[only_one, only_one], &session_id(0xEE), &digest(3));

    assert!(
        result.is_err(),
        "the same share used twice must not satisfy the threshold"
    );
}

#[test]
fn refresh_requires_every_party() {
    let (shares, _) = dkg(&session_id(14)).expect("DKG should succeed");
    let partial = vec![share_of(&shares, 0).clone(), share_of(&shares, 1).clone()];

    let result = refresh(&partial, &session_id(0x60));

    assert!(
        matches!(result, Err(Error::InvalidPartyCount { got: 2, .. })),
        "refresh must require every party"
    );
}

#[test]
fn export_requires_the_threshold() {
    let (shares, _) = dkg(&session_id(15)).expect("DKG should succeed");

    let result = export_private_key(&[share_of(&shares, 0)]);

    assert!(
        matches!(result, Err(Error::InvalidPartyCount { got: 1, .. })),
        "a single share must not be able to export the private key"
    );
}

#[test]
fn export_rejects_a_duplicated_share() {
    let (shares, _) = dkg(&session_id(16)).expect("DKG should succeed");
    let only_one = share_of(&shares, 0);

    let result = export_private_key(&[only_one, only_one]);

    assert!(
        result.is_err(),
        "the same share used twice must not reconstruct the private key"
    );
}

#[test]
fn exported_key_matches_the_public_key() {
    let (shares, public_key) = dkg(&session_id(17)).expect("DKG should succeed");

    // Any pair of shares must export the same private key, and that key's public key must
    // match the keyset's.
    let from_ab = export_private_key(&[share_of(&shares, 0), share_of(&shares, 1)])
        .expect("the export should succeed");
    let from_bc = export_private_key(&[share_of(&shares, 1), share_of(&shares, 2)])
        .expect("the export should succeed");

    assert_eq!(
        from_ab.0, from_bc.0,
        "the exported key must not depend on which pair was used"
    );

    let signing_key =
        k256::ecdsa::SigningKey::from_slice(&from_ab.0).expect("it should be a valid private key");
    let derived = signing_key.verifying_key().to_sec1_bytes();

    assert_eq!(
        derived.as_ref(),
        &public_key.0[..],
        "the exported key public key must match the keyset public key"
    );
}

#[test]
fn reshare_preserves_the_public_key_and_invalidates_old_shares() {
    let (shares, public_key) = dkg(&session_id(18)).expect("DKG should succeed");

    // One share is gone: issue a fresh set from the surviving two.
    let (fresh, fresh_public_key) = reshare(
        &[share_of(&shares, 0), share_of(&shares, 1)],
        &session_id(0x70),
    )
    .expect("reshare should succeed");

    assert_eq!(fresh.len(), 3, "there should be three shares again");
    assert_eq!(
        fresh_public_key.0, public_key.0,
        "reshare must not change the address"
    );

    // The fresh shares sign, and the signature verifies against the original public key.
    let msg = digest(4);
    let signature = sign(
        &[share_of(&fresh, 0), share_of(&fresh, 2)],
        &session_id(0xEE),
        &msg,
    )
    .expect("the fresh shares should be able to sign");
    assert!(verify(&public_key, &msg, &signature).expect("verification should run"));

    // The share we treat as lost must not combine with the fresh set.
    let mixed = sign(
        &[share_of(&shares, 2), share_of(&fresh, 0)],
        &session_id(0xEE),
        &msg,
    );
    let verified = match mixed {
        Err(_) => false,
        Ok(signature) => verify(&public_key, &msg, &signature).unwrap_or(false),
    };
    assert!(
        !verified,
        "an old share must stop working once a fresh set exists"
    );
}
