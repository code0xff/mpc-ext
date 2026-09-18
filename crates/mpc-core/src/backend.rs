//! The internal layer wrapping the upstream DKLs23 implementation.
//!
//! **Upstream types never leave this module.** Callers above it — the extension background
//! worker, the server handlers — see only `mpc-core`'s own types, so swapping the library does
//! not change them (`docs/adr/0004-mpc-library-reselection.md`, mitigation 2).
//!
//! The orchestration here runs every party in a single process. For the split deployment, where
//! the extension and the server each drive their own party, see [`crate::protocol`]. The
//! per-round message flow is identical.

use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256k1::protocols::dkg_session::DkgSession;
use dkls23_secp256k1::protocols::sign_session::SignSession;
use dkls23_secp256k1::protocols::signing::SignData;
use dkls23_secp256k1::protocols::{Parameters, Party, PartyIndex};
use dkls23_secp256k1::utilities::hashes::HashOutput;
use k256::Secp256k1;

use crate::{
    Error, KeyShare, PartyId, PublicKey, Result, SecretKeyBytes, Signature, THRESHOLD,
    TOTAL_PARTIES,
};

type UpstreamParty = Party<Secp256k1>;

/// Address strings are not this crate's concern; chain-specific derivation happens above.
fn no_address(_pk: &k256::AffinePoint) -> String {
    String::new()
}

fn upstream_params() -> Parameters {
    Parameters {
        threshold: THRESHOLD,
        share_count: TOTAL_PARTIES,
    }
}

/// Converts our 0-based `PartyId` into upstream's 1-based index.
fn to_upstream(party: PartyId) -> Result<PartyIndex> {
    PartyIndex::new(party.0 + 1).map_err(|e| Error::Backend(e.to_string()))
}

fn from_upstream(index: PartyIndex) -> PartyId {
    PartyId(index.as_u8() - 1)
}

pub(crate) fn encode(party: &UpstreamParty) -> Result<Vec<u8>> {
    bincode::serialize(party).map_err(|e| Error::Backend(format!("share encode: {e}")))
}

pub(crate) fn decode(share: &KeyShare) -> Result<UpstreamParty> {
    bincode::deserialize(share.expose_secret())
        .map_err(|e| Error::Backend(format!("share decode: {e}")))
}

pub(crate) fn public_key_of(party: &UpstreamParty) -> Result<PublicKey> {
    use elliptic_curve::sec1::ToSec1Point;
    let encoded = party.pk.to_sec1_point(true);
    let bytes = encoded.as_bytes();
    let out: [u8; 33] = bytes
        .try_into()
        .map_err(|_| Error::Backend(format!("unexpected public key length: {}", bytes.len())))?;
    Ok(PublicKey(out))
}

/// Keeps only the messages addressed to us. Used to route each round.
fn route<T: Clone>(all: &[Vec<T>], me: PartyIndex, receiver: impl Fn(&T) -> PartyIndex) -> Vec<T> {
    all.iter()
        .flatten()
        .filter(|m| receiver(m) == me)
        .cloned()
        .collect()
}

/// Three-party distributed key generation.
///
/// No party ever sees the complete private key. On failure nothing partial survives, so callers
/// must persist shares only on success.
pub fn dkg(session_id: &[u8; 32]) -> Result<(Vec<KeyShare>, PublicKey)> {
    let params = upstream_params();
    let n = TOTAL_PARTIES as usize;
    let indices: Vec<PartyIndex> = (0..TOTAL_PARTIES)
        .map(|i| to_upstream(PartyId(i)))
        .collect::<Result<_>>()?;

    let mut sessions: Vec<DkgSession<Secp256k1>> = indices
        .iter()
        .map(|&idx| DkgSession::new(params.clone(), idx, session_id.to_vec()))
        .collect();

    // Round 1 — every party sends a polynomial fragment to every party.
    let rows: Vec<Vec<k256::Scalar>> = sessions.iter().map(DkgSession::phase1).collect();
    let mut fragments: Vec<Vec<k256::Scalar>> = vec![Vec::with_capacity(n); n];
    for row in &rows {
        for (j, frag) in row.iter().enumerate().take(n) {
            fragments[j].push(*frag);
        }
    }

    // Round 2
    let mut proofs: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(n);
    let mut zero_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut bip_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> = BTreeMap::new();
    for (i, session) in sessions.iter_mut().enumerate() {
        let (proof, zero, bip) = session
            .phase2(&fragments[i])
            .map_err(|e| Error::Backend(format!("dkg phase2: {e:?}")))?;
        proofs.push(proof);
        zero_2to4.push(zero);
        bip_2to4.insert(indices[i], bip);
    }

    // Round 3
    let mut zero_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::with_capacity(n);
    let mut bip_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();
    for (i, session) in sessions.iter_mut().enumerate() {
        let (zero, mul, bip) = session
            .phase3()
            .map_err(|e| Error::Backend(format!("dkg phase3: {e:?}")))?;
        zero_3to4.push(zero);
        mul_3to4.push(mul);
        bip_3to4.insert(indices[i], bip);
    }

    // Round 4 — each party settles on its share and the joint public key.
    let mut shares = Vec::with_capacity(n);
    let mut public_key: Option<PublicKey> = None;
    for (i, session) in sessions.into_iter().enumerate() {
        let me = indices[i];
        let (party, _pkg) = session
            .phase4(
                &proofs,
                &route(&zero_2to4, me, |m| m.parties.receiver),
                &route(&zero_3to4, me, |m| m.parties.receiver),
                &route(&mul_3to4, me, |m| m.parties.receiver),
                &bip_2to4,
                &bip_3to4,
                no_address,
            )
            .map_err(|e| Error::Backend(format!("dkg phase4: {e:?}")))?;

        let pk = public_key_of(&party)?;
        match &public_key {
            None => public_key = Some(pk),
            Some(known) if *known != pk => {
                return Err(Error::Backend("parties disagree on the public key".into()))
            }
            Some(_) => {}
        }
        shares.push(KeyShare::new(
            from_upstream(party.party_index),
            encode(&party)?,
        ));
    }

    let public_key = public_key.ok_or_else(|| Error::Backend("dkg produced no parties".into()))?;
    Ok((shares, public_key))
}

/// Threshold signing. Exactly [`THRESHOLD`] shares must take part.
///
/// Everyday signing passes the extension share and the server share; recovery passes whichever
/// two survive.
pub fn sign(shares: &[&KeyShare], sign_id: &[u8; 32], digest: &[u8; 32]) -> Result<Signature> {
    if shares.len() != THRESHOLD as usize {
        return Err(Error::InvalidPartyCount {
            expected: THRESHOLD,
            got: shares.len() as u8,
        });
    }

    let parties: Vec<UpstreamParty> = shares.iter().map(|s| decode(s)).collect::<Result<_>>()?;
    let signers: Vec<PartyIndex> = parties.iter().map(|p| p.party_index).collect();

    let message_hash: HashOutput = *digest;
    let sessions_data: Vec<SignData> = signers
        .iter()
        .map(|me| SignData {
            sign_id: sign_id.to_vec(),
            counterparties: signers.iter().copied().filter(|p| p != me).collect(),
            message_hash,
        })
        .collect();

    // Round 1
    let mut sessions = Vec::with_capacity(parties.len());
    let mut transmit_1to2 = Vec::with_capacity(parties.len());
    for (party, data) in parties.iter().zip(sessions_data) {
        let (session, transmit) = SignSession::new(party, data)
            .map_err(|e| Error::Backend(format!("sign phase1: {e:?}")))?;
        sessions.push(session);
        transmit_1to2.push(transmit);
    }

    // Round 2
    let mut transmit_2to3 = Vec::with_capacity(parties.len());
    for (i, session) in sessions.iter_mut().enumerate() {
        let received = route(&transmit_1to2, signers[i], |m| m.parties.receiver);
        transmit_2to3.push(
            session
                .phase2(&received)
                .map_err(|e| Error::Backend(format!("sign phase2: {e:?}")))?,
        );
    }

    // Round 3
    let mut broadcasts = Vec::with_capacity(parties.len());
    for (i, session) in sessions.iter_mut().enumerate() {
        let received = route(&transmit_2to3, signers[i], |m| m.parties.receiver);
        broadcasts.push(
            session
                .phase3(&received)
                .map_err(|e| Error::Backend(format!("sign phase3: {e:?}")))?,
        );
    }

    // Round 4 — every participant must arrive at the same signature.
    let mut signature: Option<Signature> = None;
    for session in sessions {
        let sig = session
            .phase4(&broadcasts, true)
            .map_err(|e| Error::Backend(format!("sign phase4: {e:?}")))?;
        let sig = Signature {
            r: sig.r,
            s: sig.s,
            recovery_id: sig.recovery_id,
        };
        match &signature {
            None => signature = Some(sig),
            Some(known) if *known != sig => {
                return Err(Error::Backend(
                    "signers produced different signatures".into(),
                ))
            }
            Some(_) => {}
        }
    }

    signature.ok_or_else(|| Error::Backend("signing produced no signature".into()))
}

/// Key refresh: regenerate every share while keeping the public key.
///
/// Old shares stop working from this point on. Run it immediately after a recovery
/// (`docs/recovery.md`). **Every party must take part** — replacing a lost party with a new
/// device is a reshare, not a refresh, and follows a different procedure ([`reshare`]).
pub fn refresh(shares: &[KeyShare], session_id: &[u8; 32]) -> Result<Vec<KeyShare>> {
    if shares.len() != TOTAL_PARTIES as usize {
        return Err(Error::InvalidPartyCount {
            expected: TOTAL_PARTIES,
            got: shares.len() as u8,
        });
    }

    let n = shares.len();
    let parties: Vec<UpstreamParty> = shares.iter().map(decode).collect::<Result<_>>()?;
    let indices: Vec<PartyIndex> = parties.iter().map(|p| p.party_index).collect();

    // Round 1 — polynomial fragments with a zero constant term: corrections that leave
    // the public key untouched.
    let rows: Vec<Vec<k256::Scalar>> = parties
        .iter()
        .map(UpstreamParty::refresh_complete_phase1)
        .collect();
    let mut fragments: Vec<Vec<k256::Scalar>> = vec![Vec::with_capacity(n); n];
    for row in &rows {
        for (j, frag) in row.iter().enumerate().take(n) {
            fragments[j].push(*frag);
        }
    }

    let mut sessions: Vec<RefreshState> = Vec::with_capacity(n);
    let mut proofs: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(n);
    let mut zero_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for (i, party) in parties.iter().enumerate() {
        let (point, proof, zero_keep, zero) =
            party.refresh_complete_phase2(session_id, &fragments[i]);
        proofs.push(proof);
        zero_2to4.push(zero);
        sessions.push(RefreshState { point, zero_keep });
    }

    let mut zero_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::with_capacity(n);
    let mut keeps = Vec::with_capacity(n);
    for (i, party) in parties.iter().enumerate() {
        let (zero_keep, zero, mul_keep, mul) =
            party.refresh_complete_phase3(session_id, &sessions[i].zero_keep);
        zero_3to4.push(zero);
        mul_3to4.push(mul);
        keeps.push((zero_keep, mul_keep));
    }

    let mut refreshed = Vec::with_capacity(n);
    for (i, party) in parties.iter().enumerate() {
        let me = indices[i];
        let new_party = party
            .refresh_complete_phase4(
                session_id,
                &sessions[i].point,
                &proofs,
                &keeps[i].0,
                &route(&zero_2to4, me, |m| m.parties.receiver),
                &route(&zero_3to4, me, |m| m.parties.receiver),
                &keeps[i].1,
                &route(&mul_3to4, me, |m| m.parties.receiver),
            )
            .map_err(|e| Error::Backend(format!("refresh phase4: {e:?}")))?;
        refreshed.push(KeyShare::new(
            from_upstream(new_party.party_index),
            encode(&new_party)?,
        ));
    }

    Ok(refreshed)
}

/// Intermediate refresh state. Lives only between rounds.
struct RefreshState {
    point: k256::Scalar,
    zero_keep: BTreeMap<PartyIndex, dkls23_secp256k1::protocols::dkg::KeepInitZeroSharePhase2to3>,
}

/// Derives the ERC-55 checksummed Ethereum address for a public key.
///
/// Address derivation is chain-specific and deliberately lives at the edge of this crate: the
/// protocol core does not care about addresses, but the extension has to show one.
pub fn ethereum_address(public_key: &PublicKey) -> Result<String> {
    use elliptic_curve::sec1::FromSec1Point;

    let point = k256::AffinePoint::from_sec1_bytes(&public_key.0)
        .map_err(|e| Error::Backend(format!("invalid public key: {e}")))?;
    Ok(dkls23_secp256k1::compute_eth_address(&point))
}

/// Checks a signature against a public key.
///
/// Used by tests and by callers double-checking their own output. Touches no secrets.
pub fn verify(public_key: &PublicKey, digest: &[u8; 32], signature: &Signature) -> Result<bool> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key.0)
        .map_err(|e| Error::Backend(format!("invalid public key: {e}")))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signature.r);
    sig_bytes[32..].copy_from_slice(&signature.s);
    let sig = match k256::ecdsa::Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        // A malformed signature is "invalid", not an error.
        Err(_) => return Ok(false),
    };

    Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
}

/// Reconstructs the full private key from shares (Shamir interpolation at x = 0).
///
/// # Danger
///
/// This **removes the MPC security benefit.** The result is a complete private key sitting in
/// one place, and callers must discard it immediately. Call it on the user's device only; never
/// send it to the server or write it to disk (`docs/export.md`, `docs/recovery.md`).
fn reconstruct(shares: &[&KeyShare]) -> Result<ReconstructedKey> {
    use elliptic_curve::Field;

    if shares.len() < THRESHOLD as usize {
        return Err(Error::InvalidPartyCount {
            expected: THRESHOLD,
            got: shares.len() as u8,
        });
    }

    let parties: Vec<UpstreamParty> = shares.iter().map(|s| decode(s)).collect::<Result<_>>()?;
    let indices: Vec<u64> = parties
        .iter()
        .map(|p| u64::from(p.party_index.as_u8()))
        .collect();

    // The same party appearing twice breaks the interpolation.
    let mut seen = indices.clone();
    seen.sort_unstable();
    seen.dedup();
    if seen.len() != indices.len() {
        return Err(Error::Backend("duplicate party in share set".into()));
    }

    // secret = Σ_i ( poly_point_i · Π_{j≠i} j / (j - i) )
    let mut secret = <k256::Scalar as Field>::ZERO;
    for (i, party) in parties.iter().enumerate() {
        let me = k256::Scalar::from(indices[i]);
        let mut numerator = <k256::Scalar as Field>::ONE;
        let mut denominator = <k256::Scalar as Field>::ONE;
        for (j, &other_index) in indices.iter().enumerate() {
            if i == j {
                continue;
            }
            let other = k256::Scalar::from(other_index);
            numerator *= other;
            denominator *= other - me;
        }
        let inverse = Option::<k256::Scalar>::from(denominator.invert())
            .ok_or_else(|| Error::Backend("lagrange coefficient is not invertible".into()))?;
        secret += party.poly_point * numerator * inverse;
    }

    Ok(ReconstructedKey { scalar: secret })
}

/// A reconstructed private key. Zeroized when dropped.
struct ReconstructedKey {
    scalar: k256::Scalar,
}

impl Drop for ReconstructedKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Scalar does not implement Zeroize, so wipe the byte representation instead.
        let mut bytes = self.to_bytes();
        bytes.zeroize();
        self.scalar = <k256::Scalar as elliptic_curve::Field>::ZERO;
    }
}

impl ReconstructedKey {
    fn to_bytes(&self) -> [u8; 32] {
        use elliptic_curve::PrimeField;
        let repr = self.scalar.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_slice());
        out
    }
}

/// Exports the complete private key as 32 big-endian bytes.
///
/// # Danger
///
/// The MPC benefit disappears at this moment. Callers must warn the user explicitly and take a
/// confirmation (`docs/export.md`).
pub fn export_private_key(shares: &[&KeyShare]) -> Result<SecretKeyBytes> {
    let key = reconstruct(shares)?;
    Ok(SecretKeyBytes(key.to_bytes()))
}

/// Issues a fresh set of three shares from the surviving ones (reshare).
///
/// Use it to fill the slot of a lost share on a new device. Upstream refresh only admits parties
/// that already hold a share, so it cannot cover this case
/// (`docs/adr/0004-mpc-library-reselection.md`, finding 3).
///
/// # Danger
///
/// Internally this reconstructs the private key and immediately re-splits it. In between, the
/// key exists in one place — a single point of failure. **Call it on the user's device only**,
/// never on the server. The public key is preserved, so the address does not change.
pub fn reshare(shares: &[&KeyShare], session_id: &[u8; 32]) -> Result<(Vec<KeyShare>, PublicKey)> {
    use dkls23_secp256k1::protocols::re_key::re_key;

    let key = reconstruct(shares)?;
    let (parties, _pkg) = re_key::<Secp256k1>(
        &upstream_params(),
        session_id.as_slice(),
        &key.scalar,
        None,
        no_address,
    );

    let mut new_shares = Vec::with_capacity(parties.len());
    let mut public_key: Option<PublicKey> = None;
    for party in &parties {
        let pk = public_key_of(party)?;
        if public_key.get_or_insert(pk) != &public_key_of(party)? {
            return Err(Error::Backend(
                "reshare produced inconsistent public keys".into(),
            ));
        }
        new_shares.push(KeyShare::new(
            from_upstream(party.party_index),
            encode(party)?,
        ));
    }

    let public_key =
        public_key.ok_or_else(|| Error::Backend("reshare produced no parties".into()))?;
    Ok((new_shares, public_key))
}
