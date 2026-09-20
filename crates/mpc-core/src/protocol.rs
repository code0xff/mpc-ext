//! Per-party protocol sessions.
//!
//! [`crate::dkg`] and friends are a harness that drives all three parties in one process. This
//! module is for the **real, split deployment**: the extension drives share A's party, the
//! server drives share C's, and they exchange [`Envelope`]s (`docs/architecture.md`).
//!
//! Transport is not this module's concern. Callers hand each envelope to the other side and feed
//! back whatever arrives.

use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::dkg::{
    self, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, KeepInitMulPhase3to4,
    KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment, SessionData,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
    UniqueKeepDerivationPhase2to3,
};
use dkls23_secp256k1::protocols::signing::{
    Broadcast3to4, KeepPhase1to2, KeepPhase2to3, SignData, TransmitPhase1to2, TransmitPhase2to3,
    UniqueKeep1to2, UniqueKeep2to3,
};
use dkls23_secp256k1::protocols::{Parameters, PartyIndex};
use k256::Secp256k1;
use serde::{Deserialize, Serialize};

use crate::{Error, KeyShare, PartyId, PublicKey, Result, TOTAL_PARTIES};

/// One message from one party to another within a round.
///
/// A `to` of `None` means broadcast. The payload is opaque bytes that only the receiving
/// session can interpret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol round number, starting at 1.
    pub round: u8,
    /// The sending party.
    pub from: PartyId,
    /// The recipient. `None` broadcasts to every party.
    pub to: Option<PartyId>,
    /// The serialized body.
    pub payload: Vec<u8>,
}

impl Envelope {
    fn new<T: Serialize>(round: u8, from: PartyId, to: Option<PartyId>, body: &T) -> Result<Self> {
        Ok(Self {
            round,
            from,
            to,
            payload: bincode::serialize(body)
                .map_err(|e| Error::Backend(format!("envelope encode: {e}")))?,
        })
    }

    fn decode<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        bincode::deserialize(&self.payload)
            .map_err(|e| Error::Backend(format!("envelope decode: {e}")))
    }
}

/// The outcome of advancing a round.
#[derive(Debug)]
pub enum Progress {
    /// There are messages to send. Deliver them and feed the replies back in.
    Send(Vec<Envelope>),
    /// The protocol finished.
    Done {
        /// This party's share.
        share: KeyShare,
        /// The joint public key.
        public_key: PublicKey,
    },
}

/// Messages from the other parties, accumulated across rounds 2 and 3.
#[derive(Default, Serialize, Deserialize)]
struct Inbox {
    proofs: BTreeMap<PartyId, ProofCommitment<Secp256k1>>,
    zero_2to4: Vec<TransmitInitZeroSharePhase2to4>,
    zero_3to4: Vec<TransmitInitZeroSharePhase3to4>,
    mul_3to4: Vec<TransmitInitMulPhase3to4<Secp256k1>>,
    bip_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4>,
    bip_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4>,
}

/// What a party broadcasts in round 2.
#[derive(Serialize, Deserialize)]
struct Round2Broadcast {
    proof: ProofCommitment<Secp256k1>,
    bip: BroadcastDerivationPhase2to4,
}

/// What a party broadcasts in round 3.
#[derive(Serialize, Deserialize)]
struct Round3Broadcast {
    bip: BroadcastDerivationPhase3to4,
}

/// What a party sends to one specific peer in round 3.
#[derive(Serialize, Deserialize)]
struct Round3Private {
    zero: TransmitInitZeroSharePhase3to4,
    mul: TransmitInitMulPhase3to4<Secp256k1>,
}

/// One party taking part in distributed key generation.
///
/// It runs four rounds. Each round, deliver the envelopes that [`Progress::Send`] yields and
/// pass whatever arrives into [`Self::advance`].
///
/// All state is serializable, because the server holds nothing between HTTP requests and has to
/// store and restore it every round (`docs/server.md`).
#[derive(Serialize, Deserialize)]
pub struct DkgParty {
    me: PartyId,
    index: PartyIndex,
    round: u8,
    data: SessionData,
    fragments: BTreeMap<PartyId, k256::Scalar>,
    poly_point: Option<k256::Scalar>,
    /// Set for a reshare: the public key the new shares must reproduce (ADR-0007).
    expected_public_key: Option<Vec<u8>>,
    zero_kept_2to3: BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>,
    bip_kept_2to3: Option<UniqueKeepDerivationPhase2to3>,
    zero_kept_3to4: BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>,
    mul_kept_3to4: BTreeMap<PartyIndex, KeepInitMulPhase3to4<Secp256k1>>,
    inbox: Inbox,
}

impl core::fmt::Debug for DkgParty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgParty")
            .field("me", &self.me)
            .field("round", &self.round)
            .finish_non_exhaustive()
    }
}

fn to_index(party: PartyId) -> Result<PartyIndex> {
    PartyIndex::new(party.0 + 1).map_err(|e| Error::Backend(e.to_string()))
}

fn to_party(index: PartyIndex) -> PartyId {
    PartyId(index.as_u8() - 1)
}

fn session_data(me: PartyId, session_id: &[u8; 32]) -> Result<SessionData> {
    Ok(SessionData {
        parameters: Parameters {
            threshold: crate::THRESHOLD,
            share_count: TOTAL_PARTIES,
        },
        party_index: to_index(me)?,
        session_id: session_id.to_vec(),
    })
}

/// What a party plays in a reshare (ADR-0007).
#[derive(Debug)]
pub enum ReshareRole<'a> {
    /// Holds one of the two surviving shares.
    Survivor {
        /// The surviving share this party contributes.
        share: &'a KeyShare,
        /// Both survivors. They fix the Lagrange weights, so every survivor must pass the same
        /// pair.
        survivors: [PartyId; 2],
    },
    /// Takes a new share without having had one. Contributes nothing to the secret.
    Joiner,
}

/// The Lagrange coefficient at zero for `me` over the survivor set, as a scalar.
fn lagrange_at_zero(me: PartyId, survivors: [PartyId; 2]) -> Result<k256::Scalar> {
    let [first, second] = survivors;
    if first == second || first.0 >= TOTAL_PARTIES || second.0 >= TOTAL_PARTIES {
        return Err(Error::Backend(
            "survivors must be two distinct parties".into(),
        ));
    }
    let other = if me == first {
        second
    } else if me == second {
        first
    } else {
        return Err(Error::Backend("this party is not a survivor".into()));
    };
    let mine = k256::Scalar::from(u64::from(to_index(me)?.as_u8()));
    let theirs = k256::Scalar::from(u64::from(to_index(other)?.as_u8()));
    // Over {i, j}, the coefficient for i is j / (j - i).
    let denominator = Option::<k256::Scalar>::from((theirs - mine).invert())
        .ok_or_else(|| Error::Backend("lagrange coefficient is not invertible".into()))?;
    Ok(theirs * denominator)
}

/// This survivor's polynomial `w + r·x`, evaluated at every party index, where `w` is its
/// Lagrange-weighted share and `r` is fresh randomness.
fn reshare_row(
    me: PartyId,
    share: &KeyShare,
    survivors: [PartyId; 2],
) -> Result<Vec<k256::Scalar>> {
    use elliptic_curve::Field;

    if share.party() != me {
        return Err(Error::Backend(
            "the share belongs to a different party".into(),
        ));
    }
    let party = crate::backend::decode(share)?;
    if party.party_index != to_index(me)? {
        return Err(Error::Backend(
            "the share belongs to a different party".into(),
        ));
    }

    let constant = lagrange_at_zero(me, survivors)? * party.poly_point;
    let mut rng = dkls23_secp256k1::utilities::rng::get_rng();
    let slope = <k256::Scalar as Field>::random(&mut rng);

    Ok((1..=TOTAL_PARTIES)
        .map(|j| constant + slope * k256::Scalar::from(u64::from(j)))
        .collect())
}

impl DkgParty {
    /// Opens a session and produces the round 1 messages.
    ///
    /// Every party must use the same `session_id`, and it must never be reused.
    pub fn start(me: PartyId, session_id: &[u8; 32]) -> Result<(Self, Vec<Envelope>)> {
        let data = session_data(me, session_id)?;
        // Each party gets a different polynomial fragment, so these are point to point.
        let row = dkg::phase1::<Secp256k1>(&data);
        Self::start_with(me, data, &row, None)
    }

    /// Opens a reshare session and produces the round 1 messages (ADR-0007).
    ///
    /// A reshare is a DKG whose polynomials are chosen so that the secret stays the same. Two
    /// parties still hold a share (the *survivors*) and each contributes a polynomial whose
    /// constant term is its Lagrange-weighted share. Everyone else (a *joiner*) contributes
    /// nothing. The fresh shares that come out lie on a new polynomial with the old secret, and
    /// the multiplication and zero-share setup between every pair is redone from scratch.
    ///
    /// The session fails at the end unless the new public key equals `expected`.
    ///
    /// # Danger
    ///
    /// Whoever plays two of the new parties can reconstruct the key from what they receive. That
    /// is the same exposure DKG has for the extension, and it must only happen on the user's own
    /// device (`docs/adr/0007-distributed-reshare.md`).
    pub fn start_reshare(
        me: PartyId,
        session_id: &[u8; 32],
        role: &ReshareRole<'_>,
        expected: &PublicKey,
    ) -> Result<(Self, Vec<Envelope>)> {
        let data = session_data(me, session_id)?;
        let row = match role {
            ReshareRole::Joiner => vec![k256::Scalar::ZERO; TOTAL_PARTIES as usize],
            ReshareRole::Survivor { share, survivors } => reshare_row(me, share, *survivors)?,
        };
        Self::start_with(me, data, &row, Some(expected.0.to_vec()))
    }

    fn start_with(
        me: PartyId,
        data: SessionData,
        row: &[k256::Scalar],
        expected_public_key: Option<Vec<u8>>,
    ) -> Result<(Self, Vec<Envelope>)> {
        let index = data.party_index;
        let mut outgoing = Vec::new();
        let mut fragments = BTreeMap::new();
        for (slot, fragment) in row.iter().enumerate() {
            let target = PartyId(
                u8::try_from(slot)
                    .map_err(|_| Error::Backend("party index does not fit in u8".into()))?,
            );
            if target == me {
                fragments.insert(me, *fragment);
            } else {
                outgoing.push(Envelope::new(1, me, Some(target), fragment)?);
            }
        }

        Ok((
            Self {
                me,
                index,
                round: 1,
                data,
                fragments,
                poly_point: None,
                expected_public_key,
                zero_kept_2to3: BTreeMap::new(),
                bip_kept_2to3: None,
                zero_kept_3to4: BTreeMap::new(),
                mul_kept_3to4: BTreeMap::new(),
                inbox: Inbox::default(),
            },
            outgoing,
        ))
    }

    /// This party's identifier.
    pub fn party(&self) -> PartyId {
        self.me
    }

    /// Consumes the received envelopes and advances to the next round.
    ///
    /// An envelope from the wrong round fails the session, leaving no partial state behind.
    pub fn advance(&mut self, inbox: &[Envelope]) -> Result<Progress> {
        for envelope in inbox {
            if envelope.round != self.round {
                return Err(Error::UnexpectedRound {
                    expected: crate::Round::Round(self.round),
                    got: crate::Round::Round(envelope.round),
                });
            }
            if let Some(target) = envelope.to {
                if target != self.me {
                    return Err(Error::Backend(format!(
                        "envelope addressed to {target} arrived at {}",
                        self.me
                    )));
                }
            }
        }

        match self.round {
            1 => self.round2(inbox),
            2 => self.round3(inbox),
            3 => self.round4(inbox),
            other => Err(Error::Backend(format!("dkg has no round {other}"))),
        }
    }

    /// Serializes the state so it can be held between rounds.
    ///
    /// The result **contains secrets.** It must be encrypted before being stored.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Backend(format!("session encode: {e}")))
    }

    /// Restores state produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Backend(format!("session decode: {e}")))
    }

    fn round2(&mut self, inbox: &[Envelope]) -> Result<Progress> {
        for envelope in inbox {
            self.fragments.insert(envelope.from, envelope.decode()?);
        }
        if self.fragments.len() != TOTAL_PARTIES as usize {
            return Err(Error::InvalidPartyCount {
                expected: TOTAL_PARTIES,
                got: self.fragments.len() as u8,
            });
        }

        // Upstream expects the fragments ordered by party.
        let ordered: Vec<k256::Scalar> = self.fragments.values().copied().collect();
        let me = self.me;
        let (poly_point, proof, zero_keep, zero, bip_keep, bip) =
            dkg::phase2::<Secp256k1>(&self.data, &ordered);
        self.poly_point = Some(poly_point);
        self.zero_kept_2to3 = zero_keep;
        self.bip_kept_2to3 = Some(bip_keep);

        // phase4 wants proofs from every party including ourselves, so keep ours before
        // handing it off.
        self.inbox.proofs.insert(me, proof.clone());
        self.inbox.bip_2to4.insert(self.index, bip.clone());

        let mut outgoing = vec![Envelope::new(2, me, None, &Round2Broadcast { proof, bip })?];
        for message in zero {
            let target = to_party(message.parties.receiver);
            outgoing.push(Envelope::new(2, me, Some(target), &message)?);
        }

        self.round = 2;
        Ok(Progress::Send(outgoing))
    }

    fn round3(&mut self, inbox: &[Envelope]) -> Result<Progress> {
        for envelope in inbox {
            match envelope.to {
                None => {
                    let body: Round2Broadcast = envelope.decode()?;
                    self.inbox.proofs.insert(envelope.from, body.proof);
                    self.inbox
                        .bip_2to4
                        .insert(to_index(envelope.from)?, body.bip);
                }
                Some(_) => self.inbox.zero_2to4.push(envelope.decode()?),
            }
        }

        let me = self.me;
        let bip_kept = self
            .bip_kept_2to3
            .as_ref()
            .ok_or_else(|| Error::Backend("round 3 called before round 2".into()))?;
        let (zero_keep, zero, mul_keep, mul, bip) =
            dkg::phase3::<Secp256k1>(&self.data, &self.zero_kept_2to3, bip_kept);
        self.zero_kept_3to4 = zero_keep;
        self.mul_kept_3to4 = mul_keep;

        self.inbox.bip_3to4.insert(self.index, bip.clone());

        let mut outgoing = vec![Envelope::new(3, me, None, &Round3Broadcast { bip })?];
        // Bundle the zero and mul messages that go to the same peer.
        for zero_message in zero {
            let target = to_party(zero_message.parties.receiver);
            let mul_message = mul
                .iter()
                .find(|m| to_party(m.parties.receiver) == target)
                .ok_or_else(|| Error::Backend(format!("missing mul message for {target}")))?
                .clone();
            outgoing.push(Envelope::new(
                3,
                me,
                Some(target),
                &Round3Private {
                    zero: zero_message,
                    mul: mul_message,
                },
            )?);
        }

        self.round = 3;
        Ok(Progress::Send(outgoing))
    }

    fn round4(&mut self, inbox: &[Envelope]) -> Result<Progress> {
        for envelope in inbox {
            match envelope.to {
                None => {
                    let body: Round3Broadcast = envelope.decode()?;
                    self.inbox
                        .bip_3to4
                        .insert(to_index(envelope.from)?, body.bip);
                }
                Some(_) => {
                    let body: Round3Private = envelope.decode()?;
                    self.inbox.zero_3to4.push(body.zero);
                    self.inbox.mul_3to4.push(body.mul);
                }
            }
        }

        // Upstream phase4 expects the full list, our own proof included.
        let mut proofs: Vec<ProofCommitment<Secp256k1>> =
            Vec::with_capacity(TOTAL_PARTIES as usize);
        for party in (0..TOTAL_PARTIES).map(PartyId) {
            let proof =
                self.inbox.proofs.get(&party).ok_or_else(|| {
                    Error::Backend(format!("missing proof commitment from {party}"))
                })?;
            proofs.push(proof.clone());
        }

        let poly_point = self
            .poly_point
            .ok_or_else(|| Error::Backend("round 4 called before round 2".into()))?;
        let (party, _pkg) = dkg::phase4::<Secp256k1>(
            &self.data,
            &poly_point,
            &proofs,
            &self.zero_kept_3to4,
            &self.inbox.zero_2to4,
            &self.inbox.zero_3to4,
            &self.mul_kept_3to4,
            &self.inbox.mul_3to4,
            &self.inbox.bip_2to4,
            &self.inbox.bip_3to4,
            |_| String::new(),
        )
        .map_err(|e| Error::Backend(format!("dkg phase4: {e:?}")))?;

        let public_key = crate::backend::public_key_of(&party)?;
        if let Some(expected) = &self.expected_public_key {
            if expected.as_slice() != public_key.0.as_slice() {
                return Err(Error::Backend(
                    "the reshare would change the wallet's public key".into(),
                ));
            }
        }

        self.round = 4;
        Ok(Progress::Done {
            public_key,
            share: KeyShare::new(self.me, crate::backend::encode(&party)?),
        })
    }
}

/// Drives all three parties in one process to check that [`DkgParty`] actually meshes.
///
/// A harness for exercising the protocol without a transport layer.
pub fn run_locally(session_id: &[u8; 32]) -> Result<(Vec<KeyShare>, PublicKey)> {
    let mut parties = Vec::new();
    let mut in_flight: Vec<Envelope> = Vec::new();
    for id in (0..TOTAL_PARTIES).map(PartyId) {
        let (party, outgoing) = DkgParty::start(id, session_id)?;
        parties.push(party);
        in_flight.extend(outgoing);
    }
    drive_locally(parties, in_flight)
}

/// Reshares a key in one process from two surviving shares, giving all three parties fresh
/// shares (ADR-0007).
///
/// A harness for tests. It holds every share in one place, which the real deployment never does
/// for the server's.
pub fn reshare_locally(
    survivors: [&KeyShare; 2],
    expected: &PublicKey,
    session_id: &[u8; 32],
) -> Result<(Vec<KeyShare>, PublicKey)> {
    let ids = [survivors[0].party(), survivors[1].party()];
    let mut parties = Vec::new();
    let mut in_flight: Vec<Envelope> = Vec::new();
    for id in (0..TOTAL_PARTIES).map(PartyId) {
        let role = match survivors.iter().find(|share| share.party() == id) {
            Some(share) => ReshareRole::Survivor {
                share,
                survivors: ids,
            },
            None => ReshareRole::Joiner,
        };
        let (party, outgoing) = DkgParty::start_reshare(id, session_id, &role, expected)?;
        parties.push(party);
        in_flight.extend(outgoing);
    }
    drive_locally(parties, in_flight)
}

/// Runs the parties round by round until every one of them finishes.
fn drive_locally(
    mut parties: Vec<DkgParty>,
    mut in_flight: Vec<Envelope>,
) -> Result<(Vec<KeyShare>, PublicKey)> {
    let mut shares = Vec::new();
    let mut public_key: Option<PublicKey> = None;

    loop {
        let mut next: Vec<Envelope> = Vec::new();
        let mut finished = 0;

        for party in &mut parties {
            let me = party.party();
            let inbox: Vec<Envelope> = in_flight
                .iter()
                .filter(|e| e.from != me && e.to.is_none_or(|to| to == me))
                .cloned()
                .collect();

            match party.advance(&inbox)? {
                Progress::Send(outgoing) => next.extend(outgoing),
                Progress::Done {
                    share,
                    public_key: pk,
                } => {
                    finished += 1;
                    if let Some(known) = &public_key {
                        if *known != pk {
                            return Err(Error::Backend(
                                "parties disagree on the public key".into(),
                            ));
                        }
                    } else {
                        public_key = Some(pk);
                    }
                    shares.push(share);
                }
            }
        }

        if finished == parties.len() {
            let public_key =
                public_key.ok_or_else(|| Error::Backend("dkg produced no parties".into()))?;
            return Ok((shares, public_key));
        }
        in_flight = next;
    }
}

/// One party taking part in threshold signing.
///
/// It runs four rounds, in the same shape as [`DkgParty`]: deliver what [`Progress::Send`]
/// yields, then feed the replies into [`Self::advance`].
///
/// Unlike DKG, exactly [`crate::THRESHOLD`] parties take part, and which two they are depends on
/// the situation — extension plus server day to day, or extension plus recovery file when the
/// server is unreachable (`docs/recovery.md`).
#[derive(Serialize, Deserialize)]
pub struct SignParty {
    me: PartyId,
    counterparty: PartyId,
    round: u8,
    /// The share this party signs with. Contains a secret, so serialized state must be sealed.
    share: Vec<u8>,
    data: SignData,
    keep_1to2: Option<Keep1to2>,
    keep_2to3: Option<Keep2to3>,
    x_coord: Option<String>,
    broadcasts: Vec<Broadcast3to4<Secp256k1>>,
}

impl core::fmt::Debug for SignParty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignParty")
            .field("me", &self.me)
            .field("counterparty", &self.counterparty)
            .field("round", &self.round)
            .finish_non_exhaustive()
    }
}

/// What a signing party carries from round 1 into round 2.
type Keep1to2 = (
    UniqueKeep1to2<Secp256k1>,
    BTreeMap<PartyIndex, KeepPhase1to2<Secp256k1>>,
);

/// What a signing party carries from round 2 into round 3.
type Keep2to3 = (
    UniqueKeep2to3<Secp256k1>,
    BTreeMap<PartyIndex, KeepPhase2to3<Secp256k1>>,
);

/// The outcome of advancing a signing round.
#[derive(Debug)]
pub enum SignProgress {
    /// There are messages to send.
    Send(Vec<Envelope>),
    /// Signing finished.
    Done(crate::Signature),
}

impl SignParty {
    /// Opens a signing session and produces the round 1 messages.
    ///
    /// `sign_id` must be unique per signature and shared by both parties. `digest` is the
    /// 32-byte hash being signed.
    pub fn start(
        share: &KeyShare,
        counterparty: PartyId,
        sign_id: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<(Self, Vec<Envelope>)> {
        let me = share.party();
        if me == counterparty {
            return Err(Error::Backend(
                "a party cannot sign with itself as counterparty".into(),
            ));
        }

        let party = crate::backend::decode(share)?;
        let data = SignData {
            sign_id: sign_id.to_vec(),
            counterparties: vec![to_index(counterparty)?],
            message_hash: *digest,
        };

        let (unique_kept, kept, transmit) = party
            .sign_phase1(&data)
            .map_err(|e| Error::Backend(format!("sign phase1: {e:?}")))?;

        let outgoing = transmit
            .iter()
            .map(|message| Envelope::new(1, me, Some(to_party(message.parties.receiver)), message))
            .collect::<Result<Vec<_>>>()?;

        Ok((
            Self {
                me,
                counterparty,
                round: 1,
                share: share.expose_secret().to_vec(),
                data,
                keep_1to2: Some((unique_kept, kept)),
                keep_2to3: None,
                x_coord: None,
                broadcasts: Vec::new(),
            },
            outgoing,
        ))
    }

    /// This party's identifier.
    pub fn party(&self) -> PartyId {
        self.me
    }

    /// Serializes the state so it can be held between rounds.
    ///
    /// The result **contains the key share.** It must be encrypted before being stored.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Backend(format!("session encode: {e}")))
    }

    /// Restores state produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Backend(format!("session decode: {e}")))
    }

    /// Consumes the received envelopes and advances to the next round.
    pub fn advance(&mut self, inbox: &[Envelope]) -> Result<SignProgress> {
        for envelope in inbox {
            if envelope.round != self.round {
                return Err(Error::UnexpectedRound {
                    expected: crate::Round::Round(self.round),
                    got: crate::Round::Round(envelope.round),
                });
            }
            if envelope.from != self.counterparty {
                return Err(Error::Backend(format!(
                    "envelope from {} is not from the expected counterparty {}",
                    envelope.from, self.counterparty
                )));
            }
            if let Some(target) = envelope.to {
                if target != self.me {
                    return Err(Error::Backend(format!(
                        "envelope addressed to {target} arrived at {}",
                        self.me
                    )));
                }
            }
        }

        let party = crate::backend::decode(&KeyShare::new(self.me, self.share.clone()))?;
        match self.round {
            1 => self.round2(&party, inbox),
            2 => self.round3(&party, inbox),
            3 => self.round4(&party, inbox),
            other => Err(Error::Backend(format!("signing has no round {other}"))),
        }
    }

    fn round2(
        &mut self,
        party: &dkls23_secp256k1::protocols::Party<Secp256k1>,
        inbox: &[Envelope],
    ) -> Result<SignProgress> {
        let received: Vec<TransmitPhase1to2> = inbox
            .iter()
            .map(Envelope::decode)
            .collect::<Result<Vec<_>>>()?;
        let (unique_kept, kept) = self
            .keep_1to2
            .take()
            .ok_or_else(|| Error::Backend("round 2 called out of order".into()))?;

        let (new_unique, new_kept, transmit) = party
            .sign_phase2(&self.data, &unique_kept, &kept, &received)
            .map_err(|e| Error::Backend(format!("sign phase2: {e:?}")))?;
        self.keep_2to3 = Some((new_unique, new_kept));

        let me = self.me;
        let outgoing = transmit
            .iter()
            .map(|message| Envelope::new(2, me, Some(to_party(message.parties.receiver)), message))
            .collect::<Result<Vec<_>>>()?;

        self.round = 2;
        Ok(SignProgress::Send(outgoing))
    }

    fn round3(
        &mut self,
        party: &dkls23_secp256k1::protocols::Party<Secp256k1>,
        inbox: &[Envelope],
    ) -> Result<SignProgress> {
        let received: Vec<TransmitPhase2to3<Secp256k1>> = inbox
            .iter()
            .map(Envelope::decode)
            .collect::<Result<Vec<_>>>()?;
        let (unique_kept, kept) = self
            .keep_2to3
            .take()
            .ok_or_else(|| Error::Backend("round 3 called out of order".into()))?;

        let (x_coord, broadcast) = party
            .sign_phase3(&self.data, &unique_kept, &kept, &received)
            .map_err(|e| Error::Backend(format!("sign phase3: {e:?}")))?;
        self.x_coord = Some(x_coord);
        // Our own broadcast counts towards phase 4 as well.
        self.broadcasts.push(broadcast.clone());

        self.round = 3;
        Ok(SignProgress::Send(vec![Envelope::new(
            3, self.me, None, &broadcast,
        )?]))
    }

    fn round4(
        &mut self,
        party: &dkls23_secp256k1::protocols::Party<Secp256k1>,
        inbox: &[Envelope],
    ) -> Result<SignProgress> {
        for envelope in inbox {
            self.broadcasts.push(envelope.decode()?);
        }

        let x_coord = self
            .x_coord
            .take()
            .ok_or_else(|| Error::Backend("round 4 called out of order".into()))?;

        let (s_hex, recovery_id) = party
            .sign_phase4(&self.data, &x_coord, &self.broadcasts, true)
            .map_err(|e| Error::Backend(format!("sign phase4: {e:?}")))?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        hex_into(&x_coord, &mut r)?;
        hex_into(&s_hex, &mut s)?;

        self.round = 4;
        Ok(SignProgress::Done(crate::Signature { r, s, recovery_id }))
    }
}

fn hex_into(value: &str, out: &mut [u8; 32]) -> Result<()> {
    if value.len() != 64 {
        return Err(Error::Backend(format!(
            "expected 64 hex characters, got {}",
            value.len()
        )));
    }
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = value
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| Error::Backend("malformed hex".into()))?;
        *slot =
            u8::from_str_radix(pair, 16).map_err(|_| Error::Backend("value is not hex".into()))?;
    }
    Ok(())
}

/// Drives two parties in one process so the signing exchange can be tested without transport.
pub fn sign_locally(
    first: &KeyShare,
    second: &KeyShare,
    sign_id: &[u8; 32],
    digest: &[u8; 32],
) -> Result<crate::Signature> {
    let (mut a, mut in_flight) = SignParty::start(first, second.party(), sign_id, digest)?;
    let (mut b, from_b) = SignParty::start(second, first.party(), sign_id, digest)?;
    in_flight.extend(from_b);

    let mut signature: Option<crate::Signature> = None;
    for _ in 0..4 {
        let mut next = Vec::new();
        for party in [&mut a, &mut b] {
            let me = party.party();
            let inbox: Vec<Envelope> = in_flight
                .iter()
                .filter(|e| e.from != me && e.to.is_none_or(|to| to == me))
                .cloned()
                .collect();
            match party.advance(&inbox)? {
                SignProgress::Send(outgoing) => next.extend(outgoing),
                SignProgress::Done(sig) => match &signature {
                    Some(known) if *known != sig => {
                        return Err(Error::Backend(
                            "signers produced different signatures".into(),
                        ))
                    }
                    _ => signature = Some(sig),
                },
            }
        }
        if let Some(sig) = signature {
            return Ok(sig);
        }
        in_flight = next;
    }

    Err(Error::Backend(
        "signing did not finish within four rounds".into(),
    ))
}
