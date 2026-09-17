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

impl DkgParty {
    /// Opens a session and produces the round 1 messages.
    ///
    /// Every party must use the same `session_id`, and it must never be reused.
    pub fn start(me: PartyId, session_id: &[u8; 32]) -> Result<(Self, Vec<Envelope>)> {
        let index = to_index(me)?;
        let params = Parameters {
            threshold: crate::THRESHOLD,
            share_count: TOTAL_PARTIES,
        };
        let data = SessionData {
            parameters: params,
            party_index: index,
            session_id: session_id.to_vec(),
        };

        // Each party gets a different polynomial fragment, so these are point to point.
        let row = dkg::phase1::<Secp256k1>(&data);
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

        self.round = 4;
        Ok(Progress::Done {
            public_key: crate::backend::public_key_of(&party)?,
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
