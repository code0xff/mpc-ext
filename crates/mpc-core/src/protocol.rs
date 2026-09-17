//! 파티별 프로토콜 세션.
//!
//! [`crate::dkg`] 등은 세 파티를 한 프로세스에서 돌리는 하네스이고, 이 모듈은
//! **파티가 실제로 분리된 배치**를 위한 것이다. 확장은 셰어 A의 파티를, 서버는
//! 셰어 C의 파티를 각각 굴리며 [`Envelope`]을 주고받는다
//! (`docs/architecture.md`).
//!
//! 전송 방법은 이 모듈의 관심사가 아니다. 호출부는 봉투를 상대에게 전달하고
//! 받은 봉투를 넣어주기만 하면 된다.

use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256k1::protocols::dkg_session::DkgSession;
use dkls23_secp256k1::protocols::{Parameters, PartyIndex};
use k256::Secp256k1;
use serde::{Deserialize, Serialize};

use crate::{Error, KeyShare, PartyId, PublicKey, Result, TOTAL_PARTIES};

/// 한 라운드에서 한 파티가 다른 파티에게 보내는 메시지.
///
/// `to`가 `None`이면 브로드캐스트다. 본문은 불투명한 바이트이며, 받는 쪽의
/// 세션만 해석할 수 있다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// 프로토콜 라운드 번호 (1부터).
    pub round: u8,
    /// 보낸 파티.
    pub from: PartyId,
    /// 받을 파티. `None`이면 모든 파티에게.
    pub to: Option<PartyId>,
    /// 직렬화된 본문.
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

/// 라운드를 진행한 결과.
#[derive(Debug)]
pub enum Progress {
    /// 보낼 메시지가 있다. 상대에게 전달한 뒤 응답을 다시 넣어준다.
    Send(Vec<Envelope>),
    /// 프로토콜이 끝났다.
    Done {
        /// 이 파티의 셰어.
        share: KeyShare,
        /// 공동 공개키.
        public_key: PublicKey,
    },
}

/// 라운드 2와 3에서 모아두는 상대 메시지.
#[derive(Default)]
struct Inbox {
    proofs: BTreeMap<PartyId, ProofCommitment<Secp256k1>>,
    zero_2to4: Vec<TransmitInitZeroSharePhase2to4>,
    zero_3to4: Vec<TransmitInitZeroSharePhase3to4>,
    mul_3to4: Vec<TransmitInitMulPhase3to4<Secp256k1>>,
    bip_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4>,
    bip_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4>,
}

/// 라운드 2에서 브로드캐스트되는 묶음.
#[derive(Serialize, Deserialize)]
struct Round2Broadcast {
    proof: ProofCommitment<Secp256k1>,
    bip: BroadcastDerivationPhase2to4,
}

/// 라운드 3에서 브로드캐스트되는 묶음.
#[derive(Serialize, Deserialize)]
struct Round3Broadcast {
    bip: BroadcastDerivationPhase3to4,
}

/// 라운드 3에서 특정 상대에게만 보내는 묶음.
#[derive(Serialize, Deserialize)]
struct Round3Private {
    zero: TransmitInitZeroSharePhase3to4,
    mul: TransmitInitMulPhase3to4<Secp256k1>,
}

/// 분산 키 생성에 참여하는 한 파티.
///
/// 라운드 4개를 거친다. 각 라운드마다 [`Progress::Send`]로 나온 봉투를 상대에게
/// 전달하고, 상대에게서 받은 봉투를 [`Self::advance`]에 넣는다.
pub struct DkgParty {
    me: PartyId,
    index: PartyIndex,
    round: u8,
    session: Option<DkgSession<Secp256k1>>,
    fragments: BTreeMap<PartyId, k256::Scalar>,
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
    /// 세션을 열고 라운드 1 메시지를 만든다.
    ///
    /// `session_id`는 모든 파티가 같은 값을 써야 하며, 재사용해서는 안 된다.
    pub fn start(me: PartyId, session_id: &[u8; 32]) -> Result<(Self, Vec<Envelope>)> {
        let index = to_index(me)?;
        let params = Parameters {
            threshold: crate::THRESHOLD,
            share_count: TOTAL_PARTIES,
        };
        let session = DkgSession::new(params, index, session_id.to_vec());

        // 다항식 조각은 파티마다 다른 값을 보낸다 (p2p).
        let row = session.phase1();
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
                session: Some(session),
                fragments,
                inbox: Inbox::default(),
            },
            outgoing,
        ))
    }

    /// 이 파티의 식별자.
    pub fn party(&self) -> PartyId {
        self.me
    }

    /// 받은 봉투를 처리하고 다음 라운드로 넘어간다.
    ///
    /// 라운드 순서를 어긴 봉투는 세션을 실패시킨다. 부분 진행 상태를 남기지 않는다.
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

    fn session_mut(&mut self) -> Result<&mut DkgSession<Secp256k1>> {
        self.session
            .as_mut()
            .ok_or_else(|| Error::Backend("dkg session already finished".into()))
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

        // 업스트림은 파티 순서대로 정렬된 조각을 기대한다.
        let ordered: Vec<k256::Scalar> = self.fragments.values().copied().collect();
        let me = self.me;
        let (proof, zero, bip) = self
            .session_mut()?
            .phase2(&ordered)
            .map_err(|e| Error::Backend(format!("dkg phase2: {e:?}")))?;

        // phase4는 자신을 포함한 모든 파티의 증명을 요구한다. 보내기 전에 우리 몫을 남겨둔다.
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
        let (zero, mul, bip) = self
            .session_mut()?
            .phase3()
            .map_err(|e| Error::Backend(format!("dkg phase3: {e:?}")))?;

        self.inbox.bip_3to4.insert(self.index, bip.clone());

        let mut outgoing = vec![Envelope::new(3, me, None, &Round3Broadcast { bip })?];
        // 같은 상대에게 가는 zero/mul 메시지를 하나로 묶는다.
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

        // 업스트림 phase4는 자신의 증명도 포함한 전체 목록을 기대한다.
        let mut proofs: Vec<ProofCommitment<Secp256k1>> =
            Vec::with_capacity(TOTAL_PARTIES as usize);
        for party in (0..TOTAL_PARTIES).map(PartyId) {
            let proof =
                self.inbox.proofs.get(&party).ok_or_else(|| {
                    Error::Backend(format!("missing proof commitment from {party}"))
                })?;
            proofs.push(proof.clone());
        }

        let session = self
            .session
            .take()
            .ok_or_else(|| Error::Backend("dkg session already finished".into()))?;
        let (party, _pkg) = session
            .phase4(
                &proofs,
                &self.inbox.zero_2to4,
                &self.inbox.zero_3to4,
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

/// 세 파티를 한 프로세스에서 굴려 [`DkgParty`]가 실제로 맞물리는지 확인한다.
///
/// 전송 계층 없이 프로토콜 구현만 검증하기 위한 하네스다.
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
