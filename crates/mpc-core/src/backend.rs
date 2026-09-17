//! 업스트림 DKLs23 구현을 감싸는 내부 계층.
//!
//! **업스트림 타입은 이 모듈 밖으로 나가지 않는다.** 상위 계층(확장 background,
//! 서버 핸들러)은 `mpc-core`의 자체 타입만 보므로, 라이브러리를 교체해도
//! 호출부가 바뀌지 않는다 (`docs/adr/0004-mpc-library-reselection.md` 완화책 2).
//!
//! 현재 오케스트레이션은 모든 파티를 한 프로세스에서 실행한다. 실제 배포에서는
//! 파티가 확장 2 + 서버 1로 나뉘며, 그 전송 계층은 Phase 3에서 붙인다
//! (`docs/roadmap.md`). 라운드별 메시지 경로는 동일하다.

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

/// 주소 문자열은 `mpc-core`의 관심사가 아니다. 체인별 주소 유도는 상위 계층이 한다.
fn no_address(_pk: &k256::AffinePoint) -> String {
    String::new()
}

fn upstream_params() -> Parameters {
    Parameters {
        threshold: THRESHOLD,
        share_count: TOTAL_PARTIES,
    }
}

/// `PartyId`(0-based)를 업스트림의 1-based 인덱스로 옮긴다.
fn to_upstream(party: PartyId) -> Result<PartyIndex> {
    PartyIndex::new(party.0 + 1).map_err(|e| Error::Backend(e.to_string()))
}

fn from_upstream(index: PartyIndex) -> PartyId {
    PartyId(index.as_u8() - 1)
}

fn encode(party: &UpstreamParty) -> Result<Vec<u8>> {
    bincode::serialize(party).map_err(|e| Error::Backend(format!("share encode: {e}")))
}

fn decode(share: &KeyShare) -> Result<UpstreamParty> {
    bincode::deserialize(share.expose_secret())
        .map_err(|e| Error::Backend(format!("share decode: {e}")))
}

fn public_key_of(party: &UpstreamParty) -> Result<PublicKey> {
    use elliptic_curve::sec1::ToSec1Point;
    let encoded = party.pk.to_sec1_point(true);
    let bytes = encoded.as_bytes();
    let out: [u8; 33] = bytes
        .try_into()
        .map_err(|_| Error::Backend(format!("unexpected public key length: {}", bytes.len())))?;
    Ok(PublicKey(out))
}

/// 수신자가 우리인 메시지만 골라낸다. 각 라운드의 메시지 라우팅에 쓴다.
fn route<T: Clone>(all: &[Vec<T>], me: PartyIndex, receiver: impl Fn(&T) -> PartyIndex) -> Vec<T> {
    all.iter()
        .flatten()
        .filter(|m| receiver(m) == me)
        .cloned()
        .collect()
}

/// 3파티 분산 키 생성.
///
/// 어떤 파티도 완전한 개인키를 보지 않는다. 실패하면 부분 결과를 남기지 않고
/// 전체가 실패한다 — 호출부는 성공 시에만 셰어를 저장해야 한다.
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

    // 라운드 1 — 각 파티가 모든 파티에게 다항식 조각을 보낸다.
    let rows: Vec<Vec<k256::Scalar>> = sessions.iter().map(DkgSession::phase1).collect();
    let mut fragments: Vec<Vec<k256::Scalar>> = vec![Vec::with_capacity(n); n];
    for row in &rows {
        for (j, frag) in row.iter().enumerate().take(n) {
            fragments[j].push(*frag);
        }
    }

    // 라운드 2
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

    // 라운드 3
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

    // 라운드 4 — 각 파티가 자신의 셰어와 공동 공개키를 확정한다.
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

/// 임계 서명. 정확히 [`THRESHOLD`]개의 셰어가 참여해야 한다.
///
/// 평시에는 확장이 가진 두 셰어로, 복구 모드에서는 남은 셰어와 서버 셰어로 호출한다.
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

    // 라운드 1
    let mut sessions = Vec::with_capacity(parties.len());
    let mut transmit_1to2 = Vec::with_capacity(parties.len());
    for (party, data) in parties.iter().zip(sessions_data) {
        let (session, transmit) = SignSession::new(party, data)
            .map_err(|e| Error::Backend(format!("sign phase1: {e:?}")))?;
        sessions.push(session);
        transmit_1to2.push(transmit);
    }

    // 라운드 2
    let mut transmit_2to3 = Vec::with_capacity(parties.len());
    for (i, session) in sessions.iter_mut().enumerate() {
        let received = route(&transmit_1to2, signers[i], |m| m.parties.receiver);
        transmit_2to3.push(
            session
                .phase2(&received)
                .map_err(|e| Error::Backend(format!("sign phase2: {e:?}")))?,
        );
    }

    // 라운드 3
    let mut broadcasts = Vec::with_capacity(parties.len());
    for (i, session) in sessions.iter_mut().enumerate() {
        let received = route(&transmit_2to3, signers[i], |m| m.parties.receiver);
        broadcasts.push(
            session
                .phase3(&received)
                .map_err(|e| Error::Backend(format!("sign phase3: {e:?}")))?,
        );
    }

    // 라운드 4 — 모든 참여자가 같은 서명을 얻어야 한다.
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

/// 키 리프레시. 공개키를 유지한 채 모든 셰어를 재생성한다.
///
/// 옛 셰어는 이 시점부터 서명에 쓸 수 없다. 복구 직후 반드시 실행한다
/// (`docs/recovery.md`). **모든 파티가 참여해야 한다** — 셰어를 잃은 파티를
/// 새 기기로 대체하는 경우는 리프레시가 아니라 리셰어이며, 별도 절차다.
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

    // 라운드 1 — 상수항이 0인 다항식 조각. 공개키를 바꾸지 않는 보정값이다.
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

/// 리프레시 중간 상태. 라운드 사이에만 살아 있다.
struct RefreshState {
    point: k256::Scalar,
    zero_keep: BTreeMap<PartyIndex, dkls23_secp256k1::protocols::dkg::KeepInitZeroSharePhase2to3>,
}

/// 서명이 해당 공개키에 대해 유효한지 검증한다.
///
/// 테스트와 상위 계층의 사후 확인에 쓴다. 비밀 값을 다루지 않는다.
pub fn verify(public_key: &PublicKey, digest: &[u8; 32], signature: &Signature) -> Result<bool> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key.0)
        .map_err(|e| Error::Backend(format!("invalid public key: {e}")))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signature.r);
    sig_bytes[32..].copy_from_slice(&signature.s);
    let sig = match k256::ecdsa::Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        // 형식이 어긋난 서명은 오류가 아니라 "유효하지 않음"이다.
        Err(_) => return Ok(false),
    };

    Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
}

/// 셰어들로부터 완전한 개인키를 복원한다 (Shamir 보간, x=0).
///
/// # 위험
///
/// 이 함수는 **MPC의 보안 이점을 없앤다.** 복원된 키는 한 곳에 존재하는 완전한
/// 개인키이며, 호출부는 사용 후 즉시 폐기해야 한다. 사용자 기기에서만 호출하고,
/// 서버로 보내거나 디스크에 쓰지 않는다 (`docs/export.md`, `docs/recovery.md`).
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

    // 같은 파티가 두 번 들어오면 보간이 성립하지 않는다.
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

/// 복원된 개인키. 사용 후 zeroize된다.
struct ReconstructedKey {
    scalar: k256::Scalar,
}

impl Drop for ReconstructedKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Scalar 자체는 Zeroize를 구현하지 않으므로 바이트 표현을 지운다.
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

/// 완전한 개인키를 추출한다 (32바이트 big-endian).
///
/// # 위험
///
/// 이 순간 MPC의 이점이 사라진다. 상위 계층은 사용자에게 명시적으로 경고하고
/// 확인을 받아야 한다 (`docs/export.md`).
pub fn export_private_key(shares: &[&KeyShare]) -> Result<SecretKeyBytes> {
    let key = reconstruct(shares)?;
    Ok(SecretKeyBytes(key.to_bytes()))
}

/// 남은 셰어로부터 셰어 3개를 새로 발급한다 (리셰어).
///
/// 셰어를 잃은 자리를 새 기기로 채울 때 쓴다. 업스트림 리프레시는 셰어를 이미
/// 가진 파티만 참여할 수 있어 이 경우를 다룰 수 없다
/// (`docs/adr/0004-mpc-library-reselection.md` 발견 3).
///
/// # 위험
///
/// 내부적으로 개인키를 복원했다가 즉시 다시 나눈다. 그 사이 개인키가 한 곳에
/// 존재한다(SPOF). **사용자 기기에서만 호출한다.** 서버에서 호출해서는 안 된다.
/// 공개키는 유지되므로 주소는 바뀌지 않는다.
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
