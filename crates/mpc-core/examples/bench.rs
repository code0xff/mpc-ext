//! 프로토콜 실측. ADR-0004의 합격 기준을 확인한다.
//!
//! 실행: `cargo run --release -p mpc-core --example bench`
//!
//! 네이티브 수치는 하한선이다. 브라우저 wasm은 이보다 느리므로, 여기서 기준을
//! 넘지 못하면 wasm에서도 넘지 못한다.

// 테스트에서 panic은 단언 수단이다. 프로덕션 코드에는 이 lint가 그대로 적용된다.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rounds = 5;
    println!("2-of-3 DKLs23 · {rounds}회 평균 (네이티브 release)\n");

    let mut dkg_total = 0.0;
    let mut sign_total = 0.0;
    let mut refresh_total = 0.0;

    for i in 0..rounds {
        let mut session = [0u8; 32];
        session[0] = i;

        let t = Instant::now();
        let (shares, public_key) = mpc_core::dkg(&session)?;
        dkg_total += t.elapsed().as_secs_f64();

        let digest = [0x5Au8; 32];
        let t = Instant::now();
        let signature = mpc_core::sign(&[&shares[0], &shares[1]], &session, &digest)?;
        sign_total += t.elapsed().as_secs_f64();

        assert!(
            mpc_core::verify(&public_key, &digest, &signature)?,
            "서명 검증 실패"
        );

        let t = Instant::now();
        let _refreshed = mpc_core::refresh(&shares, &session)?;
        refresh_total += t.elapsed().as_secs_f64();
    }

    let n = f64::from(rounds);
    report("DKG (3파티)", dkg_total / n, 10.0);
    report("서명 (2파티)", sign_total / n, 1.0);
    report("리프레시 (3파티)", refresh_total / n, 30.0);

    Ok(())
}

fn report(label: &str, secs: f64, budget: f64) {
    let verdict = if secs <= budget { "통과" } else { "초과" };
    println!(
        "{label:<18} {:>8.1} ms   (기준 {:.0}s · {verdict})",
        secs * 1000.0,
        budget
    );
}
