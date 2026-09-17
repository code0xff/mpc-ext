//! Protocol measurements against the budgets in ADR-0004.
//!
//! Run with `cargo run --release -p mpc-core --example bench`.
//!
//! Native numbers are a lower bound: browser wasm is slower, so anything that misses a budget
//! here will miss it there too.

// Panicking is how a benchmark reports failure. Production code keeps these lints.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rounds = 5;
    println!("2-of-3 DKLs23, mean of {rounds} runs (native release)\n");

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
            "signature failed to verify"
        );

        let t = Instant::now();
        let _refreshed = mpc_core::refresh(&shares, &session)?;
        refresh_total += t.elapsed().as_secs_f64();
    }

    let n = f64::from(rounds);
    report("DKG (3 parties)", dkg_total / n, 10.0);
    report("Signing (2 parties)", sign_total / n, 1.0);
    report("Refresh (3 parties)", refresh_total / n, 30.0);

    Ok(())
}

fn report(label: &str, secs: f64, budget: f64) {
    let verdict = if secs <= budget { "pass" } else { "OVER" };
    println!(
        "{label:<20} {:>8.1} ms   (budget {:.0}s, {verdict})",
        secs * 1000.0,
        budget
    );
}
