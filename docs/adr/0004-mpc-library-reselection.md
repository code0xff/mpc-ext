# ADR-0004: Re-selecting the MPC library

- Status: accepted
- Date: 2026-09-16
- Supersedes: [ADR-0001](0001-mpc-library.md)

## Context

ADR-0001 was withdrawn over its licence, so we re-surveyed permissively licensed candidates.
Four requirements: (1) permissive open source, (2) 2-of-3 threshold ECDSA, (3) **key
refresh/reshare**, and (4) performance that is usable from browser wasm.

Refresh is a design requirement, not a performance one. Without it there is no way back to
2-of-3 after a recovery — only two shares remain and nothing can hand a third to a new device, so
the user has to create a new key and move funds, changing the address. That is a migration, not
a recovery.

## Survey (as of 2026-09-16)

|                                       | Licence                  | Key refresh                  | Audit                          | Maintenance                   | Browser performance      |
| ------------------------------------- | ------------------------ | ---------------------------- | ------------------------------ | ----------------------------- | ------------------------ |
| `silence-laboratories/dkls23`         | ❌ SLL (not open source) | ✅                           | ✅ Trail of Bits, 2024-02      | Healthy                       | ✅                       |
| `0xCarbon/DKLs23`                     | ✅ Apache-2.0 / MIT      | ✅ `refresh.rs`, `re_key.rs` | ❌                             | ⚠️ Effectively one person     | ✅                       |
| `LFDT-Lockness/cggmp21` (→ `cggmp24`) | ✅ MIT / Apache-2.0      | ❌ **unsupported**           | ✅ Kudelski (scope unverified) | ✅ LFDT governance            | ❌ safe-prime generation |
| `LFDT-Lockness/dkls`                  | ✅                       | —                            | ❌                             | **No code** (created 2026-08) | —                        |

Each candidate fails a different requirement. There is no clean option.

Additional findings about `cggmp24`:

- Its README states it "does not (currently) support: Key refresh for both threshold and
  non-threshold keys".
- It deliberately skips constant-time operations ("timing attacks out of scope"), which does not
  match a browser extension's threat model.
- wasm only works with the `num-bigint` backend; the faster `rug` backend is LGPL and therefore
  unavailable to us.
- Key export is supported through the `spof` feature.

## Decision

**Adopt `0xCarbon/DKLs23` (Apache-2.0 / MIT) and budget for the audit ourselves.**

It is the only permissive candidate that meets the refresh requirement, and being DKLs23 it also
performs well in the browser. The costs are the missing audit and effectively single-maintainer
development (bus factor 1), which we accept subject to the mitigations below.

## Code quality assessment (2026-09-16, `dev` at 159 commits)

Checked by cloning the repository.

**Good signs**

- `#![forbid(unsafe_code)]` — zero `unsafe`, enforced by the compiler.
- `zeroize` and `subtle` (constant-time operations) used across seven files.
- The `insecure-rng` feature is gated behind `#[cfg(all(test, feature = ...))]`, so a
  deterministic RNG cannot reach a real build. The intent is spelled out in a comment.
- **Adversarial tests exist** — tampered proofs (`tampered_enc_proof`, `tampered_dlog_proof`) and
  duplicate senders (`rejects_duplicate_mul_init_sender`) are rejected. They do not test only the
  happy path.
- 104 tests. CI runs clippy, fmt, tests, `cargo audit`, `cargo unmaintained` and spell checking.
- 38 panicking call sites across ~6,000 lines of production code — low for cryptographic code.
- `[target.'cfg(target_arch = "wasm32")'.dependencies.getrandom]` enables the `wasm_js` feature,
  so **wasm is an intended target**.

**Risks (organisational and supply-chain, not competence)**

- **Every dependency is a release candidate**: `elliptic-curve 0.14.0-rc.29`,
  `k256 0.14.0-rc.8`, `sha2 0.11.0-rc.5`, `hmac 0.13.0-rc.5`, `ripemd 0.2.0-rc.5`. Pre-release
  cryptographic code is less battle-tested and its API moves.
- Bus factor 1 — roughly 85% of 159 commits come from one person.
- No external audit. The default branch is `dev`, not `main`.
- CI uses the unmaintained `actions-rs/*` actions.

**Conclusion**: apart from the missing audit, the engineering posture matches that of audited
libraries. The decision stands.

## Phase 1 implementation results (2026-09-17)

We wired up `dkls23-secp256k1 =0.5.1` and implemented 2-of-3 DKG, signing and refresh.

### Measurements (Apple Silicon, mean of 5 runs)

| Operation           | Native release | wasm (V8)    | Budget | Result |
| ------------------- | -------------- | ------------ | ------ | ------ |
| DKG (3 parties)     | 833 ms         | **4,920 ms** | 10 s   | pass   |
| Signing (2 parties) | 4.4 ms         | **16 ms**    | 1 s    | pass   |
| Refresh (3 parties) | 834 ms         | **4,868 ms** | 30 s   | pass   |

wasm size: 623 KB raw, 459 KB after `wasm-opt` (148 KB gzipped). Acceptable for an extension
bundle.

**Everything passes.** The 16 ms signing figure matters most — the everyday path introduces no
perceptible latency.

Conditions and caveats:

- The `wasm32-unknown-unknown` build works. `getrandom` uses the `wasm_js` backend and therefore
  Web Crypto (`.cargo/config.toml`).
- The wasm figures run **all three parties on one thread**. In the real deployment the extension
  handles two parties and the server one (natively), so the extension does less work — but
  network round trips are added.
- V8 wasm is the same engine as Chrome but is not an MV3 service worker. Worker termination and
  wasm instantiation cost were measured separately in Phase 2 (wasm load: 5 ms).

### Phase 3 measurements — the real deployment (2026-09-18)

The numbers above drive all three parties in one place. These are the split deployment, measured
inside a real MV3 service worker with a real server on localhost.

| Operation           | Everything local (wasm) | Extension + server | Budget | Result |
| ------------------- | ----------------------- | ------------------ | ------ | ------ |
| DKG (3 parties)     | 4,920 ms                | **9,084 ms**       | 10 s   | pass   |
| Signing (2 parties) | 16 ms                   | **41 ms**          | 1 s    | pass   |

Splitting the work adds HTTP round trips and several passes of serializing ~114 KB shares across
the wasm boundary and the wire. The DKG figure varies a lot between runs — machine load dominates
— so the range above is what we have observed rather than a single number. Signing stays
comfortable either way.

One lesson worth keeping: the first split measurement was **12,729 ms for DKG, over budget**. The
cause was encoding envelope payloads as JSON arrays of numbers when crossing from wasm to JS.
Switching that boundary to base64 brought DKG to 9,084 ms and signing from 92 ms to 41 ms. For
100 KB payloads the encoding choice at a language boundary dominates.

These are localhost numbers. Real network latency adds to signing, so the 1 s budget should be
re-checked against a deployed server.

### Finding 1 — upstream does not build against current stable RustCrypto

`dkls23-core 0.5.1` was published against `elliptic-curve 0.14.0-rc.29` and `k256 0.14.0-rc.8`.
RustCrypto has since released stable 0.14.1. Cargo's default resolution picks the stable release,
associated types differ, and the build breaks. We fixed it by pinning those pre-release versions
with `=` in our own `Cargo.toml`.

**This is exactly the release-candidate risk this ADR anticipated, materialising.** Upstream has
had no substantive changes since April 2026 beyond dependency bumps, so it did not fix this
itself. We will report it upstream.

### Finding 2 — `re_key` is not refresh

When writing this ADR we counted `re_key.rs` as the refresh feature. It is in fact
**trusted-dealer key import**: it splits a known private key into shares. The real refresh is
`refresh_complete_*` in `refresh.rs`, which regenerates every share while preserving the public
key. Verified by test. The conclusion — refresh is supported — still holds.

### Finding 3 — refresh requires every existing party (design impact)

`refresh_complete_phase1` is a method on `Party`, so **only parties that already hold a share can
take part**. Filling the slot of a lost share with a new device is a reshare, not a refresh, and
upstream has no such protocol. Our response is recorded in `docs/recovery.md`.

## Mitigations (required)

1. **Version pinning** — an exact `=0.5.1` pin, a committed `Cargo.lock`, and a Dependabot ignore
   entry prevent automatic updates. Vendoring the source tree happens when we freeze the audit
   target.
2. **A boundary** — `mpc-core` keeps the upstream crate behind its own types. Replaceability is
   preserved structurally.
3. **Our own audit** — the external security audit covers this crate. Its scope, budget and
   timing are settled at the **end of Phase 1**, not Phase 6.
4. **Upstream relationship** — contribute bugs we find back upstream. If maintenance stops, be
   ready to take over a fork.
5. **Pinned release-candidate dependencies** — freeze the release-candidate versions in the
   lockfile at vendoring time. Do not follow upstream automatically when they go stable; verify
   first. Track each pre-release dependency and its stabilisation status.
6. **Watch the alternatives** — follow `LFDT-Lockness/dkls`. If an audited, permissive DKLs23
   implementation appears, revisit this ADR.

## Consequences

- We become de facto co-maintainers of this crate. That cost is explicit in the project plan.
- Until the audit, the README and the extension UI carry a **do not use with real assets**
  warning.
