# Roadmap

## Phase 0 — foundations

- [x] Repository scaffolding (cargo + pnpm workspaces)
- [x] Tooling, CI and quality gates (`development.md`)
- [x] Evaluate MPC library candidates and settle the ADR (ADR-0004: `0xCarbon/DKLs23`)
- [x] Pin the upstream crate by exact version and record it

## Phase 1 — MPC core

- [x] `mpc-core`: a boundary that keeps upstream types out of the public API
- [x] DKG, signing and refresh
- [x] Integration tests — signing with any two shares, rejecting a single share, refresh keeping
      the public key, and old shares being invalidated
- [x] `mpc-wasm` wasm32 build and native measurements (ADR-0004)
- [x] Browser measurements (V8 wasm) recorded
- [x] Boundary input tests (corrupted share, mixed keysets, duplicate share)
- [x] Reshare (`mpc_core::reshare`) and private key export (`mpc_core::export_private_key`)
- [x] Draft the audit scope (`docs/audit.md`)
- [ ] **Settle the auditor, budget and timing** — needs a decision
- [ ] Report the upstream release-candidate build failure

## Phase 2 — extension MVP

- [x] Confirm wasm runs in an MV3 service worker — DKG 4,856 ms, wasm load 5 ms (automated
      smoke test)
- [x] Encrypted storage (PBKDF2 + AES-GCM, with a test that no plaintext is stored)
- [x] Password setup, locking and unlocking
- [x] Run DKG, export share B as the recovery file, and keep only share A
- [x] Recovery file download
- [x] Atomic onboarding — nothing is persisted until the recovery export is confirmed
- [x] Decide the recovery file format — the full share, as a file (ADR-0005)
- [x] Basic UI (onboarding, lock/unlock)

## Phase 3 — server and the real 2-of-3

- [x] Per-party session API — round state sealed and stored between requests
- [x] `mpc-server` joins DKG (SQLite + OpenAPI/Swagger UI, spec pinned in `docs/openapi.json`)
- [ ] **Everyday signing transport** — extension (A) ↔ server (C) round exchange
- [ ] The A+B emergency signing path for server outages
- [ ] Recovery flow (B+C) and reshare
- [ ] Settle the server authentication design (cooling-off, notification, cancellation)
- [ ] Signing approval UI

## Phase 4 — web integration

- [ ] EIP-1193 / EIP-6963 provider
- [ ] Per-origin permission management
- [ ] `packages/sdk` and an example dApp

## Phase 5 — export

- [ ] Recovery file import (the export side is done)
- [ ] Full private key export in the UI, with warnings
- [ ] Re-export prompts after refresh or reshare

## Phase 6 — hardening

- [ ] Migrate storage to Argon2id + XChaCha20-Poly1305 (`security.md`)
- [ ] External security audit
- [ ] Reproducible builds and signed releases
- [ ] Web Store publication

## Deferred

- A placement that keeps two factors without the server (passkey PRF or OS keychain as a share
  holder) — the alternative that preserves privacy
  ([adr/0005](adr/0005-share-placement.md))
- Biometric unlock (WebAuthn / passkey PRF)
- Periodic automatic key refresh
- Multi-device support (extension shares spread across devices)
- Curves beyond secp256k1, and EdDSA
- Hardware wallets as share holders
- Automatic signing approval policies (off by default)
- Server authentication scheme (a development token stands in until Phase 3)
- SQLite → Postgres (when multiple server instances become necessary)
