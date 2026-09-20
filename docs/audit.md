# External security audit plan

> Status: **draft — budget and timing undecided.** This is a Phase 1 exit condition
> ([adr/0004](adr/0004-mpc-library-reselection.md), mitigation 3).

## Why we need one

The MPC library we adopted, `0xCarbon/DKLs23`, **has no external audit history**. Its code
quality is good — no `unsafe`, it uses `zeroize` and `subtle`, and it has adversarial tests —
but we are putting a key-custody product on top of an unaudited cryptographic implementation. We
chose it on the explicit assumption that we would pay for the audit ourselves.

## Scope

In priority order.

1. **The pinned MPC crates** — `dkls23-core` and `dkls23-secp256k1` at the exact version we ship.
   OT extension, the multiplication protocol, zero-knowledge proofs, and the DKG, signing and
   refresh rounds.
2. **`crates/mpc-core`**, especially:
   - The private key reconstruction inside `reshare` and `export_private_key`. It is the only
     point in the design where a single point of failure exists (`recovery.md`). Review the
     lifetime of the reconstructed value, zeroization, and every call path.
   - The distributed reshare (`DkgParty::start_reshare`): Lagrange-weighted contributions fed
     through the DKG phases, and the public key check that guards it. It is a new use of the
     upstream phases that nobody has reviewed (`adr/0007-distributed-reshare.md`).
   - Share serialization and party identifier handling.
3. **Extension storage and locking** — KDF parameters, AEAD usage, and how long secrets live in
   memory while unlocked (`security.md`).
4. **The recovery path** — server authentication, the cooling-off period, and the reshare's
   staging and commit on the server (`recovery.md`, `server.md`).
5. **The web provider boundary** — origin checks and the approval flow (`web-api.md`).

## Out of scope

- A rooted OS, kernel-level keyloggers, physical coercion.
- An attacker holding both the extension and a recovery file stored on the same machine — a
  documented user-side risk (`security.md`).

## Prerequisites

Before an audit can start:

- [ ] Vendor the MPC crate into the source tree so the audited code is frozen at a commit
- [ ] Establish reproducible builds (`development.md`)
- [ ] Bring the threat model up to date (`security.md`)
- [x] Finish the server authentication design ([adr/0006](adr/0006-server-authentication.md))
- [ ] Implement it — the design alone is not enough to audit against

## Undecided — needs a decision

| Item        | Status                                           |
| ----------- | ------------------------------------------------ |
| Auditor     | Undecided                                        |
| Budget      | Undecided                                        |
| Timing      | Before Phase 6; exact date undecided             |
| Final scope | How much of items 1–5 we cover depends on budget |

## Principles

- **Publish** the audited commit and the resulting report in this repository.
- Until the audit is complete, keep the **do not use with real assets** warning in the README and
  the extension UI.
- Disclose any upstream vulnerabilities we find responsibly, to upstream.
