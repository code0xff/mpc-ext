# ADR-0007: Distributed reshare after a device loss

- Status: accepted; implementation in progress
- Date: 2026-09-20

## Context

After a device loss the user restores share B from the recovery file and signs with B + C
(`docs/recovery.md`). The address survives, but the wallet stays degraded. The lost share A is
still valid, and the recovery file is no longer an independent backup because the extension now
holds the same share. The current advice is to create a new wallet and move the funds.

Refresh cannot fix this. Upstream refresh runs on `Party` objects, so every existing party has to
take part, and the lost one cannot. The reshare we have (`mpc_core::reshare`) reconstructs the
key in one process and re-splits it, which needs two shares in one place. C must not leave the
server, so that path is closed too (ADR-0004, finding 3).

Reading `dkls23-core` 0.5.1 shows a third way. Its DKG is public as `phase1` to `phase4`, and
`phase2` only sums the polynomial fragments it is handed. The "complete refresh" in `refresh.rs`
already exploits this by feeding zero-constant polynomials into a DKG run. Two facts make a
reshare possible on the same machinery:

- `step5` checks that the three resulting points lie on one polynomial (two overlapping
  Shamir reconstructions in the exponent must agree) and returns the public key. A malformed
  contribution is caught there.
- Two surviving shares fix the secret. With survivors at party indices `i` and `j`, the secret is
  `λ_i·s_i + λ_j·s_j` for the Lagrange coefficients at zero over `{i, j}`.

## Options considered

| Option                                                         | Pros                                                         | Cons                                                                                                     |
| -------------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Keep the advice: new wallet, move funds                        | No new protocol code                                         | The address changes, on-chain history and approvals are lost, and the old share stays valid indefinitely |
| Reshare on the device with B from the file and C over the wire | Address preserved; fresh A', B', C'; runs on upstream phases | The device can compute the key during the ceremony, and it is a new, unaudited use of the DKG phases     |
| Server-side reshare (server plays every new party)             | Simple                                                       | The server would hold two shares and could sign alone. Forbidden by `AGENTS.md`                          |
| B' produced on a second device                                 | The ceremony device never holds a pair                       | Needs a second device and a pairing protocol. Deferred                                                   |
| Contribute a reshare protocol upstream, or switch library      | Audited or reviewed by the upstream author                   | No timeline, and no audited permissive alternative exists (ADR-0004)                                     |

## Decision

Run a DKG in which the two surviving holders contribute a polynomial whose constant term is
their Lagrange-weighted share, and the new party contributes nothing.

**Roles.** After a device loss the survivors are B (party index 2) and C (index 3). The
extension, running on the new device, plays the index-2 party using B from the recovery file,
and also the new index-1 party (A'). The server plays index 3 using its stored C. The extension
therefore ends up with A' and B', exactly as it does at key creation, and the server ends up
with C'.

**Contributions.** Party 2 samples `g₂(x) = λ₂·s₂ + r₂·x` and party 3 samples
`g₃(x) = λ₃·s₃ + r₃·x`, with `λ₂ = 3` and `λ₃ = −2` for survivors `{2, 3}`. Party 1 sends zero
fragments. Each new party sums the fragments it receives (`phase2` already does this), and then
all three run `phase2` to `phase4` unchanged, which establishes fresh zero-share seeds and
fresh multiplication (OT) state for every pair. The constant term of the sum is
`λ₂·s₂ + λ₃·s₃`, which is the original secret.

**Acceptance.** Before a party keeps its new share, `mpc-core` compares the public key that
`step5` computed with the wallet's existing public key and aborts on any difference. A server
that contributes a wrong constant term fails here, and so does any inconsistent fragment set.

**Two-phase commit on the server.** The server stages C' next to the live C. It replaces C and
deletes the old share only on an explicit commit, which the extension sends after the user has
confirmed saving the new recovery file. Aborting at any earlier point leaves the previous shares
valid, as `recovery.md` already requires.

**Authorization.** Starting a reshare needs the device key and one verified passkey assertion
under the `recovery` purpose, bound to the reshare session. Nothing weaker than what recovery
signing needs is acceptable, because this operation replaces the server's share.

**Generality.** The survivor pair is a parameter. The same code covers a server migration, where
survivors are A and B and a new server takes index 3. Only the device-loss case is wired into
the extension in this decision.

## Consequences

**The ceremony device can compute the private key.** This is the honest cost, and it is the
reason `recovery.md` ruled out sending C. The server never sends C, but it sends `g₃(1)` and
`g₃(2)`, both of which land on the extension because the extension plays A' and B'. Two points
on a line fix its constant term, so the device learns `λ₃·s₃`, then `s₃`, then the key. No
design that yields a fresh A' and a fresh B' on one machine avoids this, because those two
shares are a signing pair.

This is the same exposure that key creation already has, since the extension plays two DKG
parties then too, and the architecture invariant already says reconstruction happens on the
user's device only. What changes is that a live key, not a fresh one, is exposed. So the ceremony
runs only on a freshly installed extension, the UI says what it is doing before it starts, and
all key material is zeroized afterwards. The server learns nothing beyond its own share: it
receives one evaluation of `g₂`, which a random slope hides.

**The lost share dies only if the survivors' old shares do.** Old A plus old B, or old A plus old
C, still reconstructs the key. After a successful commit the server no longer holds old C, so
the remaining exposure is an old recovery file kept next to a stolen device. The user has to
destroy the old file, and the UI has to say so. Nothing can enforce it.

**This is an unaudited adaptation.** The DKLs23 paper argues security for its own refresh and
DKG. Feeding Lagrange-weighted contributions through the DKG phases is standard proactive
resharing, but nobody has reviewed it on this codebase. It goes into the audit scope
(`docs/audit.md`), and the change is not to be advertised as audited.

**Reversing the decision is cheap.** The feature adds a session type and endpoints and changes
no stored format for keys that never reshare. Removing it returns us to the advice in
`recovery.md`.
