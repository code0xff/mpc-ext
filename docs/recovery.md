# Recovery

## Starting point

- Normal state: share A in the extension, share B in a recovery file the user keeps offline,
  share C on the server ([adr/0005](adr/0005-share-placement.md)).
- Everyday signing uses A + C, so recovery is needed when one of those two is gone.

## Scenario 0 — server outage or shutdown

No recovery procedure is needed. The user signs directly with **A + B**. When the extension
cannot reach the server it offers this emergency path and asks for the recovery file.

This path is what makes "we do not hold your key hostage" a real property rather than a promise:
if the service disappears, the user's funds are still spendable.

## Scenario 1 — device lost (share A gone)

1. Install the extension on a new device and import the recovery file (B).
2. After authenticating the user, the server agrees to join in recovery mode. **B + C** can now
   sign.
3. Issue a fresh share A to the new device — see "Issuing a new share" below.
4. Export a new recovery file and tell the user to destroy the old one.
5. Until the reshare completes, show the wallet as being in recovery mode and restrict ordinary
   signing.

### Issuing a new share (reshare)

Upstream refresh **only admits parties that already hold a share**, so it cannot fill an empty
slot on a new device ([adr/0004](adr/0004-mpc-library-reselection.md)). The recovery file (B)
and the server share (C) do meet the threshold, though.

`mpc_core::reshare` implements this. On the user's device:

1. Reconstruct the private key from the two surviving shares (Lagrange interpolation).
2. Immediately split it into three fresh shares (trusted-dealer style).
3. Distribute the new shares and discard the reconstructed key from memory.

The public key is preserved, so the address does not change, and old shares no longer combine
with the new set. Both properties are covered by tests
(`crates/mpc-core/tests/adversarial.rs`).

**This procedure briefly materialises the private key in one place (a single point of failure).**
The following constraints apply:

- It runs **only on the user's device.** The server never sees the reconstructed key.
- The key stays in memory and is zeroized immediately. It is never written to disk.
- Tell the user this moment exists. Do not hide it.
- The design already permits key export, so this adds no new trust assumption.

A reshare protocol without the single point of failure — implemented by us or contributed
upstream — is the long-term alternative. In the meantime this procedure is a priority item for
the external audit.

## Scenario 2 — device and recovery file both lost

The server share C alone cannot sign. **This case is unrecoverable.**

- Onboarding **requires** creating the recovery file; it cannot be skipped (`export.md`).
- Tell the user to store it **away from** the extension. Keeping both on one machine collapses
  two shares into one place and defeats the design.
- State this limit plainly during onboarding. Do not hide it.

## Server-side checks

- Recovery requests require account authentication plus a cooling-off period. The exact waiting
  time is an operational policy decision.
- Notify the registered channel when recovery starts, and let the user cancel.
- Log every recovery attempt in the audit log (never shares or other secrets).

## Test requirements

- Signing succeeds for all three pairings: A+C (everyday), A+B (server down), B+C (device lost).
- Aborting recovery leaves the previous shares valid (rollback safety).
- After refresh or reshare, old shares can no longer produce a valid signature.
