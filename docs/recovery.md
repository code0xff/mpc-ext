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
2. The extension stores share B under a new password and registers itself as party 1.
3. Everyday signing now runs **B + C** — the recovery share plus the server.

The address does not change and the user can spend again. **But the wallet does not return to a
healthy 2-of-3, and that limitation is structural.**

### Why recovery cannot restore three healthy shares

Two operations could fix the missing share, and neither is available:

- **Refresh** rotates every share but requires all existing parties. The lost share's party
  cannot attend ([adr/0004](adr/0004-mpc-library-reselection.md), finding 3).
- **Reshare** (`mpc_core::reshare`) reconstructs the private key and re-splits it, but it needs
  two shares **in one place.** After a device loss the user holds B and the server holds C, and C
  must never leave the server. Sending it would hand one party a signing-capable pair, which is
  the invariant the whole design rests on.

What follows from that:

- **The lost share A stays valid forever.** If someone later recovers the lost device and pairs
  share A with either the recovery file or the server, they can sign. Refresh is what would have
  invalidated it, and we cannot run it.
- **The recovery file is no longer an independent third share.** It now holds the same share the
  extension holds, so the user has two copies of B and no separate backup.

So after a device loss the honest advice is: **create a new wallet and move the funds.** The
recovered wallet is for spending, not for continuing to live in.

The UI must say this plainly. It must not present a recovered wallet as fully restored.

### Restoring full protection: a distributed reshare

A restored wallet shows a "Restore full protection" card. It runs the reshare that
[ADR-0007](adr/0007-distributed-reshare.md) describes. The extension and the server each
contribute their surviving share (B and C) as the constant term of a DKG, and a fresh A' joins on
the new device. Nothing is sent to the server that lets it learn B, and C never leaves the server.
The address stays the same.

What the user sees, in order:

1. The wallet password and a passkey approval. The server is about to replace its share, so it
   asks for the same approval as a recovery signature.
2. The reshare runs. The passkey ceremony opens a tab that closes the popup, so the popup can be
   reopened afterwards and picks the result up.
3. The user saves a **new** recovery file, encrypted under a new recovery password. This is the
   only time the new share B' exists outside memory.
4. On confirming, the server commits (its old share is deleted) and the extension stores A'. The
   wallet is a healthy 2-of-3 again and the "restored" banner goes away.

Cancelling at any point before step 4 leaves the previous shares valid, and a reshare that
stopped halfway leaves nothing behind (the server drops its staged share after 30 minutes).

Two limits remain, both stated in the ADR.

- **The new device can compute the key while the ceremony runs**, exactly as it can at key
  creation, and it learns the server's old share along the way. Run it only on a device you trust,
  and only on the fresh install you restored onto.
- **The lost share A stays dangerous for anyone who also holds the old recovery file.** Old A plus
  old B still reconstructs the key, and no reshare can change that. The server deletes its old
  share on commit, so the old file is the remaining exposure. The user has to destroy it.

A user who does not run the reshare is in the position described above, and the advice to move to
a new wallet still holds for them.

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
- After a reshare, the lost share A cannot sign with any new share (`mpc-core` and server tests).
- After a reshare, the old shares still sign among themselves. That is why the server deletes its
  old share on commit and why the old recovery file has to be destroyed.
