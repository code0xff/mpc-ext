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

### The fix: a distributed reshare

[ADR-0007](adr/0007-distributed-reshare.md) settles the design. B and C run a DKG in which each
contributes its Lagrange-weighted share as the constant term, and a fresh A' joins on the new
device. C never leaves the server and is replaced by C' only after the user has saved the new
recovery file. The address stays the same.

Two limits remain, both stated in the ADR. The new device can compute the key while the ceremony
runs, exactly as it can at key creation. And the lost share A stays dangerous for anyone who
also holds the **old** recovery file, so the user must destroy it.

Until the reshare ships, the advice above stands.

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
