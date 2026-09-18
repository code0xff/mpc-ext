# ADR-0006: Server authentication — a passkey plus a device key

- Status: accepted, with one technical question to settle before implementation
- Date: 2026-09-18

## Context

The server holds share C and takes part in every signature
([adr/0005](0005-share-placement.md)). Two different problems need answering, and conflating them
produces a weak design.

**Everyday signing.** An attacker without share A cannot complete the protocol however well they
authenticate, so authentication is not what stops a stranger. What it can stop is someone who has
**stolen share A** — the extension's storage plus its password.

**Recovery.** Here the server decides whether to hand its participation to someone claiming to
have lost their device. Authentication is the only defence.

The trap is the same one the original share placement fell into: **if the credential lives only
inside the extension, it is stolen together with share A and blocks nothing.** A device key on
its own therefore buys rate limiting and an audit trail, not a second factor.

## Decision

Two mechanisms with two jobs.

### A device key — identifies the wallet

- At setup the extension generates a non-extractable P-256 key pair via WebCrypto and registers
  the public key with the server against the wallet id.
- Every request carries a signature over the request body, a timestamp and a nonce.
- This gives the server: per-wallet rate limits, anomaly detection, an audit trail, and rejection
  of anonymous or replayed requests.
- It does **not** count as a second factor, because it is stolen with the extension. We do not
  describe it as one.

### A passkey (WebAuthn) — authorises the sensitive operations

- At setup the user registers a passkey with the server.
- A fresh assertion is required for **every signature** and for **starting a recovery**.
- The passkey lives in the platform authenticator or a security key, not in the extension, so
  stealing the extension's storage does not obtain it. That is what makes the server a real
  second factor.
- No accounts and no personal data. Nothing to leak, nothing to correlate, and self-hosting stays
  straightforward.

### Why the loss of a passkey is not a lock-out

Because share A plus the recovery file sign without the server at all
(`docs/recovery.md`, scenario 0). A user who loses their passkey still spends via A+B. The
passkey guards the server's participation, never the user's funds — which is the property that
lets us require it strictly.

## Open question — where the WebAuthn ceremony runs

**This has to be verified by a spike before implementation.** A WebAuthn relying party is
identified by a domain, and `chrome-extension://` origins do not obviously qualify. Two shapes:

1. **In the extension.** Simplest and needs no browsing. Requires confirming that current Chrome
   lets an extension page act as a relying party, and what it uses as the RP ID.
2. **On the server's own web origin.** The extension opens a tab to the server for the ceremony.
   Unambiguously supported and works for self-hosting, at the cost of friction and of the server
   needing to serve a page.

We take shape 1 if the spike confirms it and shape 2 otherwise. **We do not assume the answer**;
this project has already been burned once by recording an unverified fact as settled
([adr/0001](0001-mpc-library.md)).

## Consequences

- Signing gains a user gesture — a touch or Face ID. On platform authenticators that is roughly
  what a confirmation dialog already costs, and every signature was going to be confirmed anyway
  (`docs/web-api.md`).
- The server needs WebAuthn registration and assertion endpoints, plus storage for credentials.
  Credential public keys are not secrets, but the server still must not become a tracking
  surface: store the minimum and no personal data.
- Recovery keeps its cooling-off period, its notification and its cancellation on top of the
  passkey. A passkey proves possession, not that the request is wanted.
- **We do not deploy to production until this is implemented.** Until then the server runs with a
  development-only token and warns on start-up (`docs/server.md`).

## Alternatives

- **Device key only.** Simplest, no friction, but stolen with the extension, so it is not a second
  factor. Rejected as the primary mechanism while kept as the identity layer.
- **Accounts (email or OAuth).** A genuine second factor, but it introduces accounts, personal
  data, an account-recovery problem of its own, and it sits badly with self-hosting and privacy.
- **Hybrid: device key for everyday signing, strong authentication only for recovery.** The best
  usability, but everyday signing then has no second factor and a stolen share A still signs.
  Rejected for that reason.
