# Server

## Role

- Stores share C.
- Joins DKG as a party.
- **Takes part in everyday signing** — together with the extension (A) it forms the 2-of-3
  ([adr/0005](adr/0005-share-placement.md)).
- Takes part in recovery-mode signing.

The server is not a vault, it is a **second factor**. If the extension is compromised and the
server refuses, no signature is produced. So the server must be able to enforce:

- Per-request rate limits and anomaly blocking
- User confirmation when needed (approval request over a registered channel)
- An audit log of signing requests (the digest only, never secrets)

At the same time the server learns what the user signs. That privacy cost is deliberate and
documented in `security.md`.

## Stack

- Rust + axum. Uses the `mpc-core` crate natively — the same code the extension runs as wasm.
- Storage: **SQLite** via `sqlx` (compile-time query checking plus migrations).
- API docs: **`utoipa` + Swagger UI**, generated from handler annotations.

## Storage

A single SQLite file. It is easy to self-host with no external dependencies, and multi-step
operations such as DKG and recovery commit atomically inside a transaction. Background in
[adr/0003](adr/0003-server-storage.md).

Tables:

| Table                 | Contents                                                                               |
| --------------------- | -------------------------------------------------------------------------------------- |
| `key_shares`          | The **ciphertext** of share C, public key, `format_version`, timestamps                |
| `dkg_sessions`        | The **sealed** party state of an in-flight DKG, plus an expiry (10 minutes by default) |
| `passkey_credentials` | WebAuthn credential public state and dynamic authenticator state                       |
| `passkey_challenges`  | One-use, expiring ceremony state and operation binding                                 |
| `browser_ceremonies`  | One-use handoff, browser session, and ceremony options/status                          |
| `recovery_requests`   | Recovery requests, cooling-off expiry, status                                          |
| `reshare_sessions`    | In-flight reshare sessions, sealed party state                                         |
| `pending_reshares`    | The new share a finished reshare produced, waiting for its commit (one per wallet)     |
| `audit_log`           | Append-only audit log                                                                  |

Rules:

- Shares are **encrypted by the application before storage**. The database never sees a plaintext
  share.
- The sealing key is injected from an environment variable or a KMS. It never lives in the repo
  or the database.
- Schema changes go through `sqlx` migrations; irreversible ones get an ADR.
- Session and recovery records are swept after they expire. Audit entries are kept.
- Every multi-step operation (DKG completion, refresh) commits in one transaction, so no
  half-finished state survives.

## API

| Endpoint                             | Purpose                                               |
| ------------------------------------ | ----------------------------------------------------- |
| `POST /v1/dkg/session`               | Open a DKG session                                    |
| `POST /v1/dkg/round`                 | Exchange DKG round messages                           |
| `POST /v1/sign/session`              | Open an everyday signing session                      |
| `POST /v1/sign/round`                | Exchange signing round messages                       |
| `POST /v1/passkeys/register/options` | Start a server-origin passkey registration            |
| `POST /v1/passkeys/register/finish`  | Verify and persist a passkey registration             |
| `POST /v1/passkeys/assert/options`   | Start an operation-bound assertion                    |
| `POST /v1/passkeys/assert/finish`    | Verify and consume an assertion                       |
| `POST /v1/passkeys/handoff`          | Create a one-use server-origin browser handoff        |
| `POST /v1/passkeys/ceremony/status`  | Read browser ceremony status                          |
| `POST /v1/passkeys/registered`       | Whether the wallet has a passkey (device key only)    |
| `POST /auth/handoff`                 | Exchange a body token for an HttpOnly session         |
| `GET  /auth`                         | Serve the fixed-origin WebAuthn ceremony page         |
| `POST /v1/reshare/session`           | Open a reshare (device key + `recovery` grant)        |
| `POST /v1/reshare/round`             | Advance a reshare; the last round stages C'           |
| `POST /v1/reshare/commit`            | Swap the staged share in and delete the old one       |
| `POST /v1/reshare/abort`             | Drop a reshare; the current share stays live          |
| `POST /v1/recovery/request`          | Ask to recover onto a new device key (no proof)       |
| `POST /v1/recovery/status`           | Where a request stands; starts the wait once approved |
| `POST /v1/recovery/complete`         | Replace the device key, after the wait                |
| `POST /v1/recovery/pending`          | Recoveries waiting on a wallet, for its owner         |
| `POST /v1/recovery/cancel`           | Cancel or withdraw a recovery                         |
| `GET  /v1/health`                    | Health check                                          |

- `GET /docs` serves Swagger UI and `GET /openapi.json` the spec.
- The spec is generated from code (`make openapi`) and the generated
  [`openapi.json`](openapi.json) is committed so API changes show up in review.
- Every request and response type derives `utoipa::ToSchema`. No undocumented public endpoints.

## Authentication

The device-key layer is implemented: the extension registers a P-256 public key, signs every
signing request with the request body, timestamp and nonce, and the server verifies the signature
and rejects nonce replays. The server-side WebAuthn adapter is now implemented: it creates and
durably stores library ceremony state, verifies the fixed RP/origin, requires user verification,
persists the minimum credential state, and consumes operation bindings exactly once. A verified
signing assertion creates a short-lived one-use authorization bound to the wallet, signing ID and
digest; `/v1/sign/session` consumes that authorization atomically before opening MPC state. The
server-origin browser page and extension launcher deliver registration/assertion responses without
placing handoff tokens in URLs. Opening a session that drives the recovery share (`counterparty` 1) consumes a one-use `recovery` grant bound to the sign id and digest; a `sign` grant does not open it, and `counterparty` values other than 0 or 1 are rejected.

Two mechanisms with two jobs:

- **A device key** identifies the wallet. The extension signs every request with a
  non-extractable key registered at setup, which gives the server rate limits, anomaly detection
  and an audit trail. It is **not** a second factor: it is stolen together with the extension.
- **A passkey (WebAuthn)** authorises every signature and every recovery. It lives in the
  platform authenticator rather than the extension, so stealing the extension's storage does not
  obtain it — that is what makes the server a real second factor.

Losing the passkey is not a lock-out, because share A plus the recovery file sign without the
server at all (`recovery.md`, scenario 0). The passkey guards the server's participation, never
the user's funds.

Settled regardless:

- Recovery requires the passkey **and** a cooling-off period. Possession is not intent.
- Starting recovery notifies the registered channel and the user can cancel.
- **We do not deploy to production before recovery authorization is implemented.**
- Signing now consumes a verified assertion atomically; recovery still requires the same treatment.

The current local default is RP ID `localhost` and origin `http://localhost:8080`. Production
configuration must set `MPC_SERVER_RP_ID` and an HTTPS `MPC_SERVER_ORIGIN`; the origin is fixed at
startup and is never taken from the request Host header.

## Availability

Everyday signing depends on the server, so server availability is product availability. Two
mitigations:

- Users can sign without the server using **A + B** (`recovery.md`, scenario 0). When the
  extension cannot reach the server it offers that path.
- The server is self-hostable. If the operator disappears, users can run it themselves.

## Operations

- Deployed as a container. Configuration comes from environment variables; secrets stay out of
  the repository.
- **Back up the SQLite file and the sealing key separately.** Keeping them together defeats the
  encryption.
- Must remain self-hostable and not tied to a specific cloud.

## Reshare

[ADR-0007](adr/0007-distributed-reshare.md) describes the protocol. The server plays the
surviving party at index 3. It contributes its Lagrange-weighted share, keeps the fresh one it
receives, and never sends its old share anywhere.

- **Authorization.** Opening a reshare needs the device key and consumes one `recovery` passkey
  grant. The grant's `operation_id` is the reshare id and its digest is
  `SHA-256("mpc-ext reshare v1" || public_key || reshare_id)`, so a grant cannot be reused for
  another wallet or another session. Every later call needs the device key.
- **Staging.** A finished reshare stores the new share in `pending_reshares` and leaves the live
  share alone. Only `commit` replaces it, in one transaction that also writes the audit log. An
  abort, an error in any round, or the 30-minute timeout leaves the previous share valid.
- **Public key.** The session aborts unless the new key equals the stored one, so a commit can
  never change a wallet's address.
- **Deletion.** After a commit the old share exists nowhere on the server. That is what makes the
  lost share useless against the server, so backups of the database must not outlive the commit.

## Passkey algorithms

Registration offers **ES256 (P-256) only**, and rejects any other key type. Assertions are
verified against P-256 keys, so anything else would register successfully and then never be able to
authorize a signature. The library's default list starts with EdDSA, which an authenticator that
supports it picks first. `registration_options` is the single place the list is built, and a test
checks that it stays `[-7]`.

Rejected assertions all reach the client as `authentication failed`. The server logs the reason at
`warn` (never the credential), and that log is the only place an operator can see it.

## Device keys and recovery

[ADR-0008](adr/0008-recovery-start-and-device-key-replacement.md) has the reasoning.

- **The proof covers the exact bytes sent.** `X-Device-Signature` signs
  `METHOD \n path \n timestamp \n nonce \n body`, where `body` is the request text as received.
  The server no longer re-serializes, so key order and `null` handling cannot make it disagree with
  a client. Handlers take a `SignedJson` extractor that keeps the raw text.
- **`POST /v1/device-key` is first-use only.** A wallet that already has a key is refused. The key
  changes only through a recovery.
- **A recovery is asked for without a proof,** because the install asking has no key the server
  accepts. The request records the new key and opens a passkey ceremony bound to it: the
  assertion's operation id is the request id and its digest is
  `SHA-256("mpc-ext recovery v1" || wallet id || 0x00 || new device key || request id)`.
- **The new key signs `status` and `complete`.** The first `status` call after the assertion is
  verified consumes it and starts the wait. `complete` works after `ready_at` and within 72 hours,
  and replaces the key and ends the wallet's other open requests in one transaction.
- **`pending` and `cancel`** use the wallet's current key, so an existing install can see and object
  to a recovery. `cancel` also accepts the request's own key, so the requester can withdraw.
- **Limits.** Five requests per wallet per hour (`429` beyond that), one request waiting per
  wallet, and an unapproved request lapses after 15 minutes.
- **`MPC_SERVER_RECOVERY_COOLING_SECONDS`** sets the wait, 24 hours by default. Zero makes recovery
  instant for testing and removes the protection the wait gives.
- Times are stored as unix seconds. The older RFC 3339 columns are compared as strings, which
  orders wrongly when the fractional digits differ in length.

## Credential protection

Registration asks for `credProtect` at `userVerificationRequired` but does **not enforce** it. An
authenticator that lacks the extension still registers, and one that has it applies it.

Enforcing it (`enforceCredentialProtectionPolicy: true`) would make registration fail on
authenticators without the extension, which platform authenticators and some passkey managers are.
It buys little here: every assertion asks for user verification, and `verify_assertion` rejects one
that did not carry it, so a credential cannot authorize anything without it whatever the
authenticator does. What is lost is the authenticator's own second layer of that same rule.

This also keeps the test browser honest. Chrome's virtual authenticator cannot satisfy an enforced
credProtect at any setting, so the smoke test used to strip the flag from the page. It now runs the
options the server actually sends.
