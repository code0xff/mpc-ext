# Security

## Threat model

| Threat                                           | Mitigation                                                                                                                                                                     |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A malicious page tricks the user into signing    | Origin checks, explicit user approval, and the signing payload shown in the UI                                                                                                 |
| Server compromise                                | The server holds only share C. It cannot sign or reconstruct alone                                                                                                             |
| Device theft (extension data taken while locked) | Storage is fully encrypted and useless without the password                                                                                                                    |
| **Extension taken over while unlocked**          | The extension holds only share A, so it **cannot sign alone.** The server acts as the second factor with rate limits, anomaly blocking and user confirmation                   |
| Recovery file stolen                             | Only share B, encrypted under its own password. Cannot sign alone                                                                                                              |
| Stranger who knows a wallet id                   | Cannot replace the device key. Registration is first-use only, and a recovery needs the passkey and a wait ([adr/0008](adr/0008-recovery-start-and-device-key-replacement.md)) |
| Service shutdown or outage                       | The user signs with A + B. Funds are not locked                                                                                                                                |
| Supply chain attack                              | Minimal dependencies, pinned lockfiles, reproducible builds, signed releases                                                                                                   |
| Memory scraping                                  | Zeroize after use, auto-lock when idle                                                                                                                                         |

**Out of scope**: a rooted OS, kernel-level keyloggers, physical coercion.

## What we gave up (stated plainly)

Splitting the shares across three trust domains costs us the following
([adr/0005](adr/0005-share-placement.md)).

- **The server takes part in every signature.** It learns what the user signs, everyday signing
  stops when it is down, and censorship becomes possible. The mitigations are self-hosting and
  the A + B fallback path.
- **Every signature needs a network round trip.** The computation itself is ~16 ms, but
  perceived latency is dominated by the round trip.

One limitation remains, in a smaller form than before:

- **A lost share stays valid until its old partners are gone.** Refresh needs every party, and the
  lost one cannot attend, so a lost share is never revoked outright. A distributed reshare
  ([adr/0007](adr/0007-distributed-reshare.md)) gives the wallet fresh shares and makes the
  server delete its old one, which leaves the old recovery file as the one thing that can still
  pair with the lost share. The user has to destroy it. Until a restored wallet has been reshared,
  the old advice applies: move to a new wallet.
- **The reshare ceremony trusts the device it runs on.** That device plays two of the new parties,
  so it can compute the key, and it learns the server's old share on the way. Key creation has the
  same exposure. The reshare is offered only on a freshly restored install.

Two assumptions the user can break:

- **Keeping the recovery file on the same machine as the extension** puts two shares in one
  place, and taking over that machine makes signing possible. The UI pushes hard for separate
  storage — another device, print, a safe — and warns against leaving it in the default
  downloads folder.
- **Losing the recovery file and the device together is unrecoverable**, because only the server
  share remains. Onboarding says so explicitly.

We do not hide these limits in marketing, the README or the UI.

## Storage

- Encryption: XChaCha20-Poly1305 (AEAD) is the target. The extension currently ships PBKDF2 +
  AES-GCM via WebCrypto; migrating is a hardening task tracked in `roadmap.md`.
- KDF: Argon2id is the target; parameters are pinned as constants and changing them needs an ADR
  plus a migration.
- Fresh salt and nonce per record. Never reuse a nonce.
- Records carry a `format_version`; every change ships a migration test. The extension vault is
  at version 2, and version 1 records are refused rather than silently misread.
- The recovery file uses the same primitives with its own password (`export.md`), so a stolen
  file does not even yield one usable share.
- Only ciphertext goes into `chrome.storage.local`. Plaintext shares are never stored.

## Locking and unlocking

- The default state is **locked**; a password opens it.
- The decrypted share A exists only in service worker memory.
- **Share B is never stored.** It is exported right after DKG and zeroized. Onboarding cannot be
  skipped — nothing is persisted until the export is confirmed, so a failure leaves no trace.
- Auto-lock on idle timeout (5 minutes by default), browser shutdown, or worker termination.
- Limit password attempts and apply exponential backoff.
- Server passkey ceremonies are implemented separately from local wallet unlock. Biometric wallet
  unlock and passkey PRF remain deferred work; the extension must not treat a server assertion as
  a replacement for its password lock.

## Server passkey adapter

- Registration and assertion ceremony state is generated by `webauthn_rp` and persisted in the
  SQLite challenge table with wallet and purpose binding.
- The configured RP ID and exact origin are fixed at process startup. They are never derived from
  request headers.
- User verification is required for registration and assertion. Credential state stores only the
  credential identifier, user handle, public-key state, and dynamic authenticator state; no private
  authenticator key is stored.
- Challenge rows are consumed transactionally and cannot be replayed. Assertion bindings include
  the purpose, operation identifier, and digest, and must match exactly at completion.
- The browser ceremony uses a one-use handoff token in a POST body, exchanges it for an HttpOnly,
  SameSite cookie, and serves a fixed-origin page with restrictive CSP and no-store headers. The
  token is not placed in a URL.
- A verified signing assertion creates a short-lived one-use authorization bound to the wallet,
  signing identifier and digest. `/v1/sign/session` consumes it atomically before opening MPC
  state. Recovery is not yet wired to an equivalent authorization, so production deployment
  remains prohibited until that flow is complete.

## Coding rules

- Secret types hide their contents in `Debug`/`Display` and zeroize on `Drop`.
- Compare secrets in constant time.
- Never put secrets in logs, error messages, URLs or telemetry. Telemetry is off by default.
- Never roll your own crypto primitives.
- When adopting a crypto library that does not guarantee constant-time operation, record that
  fact and its blast radius here.

## Audit

- Get an external audit before 1.0. Publish the audited commit and the report in this
  repository.
- **The audit scope includes the vendored MPC crate** (`0xCarbon/DKLs23`). Upstream has no audit
  history, so we pay for it ([adr/0004](adr/0004-mpc-library-reselection.md)). Details in
  [audit.md](audit.md).
- Until the audit is done, the README and the extension UI carry a **do not use with real
  assets** warning.

## Accepted dependency advisories

`deny.toml` ignores two advisories. Each carries its reason there and is re-reviewed on the
condition stated next to it.

- **RUSTSEC-2023-0071 (`rsa`, Marvin Attack).** Affects RSA private-key operations and has no
  fix. `rsa` arrives only through `webauthn_rp` ([adr/0006](adr/0006-server-authentication.md)),
  which uses it to verify passkey signatures. We perform no RSA decryption or signing.
- **RUSTSEC-2025-0141 (`bincode` 1.x, unmaintained).** Not a vulnerability. It is a dependency of
  the pinned `dkls23-core` ([adr/0004](adr/0004-mpc-library-reselection.md)) and is in scope for
  the external audit ([audit.md](audit.md)).
