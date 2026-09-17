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

| Table               | Contents                                                                               |
| ------------------- | -------------------------------------------------------------------------------------- |
| `key_shares`        | The **ciphertext** of share C, public key, `format_version`, timestamps                |
| `dkg_sessions`      | The **sealed** party state of an in-flight DKG, plus an expiry (10 minutes by default) |
| `recovery_requests` | Recovery requests, cooling-off expiry, status                                          |
| `audit_log`         | Append-only audit log                                                                  |

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

| Endpoint                    | Purpose                                        |
| --------------------------- | ---------------------------------------------- |
| `POST /v1/dkg/session`      | Open a DKG session                             |
| `POST /v1/dkg/round`        | Exchange DKG round messages                    |
| `POST /v1/sign/session`     | Open an everyday signing session               |
| `POST /v1/sign/round`       | Exchange signing round messages                |
| `POST /v1/recovery/request` | Start recovery (begins the cooling-off period) |
| `POST /v1/recovery/sign`    | Join recovery-mode signing                     |
| `GET  /v1/health`           | Health check                                   |

- `GET /docs` serves Swagger UI and `GET /openapi.json` the spec.
- The spec is generated from code (`make openapi`) and the generated
  [`openapi.json`](openapi.json) is committed so API changes show up in review.
- Every request and response type derives `utoipa::ToSchema`. No undocumented public endpoints.

## Authentication

**Not designed yet.** Until then a development-only shared token stands in, and the real scheme
is designed separately (`roadmap.md`). The server logs a warning on start-up.

Regardless of the eventual scheme, these are settled:

- Recovery requests require authentication plus a cooling-off period.
- Starting recovery notifies the registered channel and the user can cancel.
- **We do not deploy to production before the authentication design is finished.**

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
