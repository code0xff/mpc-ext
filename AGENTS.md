# AGENTS.md

This file defines only the **ground rules** for coding agents working in this repository.
Detailed design, procedures and specifications live under `docs/`; write new detail there,
not here. `CLAUDE.md` is a symlink to this file.

## 1. What this project is

- **mpc-ext**: a Chrome extension plus a cooperating server that hold a 2-of-3 threshold key
  using MPC (DKLs23).
- The goal is to let web pages sign through the extension.
- **Both the extension and the server are open source** (Apache-2.0). Do not introduce designs
  that depend on closed components.

## 2. Architecture ground rules

- There are three key shares, **one per trust domain**. The threshold is 2
  (`docs/adr/0005-share-placement.md`).
  - A — the extension (encrypted at rest)
  - B — **never stored.** Exported to a file at key creation and kept offline by the user
  - C — the server
- **Everyday signing is extension (A) + server (C).** Compromising either side alone yields a
  single share, which cannot sign.
- **The extension never stores more than one share.** Changing this invariant requires an ADR.
- The recovery file (B) covers device loss and **emergency signing when the server is down**
  (A+B). If the service disappears, funds must not be locked.
- Users must be able to **export** their key at any time. No vendor lock-in. Export/import is
  also the defence against device loss, so onboarding walks the user through it.
- The extension is **locked by default** and opens with a password. Biometrics (WebAuthn /
  passkeys) are deferred work (`docs/roadmap.md`).
- The MPC protocol core is implemented **once, in Rust**. The extension consumes it as wasm and
  the server as a native crate. Never reimplement protocol logic in a second language.

## 3. Stack (changes require an ADR)

| Area       | Choice                                                        |
| ---------- | ------------------------------------------------------------- |
| MPC        | DKLs23 via `0xCarbon/DKLs23` (Apache-2.0/MIT), version-pinned |
| Extension  | TypeScript + React + Vite + WXT (Manifest V3)                 |
| Server     | Rust + axum + SQLite (sqlx), OpenAPI/Swagger UI               |
| Workspaces | pnpm workspace (JS) + cargo workspace (Rust)                  |

## 4. Security principles (non-negotiable)

- **Never** put key shares, seeds or passwords into logs, error messages, telemetry or URLs.
- Zeroize secrets after use; never write them to disk in the clear.
- At rest, always encrypt with a key derived from the user's password (KDF parameters in
  `docs/security.md`).
- **Never roll your own crypto primitives.** Use vetted crates only.
- Validate every input that crosses a trust boundary (web page → content script → background,
  client → server).
- The server holds a single share and must not be able to sign or reconstruct a key on its own.
  Changes that break this are forbidden.
- Security-relevant changes update `docs/security.md` and the threat model alongside the code.

## 5. Using open source

- Prefer vetted open source; implement it yourself only when there is no alternative.
- For every new dependency, **read the licence text before adopting it** — do not trust badges,
  READMEs or search results. No copyleft (GPL/AGPL/LGPL) dependencies.
- Available source does not mean open source. Reject licences that are non-commercial,
  revocable, or forbid redistribution.
- Record the reason for each new dependency in the PR description.

## 6. Development discipline

- **Write everything in English** — code, comments, doc comments, documentation, UI strings,
  commit messages, PR descriptions. This is an open-source project with an international
  audience.
- Read the relevant `docs/` pages before starting. If the implementation and the documentation
  disagree, **fix the documentation first.**
- Record hard-to-reverse decisions (stack swaps, protocol changes, storage format changes) as
  ADRs under `docs/adr/`.
- `make check` (fmt, lint, typecheck, test) must pass before committing. See
  `docs/development.md`.
- Use Conventional Commits. Branch from `main` and merge through pull requests.
- Never merge crypto or protocol code without tests. Include migration tests whenever the key
  storage format changes.
- Never commit real secrets or keys, including in test fixtures. Always use dummy values.
- Leave `TODO`s only with an issue number.

## 7. Map of the documentation

- `docs/architecture.md` — components, share placement, trust boundaries
- `docs/protocol.md` — DKLs23 DKG/signing/refresh flows, message formats
- `docs/security.md` — threat model, storage and encryption, locking
- `docs/recovery.md` — what to do when a share is lost
- `docs/export.md` — key export formats and procedures
- `docs/web-api.md` — the provider API web pages use
- `docs/server.md` — server API, deployment, operations
- `docs/development.md` — environment, builds, tooling, quality gates
- `docs/audit.md` — external security audit plan
- `docs/roadmap.md` — phased plan and deferred work (including biometrics)
- `docs/adr/` — architecture decision records (share placement is `0005`)
