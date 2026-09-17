# Architecture

## Overview

2-of-3 threshold signing. Each of the three shares lives in a different trust domain
([adr/0005](adr/0005-share-placement.md)).

| Share     | Where it lives                                                            | Everyday role | Recovery role                  |
| --------- | ------------------------------------------------------------------------- | ------------- | ------------------------------ |
| `share-A` | The extension (encrypted at rest)                                         | Signs         | —                              |
| `share-B` | **Not stored** — exported to a file at creation, kept offline by the user | Unused        | Used when the device is lost   |
| `share-C` | The server                                                                | Signs         | Unused when the server is down |

Everyday signing is **extension (A) + server (C)**. Compromising either side yields a single
share, which cannot sign. The server is not a vault, it is a **second factor**.

Share B is exported right after DKG and then discarded by the extension. It is used in three
situations:

- Device lost → recover with B + C
- Server outage or shutdown → sign with A + B, so funds are never locked
- Key export → reconstruct the private key from any two shares (`export.md`)

## Components

```
repo/
├─ crates/
│  ├─ mpc-core/      # DKLs23 wrapper and protocol state machines
│  ├─ mpc-wasm/      # wasm-bindgen bindings for the extension
│  └─ mpc-server/    # axum server
├─ packages/
│  ├─ extension/     # WXT + React MV3 extension
│  └─ sdk/           # provider SDK for web pages (published to npm)
└─ docs/
```

`mpc-core` is the single source of truth for the protocol. The extension and the server consume
the same crate, as wasm and natively respectively.

## Inside the extension

- **background (service worker)** — holds the share, runs the MPC, owns the lock state. The only
  place with access to secrets.
- **popup / options (React)** — UI. Never touches secrets directly; it asks the background
  worker over messages.
- **content script** — a narrow relay between the page and the background worker. It validates
  requests but makes no decisions.
- **injected provider** — the page-context `window` API (`web-api.md`).

An MV3 service worker can be terminated at any time. Decrypted shares live only in worker
memory, so termination locks the wallet automatically.

## Trust boundaries

1. Web page ↔ content script — fully untrusted. Every request is schema-validated and needs user
   approval.
2. content script ↔ background — semi-trusted. The background worker re-checks the origin.
3. Extension ↔ server — the server is assumed honest-but-curious. It holds one share and cannot
   sign alone, but because it takes part in everyday signing it **does learn what you sign**
   (`security.md`).
4. Extension ↔ OS/disk — storage is always encrypted.

## Invariants

- **The extension stores exactly one share.** Share B, created during DKG, is exported and then
  erased from memory and storage.
- No single party — extension, server or recovery file — can sign or reconstruct the key alone.
- Protocol logic exists only in `mpc-core`.
- The moments where reshare or export reconstruct a private key happen **on the user's device
  only** (`recovery.md`).
