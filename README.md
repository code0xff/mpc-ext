# mpc-ext

A Chrome extension and cooperating server that hold a **2-of-3 threshold ECDSA** key using MPC
(DKLs23). Both halves are open source (Apache-2.0).

> [!WARNING]
> **This is early-stage software and has not been audited. Do not use it with real assets.**
> The MPC library it builds on has no audit history either, so we plan to pay for one
> ([ADR-0004](docs/adr/0004-mpc-library-reselection.md)).

## How it works

Three key shares live in three different places — one each.

| Share | Where                                  | Everyday |
| ----- | -------------------------------------- | -------- |
| A     | The extension                          | Signs    |
| B     | A recovery file the user keeps offline | Unused   |
| C     | The server                             | Signs    |

- **Everyday signing** — extension (A) + server (C). Compromising the extension yields one
  share, which cannot sign; the same is true of the server. The server is not a vault, it is a
  **second factor**.
- **Lost device** — restore from the recovery file (B) + server (C). The address does not
  change.
- **Server gone** — sign directly with the extension (A) + recovery file (B). **If the service
  disappears, your funds are not locked.**
- **Export** — any two shares reconstruct the full private key, any time. We do not hold your
  key hostage.

The recovery file can only be produced once, at key creation, and onboarding will not let you
skip it.

### What we gave up

- **The server takes part in every signature.** It learns what you sign, and if it is down you
  fall back to the A+B path. We traded some privacy and availability for security
  ([ADR-0005](docs/adr/0005-share-placement.md)).
- **Keeping the recovery file on the same machine as the extension** puts two shares in one
  place and defeats the design. Store it somewhere else.
- **Losing both the device and the recovery file is unrecoverable** — only the server share
  would remain.

## Layout

```
crates/mpc-core     protocol core — the single source of truth, shared by extension and server
crates/mpc-wasm     wasm bindings for the extension
crates/mpc-server   holds share C, joins DKG and signing (axum + SQLite + Swagger UI)
packages/extension  the Chrome extension (MV3, React, WXT)
packages/sdk        provider SDK for web pages (EIP-1193 / EIP-6963)
```

## Getting started

```bash
make setup   # install toolchains and dependencies, register git hooks
make check   # the commit gate: fmt + lint + typecheck + test
make build   # wasm → extension → server
```

Once the server is running, Swagger UI is at `/docs` and the OpenAPI spec at `/openapi.json`.

## Documentation

Design and decisions live in [`docs/`](docs/). The ground rules for contributors (human or
agent) are in [AGENTS.md](AGENTS.md), and hard-to-reverse decisions are recorded as ADRs under
[`docs/adr/`](docs/adr/).

## License

[Apache-2.0](LICENSE)
