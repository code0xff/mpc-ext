# Protocol

## What we use

- **DKLs23** (Doerner–Kondi–Lee–Shelat, 2023) threshold ECDSA over secp256k1.
- Implementation: [`0xCarbon/DKLs23`](https://github.com/0xCarbon/DKLs23) (Apache-2.0 / MIT).
- Background in [adr/0004](adr/0004-mpc-library-reselection.md). We ruled out
  `silence-laboratories/dkls23` because its licence is not open source
  ([adr/0001](adr/0001-mpc-library.md), superseded).
- **Until an audit lands, do not use this with real assets.** The warning appears in the README
  and in the extension UI.

## Flows

### DKG (key generation)

1. The extension creates parties A and B locally and asks the server to join as party C.
2. Run the 3-party DKG with threshold 2.
3. Each party stores its share. The extension keeps A encrypted, exports B as a recovery file,
   and the server stores C.
4. Confirm the public key and show it to the user.

If DKG fails, discard every partially stored share. It either succeeds atomically or leaves
nothing behind.

### Signing (everyday)

- Parties A and C: the extension and the server. Requires a network round trip.
- Proceeds only after user approval, and the UI shows the requesting origin and what is being
  signed.

### Signing (server unavailable)

- Parties A and B: the extension plus the recovery file the user loads. Works fully offline.

### Signing (device lost)

- Parties B and C, after the server's recovery checks (`recovery.md`).

### Key refresh and reshare

- **Refresh** rotates every share while keeping the public key, so old shares stop working.
  It maps to the upstream `refresh_complete_*` functions and requires **all existing parties**.
- **Reshare** issues a fresh set of shares from the surviving two when a party has to be
  replaced — refresh cannot do this, since a brand-new device holds no share
  ([adr/0004](adr/0004-mpc-library-reselection.md)). It briefly reconstructs the private key, so
  it runs on the user's device only (`recovery.md`).
- Periodic refresh is deferred work (`roadmap.md`).

## Messages

- Parties exchange `Envelope`s: `{ round, from, to, payload }`, where `to = None` is a
  broadcast. Payloads are opaque bytes only the receiving session can interpret.
- Sessions carry an id that must never be reused, and they expire.
- Messages arriving out of round order abort the session; no partial state is kept.

## Implementation rules

- Protocol state machines live only in `mpc-core`. The extension and server handle transport and
  storage.
- **The upstream crate stays behind a boundary inside `mpc-core`.** Extension and server code
  never references upstream types, which keeps the library replaceable.
- Pin the upstream crate by exact version. No automatic updates; changes land after review.
- Session state must be serializable — the server keeps no state between HTTP requests and
  re-loads it (sealed) every round.
- Tests: per-round vectors, 3-party integration tests, and adversarial input tests.
