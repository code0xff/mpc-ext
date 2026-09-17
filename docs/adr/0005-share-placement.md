# ADR-0005: Share placement — one in the extension, one offline, one on the server

- Status: accepted
- Date: 2026-09-17

## Context

The original design put **two shares in the extension and one on the server**, and signed
everyday transactions offline using the extension's two shares. The goal was privacy and
availability.

A Phase 0 review exposed a problem. Shares A and B lived in the same extension, the same
storage, behind the same password, so **an attacker who took over an unlocked extension obtained
both.** At that moment the theft resistance equalled that of an ordinary encrypted wallet, and
the only thing MPC really provided was a recovery path.

## Decision

Place the shares as follows.

| Share | Where it lives                                                                   | Everyday | Recovery                       |
| ----- | -------------------------------------------------------------------------------- | -------- | ------------------------------ |
| A     | The extension (encrypted at rest)                                                | Signs    | —                              |
| B     | **Not stored** — exported to a file at key creation and kept offline by the user | Unused   | Used when the device is lost   |
| C     | The server                                                                       | Signs    | Unused when the server is down |

- **Everyday signing is extension (A) + server (C).**
- Share B is exported right after DKG and then **erased from the extension's memory and
  storage.**
- Onboarding cannot skip the export of B. Key creation is not complete without it.

## Consequences

### What we gain

- **Taking over the extension is not enough to sign.** The attacker holds only A, and the server
  becomes a real second factor that can enforce rate limits, anomaly blocking and user
  confirmation.
- **Compromising the server is not enough either.** It holds only C.
- **Stealing the recovery file is not enough either.** It holds only B.
- **Funds are not locked if the service disappears.** A + B can sign. The promise of no vendor
  lock-in only becomes a real property under this placement.
- Device loss is recovered with B + C.

### What we give up

- **The server takes part in every signature.** It learns what the user signs, and everyday
  signing stops when it is down. Censorship becomes possible. We deliberately accept what the
  original design set out to avoid.
- **Every signature needs a network round trip.** The computation is 16 ms, but perceived latency
  is dominated by the round trip ([adr/0004](0004-mpc-library-reselection.md)).
- Server availability becomes product availability. Self-hostability is the mitigation
  (`server.md`).

### New risks

- **Keeping the recovery file on the same machine as the extension** puts A and B in one place,
  which returns us to the previous design's weakness. The UI pushes hard for storing it
  elsewhere — another device, print, a safe.
- Losing the recovery file and the device together leaves only C, and recovery is impossible.
  Onboarding says so explicitly.

## Phase 2 finding — the recovery file is large

Measurements inside the MV3 service worker put **a single share at roughly 114 KB** (about 230 KB
once hex-encoded into JSON), because a DKLs23 `Party` carries the multiplication protocol's OT
setup state.

Consequences:

- The recovery file **cannot be a mnemonic or a QR code.** Paper backup is impossible and the
  user has to keep the file itself.
- Files are easier to lose or corrupt than mnemonics, which onboarding guidance has to reflect.

There was an alternative. Reconstructing the private key only needs `poly_point` (32 bytes) and
the party index, so the recovery file **could shrink to 32 bytes** and become mnemonic-friendly —
at the cost of losing the OT state, which makes **emergency A+B signing during a server outage
impossible**, leaving only "reconstruct the key and re-split".

|                                              | Full share (114 KB) | `poly_point` only (32 B)              |
| -------------------------------------------- | ------------------- | ------------------------------------- |
| Mnemonic/QR backup                           | No                  | Yes                                   |
| Immediate A+B signing during a server outage | Yes                 | No — requires reconstruct and rebuild |
| Device-loss recovery                         | Yes                 | Yes                                   |
| Key export                                   | Yes                 | Yes                                   |

**Decision: export the full share as a file (114 KB).**

Shrinking to `poly_point` makes backup convenient but forfeits **emergency A+B signing during a
server outage**. That property is the reason this placement was adopted in the first place
("funds are not locked if the service disappears"), and it is not something to trade away for
backup ergonomics. We give up mnemonic backups instead.

Requirements that follow:

- Onboarding clearly explains the fragility of file backups (loss, corruption, cloud sync).
- The recovery file's integrity must be checkable — compare its public key on import.
- Encourage the user to keep several copies. Share B cannot sign on its own, so extra copies do
  not increase risk.

## Alternative

We considered keeping the original design and moving share B to a different trust domain, such as
a passkey PRF or the OS keychain. That preserves privacy while still splitting the two factors,
but implementation complexity is high and browser support is uneven, so it stays deferred work
(`roadmap.md`).
