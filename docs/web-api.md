# Web provider API

The interface web pages use to sign through the extension.

## Design principles

- Follow the standards. Do not invent a new API (EIP-1193 / EIP-6963 compatible).
- Pages never reach the shares. They only receive signatures.
- Every connection and signing request needs user approval. There is no silent approval.

## Methods

| Method                | Behaviour                                                                                        |
| --------------------- | ------------------------------------------------------------------------------------------------ |
| `eth_accounts`        | Returns the address if this origin is already connected, otherwise an empty array. Never prompts |
| `eth_requestAccounts` | Prompts for a connection if there is none, then returns the address                              |
| `personal_sign`       | Requires a connection, then asks for approval **every time** (EIP-191 prefixed)                  |

Anything else is refused with `4200`, rather than forwarded. The surface is exactly what
`src/rpc.ts` declares.

`personal_sign` prefixes the message per EIP-191 before hashing. That prefix is what stops a page
from getting a transaction signed by presenting it as a plain message, so it is not optional.

## Connection path

```
page → provider (MAIN world) → relay (ISOLATED world) → background (runs the MPC)
```

- The provider content script runs in the page's world, announces the wallet via EIP-6963, and
  carries requests over `window.postMessage`. It is **not trusted**.
- The relay content script validates the shape of each request and forwards it. It makes no
  policy decisions.
- The background worker takes the origin **from the message sender**, never from a value the page
  supplied, and every decision is made there.

## Approval

Requests that need consent park in a queue while an approval window is open.

- Each signature is approved individually. There is no silent approval.
- **Dismissing the window rejects everything pending.** An unanswered request fails closed.
- Locking the wallet also rejects everything pending, so nothing resumes after an unlock.
- The window shows the origin the browser reported, and renders the message as text only when it
  decodes cleanly — control characters would let a page draw a misleading prompt.

## Permissions

- Connection permissions are stored per origin and the user can revoke them at any time.
- Even with a connection permission, every signature is approved individually. Automatic
  approval is deferred work and off by default.
- Requests that arrive while the extension is locked raise an unlock prompt, and return a clear
  error if the user declines.

## Errors

- Error codes follow EIP-1193 (`4001` for user rejection, and so on).
- Error messages never leak internal state or secrets.

## SDK

`packages/sdk` is a thin page-side wrapper: it discovers the wallet, exposes typed helpers for
the supported methods, and nothing more.

`examples/dapp` is a working page that uses only EIP-6963 and EIP-1193, with no mpc-ext-specific
code. If a change breaks that example, it breaks every standards-compliant dApp.
