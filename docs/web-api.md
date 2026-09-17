# Web provider API

The interface web pages use to sign through the extension.

## Design principles

- Follow the standards. Do not invent a new API (EIP-1193 / EIP-6963 compatible).
- Pages never reach the shares. They only receive signatures.
- Every connection and signing request needs user approval. There is no silent approval.

## Connection path

```
page → injected provider → content script → background (runs the MPC)
```

- The injected provider is exposed on `window` and announces the wallet via EIP-6963.
- The content script only validates the schema; policy decisions belong to the background
  worker.
- The background worker takes the origin from the message sender, never from a value the page
  supplied.

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

`packages/sdk` is a thin page-side wrapper. It detects whether the extension is installed and
provides type definitions and examples.
