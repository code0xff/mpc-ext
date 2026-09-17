# ADR-0002: Technology stack

- Status: accepted
- Date: 2026-09-16

## Context

The extension and the server have to share the same MPC protocol logic. Implementing the
protocol twice means the two implementations eventually diverge, and for cryptographic code that
divergence is a security incident.

## Decision

- **MPC core**: Rust (`mpc-core`). The extension consumes it as wasm, the server natively — the
  same crate.
- **Server**: Rust + axum.
- **Extension**: TypeScript + React + Vite + WXT (Manifest V3).
- **Workspaces**: a cargo workspace plus a pnpm workspace.

## Consequences

- There is exactly one protocol implementation.
- We have to watch wasm bundle size and service worker start-up time (measured in Phase 1).
- Contributors need both toolchains. `make setup` keeps the barrier low.

## Alternative

Writing the server in TypeScript would have required an extra binding layer (napi or wasm) around
the Rust core, so we rejected it.
