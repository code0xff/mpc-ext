# ADR-0001: MPC protocol and library

- Status: **superseded by [ADR-0004](0004-mpc-library-reselection.md)**
- Date: 2026-09-16

## Context

We need 2-of-3 threshold ECDSA. The extension (wasm) and the server (native) must run the same
implementation, browser signing latency has to be acceptable to users, and everything has to be
open source.

## Decision (withdrawn)

Adopt DKLs23 based on `silence-laboratories/dkls23`.

## Why it was withdrawn

We recorded the licence of `silence-laboratories/dkls23` as Apache-2.0. It is in fact the
**Silence Laboratories Non-Commercial Use License (SLL)**, which we cannot use:

- It permits non-commercial use only, and explicitly counts "internal business purposes" as
  commercial.
- It is **non-sublicensable**, so we could not pass rights downstream — redistribution as open
  source is impossible.
- It is **revocable**, and the terms can be changed unilaterally.

The older `silence-laboratories/silent-shard-dkls23-ll` (which ships wasm bindings) carries the
same SLL. Functionally it is strong — a Trail of Bits audit from February 2024, audited key
refresh, built-in export/import — but it conflicts with this project's open-source ground rule,
so it is out.

The replacement decision is [ADR-0004](0004-mpc-library-reselection.md).
