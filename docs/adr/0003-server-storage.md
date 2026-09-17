# ADR-0003: Server storage

- Status: accepted
- Date: 2026-09-16

## Context

The server stores share C, in-flight DKG session state, recovery requests and an audit log. It
has to be easy to self-host (this is an open-source project), and multi-step operations such as
completing a DKG or refreshing a key must not be left half-finished.

## Options considered

| Option          | Pros                                                                                   | Cons                                                                                 |
| --------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| SQLite (`sqlx`) | One file, no external dependency, transactions, migration tooling, queryable audit log | Single node; no horizontal scaling                                                   |
| Flat files      | Simplest possible                                                                      | Atomicity, migrations and queries all hand-rolled; a half-written DKG is a real risk |
| Postgres        | Scales, mature operational tooling                                                     | Raises the bar for self-hosting; overkill at this size                               |

## Decision

**SQLite with `sqlx`.** Shares are stored as application-encrypted blobs, and the encryption key
is injected from an environment variable or a KMS.

## Consequences

- The server starts out assuming a single instance. If we need several, we move to Postgres.
- Because we use `sqlx`, most queries port to Postgres unchanged, so switching stays cheap.
- A stolen database is useless without the encryption key — which is exactly why the database
  file and the key must not be backed up to the same place.
