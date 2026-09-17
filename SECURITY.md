# Security Policy

## Current status

This project **has not been audited. Do not use it with real assets.**

## Reporting a vulnerability

If you find a vulnerability, please **do not open a public issue.** Report it privately through
GitHub Security Advisories (`Security` tab → `Report a vulnerability`).

- We acknowledge reports within three business days.
- We coordinate disclosure with you after a fix lands, and will credit you if you want that.

## In scope

We treat these as vulnerabilities:

- The server being able to sign or reconstruct the private key on its own
- Any path that produces a signature without user approval
- Key shares or passwords surviving in logs, errors or storage in the clear
- Obtaining the server share by bypassing the recovery procedure
- Extracting a share from a locked extension

## Out of scope

See the threat model in `docs/security.md`:

- A rooted OS, kernel-level keyloggers, physical coercion
- **An attacker who has taken over an unlocked extension** — by design they hold a single share
  and cannot sign. Combining it with a recovery file stored on the same machine is a documented
  user-side risk, not a vulnerability.

## Please do not send us secrets

Do not include real keys, seeds or passwords in a report. Reproduction steps and dummy values
are enough.
