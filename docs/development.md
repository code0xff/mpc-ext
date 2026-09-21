# Development

## Required tooling

- Node LTS and pnpm (via corepack)
- Rust stable with the `wasm32-unknown-unknown` target, plus `wasm-pack`
- `make`
- Chrome for Testing, for the extension smoke test
  (`pnpm dlx @puppeteer/browsers install chrome@stable`). Chrome 137 and later ignore
  `--load-extension` in the regular browser, so automation needs this build.

## Layout

```
crates/mpc-core   crates/mpc-wasm   crates/mpc-server
packages/extension   packages/sdk
```

A pnpm workspace and a cargo workspace share the repository root.

## Commands

| Command        | What it does                                              |
| -------------- | --------------------------------------------------------- |
| `make setup`   | Install dependencies and register git hooks               |
| `make build`   | Build wasm → extension → server                           |
| `make test`    | `cargo test` plus vitest                                  |
| `make lint`    | clippy plus eslint                                        |
| `make fmt`     | rustfmt plus prettier                                     |
| `make openapi` | Regenerate `docs/openapi.json`                            |
| `make check`   | fmt check + lint + typecheck + test (**the commit gate**) |

The extension also has `pnpm -C packages/extension smoke`, which loads the built extension into
Chrome for Testing and drives it against a real server inside the real MV3 service worker: DKG,
onboarding, passkey registration, passkey-approved signing, the offline fallback, device-loss
recovery and the distributed reshare.

Every signature and reshare needs a passkey assertion in a tab on the server's origin. The script
attaches a CDP virtual authenticator to each tab as it opens and carries the registered credential
(with its signature counter) from tab to tab, since an authenticator lives only as long as its tab.
Three details are worth knowing when it breaks:

- The extension has to talk to `http://localhost:8080`, not `127.0.0.1`. WebAuthn needs a domain
  as its relying-party id, and the server's default is `localhost`.
- Chrome's virtual authenticator cannot satisfy `enforceCredentialProtectionPolicy` at any
  setting. The script removes only that flag in the test browser. The server still enforces it.
- The smoke server runs with `MPC_SERVER_RECOVERY_COOLING_SECONDS=0`, since a test cannot wait a
  day. The waiting rules are covered by the server's own tests.
- The script attaches the authenticator after the extension has opened the tab, so it can lose a
  race against the ceremony page. Chrome does not fail a WebAuthn call made before an
  authenticator exists. It waits, and an authenticator added later is not used for that call, so
  the ceremony hangs with no error and no server log.
- The script reloads the page in only two cases: it has waited for the authenticator prompt for
  three seconds, or the browser itself refused the call. Both happen before anything reaches the
  server. It must never reload otherwise. The challenge is consumed the moment the server checks an
  assertion, so a reload after that fails every time with "no live challenge", and a reload that
  cuts a healthy ceremony short causes exactly that failure. It also never reloads on
  "authentication failed", which is the server's own verdict.
- Each reload prints a `[ceremony]` line. A normal run prints none. Any line means the race
  happened, and many in a row mean something else is wrong.
- `SMOKE_DEBUG=1` prints each tab, HTTP status and credential event, which is usually enough to
  find where a ceremony stopped.

## Quality tooling

- **Rust**: rustfmt, clippy (`-D warnings`, with `unwrap_used`/`expect_used`/`panic` denied in
  production code), `cargo deny` for licences and advisories
- **TypeScript**: strict `tsc`, ESLint (typescript-eslint), Prettier, vitest
- **Shared**: lefthook pre-commit (fmt, lint) and pre-push (test), gitleaks secret scanning
- **CI**: GitHub Actions runs the same gate plus the wasm build, the MV3 smoke test,
  `cargo deny` and gitleaks. Nothing merges without it.
- Dependency updates are automated with Dependabot, except the pinned MPC crate
  ([adr/0004](adr/0004-mpc-library-reselection.md)).

## Test performance

Dependencies are compiled with `opt-level = 3` even in dev and test profiles
(`[profile.test.package."*"]`). DKG in an unoptimised build is tens of times slower, which made
the suite painful; our own code keeps its debug information.

## Rules

- Commit messages follow Conventional Commits.
- Write everything — code, comments, docs, UI strings, commits — **in English**.
- No direct pushes to `main`. Use pull requests.
- Never merge leaving new warnings behind.
- Never merge crypto or protocol code without tests.
- Never put real keys or secrets in fixtures. Use dummy values.

## Reproducible builds

Extension releases must be reproducible. Pin toolchain versions and publish the build procedure
and artefact hashes in the release notes.
