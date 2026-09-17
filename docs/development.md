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
Chrome for Testing and exercises DKG, onboarding and unlocking inside the real MV3 service
worker.

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
