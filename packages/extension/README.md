# extension

The Chrome extension (Manifest V3).

Stack: TypeScript + React + Vite + WXT (`docs/adr/0002-stack.md`).

The extension holds **exactly one share** (A). Decrypted shares live only in background service
worker memory, and anything at rest is always encrypted (`docs/security.md`).

## Scripts

| Command      | What it does                                                                                                                 |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `pnpm build` | Build the extension into `.output/chrome-mv3`                                                                                |
| `pnpm dev`   | Run WXT in development mode                                                                                                  |
| `pnpm smoke` | Load the built extension into Chrome for Testing and exercise DKG, onboarding and unlocking inside a real MV3 service worker |
| `pnpm test`  | Unit tests                                                                                                                   |

`pnpm smoke` needs Chrome for Testing, because Chrome 137 and later ignore `--load-extension` in
the regular browser:

```bash
pnpm dlx @puppeteer/browsers install chrome@stable
```
