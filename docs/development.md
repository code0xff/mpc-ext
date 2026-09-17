# 개발

## 요구 도구

- Node LTS + pnpm (corepack)
- Rust stable + `wasm32-unknown-unknown` 타겟, `wasm-pack`
- `just` 또는 `make` (본 문서는 `make` 기준)

## 레이아웃

```
crates/mpc-core   crates/mpc-wasm   crates/mpc-server
packages/extension   packages/sdk
```

pnpm workspace + cargo workspace를 루트에 둔다.

## 명령

| 명령         | 내용                                                 |
| ------------ | ---------------------------------------------------- |
| `make setup` | 의존성 설치, 훅 설치                                 |
| `make build` | wasm 빌드 → 확장 빌드 → 서버 빌드                    |
| `make test`  | cargo test + vitest                                  |
| `make lint`  | clippy + eslint                                      |
| `make fmt`   | rustfmt + prettier                                   |
| `make check` | fmt 검사 + lint + typecheck + test (**커밋 게이트**) |

## 품질 도구

- **Rust**: rustfmt, clippy (`-D warnings`), `cargo deny` (라이선스·취약점), `cargo audit`
- **TS**: TypeScript strict, ESLint (typescript-eslint), Prettier, vitest
- **공통**: lefthook pre-commit(fmt+lint), pre-push(test), gitleaks 시크릿 스캔
- **CI**: GitHub Actions에서 `make check` + `cargo deny` + gitleaks. 통과 없이 머지 금지.
- 의존성 업데이트는 Dependabot/Renovate로 자동화한다.

## 규칙

- 커밋 메시지는 Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`…).
- `main` 직접 푸시 금지. PR + 리뷰.
- 새 경고를 남긴 채 머지하지 않는다.
- 암호·프로토콜 코드는 테스트 없이 머지하지 않는다.
- 실제 키·시크릿을 픽스처에 넣지 않는다. 항상 더미값.

## 재현 가능 빌드

확장 릴리스는 재현 가능해야 한다. 툴체인 버전을 고정하고, 빌드 절차와 산출물 해시를 릴리스 노트에 남긴다.
