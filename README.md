# mpc-ext

MPC(DKLs23) 기반 **2-of-3 임계 ECDSA** 키를 보관·사용하는 크롬 확장과 협력 서버.
확장·서버 모두 오픈소스입니다 (Apache-2.0).

> [!WARNING]
> **개발 초기 단계이며 보안 감사를 받지 않았습니다. 실자산에 사용하지 마세요.**
> 사용 중인 MPC 라이브러리도 감사 이력이 없어 자체 감사를 계획 중입니다
> ([ADR-0004](docs/adr/0004-mpc-library-reselection.md)).

## 어떻게 동작하나

키 셰어 3개 중 **확장이 2개, 서버가 1개**를 보관합니다.

- **평시 서명** — 확장이 가진 셰어 2개로 로컬에서 완결됩니다. 서버가 꺼져 있어도 서명할 수 있고, 서버는 사용자가 무엇에 서명하는지 알지 못합니다.
- **복구** — 확장 셰어 하나를 잃으면 남은 셰어와 서버 셰어로 서명하고, 곧바로 키 리프레시를 실행해 2-of-3 상태로 되돌립니다. 공개키(주소)는 유지됩니다.
- **추출** — 사용자는 언제든 셰어를 내보내거나 완전한 개인키를 복원할 수 있습니다. 키를 인질로 잡지 않습니다.

디스크에 완전한 개인키가 존재하지 않으며, 서버 단독으로는 서명할 수도 키를 복원할 수도 없습니다.

### 이 설계가 주지 _않는_ 것

셰어 2개가 같은 확장·같은 비밀번호 아래 있으므로, **잠금 해제된 확장을 장악한 공격자는 두 셰어를 모두 얻습니다.** 즉 도난 내성은 일반적인 암호화 지갑과 같은 수준입니다. 이 설계에서 MPC가 실제로 주는 것은 복구 경로와 "디스크에 완전한 키 없음"입니다. 자세한 내용과 개선 계획은 [security.md](docs/security.md)에 정직하게 적어두었습니다.

## 구조

```
crates/mpc-core     프로토콜 코어 (확장·서버 공유, 단일 진실 공급원)
crates/mpc-wasm     wasm 바인딩 (확장용)
crates/mpc-server   셰어 C 보관 + DKG/복구 참여 서버 (axum + SQLite)
packages/extension  크롬 확장 (MV3, React + WXT)
packages/sdk        웹페이지용 provider SDK (EIP-1193 / EIP-6963)
```

## 시작하기

```bash
make setup   # 툴체인·의존성 설치, git 훅 등록
make check   # 커밋 게이트: fmt + lint + typecheck + test
make build   # wasm → 확장 → 서버
```

서버를 띄우면 Swagger UI는 `/docs`, OpenAPI 스펙은 `/openapi.json`에 있습니다.

## 문서

설계와 의사결정은 [`docs/`](docs/)에 있습니다. 개발 대전제는 [AGENTS.md](AGENTS.md),
되돌리기 어려운 결정은 [`docs/adr/`](docs/adr/)에 ADR로 남깁니다.

## 라이선스

[Apache-2.0](LICENSE)
