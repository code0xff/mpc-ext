# ADR-0001: MPC 프로토콜과 라이브러리

- 상태: **폐기됨 — ADR-0004로 대체**
- 날짜: 2026-09-16

## 맥락

2-of-3 임계 ECDSA가 필요하다. 확장(wasm)과 서버(네이티브)에서 같은 구현을 써야 하고,
브라우저 환경에서 서명 지연이 사용자 체감 수준이어야 하며, 전부 오픈소스여야 한다.

## 결정 (폐기)

DKLs23을 채택하고 `silence-laboratories/dkls23`을 기반으로 한다.

## 폐기 사유

`silence-laboratories/dkls23`의 라이선스를 Apache-2.0으로 잘못 기재했다. 실제로는
**Silence Laboratories Non-Commercial Use License (SLL)** 이며 다음 이유로 사용할 수 없다.

- 비상업적 사용만 허용하고, "internal business purposes"도 상업적 사용으로 금지한다.
- **non-sublicensable** — 하위 배포자에게 권리를 넘길 수 없어 오픈소스 재배포가 불가능하다.
- **revocable** — 라이선스를 철회할 수 있고, 약관도 일방적으로 변경할 수 있다.

구형 `silence-laboratories/silent-shard-dkls23-ll`(wasm 바인딩 포함)도 동일한 SLL이다.
기능적으로는 우수하나(Trail of Bits 감사 2024-02, 감사된 key refresh, export/import 내장)
"전부 오픈소스"라는 프로젝트 대전제와 충돌하므로 후보에서 제외한다.

대체 결정은 [ADR-0004](0004-mpc-library-reselection.md).
