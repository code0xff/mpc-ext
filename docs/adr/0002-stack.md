# ADR-0002: 기술 스택

- 상태: 승인
- 날짜: 2026-09-16

## 맥락

확장과 서버가 동일한 MPC 프로토콜 로직을 공유해야 한다. 프로토콜을 두 언어로 중복 구현하면
두 구현이 갈라질 때 보안 사고로 직결된다.

## 결정

- **MPC 코어**: Rust (`mpc-core`). 확장은 wasm, 서버는 네이티브로 같은 crate를 쓴다.
- **서버**: Rust + axum.
- **확장**: TypeScript + React + Vite + WXT (Manifest V3).
- **워크스페이스**: cargo workspace + pnpm workspace.

## 결과

- 프로토콜 구현이 하나로 유지된다.
- wasm 번들 크기와 서비스 워커 초기화 시간을 관리해야 한다 (Phase 1에서 측정).
- 기여자에게 Rust와 TS 양쪽 툴체인이 필요하다. `make setup`으로 진입 장벽을 낮춘다.

## 대안

서버를 TypeScript로 두는 안은 Rust 코어를 napi/wasm으로 감싸는 바인딩 레이어가 추가로 필요해 기각했다.
