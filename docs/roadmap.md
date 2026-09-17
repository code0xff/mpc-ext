# 로드맵

## Phase 0 — 기반

- [ ] 저장소 스캐폴딩 (cargo + pnpm workspace)
- [ ] 개발 도구·CI·품질 게이트 (`development.md`)
- [x] MPC 라이브러리 후보 검증 및 ADR 확정 (ADR-0004: `0xCarbon/DKLs23`)
- [ ] 업스트림 crate vendoring + 고정 커밋 기록

## Phase 1 — MPC 코어

- [x] `mpc-core`: 업스트림을 감싸는 추상화 계층 (업스트림 타입이 공개 API에 노출되지 않음)
- [x] DKG / 서명 / 리프레시 구현
- [x] 통합 테스트 — 임의의 2셰어 조합 서명, 단일 셰어 거부, 리프레시 후 공개키 유지, 옛 셰어 무효화
- [x] `mpc-wasm` wasm32 빌드 및 네이티브 실측 (ADR-0004)
- [x] 브라우저 실측 (V8 wasm) 및 수치 기록
- [x] 경계 입력 방어 테스트 (손상된 셰어, 다른 키셋 혼합, 셰어 중복 사용)
- [x] 리셰어 구현 (`mpc_core::reshare`) 및 개인키 추출 (`mpc_core::export_private_key`)
- [x] 감사 범위 초안 작성 (`docs/audit.md`)
- [ ] **감사 기관·예산·시기 확정** — 의사결정 필요
- [ ] 업스트림에 rc 의존성 빌드 실패 이슈 보고

## Phase 2 — 확장 MVP

- [x] 암호화 저장소 (PBKDF2 + AES-GCM, 평문 미저장 테스트)
- [ ] 잠금/해제 UI와 비밀번호 설정 흐름
- [ ] 로컬 2셰어 DKG·서명 (서버 없이)
- [ ] 기본 UI (온보딩, 잠금, 서명 승인)

## Phase 3 — 서버 + 2-of-3

- [ ] `mpc-server` DKG 참여 (SQLite + OpenAPI/Swagger UI)
- [ ] 3셰어 DKG, 평시 로컬 2셰어 서명
- [ ] 복구 흐름 + 키 리프레시

## Phase 4 — 웹 통합

- [ ] EIP-1193 / EIP-6963 provider
- [ ] origin 권한 관리
- [ ] `packages/sdk` + 예제 dApp

## Phase 5 — 추출

- [ ] 셰어 export / import (파일 포맷과 암호화 컨테이너)
- [ ] 온보딩에 export 단계 편입 + 미-export 경고
- [x] 완전 개인키 추출 프리미티브 (`mpc_core::export_private_key`) — UI 경고는 Phase 5

## Phase 6 — 하드닝

- [ ] 외부 보안 감사
- [ ] 재현 가능 빌드 + 릴리스 서명
- [ ] 웹스토어 배포

## 후속 과제 (Deferred)

- 서버 없이도 두 요소를 유지하는 배치 (passkey PRF / OS 키체인을 셰어 보관처로) — 프라이버시를 지키면서 2요소를 얻는 대안 ([adr/0005](adr/0005-share-placement.md))
- 생체인증 잠금 해제 (WebAuthn / passkey PRF) — 초기 범위에서 제외
- `LFDT-Lockness/dkls` 추적 — 감사받은 permissive DKLs23 구현이 나오면 ADR-0004 재검토
- 주기적 자동 키 리프레시
- 다중 기기 지원 (확장 셰어를 여러 기기에 분산)
- secp256k1 외 커브 / EdDSA 지원
- 하드웨어 지갑을 셰어 보관처로 사용
- 자동 서명 승인 정책 (기본 비활성)
- 서버 인증 체계 설계 (Phase 3까지는 개발용 토큰으로 대체)
- SQLite → Postgres 전환 (다중 인스턴스 운영이 필요해질 때)
