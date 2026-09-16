# 로드맵

## Phase 0 — 기반
- [ ] 저장소 스캐폴딩 (cargo + pnpm workspace)
- [ ] 개발 도구·CI·품질 게이트 (`development.md`)
- [x] MPC 라이브러리 후보 검증 및 ADR 확정 (ADR-0004: `0xCarbon/DKLs23`)
- [ ] 업스트림 crate vendoring + 고정 커밋 기록

## Phase 1 — MPC 코어
- [ ] `mpc-core`: 업스트림을 트레이트 뒤로 감싸는 추상화 계층
- [ ] DKG / 서명 / 리프레시(리셰어) 구현
- [ ] 3파티 통합 테스트, 악성 메시지 테스트, 리프레시 후 옛 셰어 무효화 테스트
- [ ] `mpc-wasm` 빌드 및 **브라우저 실측**: DKG / 리프레시 / 서명 지연, 번들 크기, MV3 서비스 워커 동작 여부
- [ ] 실측 수치를 ADR-0004에 기록
- [ ] **외부 보안 감사 범위·예산·시기 확정** (vendoring한 MPC crate 포함)

## Phase 2 — 확장 MVP
- [ ] 암호화 저장소 + 잠금/해제 (비밀번호)
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
- [ ] 셰어 export / import
- [ ] 온보딩에 export 단계 편입 + 미-export 경고
- [ ] 완전 개인키 추출 (경고 포함)

## Phase 6 — 하드닝
- [ ] 외부 보안 감사
- [ ] 재현 가능 빌드 + 릴리스 서명
- [ ] 웹스토어 배포

## 후속 과제 (Deferred)
- **셰어 B를 별도 신뢰 영역으로 분리** (passkey PRF / OS 키체인 / 별도 기기) — 현재 설계에서 MPC가 도난 내성을 주지 못하는 한계의 근본 해결책 (`security.md`)
- 생체인증 잠금 해제 (WebAuthn / passkey PRF) — 초기 범위에서 제외
- `LFDT-Lockness/dkls` 추적 — 감사받은 permissive DKLs23 구현이 나오면 ADR-0004 재검토
- 주기적 자동 키 리프레시
- 다중 기기 지원 (확장 셰어를 여러 기기에 분산)
- secp256k1 외 커브 / EdDSA 지원
- 하드웨어 지갑을 셰어 보관처로 사용
- 자동 서명 승인 정책 (기본 비활성)
- 서버 인증 체계 설계 (Phase 3까지는 개발용 토큰으로 대체)
- SQLite → Postgres 전환 (다중 인스턴스 운영이 필요해질 때)
