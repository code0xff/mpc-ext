# ADR-0004: MPC 라이브러리 재선정

- 상태: 승인
- 날짜: 2026-09-16
- 대체: [ADR-0001](0001-mpc-library.md)

## 맥락

ADR-0001이 라이선스 문제로 폐기되어 permissive 라이선스 후보를 재조사했다.
필수 요건은 네 가지다: (1) permissive 오픈소스, (2) 2-of-3 임계 ECDSA, (3) **키 리프레시/리셰어**,
(4) 브라우저 wasm에서 실사용 가능한 성능.

리프레시는 성능이 아니라 설계 요건이다. 리셰어가 없으면 복구 후 2-of-3으로 되돌아갈 수 없다 —
남은 셰어와 서버 셰어 2개만 남고 새 기기에 3번째 셰어를 나눠줄 방법이 없어, 키를 새로 만들고
자산을 옮겨야 한다(주소 변경). 이는 복구가 아니라 이전이다.

## 조사 결과 (2026-09-16 기준)

| | 라이선스 | 키 리프레시 | 감사 | 유지보수 | 브라우저 성능 |
|---|---|---|---|---|---|
| `silence-laboratories/dkls23` | ❌ SLL (비오픈소스) | ✅ | ✅ Trail of Bits 2024-02 | 양호 | ✅ |
| `0xCarbon/DKLs23` | ✅ Apache-2.0 / MIT | ✅ `refresh.rs`, `re_key.rs` | ❌ | ⚠️ 사실상 1인 | ✅ |
| `LFDT-Lockness/cggmp21`(→`cggmp24`) | ✅ MIT / Apache-2.0 | ❌ **미지원** | ✅ Kudelski (범위 미확인) | ✅ LFDT 거버넌스 | ❌ safe prime 생성 |
| `LFDT-Lockness/dkls` | ✅ | — | ❌ | **코드 없음** (2026-08 생성) | — |

각 후보가 서로 다른 필수 요건에서 하나씩 탈락한다. 깨끗한 선택지는 없다.

`cggmp24` 추가 확인 사항:
- README 명시: "does not (currently) support: Key refresh for both threshold and non-threshold keys".
- 상수 시간 연산을 의도적으로 하지 않는다("timing attacks out of scope"). 브라우저 확장의 위협 모델과 맞지 않는다.
- wasm은 `num-bigint` 백엔드만 가능하고, 빠른 `rug` 백엔드는 LGPL이라 채택할 수 없다.
- 키 추출은 `spof` 피처로 지원된다.

## 결정

**`0xCarbon/DKLs23` (Apache-2.0 / MIT)을 채택하고, 감사 비용을 우리가 부담한다.**

리프레시 요건을 충족하는 유일한 permissive 후보이며, DKLs23이라 브라우저 성능도 유리하다.
대가는 감사 부재와 사실상 1인 유지보수(bus factor 1)이며, 아래 완화책을 전제로 수용한다.

## 코드 품질 평가 (2026-09-16, `dev` @ 159 커밋 기준)

직접 클론해 확인한 내용이다.

**양호한 신호**

- `#![forbid(unsafe_code)]` — unsafe 0건, 컴파일러가 강제.
- `zeroize` + `subtle`(상수 시간 연산)을 7개 파일에 걸쳐 사용.
- `insecure-rng` 피처가 `#[cfg(all(test, feature = ...))]`로 게이팅되어, 실제 빌드에는 결정론적 RNG가 들어갈 수 없다. 의도를 주석에 명시.
- **적대적 테스트 존재** — 조작된 증명(`tampered_enc_proof`, `tampered_dlog_proof`), 중복 발신자(`rejects_duplicate_mul_init_sender`) 거부를 검증. 정상 경로만 테스트하지 않는다.
- 테스트 104개. CI: clippy / fmt / test / `cargo audit` / `cargo unmaintained` / 스펠체크.
- 프로덕션 경로 panic 38건 / 약 6,000줄 — 암호 코드치고 낮다.
- `[target.'cfg(target_arch = "wasm32")'.dependencies.getrandom]`에 `wasm_js` 피처 명시 — **wasm은 의도된 지원 대상이다.**

**리스크 (실력이 아닌 조직·공급망 리스크)**

- **의존성이 전부 릴리스 캔디데이트**: `elliptic-curve 0.14.0-rc.4`, `k256 0.14.0-rc.7`, `sha2 0.11.0-rc.5`, `hmac 0.13.0-rc.5`, `ripemd 0.2.0-rc.5`. rc 암호 코드는 안정 버전만큼 검증되지 않았고 API도 흔들린다.
- bus factor 1 — 159커밋 중 약 85%가 1인.
- 외부 감사 없음. 기본 브랜치가 `main`이 아닌 `dev`.
- CI가 유지보수 중단된 `actions-rs/*` 액션을 사용.

**결론**: 감사만 받지 않았을 뿐 설계 태도는 감사받은 라이브러리에 준한다. 채택 결정을 유지한다.

## 완화책 (필수)

1. **vendoring** — 의존성을 고정 커밋으로 vendoring하고, 업스트림 변경은 리뷰 후 수동 반영한다. 자동 업데이트하지 않는다.
2. **추상화** — `mpc-core`가 라이브러리를 트레이트 뒤로 감춘다. 교체 가능성을 코드 구조로 유지한다.
3. **자체 감사** — 외부 보안 감사 범위에 이 crate를 포함한다. Phase 6이 아니라 **Phase 1 종료 시점에 감사 범위·예산·시기를 확정**한다.
4. **업스트림 관계** — 발견한 버그는 업스트림에 기여한다. 유지보수가 멈추면 우리가 fork를 인수할 준비를 한다.
5. **rc 의존성 고정** — vendoring 시점의 release candidate 버전을 lockfile로 고정한다. 업스트림이 stable로 올라가도 자동으로 따라가지 않고, 우리가 검증한 뒤 반영한다. rc 의존성 목록과 각각의 stable 전환 상태를 추적한다.
6. **대안 추적** — `LFDT-Lockness/dkls`의 진행을 주시한다. 감사받은 permissive DKLs23 구현이 나오면 본 ADR을 재검토한다.

## 결과

- 우리는 이 crate의 사실상 공동 메인테이너가 된다. 이 비용을 프로젝트 계획에 명시적으로 반영한다.
- 감사 전까지는 **실자산 사용을 권하지 않는다**는 경고를 README와 확장 UI에 표시한다.
- Phase 1 스파이크에서 브라우저 실측(DKG / 리프레시 / 서명 / 번들 크기 / MV3 서비스 워커 동작)을 수행하고 수치를 본 ADR에 추가한다.
