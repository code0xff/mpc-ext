# 아키텍처

## 개요

2-of-3 임계 서명. 셰어 3개는 다음과 같이 배치한다.

| 셰어      | 보관 위치            | 평시 역할 | 복구 역할             |
| --------- | -------------------- | --------- | --------------------- |
| `share-A` | 확장 (암호화 저장소) | 서명 참여 | —                     |
| `share-B` | 확장 (암호화 저장소) | 서명 참여 | —                     |
| `share-C` | 서버                 | 미사용    | A 또는 B 분실 시 참여 |

평시 서명은 A+B로 확장 내부에서 완결된다. 서버는 오프라인이어도 서명이 가능하다.
A 또는 B를 잃으면 남은 셰어 + C로 서명하고, 즉시 키 리프레시로 새 3셰어를 만든다 (`recovery.md`).

## 컴포넌트

```
repo/
├─ crates/
│  ├─ mpc-core/      # DKLs23 래퍼, 프로토콜 상태머신 (no_std 지향)
│  ├─ mpc-wasm/      # wasm-bindgen 바인딩 (확장용)
│  └─ mpc-server/    # axum 서버
├─ packages/
│  ├─ extension/     # WXT + React MV3 확장
│  └─ sdk/           # 웹페이지용 provider SDK (npm 배포)
└─ docs/
```

`mpc-core`가 프로토콜의 단일 진실 공급원이다. 확장과 서버는 같은 crate를 각각 wasm/네이티브로 쓴다.

## 확장 내부 구조

- **background (service worker)** — 셰어 보관, MPC 실행, 세션 잠금 상태 소유. 유일하게 비밀에 접근한다.
- **popup / options (React)** — UI. 비밀을 직접 다루지 않고 background에 메시지로 요청한다.
- **content script** — 페이지와 background 사이의 좁은 릴레이. 요청을 검증만 하고 판단하지 않는다.
- **injected provider** — 페이지 컨텍스트의 `window` API (`web-api.md`).

MV3 서비스 워커는 언제든 종료될 수 있다. 복호화된 셰어는 워커 메모리에만 두고, 종료 시 자동 잠금된다.

## 신뢰 경계

1. 웹페이지 ↔ content script — 완전 비신뢰. 모든 요청은 스키마 검증 + 사용자 승인 필요.
2. content script ↔ background — 반신뢰. background가 origin을 재검증한다.
3. 확장 ↔ 서버 — 서버는 honest-but-curious로 가정. 셰어 1개만 보유하므로 단독 서명 불가. 다만 평시 서명에 관여하므로 **무엇에 서명하는지는 보게 된다** (`security.md`).
4. 확장 ↔ OS/디스크 — 저장소는 항상 암호화 상태.

## 불변식

- **확장은 셰어를 하나만 보관한다.** DKG 중 생성한 셰어 B는 내보낸 뒤 메모리와 저장소에서 지운다.
- 어느 한 주체(확장·서버·복구 파일)도 단독으로 서명하거나 키를 복원할 수 없다.
- 프로토콜 로직은 `mpc-core`에만 존재한다.
- 리셰어·키 추출로 개인키가 복원되는 순간은 **사용자 기기에서만** 발생한다 (`recovery.md`).
