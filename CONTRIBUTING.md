# 기여 가이드

## 시작

```bash
make setup
make check   # 커밋 전 반드시 통과해야 합니다
```

## 규칙

- 작업 전 [AGENTS.md](AGENTS.md)와 관련 [`docs/`](docs/) 문서를 읽어주세요.
- 구현이 문서와 어긋나면 **문서를 먼저 고칩니다.**
- 되돌리기 어려운 결정은 [`docs/adr/`](docs/adr/)에 ADR로 남깁니다.
- 커밋 메시지는 [Conventional Commits](https://www.conventionalcommits.org/).
- `main` 직접 푸시 금지. PR로 병합합니다.
- 암호·프로토콜 코드는 테스트 없이 머지하지 않습니다.
- **실제 키·시크릿을 커밋하지 마세요.** 테스트 픽스처에도 더미값만 씁니다.
- 새 의존성은 라이선스 원문과 유지보수 상태를 확인하고, PR 설명에 사유를 남깁니다.
  copyleft(GPL/AGPL/LGPL)는 도입하지 않습니다.

## 보안

취약점은 이슈가 아니라 [SECURITY.md](SECURITY.md)의 절차로 신고해 주세요.
