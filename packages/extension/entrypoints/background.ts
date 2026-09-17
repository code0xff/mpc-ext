/**
 * 백그라운드 서비스 워커.
 *
 * 비밀에 접근하는 유일한 곳이다. 셰어 A는 이 워커의 메모리에만 복호화된 상태로
 * 존재하며, 워커가 종료되면 자동으로 잠긴다 (`docs/architecture.md`).
 */
import type { CreatedKey, Request, Response, Status } from '../src/messages';
import * as vault from '../src/vault';
import { loadWasm, threshold_config, wasmDkg } from '../src/wasm';

/** 복호화된 셰어 A. 워커 종료와 함께 사라진다. 절대 저장하지 않는다. */
let unlockedShare: Uint8Array | undefined;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function status(): Promise<Status> {
  if (!(await vault.exists())) return { kind: 'uninitialized' };
  if (!unlockedShare) return { kind: 'locked' };
  const publicKeyHex = (await vault.publicKeyHex()) ?? '';
  return { kind: 'unlocked', address: publicKeyHex };
}

/**
 * 키를 생성한다.
 *
 * DKG는 셰어 3개를 만들지만 확장은 **A만 저장한다.** B는 호출부로 넘겨 사용자가
 * 복구 파일로 보관하게 하고, C는 Phase 3에서 서버가 갖는다
 * (`docs/adr/0005-share-placement.md`).
 */
async function createKey(): Promise<CreatedKey> {
  await loadWasm();
  const sessionId = crypto.getRandomValues(new Uint8Array(32));
  const keyset = wasmDkg(sessionId);

  const shareA = keyset.share(0);
  const shareB = keyset.share(1);
  const publicKeyHex = toHex(keyset.public_key);

  // Phase 2에서는 비밀번호 설정 UI 전이라 셰어 A를 아직 저장하지 않는다.
  // 저장 경로는 vault.store()로 이미 준비되어 있다.
  unlockedShare = shareA;

  return { publicKeyHex, recoveryShareHex: toHex(shareB) };
}

async function handle(request: Request): Promise<unknown> {
  switch (request.type) {
    case 'status':
      return status();
    case 'wasmHealth': {
      const started = performance.now();
      await loadWasm();
      return { config: threshold_config(), loadMs: Math.round(performance.now() - started) };
    }
    case 'createKey':
      return createKey();
    case 'sign':
      // 평시 서명은 확장(A) + 서버(C)이며, 전송 계층은 Phase 3에서 붙는다.
      throw new Error('서명은 서버 연동(Phase 3) 이후에 동작합니다');
    default: {
      const exhaustive: never = request;
      throw new Error(`알 수 없는 요청: ${JSON.stringify(exhaustive)}`);
    }
  }
}

export default defineBackground(() => {
  chrome.runtime.onMessage.addListener(
    (request: Request, _sender, sendResponse: (response: Response<unknown>) => void) => {
      handle(request)
        .then((value) => sendResponse({ ok: true, value }))
        // 오류 메시지에 비밀 값이 실리지 않도록 문자열만 전달한다.
        .catch((error: unknown) => {
          sendResponse({
            ok: false,
            error: error instanceof Error ? error.message : String(error),
          });
        });
      // 비동기 응답을 쓰겠다는 신호.
      return true;
    },
  );
});
