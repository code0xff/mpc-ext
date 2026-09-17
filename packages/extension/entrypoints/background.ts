/**
 * 백그라운드 서비스 워커.
 *
 * 비밀에 접근하는 유일한 곳이다. 셰어 A는 이 워커의 메모리에만 복호화된 상태로
 * 존재하며, 워커가 종료되면 자동으로 잠긴다 (`docs/architecture.md`).
 */
import type { CreatedKey, Request, Response, Status, WasmHealth } from '../src/messages';
import * as vault from '../src/vault';
import { loadWasm, threshold_config, wasmDkg } from '../src/wasm';

/** 복호화된 셰어 A. 워커 종료와 함께 사라진다. 절대 저장하지 않는다. */
let unlockedShare: Uint8Array | undefined;

/**
 * 온보딩 진행 중 상태. 복구 파일 저장이 확인될 때까지 **아무것도 저장하지 않는다.**
 *
 * 셰어 A만 저장해두고 워커가 죽으면 셰어 B는 영영 사라져 지갑이 못 쓰게 된다.
 * 그래서 둘 다 메모리에 들고 있다가 한 번에 확정한다 — 실패하면 아무 흔적도 남지 않는다.
 */
let pending: { shareA: Uint8Array; publicKeyHex: string; password: string } | undefined;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function wipe(bytes: Uint8Array | undefined): void {
  bytes?.fill(0);
}

async function status(): Promise<Status> {
  if (pending) {
    return { kind: 'awaitingRecoveryExport', publicKeyHex: pending.publicKeyHex };
  }
  const publicKeyHex = await vault.publicKeyHex();
  if (!publicKeyHex) return { kind: 'uninitialized' };
  return unlockedShare ? { kind: 'unlocked', publicKeyHex } : { kind: 'locked', publicKeyHex };
}

/**
 * 키를 생성한다.
 *
 * DKG는 셰어 3개를 만들지만 확장은 **A만 보관한다.** B는 호출부로 넘겨 사용자가
 * 복구 파일로 보관하게 하고, C는 Phase 3에서 서버가 갖는다
 * (`docs/adr/0005-share-placement.md`).
 */
async function createKey(password: string): Promise<CreatedKey> {
  if (password.length < 8) throw new Error('비밀번호는 8자 이상이어야 합니다');
  if (await vault.exists()) throw new Error('이미 키가 있습니다');

  await loadWasm();
  const sessionId = crypto.getRandomValues(new Uint8Array(32));
  const keyset = wasmDkg(sessionId);

  const shareA = keyset.share(0);
  const shareB = keyset.share(1);
  const publicKeyHex = toHex(keyset.public_key);

  pending = { shareA, publicKeyHex, password };
  // 셰어 B는 여기서 넘긴 뒤 워커 메모리에 남기지 않는다.
  const recoveryShareHex = toHex(shareB);
  wipe(shareB);

  return { publicKeyHex, recoveryShareHex };
}

/** 복구 파일 저장이 확인되었다. 이제서야 셰어 A를 저장한다. */
async function confirmRecoverySaved(): Promise<Status> {
  if (!pending) throw new Error('저장할 키가 없습니다');

  await vault.store(pending.password, pending.shareA, pending.publicKeyHex);
  unlockedShare = pending.shareA;
  // JS 문자열은 지울 수 없다. 참조를 끊어 GC에 맡기는 것이 최선이다.
  pending = undefined;

  return status();
}

/** 온보딩을 취소한다. 생성된 셰어를 모두 버린다. */
function cancelOnboarding(): void {
  wipe(pending?.shareA);
  pending = undefined;
}

async function unlock(password: string): Promise<Status> {
  const share = await vault.unlock(password);
  if (!share) throw new Error('비밀번호가 올바르지 않습니다');
  unlockedShare = share;
  return status();
}

function lock(): void {
  wipe(unlockedShare);
  unlockedShare = undefined;
}

async function handle(request: Request): Promise<unknown> {
  switch (request.type) {
    case 'status':
      return status();
    case 'wasmHealth': {
      const started = performance.now();
      await loadWasm();
      const health: WasmHealth = {
        config: threshold_config(),
        loadMs: Math.round(performance.now() - started),
      };
      return health;
    }
    case 'createKey':
      return createKey(request.password);
    case 'confirmRecoverySaved':
      return confirmRecoverySaved();
    case 'cancelOnboarding':
      cancelOnboarding();
      return status();
    case 'unlock':
      return unlock(request.password);
    case 'lock':
      lock();
      return status();
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
