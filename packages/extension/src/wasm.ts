/**
 * wasm 모듈 로딩.
 *
 * MV3 서비스 워커는 유휴 상태에서 종료되고 다음 이벤트에 다시 깨어난다. 그때마다
 * 모듈을 새로 인스턴스화해야 하므로, 초기화 Promise를 캐시해 워커 수명 동안
 * 한 번만 로드한다.
 */
import init, {
  dkg as wasmDkg,
  sign as wasmSign,
  threshold_config,
  verify as wasmVerify,
} from '../wasm/mpc_wasm.js';

let ready: Promise<void> | undefined;

/** wasm을 초기화한다. 여러 번 호출해도 실제 로드는 한 번만 일어난다. */
export function loadWasm(): Promise<void> {
  ready ??= init({ module_or_path: chrome.runtime.getURL('wasm/mpc_wasm_bg.wasm') }).then(
    () => undefined,
  );
  return ready;
}

export { threshold_config, wasmDkg, wasmSign, wasmVerify };
