/**
 * Loading the wasm module.
 *
 * An MV3 service worker is terminated when idle and woken again by the next event, so the module
 * has to be instantiated afresh each time. Caching the init promise keeps that to once per
 * worker lifetime. Measured cost: about 5 ms.
 */
import init, {
  DkgSession,
  SignSession,
  threshold_config,
  verify as wasmVerify,
} from '../wasm/mpc_wasm.js';

let ready: Promise<void> | undefined;

/** Initialises wasm. Calling it repeatedly still loads only once. */
export function loadWasm(): Promise<void> {
  ready ??= init({ module_or_path: chrome.runtime.getURL('wasm/mpc_wasm_bg.wasm') }).then(
    () => undefined,
  );
  return ready;
}

export { DkgSession, SignSession, threshold_config, wasmVerify };
