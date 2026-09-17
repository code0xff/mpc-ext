/**
 * The message contract between the popup and the background worker.
 *
 * Secrets do not cross this boundary. The one exception is exporting the recovery file, and even
 * then the value is handed to the user to save — the extension never stores it.
 */

/** The extension's current state. */
export type Status =
  | { kind: 'uninitialized' }
  /** A key exists and we are waiting for the recovery file to be saved. Nothing is persisted yet. */
  | { kind: 'awaitingRecoveryExport'; publicKeyHex: string }
  | { kind: 'locked'; publicKeyHex: string }
  | { kind: 'unlocked'; publicKeyHex: string };

export type Request =
  | { type: 'status' }
  | { type: 'wasmHealth' }
  | { type: 'createKey'; password: string }
  | { type: 'confirmRecoverySaved' }
  | { type: 'cancelOnboarding' }
  | { type: 'unlock'; password: string }
  | { type: 'lock' };

export type Response<T> = { ok: true; value: T } | { ok: false; error: string };

/** The result of key creation. `recoveryShareHex` is share B, which the user must keep as a file. */
export interface CreatedKey {
  publicKeyHex: string;
  /** Share B. The extension never stores this. */
  recoveryShareHex: string;
}

export interface WasmHealth {
  config: string;
  loadMs: number;
}
