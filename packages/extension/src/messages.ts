/**
 * The message contract between the popup and the background worker.
 *
 * Secrets do not cross this boundary, with two exceptions the user asks for explicitly: the
 * recovery file at key creation, and the full private key export (`docs/export.md`). In both the
 * value is handed to the user to save — the extension never stores it.
 */

/** The extension's current state. */
export type Status =
  | { kind: 'uninitialized' }
  /** A key exists and we are waiting for the recovery file to be saved. Nothing is persisted yet. */
  | { kind: 'awaitingRecoveryExport'; publicKeyHex: string }
  | { kind: 'locked'; publicKeyHex: string }
  | {
      kind: 'unlocked';
      publicKeyHex: string;
      /**
       * True when this install was restored from a recovery file. Such a wallet can sign but is
       * not a healthy 2-of-3, and the UI has to say so (`docs/recovery.md`).
       */
      recovered: boolean;
      /** True while a reshare has staged a new server share and is waiting to be finished. */
      reshareInProgress: boolean;
    };

export type Request =
  | { type: 'status' }
  | { type: 'wasmHealth' }
  | { type: 'serverHealth' }
  | { type: 'createKey'; password: string }
  | { type: 'confirmRecoverySaved' }
  | { type: 'cancelOnboarding' }
  | { type: 'unlock'; password: string }
  | { type: 'lock' }
  /** Sign with the extension share and the server share — the everyday path. */
  | { type: 'sign'; digestHex: string }
  /**
   * Sign with the extension share and a recovery file, for when the server is unreachable.
   * The recovery share is used once and never stored.
   */
  | { type: 'signOffline'; digestHex: string; recoveryShareHex: string }
  /**
   * Restore a wallet on a fresh install from a recovery file. The wallet can sign again, but it
   * does not return to a healthy 2-of-3 — see `docs/recovery.md`.
   */
  | {
      type: 'recoverFromFile';
      password: string;
      walletId: string;
      publicKeyHex: string;
      recoveryShareHex: string;
    }
  /**
   * Reconstruct the full private key from the extension share and a recovery file. Dangerous:
   * the MPC benefit is gone for whoever holds the result. Needs the wallet password again.
   */
  | { type: 'exportPrivateKey'; password: string; recoveryShareHex: string }
  /**
   * Begin resharing a wallet that was restored from a recovery file, giving it a healthy 2-of-3
   * again (`docs/adr/0007-distributed-reshare.md`). Needs the wallet password and a passkey
   * assertion. It returns at once: the passkey ceremony opens a tab, which closes the popup, so
   * progress is polled with `reshareProgress` and the result fetched with `takeReshareRecovery`.
   */
  | { type: 'startReshare'; password: string }
  | { type: 'reshareProgress' }
  /** The new recovery share, once and only once, after `reshareProgress` says `ready`. */
  | { type: 'takeReshareRecovery' }
  /** The new recovery file is saved: make the new server share live and store the new A. */
  | { type: 'confirmReshareSaved' }
  /** Abandon a reshare that has not been committed. The current shares stay valid. */
  | { type: 'cancelReshare' }
  | { type: 'readSettings' }
  | { type: 'setServerUrl'; serverUrl: string }
  | { type: 'registerPasskey' }
  | {
      type: 'assertPasskey';
      purpose: 'sign' | 'recovery';
      operationId: string;
      digest: string;
    }
  | { type: 'passkeyLauncherReady' }
  | { type: 'passkeyStatus'; ceremonyId: string }
  /** Relayed from a page by the content script. The origin comes from the sender, not the page. */
  | { type: 'pageRequest'; method: string; params?: unknown[] }
  | { type: 'pendingApprovals' }
  | { type: 'decideApproval'; id: string; approved: boolean }
  | { type: 'connectedOrigins' }
  | { type: 'disconnectOrigin'; origin: string };

export type Response<T> = { ok: true; value: T } | { ok: false; error: string };

/** The result of key creation. `recoveryShareHex` is share B, which the user must keep as a file. */
export interface CreatedKey {
  publicKeyHex: string;
  /** Identifies the wallet to the server. Not a secret. */
  walletId: string;
  /** Share B. The extension never stores this. */
  recoveryShareHex: string;
}

export interface WasmHealth {
  config: string;
  loadMs: number;
}

/** A completed signature. */
export interface Signed {
  /** 65 bytes as hex: r || s || v. */
  signatureHex: string;
  /** Which path produced it, so the UI can say so. */
  via: 'server' | 'recoveryFile';
}

/** The result of a private key export. Shown to the user once and never stored. */
export interface ExportedKey {
  privateKeyHex: string;
}

/** How far a reshare has got. Never carries a secret. */
export interface ReshareProgress {
  phase: 'idle' | 'working' | 'ready' | 'failed';
  /** Set once when `phase` is `failed`. */
  error?: string;
}
