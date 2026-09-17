/**
 * popup ↔ background 메시지 계약.
 *
 * 비밀 값은 이 경계를 넘지 않는다. 유일한 예외는 복구 파일 내보내기이며,
 * 그때도 사용자가 직접 저장하도록 넘길 뿐 확장은 저장하지 않는다.
 */

/** 확장의 현재 상태. */
export type Status =
  | { kind: 'uninitialized' }
  /** 키를 만들었고 복구 파일 저장을 기다리는 중. 아직 아무것도 저장되지 않았다. */
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

/** 키 생성 결과. `recoveryShareHex`는 사용자가 파일로 보관해야 하는 셰어 B다. */
export interface CreatedKey {
  publicKeyHex: string;
  /** 셰어 B. 확장은 이 값을 저장하지 않는다. */
  recoveryShareHex: string;
}

export interface WasmHealth {
  config: string;
  loadMs: number;
}
