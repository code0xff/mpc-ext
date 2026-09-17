/**
 * popup ↔ background 메시지 계약.
 *
 * 비밀 값은 이 경계를 넘지 않는다. 유일한 예외는 복구 파일 내보내기이며,
 * 그때도 사용자가 직접 저장하도록 넘길 뿐 저장소에 쓰지 않는다.
 */

/** 확장의 현재 상태. */
export type Status =
  { kind: 'uninitialized' } | { kind: 'locked' } | { kind: 'unlocked'; address: string };

export type Request =
  | { type: 'status' }
  | { type: 'wasmHealth' }
  | { type: 'createKey' }
  | { type: 'sign'; digestHex: string };

export type Response<T> = { ok: true; value: T } | { ok: false; error: string };

/** 키 생성 결과. `recoveryShare`는 사용자가 파일로 보관해야 하는 셰어 B다. */
export interface CreatedKey {
  publicKeyHex: string;
  /** 셰어 B. 확장은 이 값을 저장하지 않는다. */
  recoveryShareHex: string;
}
