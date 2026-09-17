/**
 * 복구 파일(셰어 B) 내보내기.
 *
 * 셰어 전체를 담기 때문에 약 230 KB다. 니모닉이나 QR로 만들 수 없다
 * (`docs/adr/0005-share-placement.md`).
 */
import type { CreatedKey } from '../../src/messages';

/** 복구 파일 컨테이너. `publicKey`는 가져오기 시 무결성 대조에 쓴다. */
export interface RecoveryFile {
  formatVersion: 1;
  kind: 'mpc-ext-recovery';
  createdAt: string;
  publicKey: string;
  share: string;
  note: string;
}

export function buildRecoveryFile(created: CreatedKey): RecoveryFile {
  return {
    formatVersion: 1,
    kind: 'mpc-ext-recovery',
    createdAt: new Date().toISOString(),
    publicKey: created.publicKeyHex,
    share: created.recoveryShareHex,
    note: 'mpc-ext 복구 파일 (셰어 B). 확장과 다른 곳에 보관하세요. 이 파일 하나만으로는 서명할 수 없습니다.',
  };
}

export function downloadRecoveryFile(created: CreatedKey): void {
  const file = buildRecoveryFile(created);
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = `mpc-ext-recovery-${created.publicKeyHex.slice(0, 8)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
