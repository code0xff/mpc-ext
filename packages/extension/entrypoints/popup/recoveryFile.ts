/**
 * Exporting the recovery file (share B).
 *
 * It carries the whole share, so it is about 230 KB and cannot be turned into a mnemonic or a QR
 * code (`docs/adr/0005-share-placement.md`).
 */
import type { CreatedKey } from '../../src/messages';

/** The recovery file container. `publicKey` is used to check integrity on import. */
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
    note: 'mpc-ext recovery file (share B). Store it somewhere other than the extension. This file alone cannot sign.',
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
