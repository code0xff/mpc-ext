/**
 * Exporting the recovery file (share B).
 *
 * It carries the whole share, so it is about 230 KB and cannot be turned into a mnemonic or a QR
 * code (`docs/adr/0005-share-placement.md`). The share is encrypted under a password chosen at
 * export time (`src/recoveryFile.ts`).
 */
import type { CreatedKey } from '../../src/messages';
import { encryptRecoveryFile } from '../../src/recoveryFile';

export async function downloadRecoveryFile(created: CreatedKey, password: string): Promise<void> {
  const file = await encryptRecoveryFile(
    password,
    created.recoveryShareHex,
    created.publicKeyHex,
    created.walletId,
  );
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = `mpc-ext-recovery-${created.publicKeyHex.slice(0, 8)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
