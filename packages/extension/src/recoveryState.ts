/**
 * A recovery in progress (`docs/adr/0008-recovery-start-and-device-key-replacement.md`).
 *
 * A recovery can wait a day, so it has to outlive the popup and the worker. What is kept here is
 * only what is needed to pick it up again, and none of it is secret: the wallet id and public key
 * are also in the recovery file's header, and the request id is useless without the pending
 * device key, which lives in IndexedDB. The recovery share and every password stay out. To finish,
 * the user selects the recovery file again.
 */
const STORAGE_KEY = 'recovery';

export interface RecoveryInProgress {
  walletId: string;
  publicKeyHex: string;
  requestId: string;
}

export async function read(): Promise<RecoveryInProgress | undefined> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const value = stored[STORAGE_KEY] as Partial<RecoveryInProgress> | undefined;
  if (!value?.walletId || !value.publicKeyHex || !value.requestId) return undefined;
  return { walletId: value.walletId, publicKeyHex: value.publicKeyHex, requestId: value.requestId };
}

export async function write(value: RecoveryInProgress): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: value });
}

export async function clear(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}
