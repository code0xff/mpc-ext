/**
 * Noticing that someone asked to replace this wallet's device
 * (`docs/adr/0009-managing-recoveries-with-the-passkey.md`, `docs/recovery.md`).
 *
 * The server cannot tell the owner: there is no email or phone by design. So an install that still
 * holds the wallet's device key asks the server now and then, and raises a browser notification the
 * first time it sees a recovery it has not told the user about. This helps only while that browser
 * is running. For a device that is gone, `/manage` is the way to look.
 */
import type { PendingRecoveryInfo } from './messages';

/** How often the worker asks. The wait is a day by default, so minutes are fast enough. */
export const WATCH_PERIOD_MINUTES = 5;
export const WATCH_ALARM = 'recoveryWatch';

const STORAGE_KEY = 'notifiedRecoveries';

/** Ids kept, so the list cannot grow for ever. A recovery is over long before this many others. */
const MAX_REMEMBERED = 50;

/** The recoveries in `pending` that the user has not been told about yet. */
export function unannounced(
  pending: PendingRecoveryInfo[],
  alreadyTold: string[],
): PendingRecoveryInfo[] {
  const told = new Set(alreadyTold);
  return pending.filter((item) => !told.has(item.requestId));
}

/** The ids to remember after telling the user about `fresh`, newest last, capped. */
export function remember(alreadyTold: string[], fresh: PendingRecoveryInfo[]): string[] {
  const merged = [...alreadyTold, ...fresh.map((item) => item.requestId)];
  return [...new Set(merged)].slice(-MAX_REMEMBERED);
}

export async function readTold(): Promise<string[]> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const value = stored[STORAGE_KEY];
  return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string') : [];
}

export async function writeTold(ids: string[]): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: ids });
}

/** What the notification says. It names no wallet, key or address. */
export function describeRecovery(item: PendingRecoveryInfo): { title: string; message: string } {
  const after = new Date(item.readyAt * 1000).toLocaleString();
  return {
    title: 'Someone asked to replace your wallet device',
    message: `A new device (key ${item.keyFingerprint}) can take over after ${after}. Open mpc-ext to cancel it if this was not you.`,
  };
}
