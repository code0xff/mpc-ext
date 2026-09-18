/**
 * Per-origin connection permissions.
 *
 * A connection permission lets a page see the address. It does **not** authorise signing:
 * every signature is approved individually (`docs/web-api.md`).
 */

const STORAGE_KEY = 'origins';

/** Origins the user has connected to this wallet. */
async function read(): Promise<string[]> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const saved = stored[STORAGE_KEY];
  return Array.isArray(saved) ? (saved as string[]) : [];
}

/** Whether this origin may see the address. */
export async function isConnected(origin: string): Promise<boolean> {
  return (await read()).includes(origin);
}

/** Grants an origin permission to see the address. */
export async function connect(origin: string): Promise<void> {
  const origins = await read();
  if (!origins.includes(origin)) {
    await chrome.storage.local.set({ [STORAGE_KEY]: [...origins, origin] });
  }
}

/** Revokes an origin. The user must be able to do this at any time. */
export async function disconnect(origin: string): Promise<void> {
  const origins = await read();
  await chrome.storage.local.set({ [STORAGE_KEY]: origins.filter((o) => o !== origin) });
}

/** Every connected origin, for the UI to list and revoke. */
export async function connected(): Promise<string[]> {
  return read();
}
