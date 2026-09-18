/**
 * User-visible settings.
 *
 * The server address has to be configurable: the point of a self-hostable server is that users
 * can run their own (`docs/server.md`).
 */

const STORAGE_KEY = 'settings';

/** The default server address, used until the user points somewhere else. */
export const DEFAULT_SERVER_URL = 'http://127.0.0.1:8080';

export interface Settings {
  serverUrl: string;
}

/** Reads the settings, falling back to defaults. */
export async function read(): Promise<Settings> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const saved = stored[STORAGE_KEY] as Partial<Settings> | undefined;
  return { serverUrl: saved?.serverUrl ?? DEFAULT_SERVER_URL };
}

/** The server address to use for requests. */
export async function serverUrl(): Promise<string> {
  return (await read()).serverUrl;
}

/**
 * Points the extension at a different server.
 *
 * Rejects anything that is not an http(s) URL so a typo cannot turn into a request somewhere
 * unexpected. A trailing slash is trimmed, because paths are appended directly.
 */
export async function setServerUrl(value: string): Promise<Settings> {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('That is not a valid URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('The server URL must start with http:// or https://');
  }

  const serverUrl = value.replace(/\/+$/, '');
  await chrome.storage.local.set({ [STORAGE_KEY]: { serverUrl } });
  return { serverUrl };
}
