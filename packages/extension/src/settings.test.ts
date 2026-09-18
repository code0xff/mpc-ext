/**
 * Unit tests for the settings store.
 *
 * The server URL is user input that the background worker will send requests to, so validation
 * matters more than it looks.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as settings from './settings';

const storage = new Map<string, unknown>();
vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: async (key: string) => (storage.has(key) ? { [key]: storage.get(key) } : {}),
      set: async (items: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(items)) storage.set(k, v);
      },
    },
  },
});

describe('settings', () => {
  beforeEach(() => storage.clear());

  it('falls back to the default server', async () => {
    expect((await settings.read()).serverUrl).toBe(settings.DEFAULT_SERVER_URL);
  });

  it('remembers a server the user chose', async () => {
    await settings.setServerUrl('https://mpc.example.com');

    expect(await settings.serverUrl()).toBe('https://mpc.example.com');
  });

  it('trims a trailing slash, because paths are appended directly', async () => {
    await settings.setServerUrl('https://mpc.example.com/');

    expect(await settings.serverUrl()).toBe('https://mpc.example.com');
  });

  it('rejects something that is not a URL', async () => {
    await expect(settings.setServerUrl('not a url')).rejects.toThrow(/valid URL/);
  });

  it('rejects a non-http scheme', async () => {
    // A typo must not turn into a request to somewhere unexpected.
    await expect(settings.setServerUrl('ftp://mpc.example.com')).rejects.toThrow(/http/);
    await expect(settings.setServerUrl('javascript:alert(1)')).rejects.toThrow(/http/);
  });

  it('leaves the stored value alone when validation fails', async () => {
    await settings.setServerUrl('https://mpc.example.com');

    await expect(settings.setServerUrl('nope')).rejects.toThrow();

    expect(await settings.serverUrl()).toBe('https://mpc.example.com');
  });
});
