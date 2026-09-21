import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as recoveryState from './recoveryState';

const storage = new Map<string, unknown>();
vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: async (key: string) => (storage.has(key) ? { [key]: storage.get(key) } : {}),
      set: async (items: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(items)) storage.set(k, v);
      },
      remove: async (key: string) => {
        storage.delete(key);
      },
    },
  },
});

const SAMPLE = { walletId: 'w', publicKeyHex: '02'.padEnd(66, 'a'), requestId: 'ab'.repeat(32) };

describe('recovery state', () => {
  beforeEach(() => storage.clear());

  it('starts empty', async () => {
    expect(await recoveryState.read()).toBeUndefined();
  });

  it('round-trips and clears', async () => {
    await recoveryState.write(SAMPLE);
    expect(await recoveryState.read()).toEqual(SAMPLE);
    await recoveryState.clear();
    expect(await recoveryState.read()).toBeUndefined();
  });

  it('ignores a record that is missing a field', async () => {
    storage.set('recovery', { walletId: 'w' });
    expect(await recoveryState.read()).toBeUndefined();
  });

  it('keeps no secret: only ids and the public key', async () => {
    await recoveryState.write(SAMPLE);
    expect(Object.keys(storage.get('recovery') as object).sort()).toEqual([
      'publicKeyHex',
      'requestId',
      'walletId',
    ]);
  });
});
