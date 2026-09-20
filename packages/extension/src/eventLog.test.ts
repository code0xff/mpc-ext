import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as eventLog from './eventLog';

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

describe('event log', () => {
  beforeEach(() => storage.clear());

  it('records the event type and time and nothing else', async () => {
    await eventLog.record('privateKeyExported');
    const entries = await eventLog.read();
    expect(entries).toHaveLength(1);
    expect(Object.keys(entries[0] ?? {}).sort()).toEqual(['at', 'type']);
  });

  it('keeps only the most recent entries', async () => {
    for (let i = 0; i < 120; i++) await eventLog.record('privateKeyExported');
    expect(await eventLog.read()).toHaveLength(100);
  });
});
