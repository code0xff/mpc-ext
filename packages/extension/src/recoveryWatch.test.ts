import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { PendingRecoveryInfo } from './messages';
import { describeRecovery, readTold, remember, unannounced, writeTold } from './recoveryWatch';

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

const item = (id: string): PendingRecoveryInfo => ({
  requestId: id,
  requestedAt: 1_000,
  readyAt: 2_000,
  keyFingerprint: 'deadbeef',
});

describe('recovery watch', () => {
  beforeEach(() => storage.clear());

  it('announces each recovery once', () => {
    const pending = [item('a'), item('b')];
    expect(unannounced(pending, []).map((i) => i.requestId)).toEqual(['a', 'b']);
    expect(unannounced(pending, ['a']).map((i) => i.requestId)).toEqual(['b']);
    expect(unannounced(pending, ['a', 'b'])).toEqual([]);
  });

  it('announces nothing when nothing is waiting', () => {
    expect(unannounced([], ['a'])).toEqual([]);
  });

  it('remembers what it announced, without duplicates', () => {
    expect(remember(['a'], [item('b'), item('a')])).toEqual(['a', 'b']);
  });

  it('keeps only the most recent ids', () => {
    const many = Array.from({ length: 80 }, (_, i) => `id-${i}`);
    const kept = remember([], many.map(item));
    expect(kept).toHaveLength(50);
    expect(kept[kept.length - 1]).toBe('id-79');
    expect(kept).not.toContain('id-0');
  });

  it('stores the list and ignores junk in storage', async () => {
    expect(await readTold()).toEqual([]);
    await writeTold(['a', 'b']);
    expect(await readTold()).toEqual(['a', 'b']);
    storage.set('notifiedRecoveries', ['a', 7, null, 'c']);
    expect(await readTold()).toEqual(['a', 'c']);
    storage.set('notifiedRecoveries', 'not a list');
    expect(await readTold()).toEqual([]);
  });

  it('names the key and the time but no wallet or address', () => {
    const { title, message } = describeRecovery(item('a'));
    expect(title).toMatch(/replace/i);
    expect(message).toContain('deadbeef');
    expect(message).not.toMatch(/0x|wallet id/i);
  });
});
