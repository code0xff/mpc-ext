/**
 * Unit tests for the vault.
 *
 * They check that no plaintext share survives in storage and that a wrong password does not
 * open it.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as vault from './vault';

// Stand in for chrome.storage.local with an in-memory map.
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

const SHARE = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const PUBLIC_KEY = '02'.padEnd(66, 'a');
const WALLET_ID = '11111111-2222-3333-4444-555555555555';
const EXTENSION_PARTY = 0;

describe('vault', () => {
  beforeEach(() => storage.clear());

  it('starts with no stored key', async () => {
    expect(await vault.exists()).toBe(false);
  });

  it('returns the share for the right password', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);

    expect(await vault.exists()).toBe(true);
    expect(await vault.unlock('correct horse')).toEqual(SHARE);
  });

  it('does not open with the wrong password', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);

    expect(await vault.unlock('wrong horse')).toBeUndefined();
  });

  it('leaves no plaintext share in storage', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);

    const serialized = JSON.stringify([...storage.values()]);
    // The share bytes must not survive in any recognisable form.
    expect(serialized).not.toContain(btoa(String.fromCharCode(...SHARE)));
    expect(serialized).not.toContain('1,2,3,4,5,6,7,8');
  });

  it('uses a fresh salt and nonce per record', async () => {
    await vault.store('same password', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);
    const first = structuredClone(storage.get('vault')) as Record<string, string>;
    await vault.store('same password', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);
    const second = storage.get('vault') as Record<string, string>;

    expect(first.saltB64).not.toBe(second.saltB64);
    expect(first.ivB64).not.toBe(second.ivB64);
    expect(first.ciphertextB64).not.toBe(second.ciphertextB64);
  });

  it('exposes the wallet id even while locked', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);

    expect(await vault.walletId()).toBe(WALLET_ID);
  });

  it('remembers which party the stored share belongs to', async () => {
    // A wallet restored from a recovery file holds party 1, and the UI has to know
    // (docs/recovery.md).
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, 1);

    expect(await vault.party()).toBe(1);
  });

  it('refuses a record written by an older format', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);
    const record = storage.get('vault') as Record<string, unknown>;
    storage.set('vault', { ...record, formatVersion: 2 });

    await expect(vault.unlock('correct horse')).rejects.toThrow(/storage format/);
  });

  it('exposes the public key even while locked', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);

    expect(await vault.publicKeyHex()).toBe(PUBLIC_KEY);
  });
});

describe('vault at realistic share sizes', () => {
  beforeEach(() => storage.clear());

  it('handles shares larger than 100 KB', async () => {
    // A real DKLs23 share is around 114 KB. Testing only small fixtures misses the stack limit
    // in the base64 conversion — which is exactly how we missed it once.
    // getRandomValues fills at most 65,536 bytes per call, and randomness is not what this test
    // is about, so use a deterministic pattern.
    const large = Uint8Array.from({ length: 120_000 }, (_, i) => (i * 31) % 256);

    await vault.store('correct horse', large, PUBLIC_KEY, WALLET_ID, EXTENSION_PARTY);

    expect(await vault.unlock('correct horse')).toEqual(large);
  });
});
