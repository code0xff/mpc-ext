/**
 * Tests for the page-facing surface.
 *
 * This is the boundary a malicious page attacks, so the tests are about what it must *not* be
 * able to do: read the address without consent, sign without consent, or reach a method we never
 * declared (`docs/web-api.md`).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as approvals from './approvals';
import { handlePageRequest, type PageContext } from './pageApi';
import * as permissions from './permissions';
import { RPC_ERROR } from './rpc';

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

// keccak256 comes from wasm, which is not loaded in unit tests. Only personal_sign needs it, and
// these tests never get as far as hashing without an approval first.
vi.mock('./wasm', () => ({
  keccak256: (data: Uint8Array) => new Uint8Array(32).fill(data.length % 256),
}));

const ORIGIN = 'https://dapp.example';
const ADDRESS = '0xAbC0000000000000000000000000000000000001';

/**
 * Waits for a request to reach the approval queue.
 *
 * `handlePageRequest` checks permissions before parking anything, so the queue is not populated
 * synchronously.
 */
async function waitForApproval() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const [waiting] = approvals.pending();
    if (waiting) return waiting;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error('no approval was queued');
}

function context(overrides: Partial<PageContext> = {}): PageContext {
  return {
    address: async () => ADDRESS,
    sign: async () => 'ff'.repeat(65),
    requestApproval: async () => undefined,
    ...overrides,
  };
}

describe('pageApi', () => {
  beforeEach(() => {
    storage.clear();
  });

  it('refuses a method we never declared', async () => {
    await expect(
      handlePageRequest(ORIGIN, 'eth_sendTransaction', [], context()),
    ).rejects.toMatchObject({ code: RPC_ERROR.unsupportedMethod });
  });

  it('returns no accounts to an unconnected origin', async () => {
    // Reading accounts must not prompt, and must not leak the address.
    await expect(handlePageRequest(ORIGIN, 'eth_accounts', [], context())).resolves.toEqual([]);
  });

  it('returns the address once the origin is connected', async () => {
    await permissions.connect(ORIGIN);

    await expect(handlePageRequest(ORIGIN, 'eth_accounts', [], context())).resolves.toEqual([
      ADDRESS,
    ]);
  });

  it('asks before connecting, and reports a refusal with the standard code', async () => {
    const call = handlePageRequest(ORIGIN, 'eth_requestAccounts', [], context());

    // The request is parked until the user answers.
    const waiting = await waitForApproval();
    expect(waiting.origin).toBe(ORIGIN);
    expect(waiting.request.kind).toBe('connect');

    approvals.decide(waiting.id, false);

    await expect(call).rejects.toMatchObject({ code: RPC_ERROR.userRejected });
    expect(await permissions.isConnected(ORIGIN)).toBe(false);
  });

  it('connects after the user approves', async () => {
    const call = handlePageRequest(ORIGIN, 'eth_requestAccounts', [], context());
    approvals.decide((await waitForApproval()).id, true);

    await expect(call).resolves.toEqual([ADDRESS]);
    expect(await permissions.isConnected(ORIGIN)).toBe(true);
  });

  it('refuses to sign for an origin that never connected', async () => {
    await expect(
      handlePageRequest(ORIGIN, 'personal_sign', ['0xdeadbeef'], context()),
    ).rejects.toMatchObject({ code: RPC_ERROR.unauthorized });
  });

  it('never signs without an approval, even for a connected origin', async () => {
    await permissions.connect(ORIGIN);
    const sign = vi.fn(async () => 'ff'.repeat(65));

    const call = handlePageRequest(ORIGIN, 'personal_sign', ['0xdeadbeef'], context({ sign }));
    approvals.decide((await waitForApproval()).id, false);

    await expect(call).rejects.toMatchObject({ code: RPC_ERROR.userRejected });
    expect(sign).not.toHaveBeenCalled();
  });

  it('signs once approved, and returns a 0x-prefixed signature', async () => {
    await permissions.connect(ORIGIN);

    const call = handlePageRequest(ORIGIN, 'personal_sign', ['0xdeadbeef'], context());
    const waiting = await waitForApproval();
    expect(waiting.request.kind).toBe('personalSign');
    approvals.decide(waiting.id, true);

    await expect(call).resolves.toBe(`0x${'ff'.repeat(65)}`);
  });

  it('rejects personal_sign parameters that are not hex', async () => {
    await permissions.connect(ORIGIN);

    for (const params of [[], ['not hex'], [42], [{}]]) {
      await expect(
        handlePageRequest(ORIGIN, 'personal_sign', params, context()),
      ).rejects.toMatchObject({ code: RPC_ERROR.invalidParams });
    }
  });

  it('reports a locked wallet rather than returning an empty account', async () => {
    const call = handlePageRequest(
      ORIGIN,
      'eth_requestAccounts',
      [],
      context({ address: async () => undefined }),
    );
    approvals.decide((await waitForApproval()).id, true);

    await expect(call).rejects.toMatchObject({ code: RPC_ERROR.unauthorized });
  });

  it('treats a dismissed approval window as a refusal', async () => {
    await permissions.connect(ORIGIN);
    const call = handlePageRequest(ORIGIN, 'personal_sign', ['0xdeadbeef'], context());
    await waitForApproval();

    // This is what closing the window and locking the wallet both do.
    approvals.rejectAll();

    await expect(call).rejects.toMatchObject({ code: RPC_ERROR.userRejected });
  });
});
