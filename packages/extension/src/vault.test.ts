/**
 * 저장소 단위 테스트.
 *
 * 평문 셰어가 저장소에 남지 않는지, 비밀번호가 틀리면 열리지 않는지 확인한다.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as vault from './vault';

// chrome.storage.local을 메모리 맵으로 대체한다.
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

describe('vault', () => {
  beforeEach(() => storage.clear());

  it('시작 상태에는 저장된 키가 없다', async () => {
    expect(await vault.exists()).toBe(false);
  });

  it('올바른 비밀번호로 셰어를 되찾는다', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY);

    expect(await vault.exists()).toBe(true);
    expect(await vault.unlock('correct horse')).toEqual(SHARE);
  });

  it('비밀번호가 틀리면 열리지 않는다', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY);

    expect(await vault.unlock('wrong horse')).toBeUndefined();
  });

  it('평문 셰어를 저장소에 남기지 않는다', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY);

    const serialized = JSON.stringify([...storage.values()]);
    // 셰어 바이트가 어떤 형태로든 그대로 남아 있으면 안 된다.
    expect(serialized).not.toContain(btoa(String.fromCharCode(...SHARE)));
    expect(serialized).not.toContain('1,2,3,4,5,6,7,8');
  });

  it('레코드마다 다른 솔트와 논스를 쓴다', async () => {
    await vault.store('same password', SHARE, PUBLIC_KEY);
    const first = structuredClone(storage.get('vault')) as Record<string, string>;
    await vault.store('same password', SHARE, PUBLIC_KEY);
    const second = storage.get('vault') as Record<string, string>;

    expect(first.saltB64).not.toBe(second.saltB64);
    expect(first.ivB64).not.toBe(second.ivB64);
    expect(first.ciphertextB64).not.toBe(second.ciphertextB64);
  });

  it('잠금 상태에서도 공개키는 읽을 수 있다', async () => {
    await vault.store('correct horse', SHARE, PUBLIC_KEY);

    expect(await vault.publicKeyHex()).toBe(PUBLIC_KEY);
  });
});

describe('vault — 실제 셰어 크기', () => {
  beforeEach(() => storage.clear());

  it('100 KB가 넘는 셰어를 다룬다', async () => {
    // 실제 DKLs23 셰어는 약 114 KB다. 작은 픽스처만 테스트하면
    // base64 변환의 스택 한계를 놓친다 (실제로 한 번 놓쳤다).
    // getRandomValues는 한 번에 65,536바이트까지만 채운다. 내용의 무작위성은
    // 이 테스트의 관심사가 아니므로 결정적인 패턴을 쓴다.
    const large = Uint8Array.from({ length: 120_000 }, (_, i) => (i * 31) % 256);

    await vault.store('correct horse', large, PUBLIC_KEY);

    expect(await vault.unlock('correct horse')).toEqual(large);
  });
});
