import { describe, expect, it } from 'vitest';

import { reshareGrantDigest } from './reshare';

describe('reshare grant digest', () => {
  it('matches the vector the server tests against', async () => {
    const publicKey = `02${'aa'.repeat(32)}`;
    expect(await reshareGrantDigest(publicKey, 'e1'.repeat(32))).toBe(
      '7b145ea52b0d958bfd5ebdd538e7a90ac9a6d4f4876a19c58aef96ca69069531',
    );
  });

  it('binds the wallet key and the reshare id', async () => {
    const id = '11'.repeat(32);
    const a = await reshareGrantDigest(`02${'aa'.repeat(32)}`, id);
    expect(await reshareGrantDigest(`03${'aa'.repeat(32)}`, id)).not.toBe(a);
    expect(await reshareGrantDigest(`02${'aa'.repeat(32)}`, '12'.repeat(32))).not.toBe(a);
  });
});
