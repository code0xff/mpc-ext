import { describe, expect, it } from 'vitest';

import { MPC_EXT_RDNS } from './index.js';

describe('sdk', () => {
  it('uses a reverse-DNS identifier', () => {
    expect(MPC_EXT_RDNS).toBe('labs.dsrv.mpc-ext');
  });
});
