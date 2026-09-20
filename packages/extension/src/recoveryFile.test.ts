/**
 * Tests for the recovery file container: no plaintext on disk, wrong password rejected,
 * tampering detected, and legacy plaintext (v2) files refused.
 */
import { describe, expect, it } from 'vitest';

import { encryptRecoveryFile, openRecoveryFile, WrongPasswordError } from './recoveryFile';

// Dummy values only, never real key material.
const SHARE_HEX = 'deadbeef'.repeat(64);
const PUBLIC_KEY = '02'.padEnd(66, 'a');
const WALLET_ID = '11111111-2222-3333-4444-555555555555';

describe('recovery file', () => {
  it('round-trips the share under the right password', async () => {
    const file = await encryptRecoveryFile('correct horse', SHARE_HEX, PUBLIC_KEY, WALLET_ID);
    const opened = await openRecoveryFile(JSON.parse(JSON.stringify(file)), 'correct horse');
    expect(opened).toEqual({ publicKeyHex: PUBLIC_KEY, walletId: WALLET_ID, shareHex: SHARE_HEX });
  });

  it('writes no plaintext share', async () => {
    const file = await encryptRecoveryFile('correct horse', SHARE_HEX, PUBLIC_KEY, WALLET_ID);
    expect(JSON.stringify(file)).not.toContain(SHARE_HEX.slice(0, 32));
  });

  it('rejects a wrong or missing password', async () => {
    const file = await encryptRecoveryFile('correct horse', SHARE_HEX, PUBLIC_KEY, WALLET_ID);
    await expect(openRecoveryFile(file, 'battery staple')).rejects.toBeInstanceOf(
      WrongPasswordError,
    );
    await expect(openRecoveryFile(file)).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('detects swapped public fields', async () => {
    const file = await encryptRecoveryFile('correct horse', SHARE_HEX, PUBLIC_KEY, WALLET_ID);
    const forged = { ...file, walletId: '99999999-2222-3333-4444-555555555555' };
    await expect(openRecoveryFile(forged, 'correct horse')).rejects.toBeInstanceOf(
      WrongPasswordError,
    );
  });

  it('uses a fresh salt and nonce each time', async () => {
    const a = await encryptRecoveryFile('correct horse', SHARE_HEX, PUBLIC_KEY, WALLET_ID);
    const b = await encryptRecoveryFile('correct horse', SHARE_HEX, PUBLIC_KEY, WALLET_ID);
    expect(a.saltB64).not.toBe(b.saltB64);
    expect(a.ivB64).not.toBe(b.ivB64);
  });

  it('refuses a short password', async () => {
    await expect(encryptRecoveryFile('short', SHARE_HEX, PUBLIC_KEY, WALLET_ID)).rejects.toThrow();
  });

  it('rejects legacy plaintext v2 files', async () => {
    const legacy = {
      formatVersion: 2,
      kind: 'mpc-ext-recovery',
      publicKey: PUBLIC_KEY,
      share: SHARE_HEX,
    };
    await expect(openRecoveryFile(legacy)).rejects.toThrow(/Unsupported/);
  });

  it('rejects foreign or unknown-version files', async () => {
    await expect(openRecoveryFile({ kind: 'other' })).rejects.toThrow(/does not look/);
    await expect(
      openRecoveryFile({ kind: 'mpc-ext-recovery', publicKey: PUBLIC_KEY, formatVersion: 9 }),
    ).rejects.toThrow(/Unsupported/);
  });
});
