import { describe, expect, it } from 'vitest';
import { canonicalRequest, createDeviceKey, exportDevicePublicKey, signRequest } from './deviceKey';

describe('device request authentication', () => {
  it('signs a stable request representation and exposes only the public key', async () => {
    const pair = await createDeviceKey();
    const publicKey = await exportDevicePublicKey(pair.publicKey);
    const request = await signRequest(pair.privateKey, 'POST', '/v1/sign/session', '{}', 123, 'n');

    expect(publicKey).toMatch(/^[0-9a-f]{130}$/);
    expect(request).toEqual({
      timestamp: 123,
      nonce: 'n',
      signatureB64: expect.any(String),
    });

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.publicKey,
      Uint8Array.from(atob(request.signatureB64), (value) => value.charCodeAt(0)),
      canonicalRequest('POST', '/v1/sign/session', '{}', request.timestamp, request.nonce),
    );
    expect(valid).toBe(true);
  });
});
