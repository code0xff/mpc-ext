/**
 * Client for exchanging round messages with the server (party C).
 *
 * The server is a second factor, not a vault. This client only carries envelopes; it makes no
 * protocol decisions (`docs/adr/0005-share-placement.md`).
 *
 * Device-key authentication is enforced on the server. Passkey ceremonies are launched on the
 * server origin through a one-use handoff before the signing session is opened.
 */

import { loadDeviceKey, signRequest } from './deviceKey';

/** An envelope exchanged with the server. The body is base64. */
export interface WireEnvelope {
  round: number;
  from: number;
  to?: number;
  payload: string;
}

export type AdvanceResult =
  { state: 'inProgress'; envelopes: WireEnvelope[] } | { state: 'completed'; public_key: string };

export interface PasskeyHandoff {
  ceremony_id: string;
  handoff_token: string;
}

export type PasskeyPurpose = 'register' | 'sign' | 'recovery';

export interface PasskeyCeremonyStatus {
  ceremony_id: string;
  status: 'waitingForBrowser' | 'inProgress' | 'completed';
}

/** Registers the public half of the installation device key with the server. */
export async function registerDeviceKey(
  baseUrl: string,
  walletId: string,
  publicKeyHex: string,
): Promise<void> {
  await post<void>(baseUrl, '/v1/device-key', {
    wallet_id: walletId,
    public_key: publicKeyHex,
  });
}

/** Creates a server-origin passkey handoff. The token is kept in extension memory only. */
export async function createPasskeyHandoff(
  baseUrl: string,
  walletId: string,
  purpose: PasskeyPurpose,
  operationId?: string,
  digest?: string,
): Promise<PasskeyHandoff> {
  return post<PasskeyHandoff>(
    baseUrl,
    '/v1/passkeys/handoff',
    { wallet_id: walletId, purpose, operation_id: operationId, digest },
    true,
  );
}

/** Polls the device-authenticated result of the browser ceremony. */
export async function passkeyCeremonyStatus(
  baseUrl: string,
  walletId: string,
  ceremonyId: string,
): Promise<PasskeyCeremonyStatus> {
  return post<PasskeyCeremonyStatus>(
    baseUrl,
    '/v1/passkeys/ceremony/status',
    { wallet_id: walletId, ceremony_id: ceremonyId },
    true,
  );
}

/** The default server address. Self-hosting must be able to override it in settings. */
export const DEFAULT_SERVER = 'http://127.0.0.1:8080';

export class ServerUnreachable extends Error {
  constructor(cause: unknown) {
    super('Cannot reach the server. You can sign with your recovery file instead.');
    this.name = 'ServerUnreachable';
    this.cause = cause;
  }
}

async function post<T>(
  baseUrl: string,
  path: string,
  body: unknown,
  authenticate = false,
): Promise<T> {
  const serialized = JSON.stringify(body);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (authenticate) {
    const deviceKey = await loadDeviceKey();
    if (!deviceKey) throw new Error('The device is not registered with the server.');
    const proof = await signRequest(deviceKey.privateKey, 'POST', path, serialized);
    headers['x-device-timestamp'] = String(proof.timestamp);
    headers['x-device-nonce'] = proof.nonce;
    headers['x-device-signature'] = proof.signatureB64;
  }
  let response: Response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers,
      body: serialized,
    });
  } catch (cause) {
    // A server outage is a designed-for path, not an exceptional one (docs/recovery.md,
    // scenario 0).
    throw new ServerUnreachable(cause);
  }

  if (!response.ok) {
    const detail = (await response.json().catch(() => ({}))) as { error?: string };
    throw new Error(detail.error ?? `server error (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Opens a DKG session and collects the server's round 1 envelopes. */
export async function startDkg(
  baseUrl: string,
  walletId: string,
  sessionIdHex: string,
): Promise<WireEnvelope[]> {
  const body = await post<{ envelopes: WireEnvelope[] }>(baseUrl, '/v1/dkg/session', {
    wallet_id: walletId,
    session_id: sessionIdHex,
  });
  return body.envelopes;
}

/** Sends envelopes and receives the next round. */
export async function advanceDkg(
  baseUrl: string,
  walletId: string,
  sessionIdHex: string,
  envelopes: WireEnvelope[],
): Promise<AdvanceResult> {
  return post<AdvanceResult>(baseUrl, '/v1/dkg/round', {
    wallet_id: walletId,
    session_id: sessionIdHex,
    envelopes,
  });
}

export type SignResult =
  { state: 'inProgress'; envelopes: WireEnvelope[] } | { state: 'completed'; signature: string };

/** Opens a signing session and collects the server's round 1 envelopes. */
export async function startSign(
  baseUrl: string,
  walletId: string,
  signIdHex: string,
  digestHex: string,
  counterparty: number,
): Promise<WireEnvelope[]> {
  const body = await post<{ envelopes: WireEnvelope[] }>(
    baseUrl,
    '/v1/sign/session',
    {
      wallet_id: walletId,
      sign_id: signIdHex,
      digest: digestHex,
      counterparty,
    },
    true,
  );
  return body.envelopes;
}

/** Sends signing envelopes and receives the next round. */
export async function advanceSign(
  baseUrl: string,
  walletId: string,
  signIdHex: string,
  envelopes: WireEnvelope[],
): Promise<SignResult> {
  return post<SignResult>(
    baseUrl,
    '/v1/sign/round',
    {
      wallet_id: walletId,
      sign_id: signIdHex,
      envelopes,
    },
    true,
  );
}

/** Checks whether the server is reachable. */
export async function health(baseUrl: string): Promise<boolean> {
  try {
    const response = await fetch(`${baseUrl}/v1/health`);
    return response.ok;
  } catch {
    return false;
  }
}
