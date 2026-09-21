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

/** Whether the wallet has a passkey. Only the wallet's own device key may ask. */
export async function passkeyRegistered(baseUrl: string, walletId: string): Promise<boolean> {
  const body = await post<{ registered: boolean }>(
    baseUrl,
    '/v1/passkeys/registered',
    { wallet_id: walletId },
    true,
  );
  return body.registered;
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

/**
 * Sends a JSON request. `authenticate` is `true` to sign with this install's device key, a key
 * pair to sign with that one instead (a recovery is signed by the key waiting to take over), or
 * `false` for no proof.
 *
 * The proof covers the exact text sent, which is why `serialized` is built once and reused.
 */
async function post<T>(
  baseUrl: string,
  path: string,
  body: unknown,
  authenticate: boolean | CryptoKeyPair = false,
): Promise<T> {
  const serialized = JSON.stringify(body);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (authenticate) {
    const deviceKey = authenticate === true ? await loadDeviceKey() : authenticate;
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

export type ReshareAdvance =
  { state: 'inProgress'; envelopes: WireEnvelope[] } | { state: 'staged'; public_key: string };

/**
 * Opens a reshare and collects the server's round 1 envelopes. Needs the device key and a
 * `recovery` passkey grant bound to this reshare (`docs/adr/0007-distributed-reshare.md`).
 */
export async function startReshare(
  baseUrl: string,
  walletId: string,
  reshareIdHex: string,
): Promise<WireEnvelope[]> {
  const body = await post<{ envelopes: WireEnvelope[] }>(
    baseUrl,
    '/v1/reshare/session',
    { wallet_id: walletId, reshare_id: reshareIdHex },
    true,
  );
  return body.envelopes;
}

/** Sends reshare envelopes and receives the next round. The last round stages the new share. */
export async function advanceReshare(
  baseUrl: string,
  walletId: string,
  reshareIdHex: string,
  envelopes: WireEnvelope[],
): Promise<ReshareAdvance> {
  return post<ReshareAdvance>(
    baseUrl,
    '/v1/reshare/round',
    { wallet_id: walletId, reshare_id: reshareIdHex, envelopes },
    true,
  );
}

/** Makes the staged share live on the server and deletes the old one. */
export async function commitReshare(
  baseUrl: string,
  walletId: string,
  reshareIdHex: string,
): Promise<void> {
  await post<void>(
    baseUrl,
    '/v1/reshare/commit',
    { wallet_id: walletId, reshare_id: reshareIdHex },
    true,
  );
}

/** Drops a reshare. The server keeps its current share. */
export async function abortReshare(
  baseUrl: string,
  walletId: string,
  reshareIdHex: string,
): Promise<void> {
  await post<void>(
    baseUrl,
    '/v1/reshare/abort',
    { wallet_id: walletId, reshare_id: reshareIdHex },
    true,
  );
}

/** What the server says about a recovery request. `readyAt` is unix seconds. */
export type RecoveryStatus =
  | { state: 'awaitingAssertion' }
  | { state: 'cooling'; ready_at: number }
  | { state: 'ready' }
  | { state: 'completed' }
  | { state: 'cancelled' }
  | { state: 'expired' };

export interface RecoveryRequested {
  request_id: string;
  ceremony_id: string;
  handoff_token: string;
}

export interface PendingRecovery {
  request_id: string;
  requested_at: number;
  ready_at: number;
  key_fingerprint: string;
}

/**
 * Asks to recover this wallet onto a new device key. No device proof: this install has none the
 * server accepts yet. It only asks for a passkey assertion and changes nothing by itself
 * (`docs/adr/0008-recovery-start-and-device-key-replacement.md`).
 */
export async function requestRecovery(
  baseUrl: string,
  walletId: string,
  devicePublicKeyHex: string,
): Promise<RecoveryRequested> {
  return post<RecoveryRequested>(baseUrl, '/v1/recovery/request', {
    wallet_id: walletId,
    device_public_key: devicePublicKeyHex,
  });
}

/** Where the request stands. Signed with the new key, and it starts the wait once approved. */
export async function recoveryStatus(
  baseUrl: string,
  walletId: string,
  requestId: string,
  newKey: CryptoKeyPair,
): Promise<RecoveryStatus> {
  return post<RecoveryStatus>(
    baseUrl,
    '/v1/recovery/status',
    { wallet_id: walletId, request_id: requestId },
    newKey,
  );
}

/** Replaces the wallet's device key with the new one, after the wait. Signed with the new key. */
export async function completeRecovery(
  baseUrl: string,
  walletId: string,
  requestId: string,
  newKey: CryptoKeyPair,
): Promise<void> {
  await post<void>(
    baseUrl,
    '/v1/recovery/complete',
    { wallet_id: walletId, request_id: requestId },
    newKey,
  );
}

/** Recoveries waiting on this wallet. Signed with the install's current device key. */
export async function pendingRecoveries(
  baseUrl: string,
  walletId: string,
): Promise<PendingRecovery[]> {
  const body = await post<{ pending: PendingRecovery[] }>(
    baseUrl,
    '/v1/recovery/pending',
    { wallet_id: walletId },
    true,
  );
  return body.pending;
}

/** Cancels a recovery. `key` is the pending key when withdrawing; the current key otherwise. */
export async function cancelRecovery(
  baseUrl: string,
  walletId: string,
  requestId: string,
  key: CryptoKeyPair | true = true,
): Promise<void> {
  await post<void>(
    baseUrl,
    '/v1/recovery/cancel',
    { wallet_id: walletId, request_id: requestId },
    key,
  );
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
