/**
 * Client for exchanging round messages with the server (party C).
 *
 * The server is a second factor, not a vault. This client only carries envelopes; it makes no
 * protocol decisions (`docs/adr/0005-share-placement.md`).
 *
 * Authentication is not designed yet, so this must not be used in production until it is.
 */

/** An envelope exchanged with the server. The body is base64. */
export interface WireEnvelope {
  round: number;
  from: number;
  to?: number;
  payload: string;
}

export type AdvanceResult =
  { state: 'inProgress'; envelopes: WireEnvelope[] } | { state: 'completed'; public_key: string };

/** The default server address. Self-hosting must be able to override it in settings. */
export const DEFAULT_SERVER = 'http://127.0.0.1:8080';

export class ServerUnreachable extends Error {
  constructor(cause: unknown) {
    super('Cannot reach the server. You can sign with your recovery file instead.');
    this.name = 'ServerUnreachable';
    this.cause = cause;
  }
}

async function post<T>(baseUrl: string, path: string, body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
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

/** Checks whether the server is reachable. */
export async function health(baseUrl: string): Promise<boolean> {
  try {
    const response = await fetch(`${baseUrl}/v1/health`);
    return response.ok;
  } catch {
    return false;
  }
}
