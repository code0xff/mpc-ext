/**
 * Drives the protocol rounds between the extension's local parties and the server.
 *
 * The extension holds share A and, during key creation only, share B as well. The server holds
 * share C. This module carries envelopes between them; it makes no policy decisions
 * (`docs/architecture.md`).
 */
import type { WireEnvelope } from './serverClient';
import * as server from './serverClient';
import { DkgSession, SignSession } from './wasm';

/** How many rounds each protocol takes. A guard against looping forever. */
const MAX_ROUNDS = 6;

/** The party each share belongs to. */
export const PARTY = { extension: 0, recovery: 1, server: 2 } as const;

/**
 * wasm emits and accepts envelopes in exactly the shape the server speaks, base64 payload
 * included, so this module never has to touch the bytes.
 */
function parse(json: string): WireEnvelope[] {
  return JSON.parse(json) as WireEnvelope[];
}

/** Keeps the envelopes addressed to `me`, excluding the ones `me` sent. */
function inboxFor(me: number, envelopes: WireEnvelope[]): WireEnvelope[] {
  return envelopes.filter((e) => e.from !== me && (e.to === undefined || e.to === me));
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface DkgOutcome {
  /** Share A, which the extension stores. */
  extensionShare: Uint8Array;
  /** Share B, which the user keeps as a recovery file. The extension never stores it. */
  recoveryShare: Uint8Array;
  publicKeyHex: string;
}

/**
 * Runs a three-party DKG: parties 0 and 1 locally, party 2 on the server.
 *
 * Nothing is persisted here. The caller decides what to keep once the recovery export is
 * confirmed (`docs/adr/0005-share-placement.md`).
 */
export async function runDkg(
  baseUrl: string,
  walletId: string,
  sessionId: Uint8Array,
): Promise<DkgOutcome> {
  const sessionHex = hex(sessionId);
  const extension = new DkgSession(PARTY.extension, sessionId);
  const recovery = new DkgSession(PARTY.recovery, sessionId);

  let inFlight: WireEnvelope[] = [
    ...parse(extension.outgoing),
    ...parse(recovery.outgoing),
    ...(await server.startDkg(baseUrl, walletId, sessionHex)),
  ];

  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const next: WireEnvelope[] = [];

    for (const [party, session] of [
      [PARTY.extension, extension],
      [PARTY.recovery, recovery],
    ] as const) {
      if (session.finished) continue;
      session.advance(JSON.stringify(inboxFor(party, inFlight)));
      next.push(...parse(session.outgoing));
    }

    const forServer = inboxFor(PARTY.server, inFlight);
    const result = await server.advanceDkg(baseUrl, walletId, sessionHex, forServer);

    if (result.state === 'completed') {
      if (!extension.finished || !recovery.finished) {
        throw new Error('The server finished the DKG before the local parties did.');
      }
      const publicKeyHex = hex(extension.public_key);
      if (publicKeyHex !== result.public_key) {
        // Both sides must agree, or the wallet would be unusable.
        throw new Error('The server and the extension disagree on the public key.');
      }
      return {
        extensionShare: extension.share,
        recoveryShare: recovery.share,
        publicKeyHex,
      };
    }

    next.push(...result.envelopes);
    inFlight = next;
  }

  throw new Error('Key generation did not finish in the expected number of rounds.');
}

/**
 * Signs with the extension share and the server share — the everyday path.
 */
export async function signWithServer(
  baseUrl: string,
  walletId: string,
  share: Uint8Array,
  signId: Uint8Array,
  digest: Uint8Array,
): Promise<Uint8Array> {
  const signHex = hex(signId);
  const session = new SignSession(share, PARTY.extension, PARTY.server, signId, digest);

  let inFlight: WireEnvelope[] = [
    ...parse(session.outgoing),
    ...(await server.startSign(baseUrl, walletId, signHex, hex(digest), PARTY.extension)),
  ];

  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const next: WireEnvelope[] = [];

    if (!session.finished) {
      session.advance(JSON.stringify(inboxFor(PARTY.extension, inFlight)));
      next.push(...parse(session.outgoing));
    }

    const forServer = inboxFor(PARTY.server, inFlight);
    const result = await server.advanceSign(baseUrl, walletId, signHex, forServer);

    if (result.state === 'completed') {
      if (!session.finished) {
        throw new Error('The server produced a signature before the extension did.');
      }
      return session.signature;
    }

    next.push(...result.envelopes);
    inFlight = next;
  }

  throw new Error('Signing did not finish in the expected number of rounds.');
}

/**
 * Signs with the extension share and the recovery file — the path used when the server is
 * unreachable (`docs/recovery.md`, scenario 0).
 *
 * This runs entirely offline. The recovery share is used and then dropped; it is never stored.
 */
export function signWithRecoveryFile(
  share: Uint8Array,
  recoveryShare: Uint8Array,
  signId: Uint8Array,
  digest: Uint8Array,
): Uint8Array {
  const a = new SignSession(share, PARTY.extension, PARTY.recovery, signId, digest);
  const b = new SignSession(recoveryShare, PARTY.recovery, PARTY.extension, signId, digest);

  let inFlight: WireEnvelope[] = [...parse(a.outgoing), ...parse(b.outgoing)];

  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const next: WireEnvelope[] = [];
    for (const [party, session] of [
      [PARTY.extension, a],
      [PARTY.recovery, b],
    ] as const) {
      if (session.finished) continue;
      session.advance(JSON.stringify(inboxFor(party, inFlight)));
      next.push(...parse(session.outgoing));
    }
    if (a.finished) return a.signature;
    inFlight = next;
  }

  throw new Error('Offline signing did not finish in the expected number of rounds.');
}
