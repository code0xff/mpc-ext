/**
 * Answering page requests.
 *
 * Runs inside the background worker, which is the only place allowed to decide anything. The
 * origin is whatever the browser reported for the sender — never a value the page supplied
 * (`docs/web-api.md`).
 */
import * as approvals from './approvals';
import { eip191Payload } from './digest';
import * as permissions from './permissions';
import { isSupported, parsePersonalSign, RPC_ERROR } from './rpc';
import { keccak256 } from './wasm';

/** Anything this module throws carries an EIP-1193 code, so dApp error handling works. */
function rpcError(code: number, message: string): Error {
  return Object.assign(new Error(message), { code });
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from({ length: value.length / 2 }, (_, i) =>
    Number.parseInt(value.slice(i * 2, i * 2 + 2), 16),
  );
}

/** What `pageApi` needs from the background worker, passed in to keep this module testable. */
export interface PageContext {
  /** The wallet's address, or undefined when there is no key or it is locked. */
  address(): Promise<string | undefined>;
  /** Signs a 32-byte digest. Whether that goes via the server is the worker's business. */
  sign(digestHex: string): Promise<string>;
  /** Opens the approval window so the user can answer. */
  requestApproval(): Promise<void>;
}

/**
 * Handles one page request.
 *
 * Unsupported methods are refused rather than forwarded, so the surface stays exactly what
 * `rpc.ts` declares.
 */
export async function handlePageRequest(
  origin: string,
  method: string,
  params: unknown[] | undefined,
  context: PageContext,
): Promise<unknown> {
  if (!isSupported(method)) {
    throw rpcError(RPC_ERROR.unsupportedMethod, `${method} is not supported.`);
  }

  switch (method) {
    case 'eth_accounts': {
      // Reading accounts without a connection returns nothing rather than prompting.
      if (!(await permissions.isConnected(origin))) return [];
      const address = await context.address();
      return address ? [address] : [];
    }

    case 'eth_requestAccounts': {
      if (!(await permissions.isConnected(origin))) {
        const id = crypto.randomUUID();
        const decision = approvals.ask(id, origin, { kind: 'connect' });
        await context.requestApproval();
        await decision;
        await permissions.connect(origin);
      }
      const address = await context.address();
      if (!address) throw rpcError(RPC_ERROR.unauthorized, 'The wallet is locked.');
      return [address];
    }

    case 'personal_sign': {
      // Connecting first is required, but it never implies consent to sign.
      if (!(await permissions.isConnected(origin))) {
        throw rpcError(RPC_ERROR.unauthorized, 'Connect to this wallet first.');
      }

      const { messageHex } = parsePersonalSign(params);
      // EIP-191 prefixing is what keeps a transaction from being signed as a "message".
      const digest = keccak256(eip191Payload(fromHex(messageHex)));
      const digestHex = toHex(digest);

      const id = crypto.randomUUID();
      const decision = approvals.ask(id, origin, { kind: 'personalSign', messageHex, digestHex });
      await context.requestApproval();
      await decision;

      return `0x${await context.sign(digestHex)}`;
    }

    default: {
      const exhaustive: never = method;
      throw rpcError(RPC_ERROR.unsupportedMethod, `${String(exhaustive)} is not supported.`);
    }
  }
}
