/**
 * The page-facing request contract.
 *
 * A page asks; the content script relays; the background worker decides. Pages are fully
 * untrusted, so everything here is validated before it reaches the worker
 * (`docs/web-api.md`).
 */

/** This wallet's EIP-6963 identifier. */
export const RDNS = 'labs.dsrv.mpc-ext';

/** The message type used between the injected provider and the content script. */
export const PAGE_MESSAGE = 'mpc-ext:page-request';

/** The message type the content script replies with. */
export const PAGE_RESPONSE = 'mpc-ext:page-response';

/** The RPC methods we answer. Anything else is refused. */
export const SUPPORTED_METHODS = ['eth_requestAccounts', 'eth_accounts', 'personal_sign'] as const;

export type SupportedMethod = (typeof SUPPORTED_METHODS)[number];

export interface PageRequest {
  /** Correlates a reply with its request. */
  id: string;
  method: string;
  params?: unknown[];
}

/**
 * EIP-1193 error codes, plus the ones we need.
 *
 * Using the standard codes means existing dApp error handling works unchanged.
 */
export const RPC_ERROR = {
  userRejected: 4001,
  unauthorized: 4100,
  unsupportedMethod: 4200,
  disconnected: 4900,
  internal: -32603,
  invalidParams: -32602,
} as const;

export interface RpcFailure {
  code: number;
  message: string;
}

/** Checks that a method is one we answer. */
export function isSupported(method: string): method is SupportedMethod {
  return (SUPPORTED_METHODS as readonly string[]).includes(method);
}

/**
 * Validates `personal_sign` parameters.
 *
 * EIP-191 order is `[data, address]`. We only need the data, and we require hex so a page cannot
 * smuggle something unexpected through as a string.
 */
export function parsePersonalSign(params: unknown[] | undefined): { messageHex: string } {
  const [data] = params ?? [];
  if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data)) {
    throw Object.assign(new Error('personal_sign expects hex-encoded data'), {
      code: RPC_ERROR.invalidParams,
    });
  }
  return { messageHex: data.slice(2) };
}
