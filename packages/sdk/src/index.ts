/**
 * A thin wrapper letting web pages discover the mpc-ext extension.
 *
 * The SDK never touches secrets: the extension returns signatures only, and every connection and
 * signing request goes through user approval (`docs/web-api.md`).
 *
 * It follows the EIP-6963 and EIP-1193 standards rather than inventing an API.
 */

/** Wallet identity as defined by EIP-6963. */
export interface ProviderInfo {
  /** UUID of this wallet instance. */
  uuid: string;
  /** Human-readable name. */
  name: string;
  /** Icon as a data URI. */
  icon: string;
  /** Reverse-DNS identifier. */
  rdns: string;
}

/** The minimal slice of an EIP-1193 provider this SDK uses. */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

/** What an EIP-6963 announce event carries. */
export interface ProviderDetail {
  info: ProviderInfo;
  provider: Eip1193Provider;
}

/** This extension's EIP-6963 identifier. */
export const MPC_EXT_RDNS = 'labs.dsrv.mpc-ext';

/** EIP-1193 error codes a caller is likely to branch on. */
export const USER_REJECTED = 4001;

/**
 * Collects the wallets that announce themselves over EIP-6963.
 *
 * @param timeoutMs how long to wait for announcements.
 * @returns the providers found, or an empty array if no extension is present.
 */
export function discoverProviders(timeoutMs = 300): Promise<ProviderDetail[]> {
  const found = new Map<string, ProviderDetail>();

  const onAnnounce = (event: Event): void => {
    const detail = (event as CustomEvent<ProviderDetail>).detail;
    if (detail?.info?.uuid) {
      found.set(detail.info.uuid, detail);
    }
  };

  window.addEventListener('eip6963:announceProvider', onAnnounce);
  window.dispatchEvent(new Event('eip6963:requestProvider'));

  return new Promise((resolve) => {
    setTimeout(() => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce);
      resolve([...found.values()]);
    }, timeoutMs);
  });
}

/**
 * Picks out the mpc-ext extension.
 *
 * @returns `undefined` when the extension is not installed.
 */
export async function findMpcExt(timeoutMs?: number): Promise<ProviderDetail | undefined> {
  const providers = await discoverProviders(timeoutMs);
  return providers.find((p) => p.info.rdns === MPC_EXT_RDNS);
}

/**
 * Asks the user to connect, returning the accounts they shared.
 *
 * Throws with `code === USER_REJECTED` when the user declines, which is the normal outcome to
 * handle rather than an exceptional one.
 */
export async function requestAccounts(provider: Eip1193Provider): Promise<string[]> {
  return (await provider.request({ method: 'eth_requestAccounts' })) as string[];
}

/** The accounts already shared with this page, without prompting. */
export async function accounts(provider: Eip1193Provider): Promise<string[]> {
  return (await provider.request({ method: 'eth_accounts' })) as string[];
}

/**
 * Signs a UTF-8 message with `personal_sign` (EIP-191).
 *
 * The wallet prefixes the message before hashing, so this cannot be used to get a transaction
 * signed.
 */
export async function personalSign(
  provider: Eip1193Provider,
  message: string,
  address: string,
): Promise<string> {
  const bytes = new TextEncoder().encode(message);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return (await provider.request({
    method: 'personal_sign',
    params: [`0x${hex}`, address],
  })) as string;
}
