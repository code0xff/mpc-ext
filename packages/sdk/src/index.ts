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
