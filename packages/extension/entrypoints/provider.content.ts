/**
 * The provider that lives in the page's world.
 *
 * It follows EIP-1193 and announces itself over EIP-6963 rather than inventing an API, so
 * existing dApps work without changes (`docs/web-api.md`).
 *
 * This runs in the page's world and is therefore **not trusted**. It carries requests and nothing
 * more; every decision is made by the background worker. It reaches the worker through the
 * isolated relay content script, because page-world code has no extension APIs.
 */
import { PAGE_MESSAGE, PAGE_RESPONSE, RDNS, RPC_ERROR } from '../src/rpc';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_start',
  world: 'MAIN',

  main() {
    const pending = new Map<
      string,
      { resolve: (value: unknown) => void; reject: (reason: unknown) => void }
    >();

    window.addEventListener('message', (event: MessageEvent) => {
      // Only same-window messages, so another frame cannot answer for us.
      if (event.source !== window) return;
      const data = event.data as {
        type?: string;
        id?: string;
        result?: unknown;
        error?: unknown;
      };
      if (data?.type !== PAGE_RESPONSE || typeof data.id !== 'string') return;

      const call = pending.get(data.id);
      if (!call) return;
      pending.delete(data.id);

      if (data.error) call.reject(data.error);
      else call.resolve(data.result);
    });

    /** A minimal EIP-1193 provider. */
    class MpcExtProvider {
      /** Lets libraries that sniff for a provider recognise this one. */
      readonly isMpcExt = true;

      async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
        if (typeof args?.method !== 'string') {
          throw { code: RPC_ERROR.invalidParams, message: 'A method name is required.' };
        }

        const id = crypto.randomUUID();
        return new Promise((resolve, reject) => {
          pending.set(id, { resolve, reject });
          window.postMessage(
            { type: PAGE_MESSAGE, id, method: args.method, params: args.params },
            window.location.origin,
          );
        });
      }

      /** EIP-1193 keeps these for compatibility; we have no events to emit yet. */
      on(): this {
        return this;
      }

      removeListener(): this {
        return this;
      }
    }

    const detail = Object.freeze({
      info: Object.freeze({
        uuid: crypto.randomUUID(),
        name: 'mpc-ext',
        // A neutral placeholder mark. Replace it with real artwork before release.
        icon:
          'data:image/svg+xml;base64,' +
          btoa(
            '<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96">' +
              '<rect width="96" height="96" rx="20" fill="#3b4bd0"/>' +
              '<text x="48" y="62" font-family="monospace" font-size="34" font-weight="700" ' +
              'text-anchor="middle" fill="#fff">2/3</text></svg>',
          ),
        rdns: RDNS,
      }),
      provider: new MpcExtProvider(),
    });

    const announce = () =>
      window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail }));

    // EIP-6963: announce once now, and again whenever a page asks.
    window.addEventListener('eip6963:requestProvider', announce);
    announce();
  },
});
