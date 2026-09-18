/**
 * The relay between a page and the background worker.
 *
 * It validates the shape of what arrives and forwards nothing else. **It makes no policy
 * decisions** — approval, origin checks and signing all belong to the background worker, which
 * re-derives the origin from the message sender rather than trusting anything the page said
 * (`docs/web-api.md`).
 */
import { PAGE_MESSAGE, PAGE_RESPONSE, RPC_ERROR } from '../src/rpc';
import type { Response } from '../src/messages';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_start',
  world: 'ISOLATED',

  main() {
    window.addEventListener('message', (event: MessageEvent) => {
      // Only same-window messages, so another frame cannot speak for this page.
      if (event.source !== window) return;

      const data = event.data as { type?: string; id?: string; method?: unknown; params?: unknown };
      if (data?.type !== PAGE_MESSAGE) return;
      if (typeof data.id !== 'string' || typeof data.method !== 'string') return;
      if (data.params !== undefined && !Array.isArray(data.params)) {
        reply(data.id, undefined, {
          code: RPC_ERROR.invalidParams,
          message: 'params must be an array.',
        });
        return;
      }

      chrome.runtime
        .sendMessage({
          type: 'pageRequest',
          method: data.method,
          params: data.params,
        })
        .then((response: Response<unknown>) => {
          if (response.ok) reply(data.id as string, response.value);
          else
            reply(data.id as string, undefined, {
              code: RPC_ERROR.internal,
              message: response.error,
            });
        })
        .catch(() => {
          reply(data.id as string, undefined, {
            code: RPC_ERROR.disconnected,
            message: 'The extension is not available.',
          });
        });
    });
  },
});

function reply(id: string, result?: unknown, error?: { code: number; message: string }): void {
  window.postMessage({ type: PAGE_RESPONSE, id, result, error }, window.location.origin);
}
