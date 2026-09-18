import { useCallback, useEffect, useState } from 'react';

import type { Approval } from '../../src/approvals';
import { send } from '../popup/api';

/**
 * The approval window.
 *
 * Every signature is approved individually, and the origin shown here is the one the browser
 * reported — not a value the page supplied (`docs/web-api.md`).
 */
export function ApproveApp() {
  const [queue, setQueue] = useState<Approval[]>();
  const [error, setError] = useState<string>();

  const refresh = useCallback(async () => {
    setQueue(await send<Approval[]>({ type: 'pendingApprovals' }));
  }, []);

  useEffect(() => {
    void refresh().catch((cause: unknown) =>
      setError(cause instanceof Error ? cause.message : String(cause)),
    );
  }, [refresh]);

  const decide = useCallback(async (id: string, approved: boolean) => {
    await send({ type: 'decideApproval', id, approved });
    const remaining = await send<Approval[]>({ type: 'pendingApprovals' });
    setQueue(remaining);
    // Nothing left to answer, so get out of the user's way.
    if (remaining.length === 0) window.close();
  }, []);

  if (error)
    return (
      <main>
        <p className="error">{error}</p>
      </main>
    );
  if (!queue)
    return (
      <main>
        <p>Loading…</p>
      </main>
    );
  if (queue.length === 0) {
    return (
      <main>
        <p>Nothing is waiting for you.</p>
      </main>
    );
  }

  return (
    <main>
      <header>
        <h1>Approve request</h1>
      </header>

      {queue.map((approval) => (
        <section key={approval.id} className="callout">
          <h2>{approval.request.kind === 'connect' ? 'Connect' : 'Sign a message'}</h2>
          <p>
            <b className="mono">{approval.origin}</b>
          </p>

          {approval.request.kind === 'connect' ? (
            <p>This site wants to see your wallet address. It cannot sign anything on its own.</p>
          ) : (
            <>
              <p>This site is asking you to sign a message.</p>
              <p className="mono">{decode(approval.request.messageHex)}</p>
              <p className="mono">digest {approval.request.digestHex.slice(0, 24)}…</p>
            </>
          )}

          <button
            type="button"
            id={`approve-${approval.id}`}
            onClick={() => void decide(approval.id, true)}
          >
            Approve
          </button>
          <button
            type="button"
            className="secondary"
            id={`reject-${approval.id}`}
            onClick={() => void decide(approval.id, false)}
          >
            Reject
          </button>
        </section>
      ))}
    </main>
  );
}

/** Shows the message as text when it is readable, and as hex when it is not. */
function decode(messageHex: string): string {
  try {
    const bytes = Uint8Array.from({ length: messageHex.length / 2 }, (_, i) =>
      Number.parseInt(messageHex.slice(i * 2, i * 2 + 2), 16),
    );
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    // Control characters would let a page draw a misleading prompt.
    return /^[\p{L}\p{N}\p{P}\p{Z}\n\r\t]*$/u.test(text) ? text : `0x${messageHex}`;
  } catch {
    return `0x${messageHex}`;
  }
}
