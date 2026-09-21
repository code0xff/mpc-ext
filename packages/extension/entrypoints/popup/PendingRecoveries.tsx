import { useCallback, useEffect, useState } from 'react';

import type { PendingRecoveryInfo } from '../../src/messages';
import { send } from './api';

/** How often to look while the popup is open. A recovery waits a day, so this can be slow. */
const POLL_MS = 60_000;

/**
 * Tells the owner that someone asked to replace this wallet's device
 * (`docs/adr/0008-recovery-start-and-device-key-replacement.md`).
 *
 * The server has no way to reach the user, by design: no email, no phone. This is the notice. It
 * appears whenever the extension is unlocked and asks the server, and the owner can object here.
 * If this install no longer holds the wallet's device key, the server refuses the question and
 * there is nothing to show.
 */
export function PendingRecoveries() {
  const [pending, setPending] = useState<PendingRecoveryInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      send<PendingRecoveryInfo[]>({ type: 'pendingRecoveries' })
        .then((list) => {
          if (!stopped) setPending(list);
        })
        // A failed check must not get in the way of everything else the popup does.
        .catch(() => undefined)
        .finally(() => {
          if (!stopped) timer = setTimeout(tick, POLL_MS);
        });
    };
    tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  const cancel = useCallback(async (requestId: string) => {
    setBusy(true);
    setError(undefined);
    try {
      setPending(await send<PendingRecoveryInfo[]>({ type: 'cancelPendingRecovery', requestId }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

  if (pending.length === 0) return null;

  return (
    <section className="callout" id="pending-recoveries">
      <h2>Someone asked to replace this device</h2>
      <p className="warn">
        A new device asked to take over this wallet's connection to the server. If that was you,
        restoring on a new device, you can leave it. If it was not, <b>cancel it now</b>.
      </p>
      {pending.map((item) => (
        <div key={item.requestId}>
          <p>
            Asked {new Date(item.requestedAt * 1000).toLocaleString()}. It can take over after{' '}
            <b>{new Date(item.readyAt * 1000).toLocaleString()}</b>.
            <br />
            New device fingerprint: <span className="mono">{item.keyFingerprint}</span>
          </p>
          <button
            type="button"
            className="cancel-pending"
            disabled={busy}
            onClick={() => void cancel(item.requestId)}
          >
            Cancel this recovery
          </button>
        </div>
      ))}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
