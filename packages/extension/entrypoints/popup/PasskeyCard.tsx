import { useCallback, useEffect, useState } from 'react';

import type { PasskeyState } from '../../src/messages';
import { send } from './api';

const POLL_WHILE_REGISTERING_MS = 1000;

/**
 * Registers the wallet's passkey, and tells the rest of the popup whether there is one.
 *
 * Every signature and every recovery needs the passkey, so a wallet without one cannot sign
 * through the server. The answer comes from the server, which is the only place that knows: a
 * wallet restored onto a new device already has one, and a new wallet does not until this card
 * has run (`docs/adr/0006-server-authentication.md`). The ceremony opens a tab on the server's
 * origin, which closes the popup, so this follows the outcome by asking again.
 */
export function PasskeyCard({ onState }: { onState: (state: PasskeyState | undefined) => void }) {
  const [state, setState] = useState<PasskeyState>();
  const [registering, setRegistering] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      send<PasskeyState>({ type: 'passkeyState' })
        .then((next) => {
          if (stopped) return;
          setState(next);
          onState(next);
          if (next.registered) {
            setRegistering(false);
          } else if (registering) {
            timer = setTimeout(tick, POLL_WHILE_REGISTERING_MS);
          }
        })
        // A failed check must not get in the way of everything else the popup does.
        .catch(() => undefined);
    };
    tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [registering, onState]);

  const register = useCallback(async () => {
    setBusy(true);
    setError(undefined);
    try {
      await send<{ ceremonyId: string }>({ type: 'registerPasskey' });
      setRegistering(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

  if (!state || state.registered || !state.reachable) return null;

  return (
    <section className="callout" id="passkey-card">
      <h2>Register your passkey</h2>
      <p>
        Your wallet cannot sign through the server until you do. The server holds one share, and
        your passkey is what lets it take part: every signature and every recovery needs your
        approval.
      </p>
      <p>
        You approve in a tab on the server's own page. This window may close while you do. Open it
        again afterwards.
      </p>
      <p>
        Losing the passkey does not lock you out. Your extension and your recovery file can still
        sign together without the server.
      </p>
      <button type="button" id="register-passkey" disabled={busy} onClick={() => void register()}>
        {registering ? 'Waiting for your approval…' : 'Register passkey'}
      </button>
      {error && <p className="error">{error}</p>}
    </section>
  );
}
