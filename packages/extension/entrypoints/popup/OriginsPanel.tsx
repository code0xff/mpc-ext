import { useCallback, useEffect, useState } from 'react';

import { send } from './api';

/**
 * Sites connected to this wallet.
 *
 * A connection only lets a site see the address — signing is approved every time — but the user
 * still has to be able to revoke one at any moment (`docs/web-api.md`).
 */
export function OriginsPanel() {
  const [origins, setOrigins] = useState<string[]>();

  const refresh = useCallback(async () => {
    setOrigins(await send<string[]>({ type: 'connectedOrigins' }));
  }, []);

  useEffect(() => {
    void refresh().catch(() => setOrigins([]));
  }, [refresh]);

  const disconnect = useCallback(
    async (origin: string) => {
      await send({ type: 'disconnectOrigin', origin });
      await refresh();
    },
    [refresh],
  );

  if (!origins || origins.length === 0) return null;

  return (
    <section>
      <h2>Connected sites</h2>
      <p>These sites can see your address. They still need your approval for every signature.</p>
      <ul className="origins">
        {origins.map((origin) => (
          <li key={origin}>
            <span className="mono">{origin}</span>
            <button type="button" className="quiet" onClick={() => void disconnect(origin)}>
              Disconnect
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
