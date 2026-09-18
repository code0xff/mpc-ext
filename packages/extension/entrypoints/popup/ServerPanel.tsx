import { useCallback, useEffect, useState } from 'react';

import { send } from './api';

interface Settings {
  serverUrl: string;
}

/**
 * Pointing the extension at a server.
 *
 * Self-hosting is one of the reasons this design survives the operator disappearing, so the
 * address has to be changeable (`docs/server.md`).
 */
export function ServerPanel({ onChanged }: { onChanged: () => void }) {
  const [serverUrl, setServerUrl] = useState('');
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    void send<Settings>({ type: 'readSettings' })
      .then((settings) => setServerUrl(settings.serverUrl))
      .catch(() => setError('Could not read the settings.'));
  }, []);

  const save = useCallback(async () => {
    setError(undefined);
    setSaved(false);
    try {
      await send<Settings>({ type: 'setServerUrl', serverUrl });
      setSaved(true);
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [onChanged, serverUrl]);

  return (
    <section>
      <h2>Server</h2>
      <label htmlFor="server-url">Server address</label>
      <input
        id="server-url"
        value={serverUrl}
        onChange={(event) => {
          setServerUrl(event.target.value);
          setSaved(false);
        }}
      />
      <button type="button" id="save-server" className="secondary" onClick={() => void save()}>
        Save
      </button>
      {saved && <p>Saved.</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
