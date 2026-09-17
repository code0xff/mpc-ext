import { useCallback, useEffect, useState } from 'react';

import type { CreatedKey, Status, WasmHealth } from '../../src/messages';
import { send } from './api';
import { downloadRecoveryFile } from './recoveryFile';

export function App() {
  const [status, setStatus] = useState<Status>();
  const [health, setHealth] = useState<WasmHealth>();
  const [created, setCreated] = useState<CreatedKey>();
  const [downloaded, setDownloaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const refresh = useCallback(async () => {
    setStatus(await send<Status>({ type: 'status' }));
  }, []);

  useEffect(() => {
    void refresh().catch(showError);
    void send<WasmHealth>({ type: 'wasmHealth' }).then(setHealth).catch(showError);
  }, [refresh]);

  function showError(cause: unknown) {
    setError(cause instanceof Error ? cause.message : String(cause));
  }

  const run = useCallback(async (action: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (cause) {
      showError(cause);
    } finally {
      setBusy(false);
    }
  }, []);

  return (
    <main>
      <header>
        <h1>mpc-ext</h1>
        <p className="warn">Unaudited. Do not use with real assets.</p>
      </header>

      <section>
        <h2>Status</h2>
        <dl>
          <dt>Wallet</dt>
          <dd id="wallet-status">{status ? describe(status) : 'Checking…'}</dd>
          <dt>MPC engine</dt>
          <dd>{health ? `${health.config}, loaded in ${health.loadMs} ms` : 'Checking…'}</dd>
        </dl>
      </section>

      {status?.kind === 'uninitialized' && (
        <CreateKey
          busy={busy}
          onCreate={(password) =>
            run(async () => {
              setCreated(await send<CreatedKey>({ type: 'createKey', password }));
              setDownloaded(false);
              await refresh();
            })
          }
        />
      )}

      {status?.kind === 'awaitingRecoveryExport' && created && (
        <section className="callout">
          <h2>Save your recovery file</h2>
          <p>
            This file can only be created <b>right now</b>. The extension does not store this share.
            If you lose your device, or the server goes away, this file is the only way back.
          </p>
          <p className="warn">
            Keep it <b>somewhere other than</b> this machine. Storing it alongside the extension
            defeats the design. Files are easy to lose, so keep several copies.
          </p>
          <button
            type="button"
            id="download-recovery"
            onClick={() => {
              downloadRecoveryFile(created);
              setDownloaded(true);
            }}
          >
            Download recovery file (about 230 KB)
          </button>
          <button
            type="button"
            id="confirm-recovery"
            className="secondary"
            disabled={!downloaded || busy}
            onClick={() =>
              run(async () => {
                setStatus(await send<Status>({ type: 'confirmRecoverySaved' }));
                setCreated(undefined);
              })
            }
          >
            {downloaded ? 'I saved it — start using the wallet' : 'Download the file first'}
          </button>
          <button
            type="button"
            className="quiet"
            disabled={busy}
            onClick={() =>
              run(async () => {
                setStatus(await send<Status>({ type: 'cancelOnboarding' }));
                setCreated(undefined);
              })
            }
          >
            Cancel and start over
          </button>
        </section>
      )}

      {status?.kind === 'locked' && (
        <Unlock
          busy={busy}
          onUnlock={(password) =>
            run(async () => {
              setStatus(await send<Status>({ type: 'unlock', password }));
            })
          }
        />
      )}

      {status?.kind === 'unlocked' && (
        <section>
          <h2>Wallet</h2>
          <p className="mono">{status.publicKeyHex}</p>
          <p>Signing becomes available once the server integration lands.</p>
          <button
            type="button"
            id="lock"
            className="secondary"
            onClick={() =>
              run(async () => {
                setStatus(await send<Status>({ type: 'lock' }));
              })
            }
          >
            Lock
          </button>
        </section>
      )}

      {error && (
        <p className="error" id="error">
          {error}
        </p>
      )}
    </main>
  );
}

function CreateKey({ busy, onCreate }: { busy: boolean; onCreate: (password: string) => void }) {
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');

  const tooShort = password.length > 0 && password.length < 8;
  const mismatched = confirmation.length > 0 && password !== confirmation;
  const ready = password.length >= 8 && password === confirmation;

  return (
    <section>
      <h2>Create a key</h2>
      <p>
        This creates three shares. The extension keeps <b>one</b>, one is exported as your recovery
        file, and the server holds the last one.
      </p>
      <label htmlFor="password">Password (8 characters or more)</label>
      <input
        id="password"
        type="password"
        value={password}
        autoComplete="new-password"
        onChange={(event) => setPassword(event.target.value)}
      />
      <label htmlFor="password-confirm">Confirm password</label>
      <input
        id="password-confirm"
        type="password"
        value={confirmation}
        autoComplete="new-password"
        onChange={(event) => setConfirmation(event.target.value)}
      />
      {tooShort && <p className="error">Use at least 8 characters.</p>}
      {mismatched && <p className="error">The passwords do not match.</p>}
      <button
        type="button"
        id="create-key"
        disabled={!ready || busy}
        onClick={() => onCreate(password)}
      >
        {busy ? 'Creating… (this takes a few seconds)' : 'Create key'}
      </button>
    </section>
  );
}

function Unlock({ busy, onUnlock }: { busy: boolean; onUnlock: (password: string) => void }) {
  const [password, setPassword] = useState('');

  return (
    <section>
      <h2>Unlock</h2>
      <label htmlFor="unlock-password">Password</label>
      <input
        id="unlock-password"
        type="password"
        value={password}
        autoComplete="current-password"
        onChange={(event) => setPassword(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' && password) onUnlock(password);
        }}
      />
      <button
        type="button"
        id="unlock"
        disabled={!password || busy}
        onClick={() => onUnlock(password)}
      >
        Unlock
      </button>
    </section>
  );
}

function describe(status: Status): string {
  switch (status.kind) {
    case 'uninitialized':
      return 'No key yet';
    case 'awaitingRecoveryExport':
      return 'Waiting for the recovery file to be saved';
    case 'locked':
      return 'Locked';
    case 'unlocked':
      return `Unlocked — ${status.publicKeyHex.slice(0, 16)}…`;
  }
}
