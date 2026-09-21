import { useCallback, useEffect, useState } from 'react';

import type {
  CreatedKey,
  PasskeyState,
  RecoveryProgress,
  ReshareProgress,
  Status,
  WasmHealth,
} from '../../src/messages';
import { send } from './api';
import { ExportPanel } from './ExportPanel';
import { OriginsPanel } from './OriginsPanel';
import { PasskeyCard } from './PasskeyCard';
import { PendingRecoveries } from './PendingRecoveries';
import { RecoverPanel } from './RecoverPanel';
import { RecoveryExportCard } from './RecoveryExportCard';
import { ReshareCard } from './ReshareCard';
import { ServerPanel } from './ServerPanel';
import { SignPanel } from './SignPanel';

export function App() {
  const [status, setStatus] = useState<Status>();
  const [health, setHealth] = useState<WasmHealth>();
  const [created, setCreated] = useState<CreatedKey>();
  const [reshared, setReshared] = useState<CreatedKey>();
  const [reshareWorking, setReshareWorking] = useState(false);
  const [passkey, setPasskey] = useState<PasskeyState>();
  const [serverUp, setServerUp] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  // Restoring is the exception, so it is reached from a link rather than shown beside key
  // creation. A restore already under way outlives the popup, so look for one on open.
  const [restoring, setRestoring] = useState(false);
  const [passkeySkipped, setPasskeySkipped] = useState<boolean>();

  const refresh = useCallback(async () => {
    setStatus(await send<Status>({ type: 'status' }));
  }, []);

  const checkServer = useCallback(() => {
    void send<boolean>({ type: 'serverHealth' })
      .then(setServerUp)
      .catch(() => setServerUp(false));
  }, []);

  useEffect(() => {
    void send<RecoveryProgress>({ type: 'recoveryProgress' })
      .then((progress) => {
        // 'ended' counts too: a cancelled or expired recovery has to say so, not vanish.
        if (progress.phase !== 'idle') setRestoring(true);
      })
      .catch(() => undefined);
    void readPasskeySkipped().then(setPasskeySkipped);
  }, []);

  useEffect(() => {
    void refresh().catch(showError);
    void send<WasmHealth>({ type: 'wasmHealth' }).then(setHealth).catch(showError);
    void send<boolean>({ type: 'serverHealth' })
      .then(setServerUp)
      .catch(() => setServerUp(false));
  }, [refresh]);

  // The passkey ceremony opens a tab, which closes this popup, so a reshare cannot be awaited
  // here. Follow it by polling, and pick it up again if the popup was closed and reopened.
  useEffect(() => {
    let stopped = false;
    const check = async (): Promise<boolean> => {
      const progress = await send<ReshareProgress>({ type: 'reshareProgress' });
      if (stopped) return true;
      if (progress.phase === 'ready') {
        setReshared(await send<CreatedKey>({ type: 'takeReshareRecovery' }));
        setReshareWorking(false);
        await refresh();
        return true;
      }
      if (progress.phase === 'failed') {
        setError(progress.error ?? 'The reshare failed.');
        setReshareWorking(false);
        return true;
      }
      if (progress.phase === 'idle') {
        setReshareWorking(false);
        return true;
      }
      setReshareWorking(true);
      return false;
    };

    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      void check()
        .then((done) => {
          if (!done && !stopped) timer = setTimeout(tick, 1000);
        })
        .catch((cause: unknown) => {
          setError(cause instanceof Error ? cause.message : String(cause));
          setReshareWorking(false);
        });
    };
    tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [refresh, reshareWorking]);

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

  // Onboarding is three steps in a fixed order, and each one hides everything else so that the
  // popup reads as a sequence rather than a wall of cards. Step 3 is the passkey: without one the
  // server will not take part in a signature, so it belongs on the main path, not in a side card.
  const needsPasskey =
    status?.kind === 'unlocked' &&
    !status.recovered &&
    passkey?.registered === false &&
    passkey.reachable &&
    passkeySkipped === false;
  const step =
    status?.kind === 'uninitialized' && !restoring
      ? 1
      : status?.kind === 'awaitingRecoveryExport'
        ? 2
        : needsPasskey
          ? 3
          : undefined;
  const onboarding = step !== undefined;

  const skipPasskey = () =>
    run(async () => {
      await writePasskeySkipped();
      setPasskeySkipped(true);
    });

  return (
    <main>
      <header>
        <h1>mpc-ext</h1>
        <p className="warn">Unaudited. Do not use with real assets.</p>
      </header>

      {onboarding && (
        <p className="steps" id="onboarding-step">
          Step {step} of 3 ·{' '}
          {['Create your wallet', 'Save your recovery file', 'Register your passkey'][step - 1]}
        </p>
      )}

      {!onboarding && (
        <section>
          <h2>Status</h2>
          <dl>
            <dt>Wallet</dt>
            <dd id="wallet-status">{status ? describe(status) : 'Checking…'}</dd>
            <dt>MPC engine</dt>
            <dd>{health ? `${health.config}, loaded in ${health.loadMs} ms` : 'Checking…'}</dd>
            <dt>Server</dt>
            <dd className={serverUp === false ? 'warn' : undefined}>
              {serverUp === undefined ? 'Checking…' : serverUp ? 'Reachable' : 'Unreachable'}
            </dd>
          </dl>
        </section>
      )}

      {step === 1 && (
        <CreateKey
          busy={busy}
          onCreate={(password) =>
            run(async () => {
              setCreated(await send<CreatedKey>({ type: 'createKey', password }));
              await refresh();
            })
          }
        />
      )}

      {step === 1 && (
        <button
          type="button"
          id="restore-instead"
          className="quiet"
          onClick={() => setRestoring(true)}
        >
          Lost your device? Restore from a recovery file
        </button>
      )}

      {status?.kind === 'uninitialized' && restoring && (
        <>
          <RecoverPanel onRecovered={setStatus} />
          <button type="button" className="quiet" onClick={() => setRestoring(false)}>
            Back
          </button>
        </>
      )}

      {status?.kind === 'awaitingRecoveryExport' && created && (
        <RecoveryExportCard
          created={created}
          heading="Save your recovery file"
          intro={
            <p>
              This file can only be created <b>right now</b>. The extension does not store this
              share. If you lose your device, or the server goes away, this file is the only way
              back.
            </p>
          }
          confirmLabel="I saved it — start using the wallet"
          cancelLabel="Cancel and start over"
          busy={busy}
          onConfirm={() =>
            run(async () => {
              setStatus(await send<Status>({ type: 'confirmRecoverySaved' }));
              setCreated(undefined);
            })
          }
          onCancel={() =>
            run(async () => {
              setStatus(await send<Status>({ type: 'cancelOnboarding' }));
              setCreated(undefined);
            })
          }
        />
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

      {status?.kind === 'unlocked' && !onboarding && (
        <section>
          <h2>Wallet</h2>
          <p className="mono">{status.publicKeyHex}</p>
          {status.recovered && (
            <p className="warn">
              Restored from a recovery file. The share on the lost device is still valid, so move
              your funds to a new wallet when you can.
            </p>
          )}
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

      {status?.kind === 'unlocked' && <PasskeyCard onState={setPasskey} />}
      {step === 3 && (
        <button
          type="button"
          id="skip-passkey"
          className="quiet"
          onClick={() => void skipPasskey()}
        >
          Not now — I will do this later
        </button>
      )}
      {status?.kind === 'unlocked' && !onboarding && <PendingRecoveries />}

      {status?.kind === 'unlocked' && !onboarding && status.recovered && reshared && (
        <RecoveryExportCard
          created={reshared}
          heading="Save your new recovery file"
          intro={
            <p>
              Your wallet now has three new shares and the same address. This is the only chance to
              save the new recovery file. Your <b>old</b> file no longer belongs to a healthy
              wallet, so destroy it once this one is safe.
            </p>
          }
          confirmLabel="I saved it — finish"
          cancelLabel="Cancel the reshare"
          busy={busy}
          onConfirm={() =>
            run(async () => {
              setStatus(await send<Status>({ type: 'confirmReshareSaved' }));
              setReshared(undefined);
            })
          }
          onCancel={() =>
            run(async () => {
              setStatus(await send<Status>({ type: 'cancelReshare' }));
              setReshared(undefined);
            })
          }
        />
      )}
      {status?.kind === 'unlocked' && !onboarding && status.recovered && !reshared && (
        <ReshareCard
          busy={busy}
          working={reshareWorking}
          interrupted={status.reshareInProgress}
          onStart={(password) =>
            run(async () => {
              await send<ReshareProgress>({ type: 'startReshare', password });
              setReshareWorking(true);
            })
          }
          onCancel={() =>
            run(async () => {
              setStatus(await send<Status>({ type: 'cancelReshare' }));
              setReshareWorking(false);
            })
          }
        />
      )}

      {status?.kind === 'unlocked' && !onboarding && (
        <SignPanel
          serverUp={serverUp}
          passkeyMissing={passkey?.registered === false && passkey.reachable}
        />
      )}
      {status?.kind === 'unlocked' && !onboarding && <OriginsPanel />}
      {status?.kind === 'unlocked' && !onboarding && !status.recovered && (
        <ExportPanel publicKeyHex={status.publicKeyHex} />
      )}

      {(!onboarding || step === 1) && <ServerPanel onChanged={checkServer} />}

      {error && (
        <p className="error" id="error">
          {error}
        </p>
      )}
    </main>
  );
}

/** Whether the user chose to leave the passkey until later. A preference, never a secret. */
const SKIPPED_KEY = 'onboardingPasskeySkipped';

async function readPasskeySkipped(): Promise<boolean> {
  try {
    const stored = await chrome.storage.local.get(SKIPPED_KEY);
    return stored[SKIPPED_KEY] === true;
  } catch {
    return false;
  }
}

async function writePasskeySkipped(): Promise<void> {
  await chrome.storage.local.set({ [SKIPPED_KEY]: true });
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
      return status.recovered
        ? `Unlocked (restored) — ${status.publicKeyHex.slice(0, 16)}…`
        : `Unlocked — ${status.publicKeyHex.slice(0, 16)}…`;
  }
}
