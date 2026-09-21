import { useCallback, useEffect, useRef, useState } from 'react';

import type { RecoveryProgress, Status } from '../../src/messages';
import { openRecoveryFile } from '../../src/recoveryFile';
import { send } from './api';

/** How often to ask while a recovery waits. The wait itself can be a day, so this is gentle. */
const POLL_APPROVAL_MS = 1000;
const POLL_COOLING_MS = 30_000;

/** What the recovery file's header says. It is not secret: only the share is encrypted. */
interface FileHeader {
  walletId: string;
  publicKeyHex: string;
}

function headerOf(parsed: unknown): FileHeader {
  const file = parsed as { kind?: string; walletId?: string; publicKey?: string } | null;
  if (file?.kind !== 'mpc-ext-recovery') {
    throw new Error('That does not look like an mpc-ext recovery file.');
  }
  if (!file.walletId || !file.publicKey) {
    throw new Error('This recovery file cannot be restored automatically.');
  }
  return { walletId: file.walletId, publicKeyHex: file.publicKey };
}

/**
 * Restoring a wallet from a recovery file after a device loss
 * (`docs/adr/0008-recovery-start-and-device-key-replacement.md`).
 *
 * Restoring is deliberately slow. The server needs the user's passkey and then makes a new device
 * wait, so that someone who only holds the recovery file cannot take over at once and the current
 * device has time to object. Every stage says what it is waiting for. A restored wallet is also not
 * fully healthy (`docs/recovery.md`), and this says so.
 */
export function RecoverPanel({
  onRecovered,
  onPhase,
  collapsed,
}: {
  onRecovered: (status: Status) => void;
  /** Lets the popup know a recovery is under way, so it can step out of onboarding. */
  onPhase?: (phase: RecoveryProgress['phase']) => void;
  /** True while the user has not asked to restore. The panel keeps polling but shows nothing. */
  collapsed?: boolean;
}) {
  const [progress, setProgress] = useState<RecoveryProgress>({ phase: 'idle' });
  const [parsed, setParsed] = useState<unknown>();
  const [fileName, setFileName] = useState('');
  const [filePassword, setFilePassword] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [manageUrl, setManageUrl] = useState<string>();
  const input = useRef<HTMLInputElement>(null);

  // Where a waiting recovery can be seen and cancelled from any browser, with only the passkey
  // (docs/adr/0009-managing-recoveries-with-the-passkey.md).
  useEffect(() => {
    void send<{ serverUrl: string }>({ type: 'readSettings' })
      .then((settings) => setManageUrl(`${settings.serverUrl}/manage`))
      .catch(() => undefined);
  }, []);

  const phase = progress.phase;

  // Follow a recovery that is under way, and pick it up again if the popup was closed and reopened.
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      send<RecoveryProgress>({ type: 'recoveryProgress' })
        .then((next) => {
          if (stopped) return;
          setProgress(next);
          onPhase?.(next.phase);
          const wait =
            next.phase === 'awaitingAssertion'
              ? POLL_APPROVAL_MS
              : next.phase === 'cooling'
                ? POLL_COOLING_MS
                : undefined;
          if (wait !== undefined) timer = setTimeout(tick, wait);
        })
        .catch((cause: unknown) => {
          if (!stopped) setError(cause instanceof Error ? cause.message : String(cause));
        });
    };
    tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
    // Restart the loop when the phase changes so the interval matches the stage.
  }, [phase === 'awaitingAssertion', phase === 'cooling']);

  const load = useCallback(async (picked: File) => {
    setError(undefined);
    try {
      const value: unknown = JSON.parse(await picked.text());
      headerOf(value);
      setParsed(value);
      setFileName(picked.name);
    } catch (cause) {
      setParsed(undefined);
      setFileName('');
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  const run = useCallback(async (action: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

  const start = () =>
    run(async () => {
      const header = headerOf(parsed);
      setProgress(
        await send<RecoveryProgress>({
          type: 'beginRecovery',
          walletId: header.walletId,
          publicKeyHex: header.publicKeyHex,
        }),
      );
    });

  const finish = () =>
    run(async () => {
      const opened = await openRecoveryFile(parsed, filePassword);
      onRecovered(
        await send<Status>({
          type: 'finishRecovery',
          password,
          publicKeyHex: opened.publicKeyHex,
          recoveryShareHex: opened.shareHex,
        }),
      );
    });

  const cancel = () =>
    run(async () => {
      await send<Status>({ type: 'abandonRecovery' });
      setProgress({ phase: 'idle' });
    });

  const picker = (
    <>
      <button
        type="button"
        id="pick-recovery"
        className="secondary"
        onClick={() => input.current?.click()}
      >
        {fileName || 'Choose recovery file'}
      </button>
      <input
        ref={input}
        type="file"
        accept="application/json"
        hidden
        onChange={(event) => {
          const picked = event.target.files?.[0];
          if (picked) void load(picked);
          event.target.value = '';
        }}
      />
    </>
  );

  // The progress poll has to keep running even while this is out of the way: the background
  // reports an ended recovery once, and whoever asks first is the only one who sees it.
  if (collapsed && phase === 'idle') return null;

  return (
    <section>
      <h2>Restore from a recovery file</h2>

      {phase === 'idle' && (
        <>
          <p>
            Use this if you lost the device that held your wallet. Your address stays the same and
            you can spend again.
          </p>
          <p>
            It takes two steps. First you approve with your <b>passkey</b>. Then the server makes
            this device <b>wait</b> before it is trusted, so that nobody who only found your file
            can take over at once. If you still have your old device, it will show the request and
            you can cancel it.
          </p>
          <p className="warn">
            A restored wallet is <b>not fully healthy</b>. The share on the lost device stays valid,
            and this file stops being a separate backup. You will be offered a reshare to fix that.
          </p>
          {picker}
          <button
            type="button"
            id="begin-recovery"
            disabled={parsed === undefined || busy}
            onClick={() => void start()}
          >
            {busy ? 'Starting…' : 'Start recovery'}
          </button>
        </>
      )}

      {phase === 'awaitingAssertion' && (
        <>
          <p>
            Approve the request with your passkey in the tab that just opened. This window may close
            while you do. Open it again afterwards.
          </p>
          <button type="button" className="quiet" disabled={busy} onClick={() => void cancel()}>
            Cancel
          </button>
        </>
      )}

      {phase === 'cooling' && (
        <>
          <p id="recovery-cooling">
            Your recovery is approved and waiting. You can finish it after{' '}
            <b>{new Date(progress.readyAt * 1000).toLocaleString()}</b>. You can close this window
            and come back then.
          </p>
          <p>If you did not start this, cancel it.</p>
          <p id="manage-hint">
            The owner of this wallet can also see and cancel it from any browser with their passkey,
            at <span className="mono">{manageUrl ?? 'the server address + /manage'}</span>.
          </p>
          <button type="button" className="quiet" disabled={busy} onClick={() => void cancel()}>
            Cancel the recovery
          </button>
        </>
      )}

      {phase === 'ready' && (
        <>
          <p>
            The waiting period is over. Choose your recovery file again to finish. Nothing secret
            was kept while you waited.
          </p>
          {picker}
          {parsed !== undefined && (
            <>
              <label htmlFor="recover-file-password">Recovery file password</label>
              <input
                id="recover-file-password"
                type="password"
                value={filePassword}
                autoComplete="off"
                onChange={(event) => setFilePassword(event.target.value)}
              />
            </>
          )}
          <label htmlFor="recover-password">New password (8 characters or more)</label>
          <input
            id="recover-password"
            type="password"
            value={password}
            autoComplete="new-password"
            onChange={(event) => setPassword(event.target.value)}
          />
          <button
            type="button"
            id="finish-recovery"
            disabled={parsed === undefined || !filePassword || password.length < 8 || busy}
            onClick={() => void finish()}
          >
            {busy ? 'Restoring…' : 'Finish restoring'}
          </button>
          <button type="button" className="quiet" disabled={busy} onClick={() => void cancel()}>
            Cancel the recovery
          </button>
        </>
      )}

      {phase === 'ended' && (
        <>
          <p className="warn">
            {progress.reason === 'cancelled'
              ? 'This recovery was cancelled.'
              : 'This recovery ran out of time.'}{' '}
            Start again if you still need it.
          </p>
          <button
            type="button"
            id="restart-recovery"
            className="secondary"
            onClick={() => setProgress({ phase: 'idle' })}
          >
            Start again
          </button>
        </>
      )}

      {error && <p className="error">{error}</p>}
    </section>
  );
}
