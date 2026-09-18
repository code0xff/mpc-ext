import { useCallback, useRef, useState } from 'react';

import type { Status } from '../../src/messages';
import { send } from './api';

interface RecoveryFileContents {
  kind?: string;
  formatVersion?: number;
  walletId?: string;
  publicKey?: string;
  share?: string;
}

/**
 * Restoring a wallet from a recovery file after a device loss.
 *
 * This deliberately spells out that a restored wallet is not fully healthy — the lost share
 * stays valid and there is no independent backup left (`docs/recovery.md`).
 */
export function RecoverPanel({ onRecovered }: { onRecovered: (status: Status) => void }) {
  const [password, setPassword] = useState('');
  const [file, setFile] = useState<RecoveryFileContents>();
  const [fileName, setFileName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const input = useRef<HTMLInputElement>(null);

  const ready = password.length >= 8 && file?.share && file.walletId && file.publicKey;

  const load = useCallback(async (picked: File) => {
    setError(undefined);
    try {
      const parsed = JSON.parse(await picked.text()) as RecoveryFileContents;
      if (parsed.kind !== 'mpc-ext-recovery') {
        throw new Error('That does not look like an mpc-ext recovery file.');
      }
      if (!parsed.walletId) {
        throw new Error(
          'This recovery file predates wallet ids, so it cannot be restored automatically.',
        );
      }
      setFile(parsed);
      setFileName(picked.name);
    } catch (cause) {
      setFile(undefined);
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  const recover = useCallback(async () => {
    if (!file?.share || !file.walletId || !file.publicKey) return;
    setBusy(true);
    setError(undefined);
    try {
      onRecovered(
        await send<Status>({
          type: 'recoverFromFile',
          password,
          walletId: file.walletId,
          publicKeyHex: file.publicKey,
          recoveryShareHex: file.share,
        }),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, [file, onRecovered, password]);

  return (
    <section>
      <h2>Restore from a recovery file</h2>
      <p>
        Use this if you lost the device that held your wallet. Your address stays the same and you
        can spend again.
      </p>
      <p className="warn">
        A restored wallet is <b>not fully healthy</b>. The share on the lost device stays valid, and
        this file stops being a separate backup. Move your funds to a new wallet when you can.
      </p>

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

      <label htmlFor="recover-password">New password (8 characters or more)</label>
      <input
        id="recover-password"
        type="password"
        value={password}
        autoComplete="new-password"
        onChange={(event) => setPassword(event.target.value)}
      />

      <button type="button" id="recover" disabled={!ready || busy} onClick={() => void recover()}>
        {busy ? 'Restoring…' : 'Restore wallet'}
      </button>

      {error && <p className="error">{error}</p>}
    </section>
  );
}
