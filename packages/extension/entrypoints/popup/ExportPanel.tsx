import { useCallback, useEffect, useRef, useState } from 'react';

import type { ExportedKey } from '../../src/messages';
import { openRecoveryFile } from '../../src/recoveryFile';
import { send } from './api';

/** How long the key stays on screen, and how long a copy stays on the clipboard. */
const REVEAL_MS = 60_000;
const CLIPBOARD_MS = 30_000;

/**
 * Full private key export.
 *
 * This ends the MPC protection for whoever holds the result, so it sits behind an explicit
 * acknowledgement, the wallet password, and the recovery file (`docs/export.md`). The key is held
 * in component state only, hidden again after a minute, and never written anywhere.
 */
export function ExportPanel({ publicKeyHex }: { publicKeyHex: string }) {
  const [open, setOpen] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [password, setPassword] = useState('');
  const [file, setFile] = useState<unknown>();
  const [fileName, setFileName] = useState('');
  const [filePassword, setFilePassword] = useState('');
  const [privateKey, setPrivateKey] = useState<string>();
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const input = useRef<HTMLInputElement>(null);

  const ready = acknowledged && password.length > 0 && file !== undefined && filePassword;

  const hide = useCallback(() => {
    setPrivateKey(undefined);
    setCopied(false);
    setPassword('');
    setFilePassword('');
    setFile(undefined);
    setFileName('');
    setAcknowledged(false);
  }, []);

  // Hide the key again after a while, and when the panel goes away.
  useEffect(() => {
    if (!privateKey) return;
    const timer = setTimeout(hide, REVEAL_MS);
    return () => clearTimeout(timer);
  }, [privateKey, hide]);
  useEffect(() => hide, [hide]);

  const load = useCallback(async (picked: File) => {
    setError(undefined);
    try {
      const parsed: unknown = JSON.parse(await picked.text());
      if ((parsed as { kind?: string } | null)?.kind !== 'mpc-ext-recovery') {
        throw new Error('That does not look like an mpc-ext recovery file.');
      }
      setFile(parsed);
      setFileName(picked.name);
    } catch (cause) {
      setFile(undefined);
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  const reveal = useCallback(async () => {
    if (file === undefined) return;
    setBusy(true);
    setError(undefined);
    try {
      const opened = await openRecoveryFile(file, filePassword);
      if (opened.publicKeyHex !== publicKeyHex) {
        throw new Error('This recovery file belongs to a different wallet.');
      }
      const result = await send<ExportedKey>({
        type: 'exportPrivateKey',
        password,
        recoveryShareHex: opened.shareHex,
      });
      setPrivateKey(result.privateKeyHex);
      setPassword('');
      setFilePassword('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, [file, filePassword, password, publicKeyHex]);

  const copy = useCallback(async () => {
    if (!privateKey) return;
    try {
      await navigator.clipboard.writeText(privateKey);
      setCopied(true);
      // Best effort: the popup may close first, in which case the timer never fires.
      setTimeout(() => void navigator.clipboard.writeText('').catch(() => undefined), CLIPBOARD_MS);
    } catch {
      setError('Could not copy. Select the key and copy it by hand.');
    }
  }, [privateKey]);

  if (!open) {
    return (
      <section>
        <h2>Export private key</h2>
        <p>Take the whole key out of MPC, for example to move to another wallet.</p>
        <button type="button" id="open-export" className="secondary" onClick={() => setOpen(true)}>
          Export private key…
        </button>
      </section>
    );
  }

  return (
    <section className="callout">
      <h2>Export private key</h2>
      <p className="warn">
        <b>Anyone who sees this key controls your funds, permanently.</b> Exporting it removes the
        protection of splitting it across three places. Do it only to move your funds, then stop
        using this wallet and move to a new one.
      </p>

      {privateKey ? (
        <>
          <p className="mono" id="exported-key">
            {privateKey}
          </p>
          <p>It hides itself after a minute and is never stored by the extension.</p>
          <button type="button" id="copy-key" onClick={() => void copy()}>
            {copied ? 'Copied — clears in 30 seconds' : 'Copy'}
          </button>
          <button type="button" className="secondary" onClick={hide}>
            Hide now
          </button>
        </>
      ) : (
        <>
          <label className="check">
            <input
              id="export-ack"
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />{' '}
            I understand that this key gives full, permanent control of my funds.
          </label>

          <label htmlFor="export-password">Wallet password</label>
          <input
            id="export-password"
            type="password"
            value={password}
            autoComplete="off"
            onChange={(event) => setPassword(event.target.value)}
          />

          <button
            type="button"
            id="pick-export-file"
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

          <label htmlFor="export-file-password">Recovery file password</label>
          <input
            id="export-file-password"
            type="password"
            value={filePassword}
            autoComplete="off"
            onChange={(event) => setFilePassword(event.target.value)}
          />

          <button
            type="button"
            id="reveal-key"
            disabled={!ready || busy}
            onClick={() => void reveal()}
          >
            {busy ? 'Working…' : 'Show private key'}
          </button>
          <button
            type="button"
            className="quiet"
            onClick={() => {
              hide();
              setOpen(false);
            }}
          >
            Cancel
          </button>
        </>
      )}

      {error && <p className="error">{error}</p>}
    </section>
  );
}
