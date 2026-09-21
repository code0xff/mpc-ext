import { useEffect, useState, type ReactNode } from 'react';

import type { CreatedKey } from '../../src/messages';
import { MIN_PASSWORD_LENGTH } from '../../src/recoveryFile';
import { send } from './api';
import { downloadRecoveryFile } from './recoveryFile';

/**
 * Saving a recovery file (share B). Used at key creation and again after a reshare, because both
 * hand the user a share the extension will not keep (`docs/export.md`).
 *
 * The file is encrypted under a recovery password chosen here. Confirming is possible only after
 * a download, and the caller decides what confirming does.
 */
export function RecoveryExportCard({
  created,
  heading,
  intro,
  confirmLabel,
  cancelLabel,
  busy,
  onConfirm,
  onCancel,
}: {
  created: CreatedKey;
  heading: string;
  intro: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [downloaded, setDownloaded] = useState(false);
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string>();
  const [manageUrl, setManageUrl] = useState<string>();

  // The address of the page that shows and cancels a waiting recovery with only the passkey. It is
  // worth writing down now, because it is needed on the day the device is gone
  // (docs/adr/0010-notifying-the-owner-of-a-recovery.md).
  useEffect(() => {
    void send<{ serverUrl: string }>({ type: 'readSettings' })
      .then((settings) => setManageUrl(`${settings.serverUrl}/manage`))
      .catch(() => undefined);
  }, []);

  const download = async () => {
    setWorking(true);
    setError(undefined);
    try {
      await downloadRecoveryFile(created, password);
      setDownloaded(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setWorking(false);
    }
  };

  return (
    <section className="callout">
      <h2>{heading}</h2>
      {intro}
      <p className="warn">
        Keep it <b>somewhere other than</b> this machine. Storing it alongside the extension defeats
        the design. Files are easy to lose, so keep several copies.
      </p>
      <p>
        The file is encrypted with a <b>recovery password</b> you choose now. You will need it to
        restore or to sign without the server, so write it down separately. It can differ from your
        wallet password.
      </p>
      <p id="manage-bookmark">
        Also keep this address: <span className="mono">{manageUrl ?? 'your server + /manage'}</span>
        . If someone ever asks to take over your wallet, nothing will tell you. From any browser,
        with your passkey, you can look there and cancel it.
      </p>
      <label htmlFor="recovery-password">Recovery password</label>
      <input
        id="recovery-password"
        type="password"
        value={password}
        autoComplete="new-password"
        onChange={(event) => {
          setPassword(event.target.value);
          setDownloaded(false);
        }}
      />
      <label htmlFor="recovery-password-again">Repeat recovery password</label>
      <input
        id="recovery-password-again"
        type="password"
        value={again}
        autoComplete="new-password"
        onChange={(event) => setAgain(event.target.value)}
      />
      <button
        type="button"
        id="download-recovery"
        disabled={busy || working || password.length < MIN_PASSWORD_LENGTH || password !== again}
        onClick={() => void download()}
      >
        Download recovery file (about 230 KB)
      </button>
      <button
        type="button"
        id="confirm-recovery"
        className="secondary"
        disabled={!downloaded || busy}
        onClick={onConfirm}
      >
        {downloaded ? confirmLabel : 'Download the file first'}
      </button>
      <button type="button" className="quiet" disabled={busy} onClick={onCancel}>
        {cancelLabel}
      </button>
      {error && <p className="error">{error}</p>}
    </section>
  );
}
