import { useState } from 'react';

/**
 * Offers to make a restored wallet healthy again (`docs/adr/0007-distributed-reshare.md`).
 *
 * Recovery leaves the extension and the recovery file holding the same share, and the lost
 * device's share still valid. A reshare replaces all three shares and keeps the address. This
 * card says plainly what that costs before it asks for the password.
 */
export function ReshareCard({
  busy,
  working,
  interrupted,
  onStart,
  onCancel,
}: {
  busy: boolean;
  /** A reshare is running: waiting for the passkey approval, then the protocol. */
  working: boolean;
  /** A reshare was started earlier and its recovery file was never saved. */
  interrupted: boolean;
  onStart: (password: string) => void;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState('');

  if (working) {
    return (
      <section className="callout">
        <h2>Restoring full protection</h2>
        <p>
          Approve the request with your passkey in the tab that just opened. This window may close
          while you do. Open it again afterwards to save your new recovery file.
        </p>
        <button type="button" id="cancel-reshare" className="quiet" onClick={onCancel}>
          Cancel
        </button>
      </section>
    );
  }

  if (interrupted) {
    return (
      <section className="callout">
        <h2>A reshare was interrupted</h2>
        <p>
          A new server share was prepared but its recovery file was never saved. Nothing has changed
          yet. Cancel it and start again.
        </p>
        <button type="button" id="cancel-reshare" disabled={busy} onClick={onCancel}>
          Cancel the reshare
        </button>
      </section>
    );
  }

  return (
    <section className="callout">
      <h2>Restore full protection</h2>
      <p>
        This wallet works, but it is not fully protected. The share on your lost device is still
        valid, and your recovery file is no longer a separate backup. A reshare fixes both and keeps
        your address.
      </p>
      <ul>
        <li>
          It needs your passkey. The server replaces its share, so it asks for the same approval as
          a signature.
        </li>
        <li>
          For a moment this device can work out your full key, exactly as it can when a key is
          created. Do this only on a device you trust.
        </li>
        <li>
          You will save a <b>new</b> recovery file. <b>Destroy the old one</b>: together with the
          lost device it can still sign.
        </li>
      </ul>
      <label htmlFor="reshare-password">Wallet password</label>
      <input
        id="reshare-password"
        type="password"
        value={password}
        autoComplete="current-password"
        onChange={(event) => setPassword(event.target.value)}
      />
      <button
        type="button"
        id="start-reshare"
        disabled={!password || busy}
        onClick={() => onStart(password)}
      >
        {busy ? 'Working… (this takes a few seconds)' : 'Restore full protection'}
      </button>
    </section>
  );
}
