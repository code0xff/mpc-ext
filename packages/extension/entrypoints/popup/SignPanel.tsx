import { useCallback, useRef, useState } from 'react';

import type { Signed } from '../../src/messages';
import { openRecoveryFile } from '../../src/recoveryFile';
import { send } from './api';

/**
 * The signing panel.
 *
 * Phase 3 signs a digest the user pastes in, which is enough to exercise both paths. The real
 * approval screen — showing the requesting origin and a decoded transaction — arrives with the
 * web provider (`docs/web-api.md`).
 */
export function SignPanel({
  serverUp,
  passkeyMissing = false,
}: {
  serverUp: boolean | undefined;
  /** The wallet has no passkey yet, so the server cannot take part in a signature. */
  passkeyMissing?: boolean;
}) {
  const [digest, setDigest] = useState('');
  const [result, setResult] = useState<Signed>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [filePassword, setFilePassword] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);

  const valid = /^[0-9a-fA-F]{64}$/.test(digest);

  const signWithServer = useCallback(async () => {
    setBusy(true);
    setError(undefined);
    try {
      setResult(await send<Signed>({ type: 'sign', digestHex: digest.toLowerCase() }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, [digest]);

  const signWithFile = useCallback(
    async (file: File) => {
      setBusy(true);
      setError(undefined);
      try {
        const opened = await openRecoveryFile(JSON.parse(await file.text()), filePassword);
        setResult(
          await send<Signed>({
            type: 'signOffline',
            digestHex: digest.toLowerCase(),
            recoveryShareHex: opened.shareHex,
          }),
        );
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setBusy(false);
      }
    },
    [digest, filePassword],
  );

  return (
    <section>
      <h2>Sign</h2>
      <label htmlFor="digest">32-byte digest (hex)</label>
      <input
        id="digest"
        value={digest}
        placeholder="64 hex characters"
        onChange={(event) => {
          setDigest(event.target.value);
          setResult(undefined);
        }}
      />

      {passkeyMissing && (
        <p className="warn" id="passkey-missing">
          Register your passkey above to sign through the server. You can still sign with your
          recovery file.
        </p>
      )}

      {serverUp === false && (
        <p className="warn">
          The server is unreachable. You can still sign with your recovery file.
        </p>
      )}

      <button
        type="button"
        id="sign"
        disabled={passkeyMissing || !valid || busy}
        onClick={() => void signWithServer()}
      >
        {busy ? 'Signing…' : 'Sign with the server'}
      </button>

      <label htmlFor="recovery-file-password">Recovery file password</label>
      <input
        id="recovery-file-password"
        type="password"
        value={filePassword}
        autoComplete="off"
        onChange={(event) => setFilePassword(event.target.value)}
      />

      <button
        type="button"
        id="sign-offline"
        className="secondary"
        disabled={!valid || busy}
        onClick={() => fileInput.current?.click()}
      >
        Sign with my recovery file
      </button>
      <input
        ref={fileInput}
        id="recovery-file"
        type="file"
        accept="application/json"
        hidden
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) void signWithFile(file);
          event.target.value = '';
        }}
      />

      {result && (
        <>
          <p>
            Signed via <b>{result.via === 'server' ? 'the server' : 'your recovery file'}</b>.
          </p>
          <p className="mono">{result.signatureHex}</p>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
