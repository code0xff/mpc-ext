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
        <p className="warn">감사 전입니다. 실자산에 사용하지 마세요.</p>
      </header>

      <section>
        <h2>상태</h2>
        <dl>
          <dt>지갑</dt>
          <dd id="wallet-status">{status ? describe(status) : '확인 중…'}</dd>
          <dt>MPC 엔진</dt>
          <dd>{health ? `${health.config} · ${health.loadMs}ms에 로드` : '확인 중…'}</dd>
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
          <h2>복구 파일을 저장하세요</h2>
          <p>
            이 파일은 <b>지금만</b> 만들 수 있습니다. 확장은 이 셰어를 저장하지 않습니다. 기기를
            잃거나 서버가 멈추면 이 파일이 유일한 수단입니다.
          </p>
          <p className="warn">
            확장과 <b>다른 곳</b>에 보관하세요. 같은 기기에 두면 이 설계의 의미가 사라집니다. 파일은
            잃어버리기 쉬우니 복사본을 여러 곳에 두세요.
          </p>
          <button
            type="button"
            id="download-recovery"
            onClick={() => {
              downloadRecoveryFile(created);
              setDownloaded(true);
            }}
          >
            복구 파일 내려받기 (약 230 KB)
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
            {downloaded ? '저장했습니다 — 지갑 사용 시작' : '먼저 파일을 내려받으세요'}
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
            취소하고 처음부터
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
          <h2>지갑</h2>
          <p className="mono">{status.publicKeyHex}</p>
          <p>서명은 서버 연동(Phase 3) 이후에 동작합니다.</p>
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
            잠그기
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
      <h2>키 만들기</h2>
      <p>
        셰어 3개를 만듭니다. 확장은 <b>하나만</b> 보관하고, 하나는 복구 파일로 내보내며, 나머지
        하나는 서버가 갖습니다.
      </p>
      <label htmlFor="password">비밀번호 (8자 이상)</label>
      <input
        id="password"
        type="password"
        value={password}
        autoComplete="new-password"
        onChange={(event) => setPassword(event.target.value)}
      />
      <label htmlFor="password-confirm">비밀번호 확인</label>
      <input
        id="password-confirm"
        type="password"
        value={confirmation}
        autoComplete="new-password"
        onChange={(event) => setConfirmation(event.target.value)}
      />
      {tooShort && <p className="error">8자 이상 입력하세요.</p>}
      {mismatched && <p className="error">비밀번호가 일치하지 않습니다.</p>}
      <button
        type="button"
        id="create-key"
        disabled={!ready || busy}
        onClick={() => onCreate(password)}
      >
        {busy ? '생성 중… (몇 초 걸립니다)' : '키 생성'}
      </button>
    </section>
  );
}

function Unlock({ busy, onUnlock }: { busy: boolean; onUnlock: (password: string) => void }) {
  const [password, setPassword] = useState('');

  return (
    <section>
      <h2>잠금 해제</h2>
      <label htmlFor="unlock-password">비밀번호</label>
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
        열기
      </button>
    </section>
  );
}

function describe(status: Status): string {
  switch (status.kind) {
    case 'uninitialized':
      return '아직 키가 없습니다';
    case 'awaitingRecoveryExport':
      return '복구 파일 저장 대기 중';
    case 'locked':
      return '잠김';
    case 'unlocked':
      return `열림 · ${status.publicKeyHex.slice(0, 16)}…`;
  }
}
