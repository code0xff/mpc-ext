import { useCallback, useEffect, useState } from 'react';

import type { CreatedKey, Status } from '../../src/messages';
import { send } from './api';

interface WasmHealth {
  config: string;
  loadMs: number;
}

export function App() {
  const [status, setStatus] = useState<Status>();
  const [health, setHealth] = useState<WasmHealth>();
  const [created, setCreated] = useState<CreatedKey>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    void send<Status>({ type: 'status' }).then(setStatus).catch(showError);
    // 워커가 살아 있고 wasm이 실제로 구동되는지 확인한다.
    void send<WasmHealth>({ type: 'wasmHealth' }).then(setHealth).catch(showError);
  }, []);

  function showError(cause: unknown) {
    setError(cause instanceof Error ? cause.message : String(cause));
  }

  const createKey = useCallback(async () => {
    setBusy(true);
    setError(undefined);
    try {
      setCreated(await send<CreatedKey>({ type: 'createKey' }));
      setStatus(await send<Status>({ type: 'status' }));
    } catch (cause) {
      showError(cause);
    } finally {
      setBusy(false);
    }
  }, []);

  const downloadRecoveryFile = useCallback(() => {
    if (!created) return;
    const payload = {
      formatVersion: 1,
      note: 'mpc-ext 복구 파일 (셰어 B). 확장과 다른 곳에 보관하세요.',
      publicKey: created.publicKeyHex,
      share: created.recoveryShareHex,
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = `mpc-ext-recovery-${created.publicKeyHex.slice(0, 8)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }, [created]);

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
          <dd>{status ? describe(status) : '확인 중…'}</dd>
          <dt>MPC 엔진</dt>
          <dd>{health ? `${health.config} · ${health.loadMs}ms에 로드` : '확인 중…'}</dd>
        </dl>
      </section>

      {status?.kind === 'uninitialized' && !created && (
        <section>
          <h2>키 만들기</h2>
          <p>
            셰어 3개를 만듭니다. 확장은 <b>하나만</b> 보관하고, 하나는 복구 파일로 내보내며, 나머지
            하나는 서버가 갖습니다.
          </p>
          <button type="button" onClick={() => void createKey()} disabled={busy}>
            {busy ? '생성 중… (몇 초 걸립니다)' : '키 생성'}
          </button>
        </section>
      )}

      {created && (
        <section className="callout">
          <h2>복구 파일을 저장하세요</h2>
          <p>
            이 파일은 <b>지금만</b> 만들 수 있습니다. 확장은 이 셰어를 저장하지 않습니다. 기기를
            잃거나 서버가 멈추면 이 파일이 유일한 복구 수단입니다.
          </p>
          <p className="warn">확장과 다른 곳에 보관하세요. 같은 기기에 두면 의미가 없습니다.</p>
          <button type="button" onClick={downloadRecoveryFile}>
            복구 파일 내려받기
          </button>
          <p className="mono">공개키 {created.publicKeyHex.slice(0, 20)}…</p>
        </section>
      )}

      {error && <p className="error">{error}</p>}
    </main>
  );
}

function describe(status: Status): string {
  switch (status.kind) {
    case 'uninitialized':
      return '아직 키가 없습니다';
    case 'locked':
      return '잠김';
    case 'unlocked':
      return `열림 · ${status.address.slice(0, 16)}…`;
  }
}
