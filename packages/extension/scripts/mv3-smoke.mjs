/**
 * MV3 서비스 워커에서 wasm이 실제로 구동되는지 확인한다.
 *
 * Phase 2의 최대 기술 리스크였다. 빌드가 되는 것과 서비스 워커에서 도는 것은
 * 다른 문제이므로, 실제 Chrome에 확장을 올려 워커 안에서 프로토콜을 실행한다.
 *
 * 실행: pnpm -C packages/extension smoke
 */
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import puppeteer from 'puppeteer-core';

/**
 * Chrome 137부터 일반 Chrome은 보안상 `--load-extension`을 무시한다. 자동화에는
 * Chrome for Testing을 쓴다 — `pnpm dlx @puppeteer/browsers install chrome@stable`.
 */
function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const root = new URL('../../../chrome/', import.meta.url).pathname;
  if (!existsSync(root)) return undefined;
  for (const dir of readdirSync(root)) {
    const candidate = join(
      root,
      dir,
      'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    );
    if (existsSync(candidate)) return candidate;
    const linux = join(root, dir, 'chrome-linux64/chrome');
    if (existsSync(linux)) return linux;
  }
  return undefined;
}

const CHROME = findChrome();
const EXTENSION = new URL('../.output/chrome-mv3', import.meta.url).pathname;

if (!existsSync(EXTENSION)) {
  console.error('확장 빌드가 없습니다. 먼저 `make build`를 실행하세요.');
  process.exit(1);
}

if (!CHROME) {
  console.error(
    'Chrome for Testing이 없습니다. `pnpm dlx @puppeteer/browsers install chrome@stable`을 실행하세요.',
  );
  process.exit(1);
}

const profile = await mkdtemp(join(tmpdir(), 'mpc-ext-smoke-'));
const browser = await puppeteer.launch({
  executablePath: CHROME,
  // MV3 확장은 새 headless 모드에서만 로드된다. CI에서도 동일하게 동작한다.
  headless: process.env.SMOKE_HEADFUL ? false : 'new',
  userDataDir: profile,
  // puppeteer 기본 인자에 --disable-extensions가 들어 있어 확장이 로드되지 않는다.
  ignoreDefaultArgs: ['--disable-extensions'],
  args: [
    `--disable-extensions-except=${EXTENSION}`,
    `--load-extension=${EXTENSION}`,
    '--no-first-run',
    '--no-default-browser-check',
  ],
});

let failed = false;
try {
  // 서비스 워커가 등록될 때까지 기다린다.
  const target = await browser
    .waitForTarget((t) => t.type() === 'service_worker', { timeout: 20_000 })
    .catch(async (cause) => {
      const seen = browser.targets().map((t) => `${t.type()} ${t.url()}`);
      throw new Error(`${cause.message}\n발견된 타깃:\n  ${seen.join('\n  ')}`);
    });
  const worker = await target.worker();
  if (!worker) throw new Error('서비스 워커에 붙지 못했습니다');

  console.log('서비스 워커 등록됨:', target.url());

  // 서비스 워커가 자기 자신에게 보낸 메시지는 수신되지 않는다. 실제 경로대로
  // 팝업 페이지에서 호출해 서비스 워커가 처리하게 한다.
  const extensionId = new URL(target.url()).host;
  const page = await browser.newPage();
  await page.goto(`chrome-extension://${extensionId}/popup.html`);

  const result = await page.evaluate(async () => {
    const send = (request) =>
      new Promise((resolve, reject) =>
        chrome.runtime.sendMessage(request, (response) => {
          const failure = chrome.runtime.lastError;
          if (failure) reject(new Error(failure.message));
          else resolve(response);
        }),
      );

    const health = await send({ type: 'wasmHealth' });
    if (!health.ok) throw new Error(`wasm 로드 실패: ${health.error}`);

    const started = performance.now();
    const created = await send({ type: 'createKey' });
    if (!created.ok) throw new Error(`DKG 실패: ${created.error}`);
    const dkgMs = Math.round(performance.now() - started);

    return {
      config: health.value.config,
      loadMs: health.value.loadMs,
      dkgMs,
      publicKey: created.value.publicKeyHex,
      recoveryShareBytes: created.value.recoveryShareHex.length / 2,
    };
  });

  console.log('\n--- MV3 서비스 워커 실측 ---');
  console.log(`임계 설정      ${result.config}`);
  console.log(`wasm 로드      ${result.loadMs} ms`);
  console.log(`DKG (3파티)    ${result.dkgMs} ms`);
  console.log(`공개키         ${result.publicKey.slice(0, 24)}…`);
  console.log(`복구 셰어 크기 ${result.recoveryShareBytes} bytes`);

  if (result.config !== '2-of-3') throw new Error(`임계 설정이 다릅니다: ${result.config}`);
  if (result.publicKey.length !== 66) throw new Error('공개키 길이가 33바이트가 아닙니다');
  console.log('\n통과: MV3 서비스 워커에서 wasm DKG가 동작합니다.');
} catch (error) {
  failed = true;
  console.error('\n실패:', error.message);
} finally {
  await browser.close();
  await rm(profile, { recursive: true, force: true });
}

process.exit(failed ? 1 : 0);
