/**
 * Confirms that wasm actually runs inside an MV3 service worker.
 *
 * This was the biggest technical risk of the extension work. Building successfully and running
 * inside a service worker are different questions, so we load the extension into a real Chrome
 * and drive the protocol from inside the worker.
 *
 * Run with: pnpm -C packages/extension smoke
 */
import { spawn } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import puppeteer from 'puppeteer-core';

/**
 * From Chrome 137 on, the regular browser ignores `--load-extension` for security reasons, so
 * automation needs Chrome for Testing:
 * `pnpm dlx @puppeteer/browsers install chrome@stable`.
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
  console.error('No extension build found. Run `make build` first.');
  process.exit(1);
}

if (!CHROME) {
  console.error(
    'Chrome for Testing is missing. Run `pnpm dlx @puppeteer/browsers install chrome@stable`.',
  );
  process.exit(1);
}

/**
 * The extension now needs the server to take part in DKG and signing, so the smoke test runs a
 * real one against a throwaway database.
 */
const SERVER_BIN = new URL('../../../target/release/mpc-server', import.meta.url).pathname;

if (!existsSync(SERVER_BIN)) {
  console.error('No server binary found. Run `make build-server` first.');
  process.exit(1);
}

const serverDir = await mkdtemp(join(tmpdir(), 'mpc-ext-server-'));
const server = spawn(SERVER_BIN, [], {
  stdio: 'inherit',
  env: {
    ...process.env,
    MPC_SERVER_ADDR: '127.0.0.1:8080',
    MPC_SERVER_DATABASE: `sqlite://${join(serverDir, 'smoke.db')}`,
    // A throwaway key for this run only. Never reuse a test key anywhere real.
    MPC_SERVER_SEALING_KEY: '11'.repeat(32),
    RUST_LOG: 'warn',
  },
});

// Wait for the server to answer before driving the extension.
let serverUp = false;
for (let attempt = 0; attempt < 50; attempt += 1) {
  try {
    const response = await fetch('http://127.0.0.1:8080/v1/health');
    if (response.ok) {
      serverUp = true;
      break;
    }
  } catch {
    // Not listening yet.
  }
  await delay(200);
}
if (!serverUp) {
  server.kill();
  console.error('The server did not come up on 127.0.0.1:8080.');
  process.exit(1);
}
console.log('server ready on 127.0.0.1:8080');

const profile = await mkdtemp(join(tmpdir(), 'mpc-ext-smoke-'));
const browser = await puppeteer.launch({
  executablePath: CHROME,
  // MV3 extensions load only in the new headless mode. CI behaves the same way.
  headless: process.env.SMOKE_HEADFUL ? false : 'new',
  userDataDir: profile,
  // puppeteer's default arguments include --disable-extensions, which stops the load.
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
  // Wait for the service worker to register.
  const target = await browser
    .waitForTarget((t) => t.type() === 'service_worker', { timeout: 20_000 })
    .catch(async (cause) => {
      const seen = browser.targets().map((t) => `${t.type()} ${t.url()}`);
      throw new Error(`${cause.message}\nTargets seen:\n  ${seen.join('\n  ')}`);
    });
  const worker = await target.worker();
  if (!worker) throw new Error('could not attach to the service worker');

  console.log('service worker registered:', target.url());

  // A service worker does not receive its own messages, so drive the real path: call from the
  // popup page and let the worker handle it.
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
    const expect = async (request, what) => {
      const response = await send(request);
      if (!response.ok) throw new Error(`${what}: ${response.error}`);
      return response.value;
    };

    const health = await expect({ type: 'wasmHealth' }, 'wasm load');

    const before = await expect({ type: 'status' }, 'initial status');
    if (before.kind !== 'uninitialized')
      throw new Error(`unexpected initial state: ${before.kind}`);

    const started = performance.now();
    const created = await expect({ type: 'createKey', password: 'correct horse' }, 'DKG');
    const dkgMs = Math.round(performance.now() - started);

    // Nothing may be persisted before the recovery file is saved (atomic onboarding).
    const midway = await expect({ type: 'status' }, 'intermediate status');
    if (midway.kind !== 'awaitingRecoveryExport') {
      throw new Error(`expected to be awaiting the recovery export: ${midway.kind}`);
    }
    const storedMidway = await chrome.storage.local.get('vault');
    if (storedMidway.vault) throw new Error('a share was stored before the recovery export');

    const confirmed = await expect({ type: 'confirmRecoverySaved' }, 'recovery confirmation');
    if (confirmed.kind !== 'unlocked') throw new Error(`expected unlocked: ${confirmed.kind}`);

    // Lock, reject the wrong password, then unlock with the right one.
    const locked = await expect({ type: 'lock' }, 'lock');
    if (locked.kind !== 'locked') throw new Error(`expected locked: ${locked.kind}`);

    const wrong = await send({ type: 'unlock', password: 'wrong horse' });
    if (wrong.ok) throw new Error('a wrong password was accepted');

    const unlocked = await expect({ type: 'unlock', password: 'correct horse' }, 'unlock');
    if (unlocked.kind !== 'unlocked') throw new Error(`expected unlocked: ${unlocked.kind}`);
    if (unlocked.publicKeyHex !== created.publicKeyHex) {
      throw new Error('the public key changed after unlocking');
    }

    // No plaintext share may survive in storage.
    const stored = await chrome.storage.local.get('vault');
    const serialized = JSON.stringify(stored);
    if (serialized.includes(created.recoveryShareHex.slice(0, 64))) {
      throw new Error('a plaintext share survived in storage');
    }

    // Everyday signing: extension share plus the server share.
    const digestHex = 'ab'.repeat(32);
    const signStarted = performance.now();
    const signed = await expect({ type: 'sign', digestHex }, 'signing');
    const signMs = Math.round(performance.now() - signStarted);
    if (signed.via !== 'server') throw new Error(`expected the server path, got ${signed.via}`);
    if (signed.signatureHex.length !== 130) throw new Error('a signature is 65 bytes');

    // The offline path: extension share plus the recovery file, no server involved.
    const offline = await expect(
      { type: 'signOffline', digestHex, recoveryShareHex: created.recoveryShareHex },
      'offline signing',
    );
    if (offline.via !== 'recoveryFile') throw new Error('expected the recovery-file path');
    if (offline.signatureHex.length !== 130) throw new Error('a signature is 65 bytes');

    // Locked wallets must not sign.
    await expect({ type: 'lock' }, 'lock');
    const refused = await send({ type: 'sign', digestHex });
    if (refused.ok) throw new Error('a locked wallet produced a signature');
    await expect({ type: 'unlock', password: 'correct horse' }, 'unlock');

    return {
      config: health.config,
      loadMs: health.loadMs,
      dkgMs,
      signMs,
      publicKey: created.publicKeyHex,
      recoveryShareBytes: created.recoveryShareHex.length / 2,
    };
  });

  console.log('\n--- measured inside the MV3 service worker ---');
  console.log(`threshold        ${result.config}`);
  console.log(`wasm load        ${result.loadMs} ms`);
  console.log(`DKG (3 parties)  ${result.dkgMs} ms   (extension + server)`);
  console.log(`signing          ${result.signMs} ms   (extension + server)`);
  console.log(`public key       ${result.publicKey.slice(0, 24)}…`);
  console.log(`recovery share   ${result.recoveryShareBytes} bytes`);

  if (result.config !== '2-of-3') throw new Error(`unexpected threshold: ${result.config}`);
  if (result.publicKey.length !== 66) throw new Error('the public key is not 33 bytes');
  console.log(
    '\nPASS: DKG with the server, atomic onboarding, everyday signing, the offline fallback\n' +
      '      and lock/unlock all work inside the MV3 service worker.',
  );
} catch (error) {
  failed = true;
  console.error('\nFAIL:', error.message);
} finally {
  await browser.close();
  server.kill();
  await rm(profile, { recursive: true, force: true });
  await rm(serverDir, { recursive: true, force: true });
}

process.exit(failed ? 1 : 0);
