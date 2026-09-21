/**
 * Confirms that wasm actually runs inside an MV3 service worker.
 *
 * This was the biggest technical risk of the extension work. Building successfully and running
 * inside a service worker are different questions, so we load the extension into a real Chrome
 * and drive the protocol from inside the worker.
 *
 * Every signature and every reshare needs a passkey assertion, and the assertion happens in a
 * browser tab the extension opens on the server's origin. Headless Chrome has no authenticator,
 * so this script attaches a CDP virtual authenticator to each tab as it appears and carries the
 * registered credential from tab to tab (a virtual authenticator lives and dies with its tab).
 *
 * Run with: pnpm -C packages/extension smoke
 */
import { launchBrowser, requireBuilt, startServer } from './harness.mjs';

requireBuilt();

// A real recovery waits a day. This test cannot, so it waits none. What the wait protects is
// covered by the server's own tests and by the UI smoke test.
const server = await startServer({ coolingSeconds: 0 });
const session = await launchBrowser();
const { browser, popupUrl } = session;

let failed = false;
try {
  // A service worker does not receive its own messages, so drive the real path: call from the
  // popup page and let the worker handle it.
  const page = await browser.newPage();
  const popupErrors = [];
  page.on('pageerror', (error) => popupErrors.push(error.message));
  await page.goto(popupUrl);

  // The rest of this script talks to the worker, so it never draws a component. A popup that
  // fails to render (the build once produced `React is not defined` and a blank page) would pass
  // every check below. Check that the UI actually appears.
  await page
    .waitForFunction(() => document.body.innerText.includes('Unaudited'), { timeout: 15_000 })
    .catch(() => undefined);
  const drawn = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' ').trim());
  if (popupErrors.length > 0) {
    throw new Error(`the popup threw while rendering: ${popupErrors.join('; ')}`);
  }
  // Headings are uppercased by CSS, and innerText reflects that, so match without case.
  const flat = drawn.toLowerCase();
  if (!flat.includes('unaudited') || !flat.includes('create a key')) {
    throw new Error(`the popup did not render. It shows: "${drawn.slice(0, 120)}"`);
  }
  console.log('popup rendered:', drawn.slice(0, 60) + '…');

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

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const within = async (what, ms, check) => {
      const deadline = Date.now() + ms;
      for (;;) {
        const value = await check();
        if (value) return value;
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
        await sleep(300);
      }
    };

    // WebAuthn needs a domain as its relying-party id, and an IP address is not one. The server
    // defaults to `localhost`, so point the extension at that name rather than 127.0.0.1.
    await expect({ type: 'setServerUrl', serverUrl: 'http://localhost:8080' }, 'server url');

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

    // A new wallet has no passkey, and every signature through the server needs one. Signing
    // has to fail and say why, not just "authentication failed".
    const passkeyBefore = await expect({ type: 'passkeyState' }, 'passkey state');
    if (passkeyBefore.registered) throw new Error('a new wallet already has a passkey');
    const premature = await send({ type: 'sign', digestHex: 'ab'.repeat(32) });
    if (premature.ok) throw new Error('signed through the server without a passkey');
    if (!/passkey/i.test(premature.error)) {
      throw new Error(`the error does not mention the passkey: ${premature.error}`);
    }

    // Register it. The extension opens a tab on the server's origin, the virtual authenticator
    // answers there, and the server is then the one to say the wallet has a passkey.
    await expect({ type: 'registerPasskey' }, 'passkey registration');
    await within('the passkey registration', 30_000, async () => {
      const state = await expect({ type: 'passkeyState' }, 'passkey state');
      return state.registered;
    });

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

    // Nobody may replace a wallet's device key just by knowing its id. A second registration is
    // refused, and only a recovery can change it.
    const intruder = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
    ]);
    const intruderKey = [
      ...new Uint8Array(await crypto.subtle.exportKey('raw', intruder.publicKey)),
    ]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
    const overwrite = await fetch('http://localhost:8080/v1/device-key', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ wallet_id: created.walletId, public_key: intruderKey }),
    });
    if (overwrite.status !== 400) {
      throw new Error(`a second device key was not refused (status ${overwrite.status})`);
    }
    // The real key still works after that attempt.
    const stillWorks = await expect(
      { type: 'sign', digestHex },
      'signing after a refused overwrite',
    );
    if (stillWorks.signatureHex.length !== 130) throw new Error('a signature is 65 bytes');

    // Device-loss recovery: wipe this install, then restore from the recovery file. The new
    // install asks the server to trust its device key, the passkey approves, the wait passes
    // (none here), and then it signs with the recovery share plus the server
    // (docs/recovery.md, scenario 1).
    await chrome.storage.local.clear();
    // The device key lives in IndexedDB, which a lost device takes with it.
    await new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase('mpc-ext-device');
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    const wiped = await expect({ type: 'status' }, 'status after wipe');
    if (wiped.kind !== 'uninitialized') throw new Error(`expected a clean install: ${wiped.kind}`);
    // A fresh install starts on the default address, which is an IP and so cannot be a WebAuthn
    // origin. A user restoring onto a new device points it at their server again.
    await expect({ type: 'setServerUrl', serverUrl: 'http://localhost:8080' }, 'server url');

    const recoveryStarted = performance.now();
    const begun = await expect(
      { type: 'beginRecovery', walletId: created.walletId, publicKeyHex: created.publicKeyHex },
      'recovery start',
    );
    if (begun.phase !== 'awaitingAssertion') throw new Error(`unexpected phase: ${begun.phase}`);

    // Nothing may change until the passkey has approved and the wait is over: the wallet is still
    // not restored, and finishing now is refused.
    const early = await send({
      type: 'finishRecovery',
      password: 'a whole new horse',
      publicKeyHex: created.publicKeyHex,
      recoveryShareHex: created.recoveryShareHex,
    });
    if (early.ok) throw new Error('a recovery finished before the passkey approved it');
    const notYet = await expect({ type: 'status' }, 'status while recovering');
    if (notYet.kind !== 'uninitialized') throw new Error('the wallet changed before the recovery');

    // The passkey approves in the tab the extension opened. Asking the server is what starts the
    // (here zero-length) wait, so keep asking until it says the recovery is ready.
    await within('the recovery to be approved and ready', 60_000, async () => {
      const progress = await expect({ type: 'recoveryProgress' }, 'recovery progress');
      if (progress.phase === 'ended') throw new Error(`the recovery ended: ${progress.reason}`);
      return progress.phase === 'ready';
    });
    const recoveryMs = Math.round(performance.now() - recoveryStarted);

    const restored = await expect(
      {
        type: 'finishRecovery',
        password: 'a whole new horse',
        publicKeyHex: created.publicKeyHex,
        recoveryShareHex: created.recoveryShareHex,
      },
      'recovery',
    );
    if (restored.kind !== 'unlocked') throw new Error(`expected unlocked: ${restored.kind}`);
    if (!restored.recovered) throw new Error('a restored wallet must be marked as recovered');
    if (restored.publicKeyHex !== created.publicKeyHex) {
      throw new Error('recovery changed the address');
    }

    const recoveredStarted = performance.now();
    const afterRecovery = await expect({ type: 'sign', digestHex }, 'signing after recovery');
    const recoveredSignMs = Math.round(performance.now() - recoveredStarted);
    if (afterRecovery.via !== 'server') throw new Error('expected the server path');
    if (afterRecovery.signatureHex.length !== 130) throw new Error('a signature is 65 bytes');

    // Restore full protection: reshare the restored wallet (docs/adr/0007-distributed-reshare.md).
    const reshareStarted = performance.now();
    await expect({ type: 'startReshare', password: 'a whole new horse' }, 'reshare start');
    await within('the reshare', 120_000, async () => {
      const progress = await expect({ type: 'reshareProgress' }, 'reshare progress');
      if (progress.phase === 'failed') throw new Error(`the reshare failed: ${progress.error}`);
      return progress.phase === 'ready';
    });
    const reshareMs = Math.round(performance.now() - reshareStarted);
    const fresh = await expect({ type: 'takeReshareRecovery' }, 'new recovery share');
    if (fresh.publicKeyHex !== created.publicKeyHex)
      throw new Error('the reshare changed the address');
    if (fresh.recoveryShareHex === created.recoveryShareHex) {
      throw new Error('the new recovery share is the old one');
    }
    // The new recovery share is handed over once and not kept.
    const again = await send({ type: 'takeReshareRecovery' });
    if (again.ok) throw new Error('the new recovery share was handed over twice');

    // Nothing local has changed until the new recovery file is confirmed saved.
    const pendingStatus = await expect({ type: 'status' }, 'status mid-reshare');
    if (!pendingStatus.recovered || !pendingStatus.reshareInProgress) {
      throw new Error('the wallet changed before the reshare was confirmed');
    }
    const storedMidReshare = await chrome.storage.local.get('vault');
    if (storedMidReshare.vault.party !== 1) throw new Error('the vault changed before confirming');

    const healthy = await expect({ type: 'confirmReshareSaved' }, 'reshare confirmation');
    if (healthy.kind !== 'unlocked') throw new Error(`expected unlocked: ${healthy.kind}`);
    if (healthy.recovered || healthy.reshareInProgress) {
      throw new Error('a reshared wallet must no longer be marked as restored');
    }
    if (healthy.publicKeyHex !== created.publicKeyHex) throw new Error('the address changed');
    const storedAfter = await chrome.storage.local.get('vault');
    if (storedAfter.vault.party !== 0) throw new Error('the vault did not take the new share A');

    // Everyday signing with the new A' and the new C'.
    const afterReshare = await expect({ type: 'sign', digestHex }, 'signing after the reshare');
    if (afterReshare.via !== 'server') throw new Error('expected the server path');
    if (afterReshare.signatureHex.length !== 130) throw new Error('a signature is 65 bytes');

    // The new recovery file works with the new A'...
    const newFile = await expect(
      { type: 'signOffline', digestHex, recoveryShareHex: fresh.recoveryShareHex },
      'offline signing with the new recovery file',
    );
    if (newFile.signatureHex.length !== 130) throw new Error('a signature is 65 bytes');

    // ...and the old one no longer does. It belongs to a different polynomial.
    const staleFile = await send({
      type: 'signOffline',
      digestHex,
      recoveryShareHex: created.recoveryShareHex,
    });
    if (staleFile.ok) throw new Error('the old recovery file still signs with the new A');

    return {
      reshareMs,
      recoveryMs,
      config: health.config,
      loadMs: health.loadMs,
      dkgMs,
      signMs,
      recoveredSignMs,
      publicKey: created.publicKeyHex,
      recoveryShareBytes: created.recoveryShareHex.length / 2,
    };
  });

  console.log('\n--- measured inside the MV3 service worker ---');
  console.log(`threshold        ${result.config}`);
  console.log(`wasm load        ${result.loadMs} ms`);
  console.log(`DKG (3 parties)  ${result.dkgMs} ms   (extension + server)`);
  console.log(`signing          ${result.signMs} ms   (extension + server)`);
  console.log(`signing restored ${result.recoveredSignMs} ms   (recovery file + server)`);
  console.log(`recovery         ${result.recoveryMs} ms   (passkey approval included, no wait)`);
  console.log(`reshare          ${result.reshareMs} ms   (passkey approval included)`);
  console.log(`public key       ${result.publicKey.slice(0, 24)}…`);
  console.log(`recovery share   ${result.recoveryShareBytes} bytes`);

  if (result.config !== '2-of-3') throw new Error(`unexpected threshold: ${result.config}`);
  if (result.publicKey.length !== 66) throw new Error('the public key is not 33 bytes');
  console.log(
    '\nPASS: DKG with the server, atomic onboarding, passkey-approved signing, the offline\n' +
      '      fallback, lock/unlock, device-loss recovery and the distributed reshare all work\n' +
      '      inside the MV3 service worker.',
  );
} catch (error) {
  failed = true;
  console.error('\nFAIL:', error.message);
} finally {
  await session?.close();
  await server?.stop();
}

process.exit(failed ? 1 : 0);
