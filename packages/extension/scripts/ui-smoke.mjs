/**
 * Drives the popup the way a user does, in a real Chrome against a real server.
 *
 * `mv3-smoke.mjs` sends messages to the service worker, which proves the protocol works but never
 * exercises a component. Nothing there would notice a card that throws while rendering, a button
 * that is never enabled, or a state the UI does not follow. It did not even notice that the popup
 * was a blank page. This script only types, clicks and chooses files, and asserts on what the page
 * shows.
 *
 * Scenario A is one person on one device: create a wallet, save the recovery file, register the
 * passkey, sign, lose the device, restore, reshare and take the key out.
 * Scenario B is two devices: a recovery started on a new one shows up on the old one, which
 * cancels it.
 * Scenario C is the same recovery with the old device gone, cancelled from a browser that has only
 * the passkey, at the server's own /manage page.
 *
 * Run with: pnpm -C packages/extension ui-smoke
 */
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { launchBrowser, requireBuilt, startServer } from './harness.mjs';

requireBuilt();

const SERVER = 'http://localhost:8080';
const WALLET_PASSWORD = 'correct horse';
const RECOVERY_PASSWORD = 'staple battery';
const NEW_WALLET_PASSWORD = 'a whole new horse';
const RESHARED_RECOVERY_PASSWORD = 'another staple';

// ---------------------------------------------------------------------------------------------
// Small helpers. Each does one thing a user does, and fails with what it was waiting for.
// ---------------------------------------------------------------------------------------------

async function shown(page) {
  const text = await page.evaluate(() => document.body.innerText).catch(() => '(page gone)');
  return text.replace(/\s+/g, ' ').slice(0, 500);
}

/** Waits for a selector, and fails with what the page shows instead. */
async function see(page, selector, { timeout = 20_000, hidden = false } = {}) {
  try {
    return await page.waitForSelector(selector, { timeout, hidden, visible: !hidden });
  } catch {
    const what = hidden ? 'expected to stop seeing' : 'expected to see';
    throw new Error(`${what} ${selector}. The page shows:\n${await shown(page)}`);
  }
}

/**
 * Waits until the page's text contains `text`, ignoring case.
 *
 * Headings are upper-cased by the stylesheet, and `innerText` returns the text as it is drawn, so
 * "Someone asked" reads as "SOMEONE ASKED" on the page.
 */
async function seeText(page, text, { timeout = 20_000 } = {}) {
  try {
    await page.waitForFunction(
      (t) => document.body.innerText.toLowerCase().includes(t.toLowerCase()),
      { timeout },
      text,
    );
  } catch {
    throw new Error(`expected the page to say "${text}". It shows:\n${await shown(page)}`);
  }
}

/**
 * Types into a field the way a user would, replacing whatever is there.
 *
 * Selecting the old text with a triple click did not work in headless Chrome (the new text was
 * appended to the old one), so the field is emptied first. The keystrokes still go through the
 * real input path, which is what the component's onChange listens to.
 */
async function type(page, selector, text) {
  await see(page, selector);
  await page.focus(selector);
  await page.$eval(selector, (element) => {
    element.select();
  });
  await page.keyboard.press('Backspace');
  const left = await page.$eval(selector, (element) => element.value);
  if (left !== '') throw new Error(`could not clear ${selector}, it still holds "${left}"`);
  await page.type(selector, text);
}

async function click(page, selector) {
  await see(page, selector);
  await page.click(selector);
}

async function isDisabled(page, selector) {
  return page.$eval(selector, (element) => element.disabled);
}

async function waitEnabled(page, selector) {
  try {
    await page.waitForFunction(
      (s) => {
        const element = document.querySelector(s);
        return element && !element.disabled;
      },
      { timeout: 10_000 },
      selector,
    );
  } catch {
    const state = await page
      .$eval(selector, (element) => (element.disabled ? 'present but disabled' : 'enabled'))
      .catch(() => 'not on the page');
    throw new Error(
      `expected ${selector} to be enabled, but it is ${state}. The page shows:\n${await shown(page)}`,
    );
  }
}

/** Opens the popup as its own page. It is the real UI: the same document Chrome would show. */
async function openPopup(browser, popupUrl) {
  const page = await browser.newPage();
  page.on('pageerror', (error) => console.error(`[popup error] ${error.message}`));
  await page.goto(popupUrl);
  // A blank page is a failure, and the popup once was one.
  await seeText(page, 'MPC engine');
  return page;
}

/**
 * Chrome saves downloads into the directory it is told to. Every download gets a directory of its
 * own, because the recovery file's name depends only on the wallet, so two downloads for the same
 * wallet have the same name and one would otherwise be mistaken for the other.
 */
async function expectDownload(page, root, label) {
  const directory = await mkdtemp(join(root, `${label}-`));
  const client = await page.createCDPSession();
  await client.send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: directory });
  return directory;
}

/** Reads the file right away. A later download may reuse the name, so keep what it held. */
async function readNow(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function waitForDownload(directory, timeout = 15_000) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const names = (await readdir(directory)).filter((n) => !n.endsWith('.crdownload'));
    if (names.length > 0) {
      // Give Chrome a moment to finish writing before the file is read.
      await delay(300);
      return join(directory, names[0]);
    }
    if (Date.now() > deadline) throw new Error('the recovery file was never downloaded');
    await delay(200);
  }
}

/**
 * Chooses a file the way a user does: through the button that opens the file dialog.
 *
 * The page can hold several file inputs at once. The signing panel always has one, and so do the
 * recovery and export panels when they are open, so picking "the first one" uploads to the wrong
 * panel. `trigger` is the visible control whose file dialog is meant, and the input it clicks is
 * the one used.
 */
async function chooseFile(page, filePath, trigger) {
  await see(page, trigger);
  const [chooser] = await Promise.all([
    page.waitForFileChooser({ timeout: 10_000 }),
    page.click(trigger),
  ]);
  await chooser.accept([filePath]);
}

async function setServer(page) {
  await type(page, '#server-url', SERVER);
  await click(page, '#save-server');
  await seeText(page, 'Saved.');
}

/**
 * Creates a wallet through the form, saves the recovery file through the download button, and
 * confirms. Returns the path of the saved recovery file.
 */
async function createWallet(page, downloadsRoot) {
  const downloads = await expectDownload(page, downloadsRoot, 'first');
  await type(page, '#password', WALLET_PASSWORD);
  await type(page, '#password-confirm', WALLET_PASSWORD);
  await click(page, '#create-key');
  // Key generation runs with the server and takes a few seconds.
  await see(page, '#recovery-password', { timeout: 60_000 });

  // The download is not offered until the recovery password is chosen and repeated, and the
  // wallet cannot be started before the file is saved.
  if (!(await isDisabled(page, '#download-recovery'))) {
    throw new Error('the recovery file can be downloaded before a recovery password is chosen');
  }
  if (!(await isDisabled(page, '#confirm-recovery'))) {
    throw new Error('the wallet can be started before the recovery file is saved');
  }
  // The card tells the owner where to look if someone ever asks to take over the wallet.
  await see(page, '#manage-bookmark');
  await seeText(page, `${SERVER}/manage`);
  await type(page, '#recovery-password', RECOVERY_PASSWORD);
  await type(page, '#recovery-password-again', RECOVERY_PASSWORD);
  await click(page, '#download-recovery');
  const file = await waitForDownload(downloads);
  await click(page, '#confirm-recovery');
  await seeText(page, 'Unlocked');
  return file;
}

/**
 * Registers the passkey through the card and waits until the card has done its job.
 *
 * The sign button is also disabled while the digest field is empty, so checking it before a digest
 * is typed proves nothing about the passkey. A valid digest goes in first, and then the button has
 * to be disabled because of the missing passkey alone.
 */
async function registerPasskey(page, digest) {
  await see(page, '#passkey-card');
  await type(page, '#digest', digest);
  if (!(await isDisabled(page, '#sign'))) {
    throw new Error('the server sign button is usable with a valid digest but no passkey');
  }
  await see(page, '#passkey-missing');
  await click(page, '#register-passkey');
  await see(page, '#passkey-card', { hidden: true, timeout: 40_000 });
  await see(page, '#passkey-missing', { hidden: true });
  // With the passkey there, the same digest now allows signing.
  await waitEnabled(page, '#sign');
}

async function signWithServer(page, digest) {
  await type(page, '#digest', digest);
  await waitEnabled(page, '#sign');
  await click(page, '#sign');
  await seeText(page, 'Signed via the server', { timeout: 40_000 });
}

/** A lost device takes its storage with it. */
async function loseTheDevice(page) {
  await page.evaluate(async () => {
    await chrome.storage.local.clear();
    await new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase('mpc-ext-device');
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  });
  await page.reload();
  await seeText(page, 'MPC engine');
}

// ---------------------------------------------------------------------------------------------
// Scenario A: one person, one device.
// ---------------------------------------------------------------------------------------------

async function scenarioA() {
  console.log('\n== Scenario A: create, sign, lose the device, restore, reshare, export');
  const downloads = await mkdtemp(join(tmpdir(), 'mpc-ext-downloads-'));
  const server = await startServer({ coolingSeconds: 0 });
  const session = await launchBrowser();
  try {
    const page = await openPopup(session.browser, session.popupUrl);
    const digest = 'ab'.repeat(32);

    await see(page, '#create-key');
    await setServer(page);
    const recoveryFile = await createWallet(page, downloads);
    const fileHeader = JSON.parse(await readFile(recoveryFile, 'utf8'));
    if (fileHeader.kind !== 'mpc-ext-recovery' || fileHeader.formatVersion !== 3) {
      throw new Error('the downloaded file is not an encrypted recovery file');
    }
    if ('share' in fileHeader) throw new Error('the recovery file holds a plaintext share');
    console.log('  created a wallet and saved its recovery file');

    await registerPasskey(page, digest);
    console.log('  registered the passkey through the card');

    await signWithServer(page, digest);
    console.log('  signed through the server');

    // The recovery file works on its own, without the server: lock, unlock, sign offline.
    await click(page, '#lock');
    await see(page, '#unlock-password');
    await type(page, '#unlock-password', WALLET_PASSWORD);
    await click(page, '#unlock');
    await seeText(page, 'Unlocked');
    await type(page, '#recovery-file-password', RECOVERY_PASSWORD);
    await type(page, '#digest', digest);
    await chooseFile(page, recoveryFile, '#sign-offline');
    await seeText(page, 'Signed via your recovery file', { timeout: 40_000 });
    console.log('  locked, unlocked and signed offline with the recovery file');

    // Lose the device and restore from the file. The new install has to be approved and wait.
    await loseTheDevice(page);
    await see(page, '#begin-recovery');
    if (!(await isDisabled(page, '#begin-recovery'))) {
      throw new Error('a recovery can start before a recovery file is chosen');
    }
    await setServer(page);
    await chooseFile(page, recoveryFile, '#pick-recovery');
    await waitEnabled(page, '#begin-recovery');
    await click(page, '#begin-recovery');
    // The passkey approves in another tab. Then the wait, here zero, and then the finish form.
    await see(page, '#finish-recovery', { timeout: 60_000 });
    if (!(await isDisabled(page, '#finish-recovery'))) {
      throw new Error('a recovery can finish without the file password and a new password');
    }
    await type(page, '#recover-file-password', RECOVERY_PASSWORD);
    await type(page, '#recover-password', NEW_WALLET_PASSWORD);
    await click(page, '#finish-recovery');
    await seeText(page, 'Unlocked (restored)', { timeout: 40_000 });
    console.log('  restored onto a new install through the passkey and the wait');

    // A restored wallet says it is not healthy, and offers to fix that.
    await seeText(page, 'not fully protected');
    await signWithServer(page, digest);
    console.log('  signed again after restoring');

    // Reshare through the card, and save the new recovery file. It goes to a directory of its
    // own, because it has the same name as the first one.
    const reshareDownloads = await expectDownload(page, downloads, 'reshared');
    await type(page, '#reshare-password', NEW_WALLET_PASSWORD);
    await click(page, '#start-reshare');
    await see(page, '#recovery-password', { timeout: 90_000 });
    await type(page, '#recovery-password', RESHARED_RECOVERY_PASSWORD);
    await type(page, '#recovery-password-again', RESHARED_RECOVERY_PASSWORD);
    await click(page, '#download-recovery');
    const newFile = await waitForDownload(reshareDownloads);
    const oldBody = await readNow(recoveryFile);
    const newBody = await readNow(newFile);
    if (newBody.ciphertextB64 === oldBody.ciphertextB64) {
      throw new Error('the reshare handed out the old recovery share again');
    }
    if (newBody.publicKey !== oldBody.publicKey || newBody.walletId !== oldBody.walletId) {
      throw new Error('the reshare changed the wallet the recovery file belongs to');
    }
    await click(page, '#confirm-recovery');
    await seeText(page, 'Unlocked —', { timeout: 40_000 });
    if ((await shown(page)).toLowerCase().includes('restored')) {
      throw new Error('a reshared wallet is still shown as restored');
    }
    console.log('  reshared and saved the new recovery file');
    await signWithServer(page, digest);

    // Taking the key out: acknowledgement, both passwords, and the new recovery file.
    await click(page, '#open-export');
    if (!(await isDisabled(page, '#reveal-key'))) {
      throw new Error('the private key can be shown without any confirmation');
    }
    await click(page, '#export-ack');
    await type(page, '#export-password', NEW_WALLET_PASSWORD);
    await chooseFile(page, newFile, '#pick-export-file');
    await type(page, '#export-file-password', RESHARED_RECOVERY_PASSWORD);
    await waitEnabled(page, '#reveal-key');
    await click(page, '#reveal-key');
    await see(page, '#exported-key', { timeout: 40_000 });
    const key = await page.$eval('#exported-key', (element) => element.textContent.trim());
    if (!/^[0-9a-f]{64}$/.test(key))
      throw new Error(`the exported key is not 32 bytes of hex: ${key}`);
    console.log('  exported the private key with the new recovery file');
  } finally {
    await session.close();
    await server.stop();
    await rm(downloads, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------------------------
// Scenario B: two devices. A recovery started on the new one shows on the old one.
// ---------------------------------------------------------------------------------------------

async function scenarioB() {
  console.log('\n== Scenario B: a recovery on a new device is seen and cancelled on the old one');
  const downloads = await mkdtemp(join(tmpdir(), 'mpc-ext-downloads-'));
  // A day, as a real deployment waits, so the recovery stays waiting while the old device looks.
  const server = await startServer({ coolingSeconds: 86_400 });
  // One authenticator: the user carries the same passkey to their new device.
  const credentials = new Map();
  const oldDevice = await launchBrowser({ credentials });
  const newDevice = await launchBrowser({ credentials });
  try {
    const old = await openPopup(oldDevice.browser, oldDevice.popupUrl);
    await see(old, '#create-key');
    await setServer(old);
    const recoveryFile = await createWallet(old, downloads);
    await registerPasskey(old, 'cd'.repeat(32));
    console.log('  the old device has a wallet, a recovery file and a passkey');

    // Nothing is waiting yet, so the old device shows no warning.
    await old.reload();
    await seeText(old, 'MPC engine');
    await delay(1500);
    if (await old.$('#pending-recoveries')) throw new Error('a warning shows with nothing waiting');

    // The new device starts a recovery from the recovery file.
    const fresh = await openPopup(newDevice.browser, newDevice.popupUrl);
    await see(fresh, '#begin-recovery');
    await setServer(fresh);
    await chooseFile(fresh, recoveryFile, '#pick-recovery');
    await waitEnabled(fresh, '#begin-recovery');
    await click(fresh, '#begin-recovery');
    // Approved by the passkey, and now it waits. It says when it can finish.
    await see(fresh, '#recovery-cooling', { timeout: 60_000 });
    await seeText(fresh, 'You can finish it after');
    if (await fresh.$('#finish-recovery')) {
      throw new Error('a recovery offers to finish while it is still waiting');
    }
    console.log('  the new device asked to recover and is waiting');

    // The old device sees it, with the key's fingerprint, and can object.
    await old.reload();
    await see(old, '#pending-recoveries', { timeout: 30_000 });
    await seeText(old, 'Someone asked to replace this device');
    const fingerprint = await old.$eval('#pending-recoveries .mono', (element) =>
      element.textContent.trim(),
    );
    if (!/^[0-9a-f]{8}$/.test(fingerprint)) throw new Error(`odd key fingerprint: ${fingerprint}`);
    console.log(`  the old device shows the request (key ${fingerprint})`);

    // It also raises a browser notification, without the popup being open. The check runs every
    // few minutes in the background, so run it now instead of waiting.
    // It works while the wallet is locked: the check needs the device key and never the password.
    await click(old, '#lock');
    await see(old, '#unlock-password');
    const alarm = await old.evaluate(() => chrome.alarms.get('recoveryWatch'));
    if (!alarm || !alarm.periodInMinutes) {
      throw new Error('the periodic recovery check is not scheduled');
    }
    const check = () =>
      old.evaluate(
        () =>
          new Promise((resolve, reject) =>
            chrome.runtime.sendMessage({ type: 'checkRecoveries' }, (response) => {
              if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
              else if (!response.ok) reject(new Error(response.error));
              else resolve(response.value);
            }),
          ),
      );
    const raised = await check();
    if (raised !== 1) throw new Error(`expected one notification, got ${raised}`);
    const notifications = await old.evaluate(
      () => new Promise((resolve) => chrome.notifications.getAll(resolve)),
    );
    const ids = Object.keys(notifications);
    if (ids.length !== 1 || !ids[0].startsWith('recovery-')) {
      throw new Error(`the notification was not created: ${JSON.stringify(ids)}`);
    }
    // Once told, it must not be told again on the next check.
    const again = await check();
    if (again !== 0) throw new Error(`the same recovery was announced again (${again})`);
    console.log('  the old device raised a notification once, and not a second time, while locked');
    await type(old, '#unlock-password', WALLET_PASSWORD);
    await click(old, '#unlock');
    await seeText(old, 'Unlocked');

    await click(old, '#pending-recoveries .cancel-pending');
    await see(old, '#pending-recoveries', { hidden: true, timeout: 20_000 });

    // The new device finds out it was cancelled.
    await fresh.reload();
    await see(fresh, '#restart-recovery', { timeout: 30_000 });
    await seeText(fresh, 'This recovery was cancelled');
    console.log('  the old device cancelled it and the new device was told');
  } finally {
    await newDevice.close();
    await oldDevice.close();
    await server.stop();
    await rm(downloads, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------------------------
// Scenario C: the old device is gone. The owner cancels from a browser with only the passkey.
// ---------------------------------------------------------------------------------------------

async function scenarioC() {
  console.log(
    '\n== Scenario C: a recovery is cancelled from a plain browser with only the passkey',
  );
  const downloads = await mkdtemp(join(tmpdir(), 'mpc-ext-downloads-'));
  const server = await startServer({ coolingSeconds: 86_400 });
  const credentials = new Map();
  const oldDevice = await launchBrowser({ credentials });
  const newDevice = await launchBrowser({ credentials });
  // The owner's authenticator on a computer with no extension and no wallet on it.
  const stranger = await launchBrowser({ credentials });
  // Someone else entirely: their own wallet and their own passkey on the same server, in an
  // authenticator that holds only that passkey. The page must never show them this owner's
  // recovery, nor show this owner theirs.
  const otherCredentials = new Map();
  const otherDevice = await launchBrowser({ credentials: otherCredentials });
  const otherDownloads = await mkdtemp(join(tmpdir(), 'mpc-ext-downloads-'));
  try {
    const old = await openPopup(oldDevice.browser, oldDevice.popupUrl);
    await see(old, '#create-key');
    await setServer(old);
    const recoveryFile = await createWallet(old, downloads);
    await registerPasskey(old, 'ef'.repeat(32));
    console.log('  the owner has a wallet, a recovery file and a passkey');

    // A second person with their own wallet and passkey, and no recovery waiting.
    const other = await openPopup(otherDevice.browser, otherDevice.popupUrl);
    await see(other, '#create-key');
    await setServer(other);
    await createWallet(other, otherDownloads);
    await registerPasskey(other, '12'.repeat(32));
    console.log('  a second person has their own wallet and passkey on the same server');

    // Someone with the recovery file asks to take over from a new device.
    const fresh = await openPopup(newDevice.browser, newDevice.popupUrl);
    await see(fresh, '#begin-recovery');
    await setServer(fresh);
    await chooseFile(fresh, recoveryFile, '#pick-recovery');
    await waitEnabled(fresh, '#begin-recovery');
    await click(fresh, '#begin-recovery');
    await see(fresh, '#recovery-cooling', { timeout: 60_000 });
    // The recovery panel says where the owner can cancel it from anywhere.
    await seeText(fresh, '/manage');
    console.log('  a recovery is waiting, and the new device says where it can be cancelled');

    // The old device is lost. Nothing of it is used from here on.
    await old.close();
    await oldDevice.close();

    // The owner opens the server's own page in a browser that has only the passkey.
    const page = await stranger.browser.newPage();
    page.on('pageerror', (error) => console.error(`[manage page error] ${error.message}`));
    await page.goto(`${SERVER}/manage`);
    await see(page, '#lookup');
    // Nothing is listed before the passkey is used, and no wallet id is asked for.
    if ((await shown(page)).toLowerCase().includes('fingerprint')) {
      throw new Error('the page lists recoveries before the passkey is used');
    }
    if (await page.$('input')) throw new Error('the page asks for something to type');
    await click(page, '#lookup');
    await seeText(page, 'A recovery is waiting on your wallet', { timeout: 30_000 });
    await seeText(page, 'fingerprint');
    console.log('  the passkey alone found the wallet and listed the recovery');

    // The second person uses the same page with their own passkey. They must get their own wallet,
    // which has nothing waiting, and not the owner's recovery. This is what tells "the passkey
    // names the wallet" apart from "any wallet will do", which a single wallet cannot.
    const otherPage = await otherDevice.browser.newPage();
    await otherPage.goto(`${SERVER}/manage`);
    await click(otherPage, '#lookup');
    await seeText(otherPage, 'Nothing is waiting on your wallet', { timeout: 30_000 });
    if ((await shown(otherPage)).toLowerCase().includes('fingerprint')) {
      throw new Error("the second person was shown someone else's recovery");
    }
    console.log('  the second person, with their own passkey, saw nothing of the owner');

    await click(page, '#recoveries .cancel');
    await seeText(page, 'Nothing is waiting on your wallet', { timeout: 20_000 });
    console.log('  the owner cancelled it from that page');

    // The new device finds out.
    await fresh.reload();
    await see(fresh, '#restart-recovery', { timeout: 30_000 });
    await seeText(fresh, 'This recovery was cancelled');
    console.log('  the new device was told it was cancelled');
  } finally {
    await otherDevice.close();
    await stranger.close();
    await newDevice.close();
    await oldDevice.close().catch(() => undefined);
    await server.stop();
    await rm(downloads, { recursive: true, force: true });
    await rm(otherDownloads, { recursive: true, force: true });
  }
}

let failed = false;
try {
  await scenarioA();
  await scenarioB();
  await scenarioC();
  console.log(
    '\nPASS: the popup creates a wallet, registers the passkey, signs, restores, reshares and\n' +
      '      exports. A recovery started elsewhere is shown and cancelled on the old device, and\n' +
      '      from a plain browser with only the passkey.',
  );
} catch (error) {
  failed = true;
  console.error('\nFAIL:', error.message);
}
process.exit(failed ? 1 : 0);
