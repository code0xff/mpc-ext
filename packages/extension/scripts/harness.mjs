/**
 * Shared machinery for the browser smoke tests: the real server, Chrome for Testing with the
 * extension loaded, and a virtual authenticator that answers the passkey ceremonies.
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
const SERVER_BIN = new URL('../../../target/release/mpc-server', import.meta.url).pathname;

/** Exits with a hint when something the tests need has not been built or installed. */
export function requireBuilt() {
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
  if (!existsSync(SERVER_BIN)) {
    console.error('No server binary found. Run `make build-server` first.');
    process.exit(1);
  }
}

/**
 * Runs a real server against a throwaway database.
 *
 * `coolingSeconds` is how long a recovery waits. A real one waits a day. Most scenarios cannot, so
 * they use zero, and the ones about the waiting itself use a long period. What the wait protects
 * is also covered by the server's own tests.
 */
export async function startServer({ coolingSeconds }) {
  const dir = await mkdtemp(join(tmpdir(), 'mpc-ext-server-'));
  const server = spawn(SERVER_BIN, [], {
    stdio: 'inherit',
    env: {
      ...process.env,
      MPC_SERVER_ADDR: '127.0.0.1:8080',
      MPC_SERVER_DATABASE: `sqlite://${join(dir, 'smoke.db')}`,
      // A throwaway key for this run only. Never reuse a test key anywhere real.
      MPC_SERVER_SEALING_KEY: '11'.repeat(32),
      MPC_SERVER_RECOVERY_COOLING_SECONDS: String(coolingSeconds),
      RUST_LOG: 'warn',
    },
  });

  // Wait for the server to answer before driving the extension.
  let up = false;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch('http://127.0.0.1:8080/v1/health');
      if (response.ok) {
        up = true;
        break;
      }
    } catch {
      // Not listening yet.
    }
    await delay(200);
  }
  if (!up) {
    server.kill();
    throw new Error('The server did not come up on 127.0.0.1:8080.');
  }
  console.log(`server ready on 127.0.0.1:8080 (recovery wait ${coolingSeconds}s)`);

  return {
    async stop() {
      server.kill();
      // Give the port back before the next scenario starts a server of its own.
      await new Promise((resolve) => {
        if (server.exitCode !== null) resolve();
        else server.once('exit', resolve);
      });
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/**
 * The passkey credentials seen so far, by id. A virtual authenticator disappears with its tab,
 * and the extension opens a fresh tab for every ceremony, so the registered credential and its
 * latest signature counter have to be handed to each new authenticator. Without the counter the
 * server would see it go backwards and reject the assertion as a cloned key.
 */
async function attachAuthenticator(target, credentials) {
  if (target.type() !== 'page') return;

  // The authenticator comes first. It is what the ceremony page needs, and the page can call
  // WebAuthn within a few round trips of the tab opening.
  const session = await target.createCDPSession();
  await session.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  for (const credential of credentials.values()) {
    await session.send('WebAuthn.addCredential', { authenticatorId, credential });
  }
  const remember = ({ credential }) => {
    if (process.env.SMOKE_DEBUG) {
      console.log(
        `[credential] ${credential.credentialId.slice(0, 12)}… count=${credential.signCount}`,
      );
    }
    credentials.set(credential.credentialId, credential);
  };
  session.on('WebAuthn.credentialAdded', remember);
  session.on('WebAuthn.credentialAsserted', remember);

  const page = await target.page();
  if (page) void rescueStuckCeremony(page);
}

/**
 * Rescues a ceremony page that asked for a credential before an authenticator was there.
 *
 * The extension opens the tab, and this script attaches an authenticator to it afterwards. If the
 * page calls WebAuthn first, Chrome does not fail the call. It waits for a device, and one added
 * later is not used for that call, so the ceremony hangs with no error. That is a race between
 * this script and the page, and it shows up on slow machines.
 *
 * Reloading is safe only **before the page has sent anything to the server.** The server hands out
 * the same options again for the same ceremony, but the challenge is consumed as soon as an
 * assertion is checked, so a reload after that fails every time ("no live challenge"). So this
 * reloads in exactly two cases, both of which happen before the server is involved:
 *
 * - the page is still waiting for the authenticator prompt after it should have been answered, or
 * - the browser itself refused the call (NotAllowedError), which is what a missing authenticator
 *   looks like once Chrome gives up.
 *
 * It never reloads on "authentication failed". That is the server's verdict, and repeating the
 * ceremony cannot change it. Every reload is logged, so a real problem is visible and not hidden.
 */
async function rescueStuckCeremony(page) {
  let waitingSince;
  let reloads = 0;
  for (let check = 1; check <= 40 && reloads < 3; check += 1) {
    await delay(500);
    if (page.isClosed()) return;
    const view = await page
      .evaluate(() => {
        const error = document.getElementById('error');
        const status = document.getElementById('status');
        return {
          failure: error && !error.hidden ? error.textContent : '',
          waiting: Boolean(
            status && !status.hidden && /authenticator prompt/i.test(status.textContent),
          ),
        };
      })
      .catch(() => ({ failure: '', waiting: false }));

    // A failure only the browser could have produced, before anything reached the server.
    const refusedByBrowser = /not allowed|timed out/i.test(view.failure);
    if (refusedByBrowser) {
      console.log(`[ceremony] the browser refused the call ("${view.failure}"), reloading`);
      waitingSince = undefined;
      reloads += 1;
      await page.reload().catch(() => undefined);
    } else if (view.waiting) {
      waitingSince ??= Date.now();
      // Answering the prompt takes a fraction of a second here. Three seconds means it is stuck.
      if (Date.now() - waitingSince > 3000) {
        console.log('[ceremony] the page has waited for the authenticator too long, reloading');
        waitingSince = undefined;
        reloads += 1;
        await page.reload().catch(() => undefined);
      }
    } else {
      waitingSince = undefined;
      // Anything else is not this race. In particular the server's own answer is left alone.
      if (view.failure) {
        console.log(`[ceremony] the page reported "${view.failure}", leaving it alone`);
        return;
      }
    }
  }
}

const DEBUG = Boolean(process.env.SMOKE_DEBUG);

/**
 * Launches Chrome with the extension and answers passkey ceremonies in every tab it opens.
 *
 * `credentials` is shared between browsers, so a second device sees the same passkey the first one
 * registered, which is what a real user's authenticator does.
 */
export async function launchBrowser({ credentials = new Map() } = {}) {
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
      // GitHub's Ubuntu runners block unprivileged user namespaces through AppArmor, so Chrome's
      // sandbox cannot start. The runner is a throwaway VM and the page under test is our own.
      ...(process.env.CI ? ['--no-sandbox'] : []),
    ],
  });

  browser.on('targetcreated', (target) => {
    if (DEBUG) console.log(`[target] ${target.type()} ${target.url()}`);
    attachAuthenticator(target, credentials)
      .then(() => {
        if (DEBUG && target.type() === 'page') console.log('[authenticator] attached');
      })
      .catch((cause) => {
        console.error('could not attach a virtual authenticator:', cause.message);
      });
    if (DEBUG && target.type() === 'page') traceCeremony(target);
  });

  // The extension's id is fixed by its files, and the service worker is what carries it.
  const worker = await browser
    .waitForTarget((t) => t.type() === 'service_worker', { timeout: 20_000 })
    .catch(async (cause) => {
      const seen = browser.targets().map((t) => `${t.type()} ${t.url()}`);
      throw new Error(`${cause.message}\nTargets seen:\n  ${seen.join('\n  ')}`);
    });
  const extensionId = new URL(worker.url()).host;
  console.log('service worker registered:', worker.url());

  return {
    browser,
    extensionId,
    popupUrl: `chrome-extension://${extensionId}/popup.html`,
    async close() {
      await browser.close();
      await rm(profile, { recursive: true, force: true });
    },
  };
}

function traceCeremony(target) {
  target
    .page()
    .then((page) => {
      page?.on('console', (message) => console.log(`[page console] ${message.text()}`));
      page?.on('framenavigated', (frame) => {
        if (frame !== page.mainFrame()) return;
        console.log(`[navigated] ${frame.url()}`);
        if (frame.url().includes('/auth')) {
          setTimeout(async () => {
            const text = await page.evaluate(() => document.body.innerText).catch(() => '(gone)');
            console.log(`[auth page after 4s] ${text.replace(/\s+/g, ' ')}`);
          }, 4000);
        }
      });
      page?.on('response', (response) => {
        if (response.url().endsWith('/auth/session')) {
          response
            .text()
            .then((text) => console.log(`[options] ${text}`))
            .catch(() => undefined);
        }
        if (response.url().includes('/auth')) {
          console.log(
            `[http] ${response.status()} ${response.request().method()} ${response.url()}`,
          );
        }
      });
    })
    .catch(() => undefined);
}
