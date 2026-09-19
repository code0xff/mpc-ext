/**
 * The background service worker.
 *
 * The only place with access to secrets. Share A exists in decrypted form solely in this
 * worker's memory, so the wallet locks itself whenever the worker is terminated
 * (`docs/architecture.md`).
 */
import * as approvals from '../src/approvals';
import type { CreatedKey, Request, Response, Signed, Status, WasmHealth } from '../src/messages';
import { handlePageRequest } from '../src/pageApi';
import * as permissions from '../src/permissions';
import { PARTY, runDkg, signWithRecoveryFile, signWithServer } from '../src/protocolRunner';
import {
  createPasskeyHandoff,
  health as serverHealth,
  passkeyCeremonyStatus,
  registerDeviceKey,
  ServerUnreachable,
} from '../src/serverClient';
import { createDeviceKey, exportDevicePublicKey, storeDeviceKey } from '../src/deviceKey';
import * as settings from '../src/settings';
import * as vault from '../src/vault';
import { ethereum_address, loadWasm, threshold_config } from '../src/wasm';

/** The decrypted share A. Disappears with the worker, and is never persisted. */
let unlockedShare: Uint8Array | undefined;

/** A handoff token is held only until the extension launcher submits its form body. */
let pendingPasskey:
  | {
      serverUrl: string;
      handoffToken: string;
      ceremonyId: string;
      tabId?: number;
    }
  | undefined;

/**
 * In-flight onboarding state. **Nothing is persisted** until the recovery file is confirmed
 * saved.
 *
 * Storing share A first would mean that if the worker died before the export, share B would be
 * gone forever and the wallet unusable. So both are held in memory and committed together:
 * a failure leaves no trace at all.
 */
let pending:
  | {
      shareA: Uint8Array;
      publicKeyHex: string;
      walletId: string;
      password: string;
      deviceKey: CryptoKeyPair;
    }
  | undefined;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error('Hex input has an odd length.');
  return Uint8Array.from({ length: value.length / 2 }, (_, i) =>
    Number.parseInt(value.slice(i * 2, i * 2 + 2), 16),
  );
}

function wipe(bytes: Uint8Array | undefined): void {
  bytes?.fill(0);
}

function requireUnlocked(): Uint8Array {
  if (!unlockedShare) throw new Error('The wallet is locked.');
  return unlockedShare;
}

async function status(): Promise<Status> {
  if (pending) {
    return { kind: 'awaitingRecoveryExport', publicKeyHex: pending.publicKeyHex };
  }
  const publicKeyHex = await vault.publicKeyHex();
  if (!publicKeyHex) return { kind: 'uninitialized' };
  if (!unlockedShare) return { kind: 'locked', publicKeyHex };

  // A wallet holding the recovery share was restored after a device loss.
  const recovered = (await vault.party()) === PARTY.recovery;
  return { kind: 'unlocked', publicKeyHex, recovered };
}

/**
 * Creates a key.
 *
 * DKG runs across three parties — two here, one on the server — but the extension **keeps only
 * A.** B is handed back so the user can store it as a recovery file, and C stays with the
 * server (`docs/adr/0005-share-placement.md`).
 */
async function createKey(password: string): Promise<CreatedKey> {
  if (password.length < 8) throw new Error('The password must be at least 8 characters.');
  if (await vault.exists()) throw new Error('A key already exists.');

  await loadWasm();
  const sessionId = crypto.getRandomValues(new Uint8Array(32));
  const walletId = crypto.randomUUID();

  const outcome = await runDkg(await settings.serverUrl(), walletId, sessionId);
  const deviceKey = await createDeviceKey();

  pending = {
    shareA: outcome.extensionShare,
    publicKeyHex: outcome.publicKeyHex,
    walletId,
    password,
    deviceKey,
  };

  // Share B is handed over here and left nowhere in worker memory.
  const recoveryShareHex = toHex(outcome.recoveryShare);
  wipe(outcome.recoveryShare);

  return { publicKeyHex: outcome.publicKeyHex, walletId, recoveryShareHex };
}

/** The recovery file is saved. Only now do we store share A. */
async function confirmRecoverySaved(): Promise<Status> {
  if (!pending) throw new Error('There is no key waiting to be stored.');

  const publicDeviceKey = await exportDevicePublicKey(pending.deviceKey.publicKey);
  await registerDeviceKey(await settings.serverUrl(), pending.walletId, publicDeviceKey);
  await storeDeviceKey(pending.deviceKey);
  await vault.store(
    pending.password,
    pending.shareA,
    pending.publicKeyHex,
    pending.walletId,
    PARTY.extension,
  );
  unlockedShare = pending.shareA;
  // JS strings cannot be wiped; dropping the reference and leaving it to the GC is the best
  // we can do.
  pending = undefined;

  return status();
}

/** Cancels onboarding, discarding every share that was created. */
function cancelOnboarding(): void {
  wipe(pending?.shareA);
  pending = undefined;
}

/**
 * Restores a wallet on a fresh install from a recovery file.
 *
 * The imported share becomes this install's share, and everyday signing runs recovery share plus
 * server. The wallet can spend again but is **not** a healthy 2-of-3: the lost share stays valid
 * and there is no longer an independent backup, because reshaping the key would need two shares
 * in one place (`docs/recovery.md`). The UI has to tell the user that.
 */
async function recoverFromFile(
  password: string,
  walletId: string,
  publicKeyHex: string,
  recoveryShareHex: string,
): Promise<Status> {
  if (password.length < 8) throw new Error('The password must be at least 8 characters.');
  if (await vault.exists()) throw new Error('A key already exists.');

  const share = fromHex(recoveryShareHex);
  const deviceKey = await createDeviceKey();
  const publicDeviceKey = await exportDevicePublicKey(deviceKey.publicKey);
  await registerDeviceKey(await settings.serverUrl(), walletId, publicDeviceKey);
  await storeDeviceKey(deviceKey);
  await vault.store(password, share, publicKeyHex, walletId, PARTY.recovery);
  unlockedShare = share;

  return status();
}

async function unlock(password: string): Promise<Status> {
  const share = await vault.unlock(password);
  if (!share) throw new Error('That password is not correct.');
  unlockedShare = share;
  return status();
}

async function startPasskey(
  purpose: 'register' | 'sign' | 'recovery',
  operationId?: string,
  digest?: string,
): Promise<{ ceremonyId: string }> {
  const walletId = await vault.walletId();
  if (!walletId) throw new Error('This wallet is not initialized.');
  const serverUrl = await settings.serverUrl();
  const handoff = await createPasskeyHandoff(serverUrl, walletId, purpose, operationId, digest);
  pendingPasskey = {
    serverUrl,
    handoffToken: handoff.handoff_token,
    ceremonyId: handoff.ceremony_id,
  };
  const tab = await chrome.tabs.create({ url: chrome.runtime.getURL('auth-launcher.html') });
  pendingPasskey.tabId = tab.id;
  return { ceremonyId: handoff.ceremony_id };
}

async function passkeyLauncherReady(): Promise<{ serverUrl: string; handoffToken: string }> {
  if (!pendingPasskey) throw new Error('There is no pending passkey ceremony.');
  return {
    serverUrl: pendingPasskey.serverUrl,
    handoffToken: pendingPasskey.handoffToken,
  };
}

async function passkeyStatus(ceremonyId: string) {
  const walletId = await vault.walletId();
  if (!walletId) throw new Error('This wallet is not initialized.');
  return passkeyCeremonyStatus(await settings.serverUrl(), walletId, ceremonyId);
}

/** Completes a server-origin passkey ceremony before a signing session is opened. */
async function authorizeSign(signId: string, digest: string): Promise<void> {
  const { ceremonyId } = await startPasskey('sign', signId, digest);
  const startedAt = Date.now();
  try {
    for (;;) {
      if (Date.now() - startedAt > 120_000) {
        throw new Error('The passkey ceremony timed out.');
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
      const result = await passkeyStatus(ceremonyId);
      if (result.status === 'completed') return;
    }
  } finally {
    const tabId = pendingPasskey?.tabId;
    pendingPasskey = undefined;
    if (tabId !== undefined) {
      await chrome.tabs.remove(tabId).catch(() => undefined);
    }
  }
}

function lock(): void {
  wipe(unlockedShare);
  unlockedShare = undefined;
  // Anything still waiting for the user must fail closed rather than resume after an unlock.
  approvals.rejectAll();
}

/** The wallet's Ethereum address, or undefined while locked or before setup. */
async function address(): Promise<string | undefined> {
  if (!unlockedShare) return undefined;
  const publicKeyHex = await vault.publicKeyHex();
  if (!publicKeyHex) return undefined;
  await loadWasm();
  return ethereum_address(fromHex(publicKeyHex));
}

/**
 * Opens the approval window.
 *
 * A popup cannot be relied on — it may be closed — so requests that need consent get their own
 * window. Closing it without answering rejects everything pending (`docs/web-api.md`).
 */
async function openApprovalWindow(): Promise<void> {
  const created = await chrome.windows.create({
    url: chrome.runtime.getURL('approve.html'),
    type: 'popup',
    width: 400,
    height: 620,
  });

  if (created.id === undefined) return;
  const windowId = created.id;

  const onClosed = (closed: number) => {
    if (closed !== windowId) return;
    chrome.windows.onRemoved.removeListener(onClosed);
    // A closed window is a refusal, never a silent approval.
    approvals.rejectAll();
  };
  chrome.windows.onRemoved.addListener(onClosed);
}

/**
 * Signs using the extension share and the server share.
 *
 * If the server cannot be reached the error says so, and the UI offers the recovery-file path
 * instead (`docs/recovery.md`, scenario 0).
 */
async function sign(digestHex: string): Promise<Signed> {
  const share = requireUnlocked();
  const walletId = await vault.walletId();
  const localParty = await vault.party();
  if (!walletId || localParty === undefined) {
    throw new Error('This wallet has no server registration.');
  }

  await loadWasm();
  const signId = crypto.getRandomValues(new Uint8Array(32));
  await authorizeSign(toHex(signId), digestHex);
  const signature = await signWithServer(
    await settings.serverUrl(),
    walletId,
    share,
    localParty,
    signId,
    fromHex(digestHex),
  );

  return { signatureHex: toHex(signature), via: 'server' };
}

/**
 * Signs using the extension share and a recovery file, entirely offline.
 *
 * The recovery share is used for this signature and then wiped. It is never stored.
 */
async function signOffline(digestHex: string, recoveryShareHex: string): Promise<Signed> {
  const share = requireUnlocked();
  await loadWasm();

  const recoveryShare = fromHex(recoveryShareHex);
  try {
    const signId = crypto.getRandomValues(new Uint8Array(32));
    const signature = signWithRecoveryFile(share, recoveryShare, signId, fromHex(digestHex));
    return { signatureHex: toHex(signature), via: 'recoveryFile' };
  } finally {
    wipe(recoveryShare);
  }
}

async function handle(request: Request): Promise<unknown> {
  switch (request.type) {
    case 'status':
      return status();
    case 'wasmHealth': {
      const started = performance.now();
      await loadWasm();
      const health: WasmHealth = {
        config: threshold_config(),
        loadMs: Math.round(performance.now() - started),
      };
      return health;
    }
    case 'serverHealth':
      return serverHealth(await settings.serverUrl());
    case 'createKey':
      return createKey(request.password);
    case 'confirmRecoverySaved':
      return confirmRecoverySaved();
    case 'cancelOnboarding':
      cancelOnboarding();
      return status();
    case 'unlock':
      return unlock(request.password);
    case 'lock':
      lock();
      return status();
    case 'sign':
      return sign(request.digestHex);
    case 'signOffline':
      return signOffline(request.digestHex, request.recoveryShareHex);
    case 'recoverFromFile':
      return recoverFromFile(
        request.password,
        request.walletId,
        request.publicKeyHex,
        request.recoveryShareHex,
      );
    case 'readSettings':
      return settings.read();
    case 'setServerUrl':
      return settings.setServerUrl(request.serverUrl);
    case 'registerPasskey':
      return startPasskey('register');
    case 'assertPasskey':
      return startPasskey(request.purpose, request.operationId, request.digest);
    case 'passkeyLauncherReady':
      return passkeyLauncherReady();
    case 'passkeyStatus':
      return passkeyStatus(request.ceremonyId);
    case 'pendingApprovals':
      return approvals.pending();
    case 'decideApproval':
      return approvals.decide(request.id, request.approved);
    case 'connectedOrigins':
      return permissions.connected();
    case 'disconnectOrigin':
      return permissions.disconnect(request.origin);
    case 'pageRequest':
      // Handled separately: it needs the sender's origin, which `handle` does not see.
      throw new Error('Page requests are dispatched with their sender.');
    default: {
      const exhaustive: never = request;
      throw new Error(`Unknown request: ${JSON.stringify(exhaustive)}`);
    }
  }
}

export default defineBackground(() => {
  chrome.runtime.onMessage.addListener(
    (request: Request, sender, sendResponse: (response: Response<unknown>) => void) => {
      // Page requests are answered against the origin the browser reports for the sender. A page
      // cannot influence this value, which is the point (`docs/web-api.md`).
      const work =
        request.type === 'pageRequest'
          ? (async () => {
              const origin = sender.origin ?? (sender.url ? new URL(sender.url).origin : undefined);
              if (!origin) throw new Error('This request has no verifiable origin.');
              return handlePageRequest(origin, request.method, request.params, {
                address,
                sign: async (digestHex) => (await sign(digestHex)).signatureHex,
                requestApproval: openApprovalWindow,
              });
            })()
          : handle(request);

      work
        .then((value) => sendResponse({ ok: true, value }))
        // Pass a string only, so no secret can ride along in an error object.
        .catch((error: unknown) => {
          const message =
            error instanceof ServerUnreachable
              ? error.message
              : error instanceof Error
                ? error.message
                : String(error);
          sendResponse({ ok: false, error: message });
        });
      // Signals that we will respond asynchronously.
      return true;
    },
  );
});
