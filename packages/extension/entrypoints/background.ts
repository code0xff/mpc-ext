/**
 * The background service worker.
 *
 * The only place with access to secrets. Share A exists in decrypted form solely in this
 * worker's memory, so the wallet locks itself whenever the worker is terminated
 * (`docs/architecture.md`).
 */
import * as approvals from '../src/approvals';
import * as eventLog from '../src/eventLog';
import type {
  CreatedKey,
  ExportedKey,
  Request,
  ReshareProgress,
  Response,
  Signed,
  Status,
  WasmHealth,
} from '../src/messages';
import { handlePageRequest } from '../src/pageApi';
import * as permissions from '../src/permissions';
import {
  PARTY,
  runDkg,
  runReshare,
  signWithRecoveryFile,
  signWithServer,
} from '../src/protocolRunner';
import { reshareGrantDigest } from '../src/reshare';
import {
  createPasskeyHandoff,
  abortReshare,
  commitReshare,
  health as serverHealth,
  passkeyCeremonyStatus,
  registerDeviceKey,
  ServerUnreachable,
} from '../src/serverClient';
import { createDeviceKey, exportDevicePublicKey, storeDeviceKey } from '../src/deviceKey';
import * as settings from '../src/settings';
import * as vault from '../src/vault';
import { ethereum_address, export_private_key, loadWasm, threshold_config } from '../src/wasm';

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

/**
 * In-flight reshare state (`docs/adr/0007-distributed-reshare.md`).
 *
 * The server has staged its new share, but nothing local has changed. Once the user has saved the
 * new recovery file we commit on the server and only then replace the vault. `committed` records
 * that the server side is done, so a failure while storing locally can be retried without
 * committing twice.
 */
let pendingReshare:
  | {
      shareA: Uint8Array;
      publicKeyHex: string;
      walletId: string;
      password: string;
      reshareIdHex: string;
      committed: boolean;
    }
  | undefined;

/**
 * The reshare that is being set up. The passkey ceremony opens a tab, which closes the popup, so
 * the popup cannot wait for the result and instead polls this. `ready` holds the new recovery
 * share until the popup takes it, once.
 */
let reshareRun:
  | { phase: 'working' }
  | { phase: 'ready'; created: CreatedKey }
  | { phase: 'failed'; error: string }
  | undefined;

/**
 * Identifies the current reshare run. Cancelling bumps it, so a run that was cancelled while it
 * was still working notices when it finishes and undoes itself instead of reviving.
 */
let reshareToken = 0;

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
  return {
    kind: 'unlocked',
    publicKeyHex,
    recovered,
    reshareInProgress: pendingReshare !== undefined,
  };
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

/**
 * Completes a server-origin passkey ceremony before the operation it authorizes begins. A wallet
 * restored from a recovery file signs under the `recovery` policy, and a reshare always does.
 */
async function authorizeWithPasskey(
  purpose: 'sign' | 'recovery',
  operationId: string,
  digest: string,
): Promise<void> {
  const { ceremonyId } = await startPasskey(purpose, operationId, digest);
  const startedAt = Date.now();
  try {
    for (;;) {
      if (Date.now() - startedAt > 120_000) {
        throw new Error('The passkey ceremony timed out.');
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
      // An MV3 worker is stopped after 30 seconds without an extension API call, and the ceremony
      // can take longer. A cheap call each round keeps it alive until the user answers.
      await chrome.runtime.getPlatformInfo();
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
  await authorizeWithPasskey(
    localParty === PARTY.recovery ? 'recovery' : 'sign',
    toHex(signId),
    digestHex,
  );
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

/**
 * Reshares a wallet that was restored from a recovery file.
 *
 * Recovery leaves the wallet degraded: the extension holds share B, the same share the recovery
 * file carries, and the lost share A stays valid. A reshare replaces all three shares while
 * keeping the address (`docs/adr/0007-distributed-reshare.md`). The server stages its new share
 * and nothing local changes until `confirmReshareSaved`.
 *
 * While it runs, this extension holds two new shares and can compute the key, exactly as it can
 * at key creation. It is only offered on the device the user just restored onto.
 */
async function startReshare(password: string): Promise<ReshareProgress> {
  requireUnlocked();
  if ((await vault.party()) !== PARTY.recovery) {
    throw new Error('Only a wallet restored from a recovery file needs a reshare.');
  }
  if (pendingReshare || reshareRun) {
    throw new Error('A reshare is already in progress. Finish or cancel it.');
  }
  const walletId = await vault.walletId();
  const publicKeyHex = await vault.publicKeyHex();
  if (!walletId || !publicKeyHex) throw new Error('This wallet is not initialized.');

  // Re-authenticate: this replaces the server's share, so an unlocked session is not enough.
  const oldShare = await vault.unlock(password);
  if (!oldShare) throw new Error('That password is not correct.');

  reshareRun = { phase: 'working' };
  reshareToken += 1;
  const token = reshareToken;
  void performReshare(password, walletId, publicKeyHex, oldShare, token).then(
    (created) => {
      if (token === reshareToken) reshareRun = { phase: 'ready', created };
    },
    (error: unknown) => {
      if (token !== reshareToken) return;
      reshareRun = {
        phase: 'failed',
        error: error instanceof Error ? error.message : String(error),
      };
    },
  );
  return { phase: 'working' };
}

async function performReshare(
  password: string,
  walletId: string,
  publicKeyHex: string,
  oldShare: Uint8Array,
  token: number,
): Promise<CreatedKey> {
  try {
    await loadWasm();
    const reshareId = crypto.getRandomValues(new Uint8Array(32));
    const reshareIdHex = toHex(reshareId);
    await authorizeWithPasskey(
      'recovery',
      reshareIdHex,
      await reshareGrantDigest(publicKeyHex, reshareIdHex),
    );

    const outcome = await runReshare(
      await settings.serverUrl(),
      walletId,
      reshareId,
      oldShare,
      fromHex(publicKeyHex),
    );

    if (token !== reshareToken) {
      // Cancelled while the server was working. Undo it rather than leave a share staged.
      wipe(outcome.extensionShare);
      wipe(outcome.recoveryShare);
      await abortReshare(await settings.serverUrl(), walletId, reshareIdHex).catch(() => undefined);
      throw new Error('The reshare was cancelled.');
    }

    pendingReshare = {
      shareA: outcome.extensionShare,
      publicKeyHex: outcome.publicKeyHex,
      walletId,
      password,
      reshareIdHex,
      committed: false,
    };

    // The new recovery share waits here for the popup to take it, and is left nowhere else.
    const recoveryShareHex = toHex(outcome.recoveryShare);
    wipe(outcome.recoveryShare);
    return { publicKeyHex: outcome.publicKeyHex, walletId, recoveryShareHex };
  } finally {
    wipe(oldShare);
  }
}

/** Reports how far the reshare has got. A failure is reported once and then forgotten. */
function reshareProgress(): ReshareProgress {
  if (!reshareRun) return { phase: 'idle' };
  if (reshareRun.phase === 'failed') {
    const { error } = reshareRun;
    reshareRun = undefined;
    return { phase: 'failed', error };
  }
  return { phase: reshareRun.phase };
}

/** Hands over the new recovery share, once. It is not kept afterwards. */
function takeReshareRecovery(): CreatedKey {
  if (reshareRun?.phase !== 'ready') throw new Error('There is no new recovery file to save.');
  const { created } = reshareRun;
  reshareRun = undefined;
  return created;
}

/**
 * The new recovery file is saved, so make the reshare real.
 *
 * Order matters. The server commits first, and only then is the vault replaced. If storing
 * locally fails after the commit, the wallet is still recoverable from the new recovery file, and
 * retrying this call skips the commit it already made.
 */
async function confirmReshareSaved(): Promise<Status> {
  const reshare = pendingReshare;
  if (!reshare) throw new Error('There is no reshare waiting to be finished.');

  if (!reshare.committed) {
    await commitReshare(await settings.serverUrl(), reshare.walletId, reshare.reshareIdHex);
    reshare.committed = true;
  }
  await vault.store(
    reshare.password,
    reshare.shareA,
    reshare.publicKeyHex,
    reshare.walletId,
    PARTY.extension,
  );
  wipe(unlockedShare);
  unlockedShare = reshare.shareA;
  pendingReshare = undefined;

  return status();
}

/** Abandons a reshare that has not been committed. The current shares stay valid. */
async function cancelReshare(): Promise<Status> {
  const reshare = pendingReshare;
  if (!reshare) {
    // Nothing was staged yet, or the setup is still running. Forget any result it produces.
    reshareToken += 1;
    reshareRun = undefined;
    return status();
  }
  if (reshare.committed) {
    throw new Error(
      'The new server share is already live. Finish storing the new share; the old one no longer works.',
    );
  }
  // A failure to reach the server must not keep the user stuck. The staged share expires there.
  await abortReshare(await settings.serverUrl(), reshare.walletId, reshare.reshareIdHex).catch(
    () => undefined,
  );
  wipe(reshare.shareA);
  pendingReshare = undefined;
  return status();
}

/**
 * Reconstructs the full private key from the extension share and a recovery file.
 *
 * Only a wallet that still holds share A can do this. A restored wallet holds B, the same share
 * the recovery file carries, and C never leaves the server, so there is no second share to
 * combine. The password is checked again, and the result is verified against the wallet's public
 * key so a wrong share pair fails rather than returning an unrelated key.
 */
async function exportPrivateKey(password: string, recoveryShareHex: string): Promise<ExportedKey> {
  requireUnlocked();
  if ((await vault.party()) !== PARTY.extension) {
    throw new Error(
      'This wallet was restored from a recovery file, so it has no second share to export with. Sign what you need and move the funds to a new wallet.',
    );
  }
  const publicKeyHex = await vault.publicKeyHex();
  if (!publicKeyHex) throw new Error('This wallet is not initialized.');

  // Re-authenticate: an unlocked session alone must not be enough to take the key out.
  const share = await vault.unlock(password);
  if (!share) throw new Error('That password is not correct.');

  await loadWasm();
  const recoveryShare = fromHex(recoveryShareHex);
  let key: Uint8Array | undefined;
  try {
    const exported = export_private_key(
      share,
      PARTY.extension,
      recoveryShare,
      PARTY.recovery,
      fromHex(publicKeyHex),
    );
    key = exported;
    // Log the fact of the export, never its value.
    await eventLog.record('privateKeyExported');
    return { privateKeyHex: toHex(exported) };
  } finally {
    wipe(share);
    wipe(recoveryShare);
    wipe(key);
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
    case 'startReshare':
      return startReshare(request.password);
    case 'reshareProgress':
      return reshareProgress();
    case 'takeReshareRecovery':
      return takeReshareRecovery();
    case 'confirmReshareSaved':
      return confirmReshareSaved();
    case 'cancelReshare':
      return cancelReshare();
    case 'exportPrivateKey':
      return exportPrivateKey(request.password, request.recoveryShareHex);
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
