/**
 * The background service worker.
 *
 * The only place with access to secrets. Share A exists in decrypted form solely in this
 * worker's memory, so the wallet locks itself whenever the worker is terminated
 * (`docs/architecture.md`).
 */
import type { CreatedKey, Request, Response, Signed, Status, WasmHealth } from '../src/messages';
import { PARTY, runDkg, signWithRecoveryFile, signWithServer } from '../src/protocolRunner';
import { health as serverHealth, ServerUnreachable } from '../src/serverClient';
import * as settings from '../src/settings';
import * as vault from '../src/vault';
import { loadWasm, threshold_config } from '../src/wasm';

/** The decrypted share A. Disappears with the worker, and is never persisted. */
let unlockedShare: Uint8Array | undefined;

/**
 * In-flight onboarding state. **Nothing is persisted** until the recovery file is confirmed
 * saved.
 *
 * Storing share A first would mean that if the worker died before the export, share B would be
 * gone forever and the wallet unusable. So both are held in memory and committed together:
 * a failure leaves no trace at all.
 */
let pending:
  { shareA: Uint8Array; publicKeyHex: string; walletId: string; password: string } | undefined;

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

  pending = {
    shareA: outcome.extensionShare,
    publicKeyHex: outcome.publicKeyHex,
    walletId,
    password,
  };

  // Share B is handed over here and left nowhere in worker memory.
  const recoveryShareHex = toHex(outcome.recoveryShare);
  wipe(outcome.recoveryShare);

  return { publicKeyHex: outcome.publicKeyHex, walletId, recoveryShareHex };
}

/** The recovery file is saved. Only now do we store share A. */
async function confirmRecoverySaved(): Promise<Status> {
  if (!pending) throw new Error('There is no key waiting to be stored.');

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

function lock(): void {
  wipe(unlockedShare);
  unlockedShare = undefined;
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
    default: {
      const exhaustive: never = request;
      throw new Error(`Unknown request: ${JSON.stringify(exhaustive)}`);
    }
  }
}

export default defineBackground(() => {
  chrome.runtime.onMessage.addListener(
    (request: Request, _sender, sendResponse: (response: Response<unknown>) => void) => {
      handle(request)
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
