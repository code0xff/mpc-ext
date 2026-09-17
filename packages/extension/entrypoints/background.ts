/**
 * The background service worker.
 *
 * The only place with access to secrets. Share A exists in decrypted form solely in this
 * worker's memory, so the wallet locks itself whenever the worker is terminated
 * (`docs/architecture.md`).
 */
import type { CreatedKey, Request, Response, Status, WasmHealth } from '../src/messages';
import * as vault from '../src/vault';
import { loadWasm, threshold_config, wasmDkg } from '../src/wasm';

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
let pending: { shareA: Uint8Array; publicKeyHex: string; password: string } | undefined;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function wipe(bytes: Uint8Array | undefined): void {
  bytes?.fill(0);
}

async function status(): Promise<Status> {
  if (pending) {
    return { kind: 'awaitingRecoveryExport', publicKeyHex: pending.publicKeyHex };
  }
  const publicKeyHex = await vault.publicKeyHex();
  if (!publicKeyHex) return { kind: 'uninitialized' };
  return unlockedShare ? { kind: 'unlocked', publicKeyHex } : { kind: 'locked', publicKeyHex };
}

/**
 * Creates a key.
 *
 * DKG produces three shares, but the extension **keeps only A.** B is handed back so the user
 * can store it as a recovery file, and C belongs to the server
 * (`docs/adr/0005-share-placement.md`).
 */
async function createKey(password: string): Promise<CreatedKey> {
  if (password.length < 8) throw new Error('The password must be at least 8 characters.');
  if (await vault.exists()) throw new Error('A key already exists.');

  await loadWasm();
  const sessionId = crypto.getRandomValues(new Uint8Array(32));
  const keyset = wasmDkg(sessionId);

  const shareA = keyset.share(0);
  const shareB = keyset.share(1);
  const publicKeyHex = toHex(keyset.public_key);

  pending = { shareA, publicKeyHex, password };
  // Share B is handed over here and left nowhere in worker memory.
  const recoveryShareHex = toHex(shareB);
  wipe(shareB);

  return { publicKeyHex, recoveryShareHex };
}

/** The recovery file is saved. Only now do we store share A. */
async function confirmRecoverySaved(): Promise<Status> {
  if (!pending) throw new Error('There is no key waiting to be stored.');

  await vault.store(pending.password, pending.shareA, pending.publicKeyHex);
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
          sendResponse({
            ok: false,
            error: error instanceof Error ? error.message : String(error),
          });
        });
      // Signals that we will respond asynchronously.
      return true;
    },
  );
});
