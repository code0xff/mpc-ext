/**
 * Encrypted storage for share A.
 *
 * Plaintext shares never reach the disk; all that is stored is KDF parameters and ciphertext
 * (`docs/security.md`).
 *
 * This uses WebCrypto's PBKDF2 + AES-GCM. Moving to the Argon2id + XChaCha20-Poly1305 that
 * `security.md` calls for is a Phase 6 hardening task, migrated via `formatVersion`.
 */

const STORAGE_KEY = 'vault';
const FORMAT_VERSION = 3;
const PBKDF2_ITERATIONS = 600_000;

interface VaultRecord {
  formatVersion: number;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltB64: string;
  ivB64: string;
  ciphertextB64: string;
  /** Public information that can be shown while locked. */
  publicKeyHex: string;
  /** Identifies this wallet to the server. Not a secret. */
  walletId: string;
  /**
   * Which party the stored share belongs to: 0 for the extension share created at setup, 1 for
   * a recovery share imported after a device loss (`docs/recovery.md`).
   */
  party: number;
}

function toB64(bytes: Uint8Array): string {
  // Shares are over 100 KB. Spreading them into String.fromCharCode(...bytes) in one go blows
  // the argument-count limit and overflows the stack, so build the string in chunks.
  const CHUNK = 0x8000;
  let out = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(out);
}

function fromB64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

async function deriveKey(password: string, salt: Uint8Array, iterations: number) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Encrypts a share under the password and stores it. */
export async function store(
  password: string,
  share: Uint8Array,
  publicKeyHex: string,
  walletId: string,
  party: number,
): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // A fresh nonce per record. Reuse breaks AES-GCM.
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      share as BufferSource,
    ),
  );

  const record: VaultRecord = {
    formatVersion: FORMAT_VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    saltB64: toB64(salt),
    ivB64: toB64(iv),
    ciphertextB64: toB64(ciphertext),
    publicKeyHex,
    walletId,
    party,
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: record });
}

async function read(): Promise<VaultRecord | undefined> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] as VaultRecord | undefined;
}

/** Whether a key is stored. */
export async function exists(): Promise<boolean> {
  return (await read()) !== undefined;
}

/** The public key, readable even while locked. */
export async function publicKeyHex(): Promise<string | undefined> {
  return (await read())?.publicKeyHex;
}

/** The wallet id the server knows us by. Readable while locked; it is not a secret. */
export async function walletId(): Promise<string | undefined> {
  return (await read())?.walletId;
}

/** Which party the stored share belongs to. */
export async function party(): Promise<number | undefined> {
  return (await read())?.party;
}

/** Decrypts the share with the password. Returns `undefined` if the password is wrong. */
export async function unlock(password: string): Promise<Uint8Array | undefined> {
  const record = await read();
  if (!record) return undefined;
  if (record.formatVersion !== FORMAT_VERSION) {
    throw new Error(`unsupported storage format (v${record.formatVersion})`);
  }

  const key = await deriveKey(password, fromB64(record.saltB64), record.iterations);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(record.ivB64) as BufferSource },
      key,
      fromB64(record.ciphertextB64) as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Authentication failure means a wrong password. We do not distinguish the two for the
    // caller.
    return undefined;
  }
}
