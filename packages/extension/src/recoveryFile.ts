/**
 * The recovery file (share B): its container format and password encryption.
 *
 * The share is encrypted under a password the user picks at export time, so a stolen file is
 * not enough to hold even one usable share (`docs/export.md`).
 */
import { fromB64, toB64 } from './vault';

export const RECOVERY_KIND = 'mpc-ext-recovery';
const FORMAT_VERSION = 3;
const PBKDF2_ITERATIONS = 600_000;
export const MIN_PASSWORD_LENGTH = 8;

/** The file as written to disk. Everything but `ciphertextB64` is public. */
export interface EncryptedRecoveryFile {
  formatVersion: typeof FORMAT_VERSION;
  kind: typeof RECOVERY_KIND;
  createdAt: string;
  publicKey: string;
  /** Identifies the wallet to the server, so a fresh install can find share C. Not a secret. */
  walletId: string;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltB64: string;
  ivB64: string;
  ciphertextB64: string;
  note: string;
}

/** What a caller needs after opening a file, whichever version it was. */
export interface OpenedRecovery {
  publicKeyHex: string;
  walletId?: string;
  shareHex: string;
}

/** Thrown when a file is readable but the password does not open it. */
export class WrongPasswordError extends Error {
  constructor() {
    super('Wrong password for this recovery file.');
  }
}

/** Binds the public fields to the ciphertext, so they cannot be swapped between files. */
function aad(publicKey: string, walletId: string): BufferSource {
  return new TextEncoder().encode(
    JSON.stringify([RECOVERY_KIND, FORMAT_VERSION, publicKey, walletId]),
  ) as BufferSource;
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

const toHex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export async function encryptRecoveryFile(
  password: string,
  shareHex: string,
  publicKeyHex: string,
  walletId: string,
): Promise<EncryptedRecoveryFile> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`The recovery password needs at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // A fresh nonce per file. Reuse breaks AES-GCM.
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const plaintext = Uint8Array.from(shareHex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad(publicKeyHex, walletId) },
        key,
        plaintext as BufferSource,
      ),
    );
    return {
      formatVersion: FORMAT_VERSION,
      kind: RECOVERY_KIND,
      createdAt: new Date().toISOString(),
      publicKey: publicKeyHex,
      walletId,
      kdf: 'PBKDF2-SHA256',
      iterations: PBKDF2_ITERATIONS,
      saltB64: toB64(salt),
      ivB64: toB64(iv),
      ciphertextB64: toB64(ciphertext),
      note: 'mpc-ext recovery file (share B), encrypted with your recovery password. Store it somewhere other than the extension. This file alone cannot sign.',
    };
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Validates a parsed file and returns the share. Only encrypted (version 3) files are accepted.
 */
export async function openRecoveryFile(
  parsed: unknown,
  password?: string,
): Promise<OpenedRecovery> {
  const file = parsed as Partial<EncryptedRecoveryFile> | null;
  if (!file || file.kind !== RECOVERY_KIND) {
    throw new Error('That does not look like an mpc-ext recovery file.');
  }
  if (!file.publicKey) throw new Error('This recovery file is missing its public key.');

  if (file.formatVersion !== FORMAT_VERSION) {
    throw new Error(`Unsupported recovery file format (v${String(file.formatVersion)}).`);
  }
  if (!file.walletId || !file.saltB64 || !file.ivB64 || !file.ciphertextB64 || !file.iterations) {
    throw new Error('This recovery file is damaged.');
  }
  if (!password) throw new WrongPasswordError();

  const key = await deriveKey(password, fromB64(file.saltB64), file.iterations);
  try {
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: fromB64(file.ivB64) as BufferSource,
          additionalData: aad(file.publicKey, file.walletId),
        },
        key,
        fromB64(file.ciphertextB64) as BufferSource,
      ),
    );
    const shareHex = toHex(plaintext);
    plaintext.fill(0);
    return { publicKeyHex: file.publicKey, walletId: file.walletId, shareHex };
  } catch {
    // Authentication failure: a wrong password or a file altered after export.
    throw new WrongPasswordError();
  }
}
