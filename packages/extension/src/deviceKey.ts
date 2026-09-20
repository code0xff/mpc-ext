/**
 * Device-key request authentication primitives.
 *
 * The private key is non-extractable and lives in IndexedDB, which stores `CryptoKey` objects by
 * structured clone. `chrome.storage.local` cannot: it serialises to JSON, so a stored key comes
 * back as an empty object and signing fails. This key identifies an installation; it is not a
 * second factor (`docs/adr/0006-server-authentication.md`).
 */

const encoder = new TextEncoder();
const DB_NAME = 'mpc-ext-device';
const STORE = 'device-key';
const RECORD = 'pair';

export interface SignedRequest {
  timestamp: number;
  nonce: string;
  signatureB64: string;
}

function base64(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, '0')).join('');
}

/** Stable bytes signed for every server request. */
export function canonicalRequest(
  method: string,
  path: string,
  body: string,
  timestamp: number,
  nonce: string,
): Uint8Array {
  return encoder.encode(`${method}\n${path}\n${timestamp}\n${nonce}\n${body}`);
}

/** Creates the non-extractable P-256 key used to identify this extension installation. */
export function createDeviceKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]) as Promise<CryptoKeyPair>;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error('Could not open the device key store.'));
  });
}

async function withStore<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = run(db.transaction(STORE, mode).objectStore(STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error('Could not access the device key store.'));
    });
  } finally {
    db.close();
  }
}

/** Stores the non-extractable pair. It never leaves this browser profile. */
export async function storeDeviceKey(pair: CryptoKeyPair): Promise<void> {
  await withStore('readwrite', (store) => store.put(pair, RECORD));
}

/** Loads the installation key pair, if this wallet has one. */
export async function loadDeviceKey(): Promise<CryptoKeyPair | undefined> {
  const pair = await withStore<CryptoKeyPair | undefined>('readonly', (store) => store.get(RECORD));
  // A pair that lost its keys on the way in would fail later with a confusing WebCrypto error.
  return pair?.privateKey instanceof CryptoKey ? pair : undefined;
}

/** Exports only the public key, in the format accepted by WebCrypto importKey. */
export async function exportDevicePublicKey(key: CryptoKey): Promise<string> {
  return hex(await crypto.subtle.exportKey('raw', key));
}

/** Signs one request body with a fresh nonce and current timestamp. */
export async function signRequest(
  privateKey: CryptoKey,
  method: string,
  path: string,
  body: string,
  now = Date.now(),
  nonce = crypto.randomUUID(),
): Promise<SignedRequest> {
  const data = canonicalRequest(method, path, body, now, nonce);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
  return { timestamp: now, nonce, signatureB64: base64(signature) };
}
