/**
 * Device-key request authentication primitives.
 *
 * The private key is non-extractable and is intended to be kept in extension storage. This key
 * identifies an installation; it is not a second factor (`docs/adr/0006-server-authentication.md`).
 */

const encoder = new TextEncoder();
const STORAGE_KEY = 'device-key';

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

/** Stores the non-extractable pair in extension storage. */
export async function storeDeviceKey(pair: CryptoKeyPair): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: pair });
}

/** Loads the installation key pair, if this wallet has one. */
export async function loadDeviceKey(): Promise<CryptoKeyPair | undefined> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] as CryptoKeyPair | undefined;
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
