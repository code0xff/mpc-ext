/**
 * 셰어 A의 암호화 저장소.
 *
 * 평문 셰어는 절대 디스크에 쓰지 않는다. 저장되는 것은 KDF 파라미터와 암호문뿐이다
 * (`docs/security.md`).
 *
 * Phase 2는 WebCrypto의 PBKDF2 + AES-GCM을 쓴다. `security.md`가 규정한
 * Argon2id + XChaCha20-Poly1305으로의 전환은 Phase 6 하드닝 항목이며,
 * `formatVersion`으로 마이그레이션한다.
 */

const STORAGE_KEY = 'vault';
const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

interface VaultRecord {
  formatVersion: number;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltB64: string;
  ivB64: string;
  ciphertextB64: string;
  /** 잠금 상태에서도 보여줄 수 있는 공개 정보. */
  publicKeyHex: string;
}

function toB64(bytes: Uint8Array): string {
  // 셰어는 100 KB를 넘는다. String.fromCharCode(...bytes)로 한 번에 펼치면
  // 인자 개수가 스택 한계를 넘어 터진다. 조각내서 이어붙인다.
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

/** 셰어를 비밀번호로 암호화해 저장한다. */
export async function store(
  password: string,
  share: Uint8Array,
  publicKeyHex: string,
): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // 논스는 레코드마다 새로 만든다. 재사용은 AES-GCM을 깨뜨린다.
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
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: record });
}

async function read(): Promise<VaultRecord | undefined> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] as VaultRecord | undefined;
}

/** 저장된 키가 있는지. */
export async function exists(): Promise<boolean> {
  return (await read()) !== undefined;
}

/** 잠금 상태에서도 읽을 수 있는 공개키. */
export async function publicKeyHex(): Promise<string | undefined> {
  return (await read())?.publicKeyHex;
}

/** 비밀번호로 셰어를 복호화한다. 비밀번호가 틀리면 `undefined`. */
export async function unlock(password: string): Promise<Uint8Array | undefined> {
  const record = await read();
  if (!record) return undefined;
  if (record.formatVersion !== FORMAT_VERSION) {
    throw new Error(`지원하지 않는 저장 포맷입니다 (v${record.formatVersion})`);
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
    // 인증 실패 = 비밀번호 오류. 어느 쪽인지 구분해 알려주지 않는다.
    return undefined;
  }
}
