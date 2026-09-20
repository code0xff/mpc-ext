/**
 * Values shared with the server for a reshare (`docs/adr/0007-distributed-reshare.md`).
 */

const encoder = new TextEncoder();

function bytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Hex input has an odd length.');
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) =>
    Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16),
  );
}

/**
 * The digest a `recovery` passkey assertion is bound to for one reshare:
 * SHA-256("mpc-ext reshare v1" || public key || reshare id).
 *
 * The server recomputes it (`grant_digest` in `crates/mpc-server/src/reshare.rs`), so a grant
 * for one wallet or one session cannot start another. Both sides test the same vector.
 */
export async function reshareGrantDigest(
  publicKeyHex: string,
  reshareIdHex: string,
): Promise<string> {
  const label = encoder.encode('mpc-ext reshare v1');
  const publicKey = bytes(publicKeyHex);
  const id = bytes(reshareIdHex);
  const input = new Uint8Array(label.length + publicKey.length + id.length);
  input.set(label, 0);
  input.set(publicKey, label.length);
  input.set(id, label.length + publicKey.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}
