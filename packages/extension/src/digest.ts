/**
 * EIP-191 message hashing.
 *
 * `personal_sign` does not sign the raw bytes: it prefixes them first. That prefix is what stops
 * a page from getting a transaction signed by dressing it up as a plain message, so it is not
 * optional (`docs/web-api.md`).
 */

/** The byte EIP-191 uses to mark a personal message. */
const EIP191_VERSION_BYTE = 0x19;

/** Concatenates the EIP-191 prefix with the message bytes. */
export function eip191Payload(message: Uint8Array): Uint8Array {
  const label = new TextEncoder().encode(`Ethereum Signed Message:\n${message.length}`);

  const payload = new Uint8Array(1 + label.length + message.length);
  payload[0] = EIP191_VERSION_BYTE;
  payload.set(label, 1);
  payload.set(message, 1 + label.length);
  return payload;
}
