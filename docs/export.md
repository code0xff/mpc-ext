# Key export

## Principle

Users must be able to take their key out at any time. This project does not hold keys hostage.
At the same time, export is the **only defence against losing the device** — it cannot be
created after the fact.

## Two kinds of export

### 1. The recovery file (share B) — **mandatory, cannot be skipped**

- Right after DKG, share B is exported as a file encrypted with the user's password. The
  extension never stores B ([adr/0005](adr/0005-share-placement.md)).
- Used for: recovering a lost device, emergency signing when the server is down, and key export.
- Format (version 3): a JSON container with `format_version`, KDF/AEAD parameters, salt, nonce,
  ciphertext, the public key and the wallet id. The share is encrypted with PBKDF2-SHA256 +
  AES-GCM under a **recovery password** chosen at export time (it may differ from the wallet
  password, and must be stored apart from the file). The public key and wallet id are bound to
  the ciphertext as associated data, so they cannot be swapped between files.
- Version 2 files were plaintext. No key was ever issued with one, so import refuses them.
- **It is roughly 230 KB** (the share itself is ~114 KB because it carries OT setup state). It
  cannot be turned into a mnemonic or a QR code, so it has to be kept as a file
  ([adr/0005](adr/0005-share-placement.md)).
- Files are easier to lose than mnemonics, so **encourage several copies**. Share B alone cannot
  sign, so extra copies do not increase risk.
- On import, check the file's public key against the wallet's to confirm integrity.
- A matching **import** path must always exist. A backup you cannot restore is not a backup.

### 2. Full private key export (dangerous, explicit opt-in)

- Combines two of the three shares to reconstruct a single private key and prints it in a
  standard format (`mpc_core::export_private_key`).
- Output: hex private key and standard wallet-compatible formats.
- The MPC security benefit disappears at that moment. The UI warns loudly and the user must
  explicitly confirm the risk.
- Afterwards, advise retiring the key and moving to a new one.
- **Implementation.** The popup asks for an explicit acknowledgement, the wallet password again,
  and the recovery file with its password. The extension combines its own share (A) with the
  recovery file (B) in wasm (`export_private_key`). The result is checked against the wallet's
  public key, because two shares from different wallets or refresh epochs interpolate to a
  plausible but unrelated scalar; a mismatch fails instead of returning a wrong key.
- **Not available after a device-loss restore.** That wallet holds share B, the same share the
  recovery file carries, and C never leaves the server, so there is no second share to combine
  (`recovery.md`). The panel is hidden for restored wallets.
- The key is shown for a minute and then hidden, is never stored, and the clipboard is cleared
  30 seconds after a copy (best effort: it does not fire if the popup closes first). An event
  with a timestamp and no key material is kept in the local event log.

## Onboarding requirements

- **Exporting the recovery file cannot be skipped.** Key creation is not complete until the
  export is confirmed, because share B can never be produced again.
- After the export, zeroize share B in the extension's memory and never write it to storage.
- **Tell the user to store it away from the extension.** Leaving it in the default downloads
  folder on the same machine puts two shares in one place.
- State plainly that losing the recovery file and the device together is unrecoverable.
- Refresh or reshare invalidates the existing recovery file. Prompt for a new export and tell the
  user to destroy the old one.

## Procedural requirements

- Require the password again before exporting.
- Let the user save the plaintext key themselves; the extension never writes it to disk.
- Clear the clipboard automatically after a short delay.
- Record that an export happened in the local event log (never the key material).
- Export and import must work fully offline, without the server.
