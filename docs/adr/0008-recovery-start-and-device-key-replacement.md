# ADR-0008: Starting a recovery and replacing the device key

- Status: accepted; implementation in progress
- Date: 2026-09-21

## Context

The server holds share C and takes part in every signature. What stands between a stranger and
that participation is the device key (identifies an installation) and the passkey (the real second
factor). ADR-0006 says a recovery needs the passkey and a cooling-off period, but the code does
neither.

Three gaps follow from that.

- `POST /v1/device-key` takes no proof and overwrites. Anyone who knows a wallet id can replace its
  device key and lock the real extension out of the server.
- `recoverFromFile` uses that endpoint to register the new install's key, so a recovery today is
  just "hold the recovery file and know the wallet id". No passkey, no waiting, no way to object.
- The device proof covers a re-serialization of the parsed body, not the bytes that were sent. A
  `register` handoff was rejected for months because of one `null`. It is also a standing hazard
  (key order, escaping) for every signed endpoint.

A recovery has a chicken-and-egg problem. The new install has no device key the server accepts, so
it cannot use any endpoint that needs one. The passkey ceremony needs a device-authenticated
handoff. Whatever starts a recovery therefore has to work without a device proof, and its only
defences are the passkey and time.

## Options considered

| Option                                                    | Pros                                          | Cons                                                                                            |
| --------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Keep replacing the key with no checks                     | Nothing to build                              | Anyone with a wallet id can lock the user out, and a recovery needs no passkey                  |
| Passkey assertion only, effective immediately             | Simple, one approval                          | A phished or coerced approval takes effect at once, and nobody with the old device can object   |
| Passkey assertion, then a cooling-off wait, then complete | The old device or the user can object in time | Recovery is slow, and with no notification channel only someone who checks can object           |
| Email or phone confirmation                               | Familiar                                      | Needs accounts and personal data, which the design avoids (ADR-0006), and adds a party to trust |

## Decision

**Registering a device key is first-use only.** `POST /v1/device-key` succeeds only while the
wallet has no device key, which is the moment right after key creation. Replacing a key is
possible only through a recovery.

**A recovery is three calls.**

1. `POST /v1/recovery/request` carries the wallet id and the new install's public device key, with
   no device proof. It returns a browser handoff for a passkey ceremony bound to this request and to
   the new key: the assertion's operation id is the request id and its digest is
   `SHA-256("mpc-ext recovery v1" || wallet id || new device key || request id)`. The request only
   asks for an assertion. Requests that never get one expire after 15 minutes, and a wallet may
   open at most five per hour.
2. `POST /v1/recovery/status` is signed with the **new** device key, which the server already
   holds from step 1. When it finds the verified assertion it consumes it and moves the request to
   `cooling`, with `ready_at` set one cooling period ahead. It reports the state and `ready_at`.
3. `POST /v1/recovery/complete` is signed with the new key too. It succeeds only after `ready_at`
   and before the request expires, and replaces the wallet's device key in one transaction.

A wallet has at most one request in `cooling`. A second assertion while one is cooling is refused.

**The cooling period is a server setting**, `MPC_SERVER_RECOVERY_COOLING_SECONDS`, 24 hours by
default. Self-hosters and tests can shorten it. A cooling request must be completed within 72
hours of `ready_at` or it expires.

**Objecting.** `POST /v1/recovery/pending`, signed with the wallet's current device key, lists
what is waiting. `POST /v1/recovery/cancel` cancels a request and accepts either the current key
or the request's own new key. The extension checks for a pending recovery whenever it is unlocked
and offers to cancel, showing when it was asked and a short fingerprint of the new key.

**The ceremony page says what it is approving.** The passkey prompt alone tells the user nothing,
and a page could submit a handoff token to the server origin on the user's behalf. The page shows
the purpose (a recovery of this wallet's device) before the authenticator prompt.

**Every step is written to the audit log** (requested, cooling, cancelled, completed), without any
key material.

**The device proof covers the request body bytes as received.** The server signs and verifies the
exact string. It no longer re-serializes, so key order and `null` handling cannot make the two
sides disagree.

**In the extension, nothing secret waits.** A recovery can take a day, so the new install keeps
the pending device key (non-extractable, in IndexedDB), the request id and the wallet id, but
neither the recovery share nor any password. To finish, the user selects the recovery file again.

## Consequences

**Recovery is now slow on purpose.** A user who loses a device waits a day, by default, before
signing with B and C again. The A+B path (share A on the device, recovery file B) is unaffected,
but it needs the device. So in the case that matters, a lost device, the wait is real. A shorter
setting trades protection for convenience, and each self-hoster picks their own.

**Objection depends on someone looking.** There is no email or phone by design, so nothing pushes
a notice. The old extension shows pending recoveries when unlocked, which helps a user who still
has the device, or who finds it again. A user whose device is gone and whose passkey is misused
gets the wait but no warning. Passkey-signed cancellation, and a way to look up pending requests
from a fresh browser, are deferred.

**The passkey is the whole defence against a determined attacker.** With the passkey and the
recovery file an attacker wins after the wait. That is the same strength ADR-0006 already assumed.
This decision adds delay and visibility, not a new factor.

**A stranger can no longer lock a user out.** Replacing a key needs a passkey assertion, and the
request that asks for one changes nothing by itself.

**The signed-body change touches every authenticated endpoint,** and any client that signs a
different string than it sends now fails. The extension already signs what it sends. Tests that
built headers from a typed round trip have to sign the real body, which is what they should have
done.

**Reversing it** means restoring the unauthenticated overwrite, which nobody should want. The
cooling period can be set to zero to make the flow instant without removing it.
