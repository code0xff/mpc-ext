# ADR-0009: Seeing and cancelling a recovery with the passkey alone

- Status: accepted; implemented
- Date: 2026-09-21

## Context

A recovery waits before it can replace a wallet's device key ([ADR-0008](0008-recovery-start-and-device-key-replacement.md)).
The wait only helps if the owner can object during it, and the only way to object today is the
extension on the wallet's current device. That works for someone who still has the device. It does
not work for the case the wait exists for: the device is lost, a stranger holds the recovery file,
and the owner has nothing but their passkey.

There is no email or phone by design, so nothing can tell the owner. They have to be able to come
and look, from any browser, with only the passkey.

## Questions this decides

The earlier design notes left three questions open. This decision answers them, with the reason.

**Who may cancel?** Anyone who can complete a passkey assertion with user verification for the
wallet. That is the same test every signature and every recovery already has to pass.

The cost: an attacker who holds the passkey can cancel the owner's real recovery, and so can delay
it. They can already approve a recovery of their own, so this adds no new way in, only a way to
annoy. The owner can start again. Making cancellation harder would be worse, because it is the
protective action and it should be the easy one.

**Where does it live?** A page on the server's own origin, `/manage`, the same origin the passkey
was registered on. A passkey is bound to that origin, so no other place can ask for it. The
extension is not involved, which is the point: it may be the thing that was lost.

**Does looking notify anyone?** No. It only makes checking possible. Someone still has to think to
check, and a user who does not know a recovery was started will not. That limit stays and is
stated in [recovery.md](../recovery.md).

## Options considered

| Option                                                     | Pros                                          | Cons                                                                                           |
| ---------------------------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Enter the wallet id on the page, then prove the passkey    | Simple lookup                                 | The user must have kept the id, and a page that takes ids can be probed to learn which exist   |
| Identify the wallet from the passkey itself (usernameless) | Nothing to remember or type, nothing to probe | Needs an index from the passkey's user handle to the wallet                                    |
| A second passkey assertion for each cancel                 | Each cancel is individually approved          | Adds a prompt without protecting against anyone who holds the passkey, who can just approve it |
| Short session after one assertion, cancel within it        | One prompt, and cancelling several is easy    | A session to manage                                                                            |

## Decision

**Identify the wallet by the passkey.** The credential is discoverable and the server already asks
for a discoverable assertion, so the browser lets the user pick their passkey and the response
carries its user handle. The handle is 64 random bytes chosen at registration. It is stored in an
indexed column (`passkey_credentials.user_handle`) so the server can find the wallet from it. A
handle that matches no wallet gets the same refusal as a failed assertion, so the page cannot be
used to ask which passkeys exist.

**One assertion opens a short session.** The page asks for a challenge, the user approves, and the
server verifies the assertion exactly as for a signature: origin, relying party, signature
counter, and user verification required. It then sets an HttpOnly, `SameSite=Strict` cookie scoped
to `/manage`, valid for five minutes, and returns the recoveries waiting on that wallet.
Cancelling a recovery within the session needs no second prompt. A second assertion would add a
prompt without stopping anyone who holds the passkey.

**Cancel checks the session and the origin.** `POST /manage/cancel` requires the cookie and an
`Origin` header equal to the configured origin. It cancels through the same code as the extension's
cancel and writes the same audit entry.

**What the page shows.** Each waiting recovery with when it was asked, when it could take over,
and the same short fingerprint the extension shows. It never shows the wallet id.

**The challenge endpoint is open, so it is bounded.** It takes no proof, so an unauthenticated
caller could fill the table. Challenges live five minutes and only a fixed number may be live at
once. Beyond that the server answers `429`.

**The extension points to it.** While a recovery waits, the extension's recovery panel says that it
can be cancelled from any browser at `<server>/manage` with the passkey.

## Consequences

**The lost-device case is covered.** The owner needs only their passkey and the server's address,
which is in the recovery file's header and in the extension's settings.

**A new unauthenticated surface exists.** It is small: one page, one challenge endpoint that
reveals nothing, and endpoints that answer only after a verified assertion. It gets the same
`no-store` and CSP headers as the ceremony page.

**Passkey holders can cancel each other's intent.** Stated above. It is the price of keeping
cancellation easy.

**It does not tell anyone.** A recovery that nobody looks for still completes after the wait. The
wait plus a place to look is the most this design offers without a notification channel.

**Existing credentials need their handle indexed.** A migration adds the column, and the server
fills it for credentials registered before it. New registrations write it.

**Reversing it** means removing the page and the endpoints. The extension's own cancel is
unaffected.
