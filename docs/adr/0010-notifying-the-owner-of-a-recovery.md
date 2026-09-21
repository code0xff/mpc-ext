# ADR-0010: Telling the owner that a recovery was asked for

- Status: accepted. The browser notification is implemented. Web Push is not adopted for now.
- Date: 2026-09-21

## Context

A recovery waits before it can replace a wallet's device key ([ADR-0008](0008-recovery-start-and-device-key-replacement.md)),
and the owner can cancel it ([ADR-0009](0009-managing-recoveries-with-the-passkey.md)). Both help
only if the owner finds out. There is no email or phone by design, so nothing tells them.

The case that matters most is the one where the owner has lost their device. Any notice sent to the
extension on that device goes to the device that is gone.

## What is implemented

The extension asks the server every five minutes for recoveries waiting on its wallet, using only
its device key, so it works while the wallet is locked. The first time it sees one it raises a
browser notification and remembers the request id so it does not repeat. This needs no server
change and no new party.

It works only while that browser is running. It does not reach a lost or powered-off device, which
is the case this ADR is about.

## Options for reaching an owner who no longer has the device

| Option                                                    | Reaches a lost device's owner | Cost                                                                                              |
| --------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------- |
| Nothing more                                              | No                            | None. The owner has to think to look at `/manage`                                                 |
| `chrome.gcm` push to the extension                        | No                            | It goes to the browser install that registered, which is the lost one, and needs an FCM sender id |
| **Web Push to a second browser, subscribed on `/manage`** | Yes, if set up beforehand     | Below                                                                                             |
| Email or SMS                                              | Yes                           | Needs accounts and personal data, which ADR-0006 avoids, and adds a party to trust                |

## Proposal: Web Push, subscribed from `/manage`

Before losing anything, the owner opens `/manage` in a browser they will keep (a phone, another
computer), proves the passkey, and chooses "notify this browser". The page subscribes to Web Push
and sends the subscription to the server, which attaches it to the wallet. When a recovery is
requested, the server sends a push to each subscription. The message says only that a recovery was
requested.

It fits the existing session: the subscription is stored under the wallet the passkey named, so no
new proof or identifier is needed.

## What it costs, which is why this is not decided

**The server starts making outbound requests.** Today it only answers. Sending a push means calling
whatever URL the subscription names, which is a push service address chosen by the browser and
reached over TLS. A subscription that names an internal address would make the server call it
(SSRF), so it has to be restricted to public hosts and to `https`, with a short timeout and no
redirects. The deployment also has to allow outbound traffic.

**HTTPS becomes required to use it.** Service workers and push work only on secure origins, with
`localhost` as the exception. A self-hoster who runs plain HTTP loses the feature.

**The server stores one more identifier per wallet.** A subscription is a push service URL plus keys,
issued by Google, Mozilla or Apple. It does not name the user, but it links the wallet to a browser
install, and the push service sees that a message was sent at that time. The body is encrypted and
would carry no wallet detail. This is a real privacy cost for a design that stores no accounts.

**It still needs setup beforehand.** It moves the burden from "someone must check" to "someone must
have subscribed". An owner who never did gets nothing, and a user who loses the device before
subscribing is where they are today.

**Delivery is not guaranteed.** Push services can drop or delay messages, and iOS delivers only to
a web app added to the home screen.

**A dependency.** Two Rust crates could do the encryption. Their licences were read from the
published sources, not from badges.

| Crate                   | Licence           | Crates pulled in | Note                                                      |
| ----------------------- | ----------------- | ---------------- | --------------------------------------------------------- |
| `web-push` 0.11.0       | Apache-2.0        | 261              | Brings an HTTP client (`isahc`, libcurl) and openssl      |
| `web-push-native` 0.5.0 | MIT OR Apache-2.0 | 163              | Encryption only, no openssl. The caller sends the request |

`web-push-native` matches the project's rule of using vetted crates and keeping the native
dependency surface small, and it uses RustCrypto libraries the server already has (`p256`,
`aes-gcm`, `hkdf`). The server would still need an HTTP client of its own to send the request. That
is a second dependency choice, made when this is decided.

## Decision

**Web Push is not adopted for now.** The project is at the demo stage, where the server making
outbound requests and storing a push subscription per wallet is a cost with no user to justify it.
What stays: the browser notification on the current device, the wait, `/manage`, and the reminder
on the recovery file card to keep the `/manage` address.

The honest position is the one in [recovery.md](../recovery.md): those are what the design offers,
and it tells an owner who has lost the device and everything else nothing.

**Revisit before real assets are involved, or before a Web Store listing.** At that point three
things need settling, and the analysis above is the starting point:

1. Is a second browser a reasonable thing to ask of the owner, given that it only helps if done
   before the loss?
2. Is the server allowed to make outbound requests, and to store a push subscription per wallet?
3. Which HTTP client, and how subscription URLs are restricted.

Until then nothing in the code depends on this option, so leaving it costs no rework.

## Consequences of leaving it as it is

An owner who has lost the device, and whose recovery file has been found, is protected by the wait
and by remembering to look at `/manage`. Nothing prompts them. Users should be told, at onboarding,
to bookmark the server's `/manage` address, and that is worth doing whichever way this goes.
