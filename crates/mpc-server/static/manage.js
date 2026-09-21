(() => {
  'use strict';

  const lookup = document.getElementById('lookup');
  const status = document.getElementById('status');
  const error = document.getElementById('error');
  const list = document.getElementById('recoveries');

  function base64urlToBytes(value) {
    const padded =
      value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function bytesToBase64url(value) {
    let binary = '';
    for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function credentialOptions(value) {
    const options = { ...value };
    if (typeof options.challenge === 'string')
      options.challenge = base64urlToBytes(options.challenge);
    return options;
  }

  function credentialJson(credential) {
    if (typeof credential.toJSON === 'function') return credential.toJSON();
    const response = credential.response;
    return {
      id: credential.id,
      rawId: bytesToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bytesToBase64url(response.clientDataJSON),
        authenticatorData: bytesToBase64url(response.authenticatorData),
        signature: bytesToBase64url(response.signature),
        userHandle: response.userHandle ? bytesToBase64url(response.userHandle) : undefined,
      },
    };
  }

  async function json(path, init) {
    const response = await fetch(path, { ...init, credentials: 'same-origin' });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) throw new Error('That passkey could not be verified.');
      if (response.status === 429) throw new Error('Too many people are checking. Try again soon.');
      throw new Error(body.error || `The request failed (${response.status}).`);
    }
    return body;
  }

  function say(text) {
    error.hidden = true;
    status.hidden = false;
    status.textContent = text;
  }

  function fail(text) {
    status.hidden = true;
    error.hidden = false;
    error.textContent = text;
  }

  function when(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  /** Draws what is waiting. Everything is set as text, never as HTML. */
  function show(view) {
    list.replaceChildren();
    if (view.recoveries.length === 0) {
      say('Nothing is waiting on your wallet.');
      return;
    }
    say(
      view.recoveries.length === 1
        ? 'A recovery is waiting on your wallet.'
        : `${view.recoveries.length} recoveries are waiting on your wallet.`,
    );
    for (const recovery of view.recoveries) {
      const item = document.createElement('li');
      const text = document.createElement('p');
      text.textContent =
        `Asked ${when(recovery.requested_at)}. It can take over after ${when(recovery.ready_at)}. ` +
        `New device fingerprint: ${recovery.key_fingerprint}.`;
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'cancel';
      cancel.textContent = 'Cancel this recovery';
      cancel.addEventListener('click', () => cancelRecovery(recovery.request_id, cancel));
      item.append(text, cancel);
      list.append(item);
    }
  }

  async function cancelRecovery(requestId, button) {
    button.disabled = true;
    try {
      show(
        await json('/manage/cancel', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ request_id: requestId }),
        }),
      );
    } catch (cause) {
      button.disabled = false;
      fail(cause instanceof Error ? cause.message : 'Could not cancel.');
    }
  }

  async function run() {
    lookup.disabled = true;
    error.hidden = true;
    try {
      say('Follow your authenticator prompt.');
      const challenge = await json('/manage/challenge');
      const credential = await navigator.credentials.get({
        publicKey: credentialOptions(challenge.options),
      });
      if (!credential) throw new Error('The authenticator did not return a credential.');
      show(
        await json('/manage/session', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            challenge_id: challenge.challenge_id,
            credential: credentialJson(credential),
          }),
        }),
      );
    } catch (cause) {
      fail(cause instanceof Error ? cause.message : 'Could not check.');
    } finally {
      lookup.disabled = false;
    }
  }

  lookup.addEventListener('click', () => void run());
})();
