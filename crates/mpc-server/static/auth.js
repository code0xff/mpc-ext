(() => {
  'use strict';

  const status = document.getElementById('status');
  const error = document.getElementById('error');

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
    if (options.user && typeof options.user.id === 'string') {
      options.user = { ...options.user, id: base64urlToBytes(options.user.id) };
    }
    if (Array.isArray(options.allowCredentials)) {
      options.allowCredentials = options.allowCredentials.map((credential) => ({
        ...credential,
        id: typeof credential.id === 'string' ? base64urlToBytes(credential.id) : credential.id,
      }));
    }
    if (Array.isArray(options.excludeCredentials)) {
      options.excludeCredentials = options.excludeCredentials.map((credential) => ({
        ...credential,
        id: typeof credential.id === 'string' ? base64urlToBytes(credential.id) : credential.id,
      }));
    }
    return options;
  }

  function credentialJson(credential) {
    if (typeof credential.toJSON === 'function') return credential.toJSON();
    const response = credential.response;
    const result = {
      id: credential.id,
      rawId: bytesToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bytesToBase64url(response.clientDataJSON),
      },
    };
    if ('attestationObject' in response) {
      result.response.attestationObject = bytesToBase64url(response.attestationObject);
    }
    if ('authenticatorData' in response) {
      result.response.authenticatorData = bytesToBase64url(response.authenticatorData);
      result.response.signature = bytesToBase64url(response.signature);
      if (response.userHandle) result.response.userHandle = bytesToBase64url(response.userHandle);
    }
    return result;
  }

  async function json(path, init) {
    const response = await fetch(path, { ...init, credentials: 'same-origin' });
    const body = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(body.error || `Authentication request failed (${response.status})`);
    return body;
  }

  // What the authenticator is about to approve. The prompt alone says nothing, and another page
  // can send a browser here, so the user is told before being asked. Set as text, never as HTML.
  const PURPOSES = {
    register: 'You are registering a passkey for your wallet.',
    sign: 'You are approving a signature from your wallet.',
    recovery:
      'You are approving a recovery operation for your wallet, such as restoring it on a new ' +
      'device. If you did not just start one, close this tab and do not approve.',
  };

  async function run() {
    const ceremony = await json('/auth/session');
    document.getElementById('purpose').textContent =
      PURPOSES[ceremony.purpose] || 'You are approving an operation on your wallet.';
    const publicKey = credentialOptions(ceremony.options);
    const credential =
      ceremony.kind === 'register'
        ? await navigator.credentials.create({ publicKey })
        : await navigator.credentials.get({ publicKey });
    if (!credential) throw new Error('The authenticator did not return a credential.');
    await json('/auth/session/finish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(credentialJson(credential)),
    });
    status.textContent = 'Authentication completed. You can close this tab.';
  }

  run().catch((cause) => {
    status.hidden = true;
    error.hidden = false;
    error.textContent = cause instanceof Error ? cause.message : 'Authentication failed.';
  });
})();
