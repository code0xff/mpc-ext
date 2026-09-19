interface Handoff {
  serverUrl: string;
  handoffToken: string;
}

type ResponseMessage = { ok: true; value: Handoff } | { ok: false; error: string };

async function loadHandoff(): Promise<Handoff> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'passkeyLauncherReady' }, (response: ResponseMessage) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (!response?.ok) {
        reject(new Error(response?.error ?? 'The passkey ceremony is unavailable.'));
      } else {
        resolve(response.value);
      }
    });
  });
}

async function launch(): Promise<void> {
  const handoff = await loadHandoff();
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${handoff.serverUrl}/auth/handoff`;
  form.style.display = 'none';
  const token = document.createElement('input');
  token.type = 'hidden';
  token.name = 'handoff_token';
  token.value = handoff.handoffToken;
  form.append(token);
  document.body.append(form);
  form.submit();
}

launch().catch((error: unknown) => {
  document.body.textContent =
    error instanceof Error ? error.message : 'The passkey ceremony could not start.';
});
