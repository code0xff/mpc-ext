/**
 * The example dApp.
 *
 * Written against the standards on purpose: EIP-6963 to discover the wallet, EIP-1193 to talk to
 * it. Nothing here knows anything specific about mpc-ext, which is the point.
 */

const RDNS = 'labs.dsrv.mpc-ext';
const USER_REJECTED = 4001;

const walletLine = document.getElementById('wallet');
const connectButton = document.getElementById('connect');
const accountBox = document.getElementById('account');
const messageInput = document.getElementById('message');
const signButton = document.getElementById('sign');
const signatureBox = document.getElementById('signature');
const errorLine = document.getElementById('error');

let provider;
let account;

function show(element, text) {
  element.textContent = text;
  element.hidden = false;
}

function fail(cause) {
  const message =
    cause?.code === USER_REJECTED ? 'You rejected the request.' : (cause?.message ?? String(cause));
  show(errorLine, message);
}

/** Collects announced wallets and picks mpc-ext. */
function discover() {
  return new Promise((resolve) => {
    const found = [];
    const onAnnounce = (event) => found.push(event.detail);

    window.addEventListener('eip6963:announceProvider', onAnnounce);
    window.dispatchEvent(new Event('eip6963:requestProvider'));

    setTimeout(() => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce);
      resolve(found.find((detail) => detail.info.rdns === RDNS));
    }, 300);
  });
}

const detail = await discover();

if (!detail) {
  walletLine.textContent = 'No mpc-ext wallet found. Is the extension installed?';
} else {
  provider = detail.provider;
  walletLine.textContent = `Found ${detail.info.name}.`;
  connectButton.hidden = false;

  // Accounts already shared with this page do not need a prompt.
  try {
    const [existing] = await provider.request({ method: 'eth_accounts' });
    if (existing) {
      account = existing;
      show(accountBox, account);
      signButton.disabled = false;
      connectButton.hidden = true;
    }
  } catch (cause) {
    fail(cause);
  }
}

connectButton.addEventListener('click', async () => {
  errorLine.hidden = true;
  try {
    const [connected] = await provider.request({ method: 'eth_requestAccounts' });
    account = connected;
    show(accountBox, account);
    signButton.disabled = false;
    connectButton.hidden = true;
  } catch (cause) {
    fail(cause);
  }
});

signButton.addEventListener('click', async () => {
  errorLine.hidden = true;
  signatureBox.hidden = true;
  try {
    const bytes = new TextEncoder().encode(messageInput.value);
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
    const signature = await provider.request({
      method: 'personal_sign',
      params: [`0x${hex}`, account],
    });
    show(signatureBox, signature);
  } catch (cause) {
    fail(cause);
  }
});
