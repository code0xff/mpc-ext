import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'mpc-ext',
    description: 'Holds a 2-of-3 MPC key. Unaudited — do not use with real assets.',
    // `alarms` and `notifications` are for telling the owner that a recovery was asked for.
    permissions: ['storage', 'alarms', 'notifications'],
    // Placeholder artwork from `scripts/make-icons.mjs`. Replace it before a Web Store listing.
    icons: {
      16: 'icon/16.png',
      32: 'icon/32.png',
      48: 'icon/48.png',
      128: 'icon/128.png',
    },
    action: { default_icon: { 16: 'icon/16.png', 32: 'icon/32.png' } },
    // The background worker talks to the MPC server. Self-hosting means this list has to become
    // configurable before release; for now it covers local development.
    host_permissions: ['http://127.0.0.1:8080/*', 'http://localhost:8080/*'],
    // Required to run wasm. We never load remote code (MV3 policy).
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
