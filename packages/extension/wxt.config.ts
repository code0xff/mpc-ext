import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'mpc-ext',
    description: 'Holds a 2-of-3 MPC key. Unaudited — do not use with real assets.',
    permissions: ['storage'],
    // The background worker talks to the MPC server. Self-hosting means this list has to become
    // configurable before release; for now it covers local development.
    host_permissions: ['http://127.0.0.1:8080/*', 'http://localhost:8080/*'],
    // Required to run wasm. We never load remote code (MV3 policy).
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
