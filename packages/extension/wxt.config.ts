import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'mpc-ext',
    description: 'Holds a 2-of-3 MPC key. Unaudited — do not use with real assets.',
    permissions: ['storage'],
    // Required to run wasm. We never load remote code (MV3 policy).
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
