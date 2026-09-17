import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'mpc-ext',
    description: '2-of-3 MPC 키 보관 · 감사 전이므로 실자산에 사용하지 마세요',
    permissions: ['storage'],
    // wasm 실행에 필요하다. 원격 코드는 로드하지 않는다 (MV3 정책).
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
