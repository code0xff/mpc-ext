import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/.output/**',
      '**/.wxt/**',
      '**/pkg/**',
      'target/**',
      'chrome/**',
      // wasm-pack이 생성하는 바인딩. 우리가 손대지 않는다.
      'packages/extension/wasm/**',
      'packages/extension/public/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // 비밀 값이 실수로 로그에 찍히는 것을 막는다 (AGENTS.md 보안 원칙).
      'no-console': ['error', { allow: ['warn', 'error'] }],
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
  {
    // 개발용 Node 스크립트. 콘솔 출력이 곧 결과물이다.
    files: ['**/scripts/**/*.mjs', '*.config.{js,ts,mjs}'],
    languageOptions: {
      globals: {
        console: 'readonly',
        process: 'readonly',
        URL: 'readonly',
        // page.evaluate 안에서 브라우저 컨텍스트로 실행되는 코드.
        chrome: 'readonly',
        performance: 'readonly',
      },
    },
    rules: { 'no-console': 'off' },
  },
);
