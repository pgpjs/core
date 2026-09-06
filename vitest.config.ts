import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@pgpjs/core': path.resolve(__dirname, 'packages/core/src/index.ts'),
      '@pgpjs/node': path.resolve(__dirname, 'packages/node/src/index.ts'),
      '@pgpjs/react': path.resolve(__dirname, 'packages/react/src/index.ts'),
      '@pgpjs/next': path.resolve(__dirname, 'packages/next/src/index.ts')
    }
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'packages/*/src/**/*.test.ts'],
  },
});
