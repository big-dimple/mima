import { defineConfig } from 'vitest/config';

process.env.MIMA_DEMO_MODE ??= 'true';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          environment: 'node',
          include: [
            'packages/*/test/**/*.test.ts',
            'apps/api/test/unit/**/*.test.ts',
            'apps/recovery-tool/test/**/*.test.ts',
          ],
        },
      },
      {
        test: {
          name: 'web',
          environment: 'jsdom',
          include: ['apps/web/test/**/*.test.{ts,tsx}'],
          setupFiles: ['apps/web/test/setup.ts'],
        },
      },
      {
        test: {
          name: 'extension',
          environment: 'jsdom',
          include: ['apps/extension/test/**/*.test.ts'],
        },
      },
      {
        test: {
          name: 'integration',
          environment: 'node',
          include: ['apps/api/test/integration/**/*.test.ts'],
          fileParallelism: false,
          hookTimeout: 60_000,
          testTimeout: 30_000,
        },
      },
    ],
  },
});
