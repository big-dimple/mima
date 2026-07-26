import { defineConfig } from '@playwright/test';

/**
 * E2E 完全独立于开发实例：
 * - 数据库 mima_test_e2e（e2e-server 启动时校验库名并 DROP 重建 + seed）
 * - API 14274 / Web 14273（不复用 4173/4174 的进程，reuseExistingServer=false）
 */
const E2E_WEB_PORT = 14273;
const E2E_API_PORT = 14274;
const E2E_WEB_HOST = '[::1]';
const E2E_API_HOST = process.env.MIMA_E2E_API_HOST ?? '127.0.0.1';
const E2E_API_URL_HOST = E2E_API_HOST.includes(':') ? `[${E2E_API_HOST}]` : E2E_API_HOST;
const E2E_API_BIND_HOST = E2E_API_HOST === 'localhost' ? '127.0.0.1' : E2E_API_HOST;
const E2E_WEB_ORIGIN = `http://${E2E_WEB_HOST}:${E2E_WEB_PORT}`;
const E2E_DB_URL = process.env.MIMA_E2E_DATABASE_URL
  ?? 'postgres://mima:mima_dev_pw@127.0.0.1:55432/mima_test_e2e';

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.ts',
  timeout: 45_000,
  fullyParallel: false,
  workers: 1,
  retries: 1,
  reporter: [['list']],
  use: {
    baseURL: E2E_WEB_ORIGIN,
    locale: 'zh-CN',
    // 报告与追踪中不采集可能包含密码或 Token 的内容
    screenshot: 'off',
    video: 'off',
    trace: 'off',
  },
  projects: [
    {
      name: 'web',
      testMatch: /web\.spec\.ts|layout\.spec\.ts|hardening\.spec\.ts|onboarding\.spec\.ts|migration\.spec\.ts/,
      use: { viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'extension',
      testMatch: /extension\.spec\.ts/,
    },
  ],
  webServer: [
    {
      command: 'pnpm --filter @mima/api run e2e:server',
      url: `http://${E2E_API_URL_HOST}:${E2E_API_PORT}/api/healthz`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        MIMA_DEMO_MODE: 'true',
        MIMA_DATABASE_URL: E2E_DB_URL,
        MIMA_API_PORT: String(E2E_API_PORT),
        MIMA_API_HOST: E2E_API_BIND_HOST,
        MIMA_WEB_ORIGINS: E2E_WEB_ORIGIN,
        MIMA_PUBLIC_BASE_URL: E2E_WEB_ORIGIN,
      },
    },
    {
      command: 'pnpm --filter @mima/web build && pnpm --filter @mima/web preview --host ::1',
      url: E2E_WEB_ORIGIN,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        MIMA_WEB_PORT: String(E2E_WEB_PORT),
        MIMA_API_PORT: String(E2E_API_PORT),
        MIMA_API_PROXY_HOST: E2E_API_HOST,
      },
    },
  ],
});
