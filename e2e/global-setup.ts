import { execSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * E2E 全局准备：把扩展构建到独立的 dist-e2e（API 指向 E2E 专用端口 14274），
 * 不覆盖手动加载用的 dist 产物。
 */
export default function globalSetup(): void {
  const root = dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = join(root, '..');
  const e2eApiHost = process.env.MIMA_E2E_API_HOST ?? '127.0.0.1';
  const apiUrlHost = e2eApiHost.includes(':') ? `[${e2eApiHost}]` : e2eApiHost;
  const apiOrigin = `http://${apiUrlHost}:14274`;
  const apiPermission = `http://${apiUrlHost}/*`;
  const webOrigin = 'http://[::1]:14273';
  const screenshotDir = process.env.MIMA_E2E_SCREENSHOT_DIR
    ?? join(tmpdir(), 'mima-e2e-screenshots');
  mkdirSync(screenshotDir, { recursive: true });
  execSync('pnpm --filter @mima/extension build', {
    cwd: repositoryRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      VITE_MIMA_API_BASE: apiOrigin,
      VITE_MIMA_WEB_ORIGIN: webOrigin,
      MIMA_EXT_OUT_DIR: 'dist-e2e',
    },
  });

  const manifestPath = join(repositoryRoot, 'apps/extension/dist-e2e/manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
    host_permissions: string[];
    externally_connectable: { matches: string[] };
  };
  manifest.host_permissions = [...new Set([
    ...manifest.host_permissions,
    apiPermission,
  ])];
  manifest.externally_connectable.matches = [...new Set([
    ...manifest.externally_connectable.matches,
    `${webOrigin}/*`,
  ])];
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}
