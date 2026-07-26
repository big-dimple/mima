import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

Object.assign(process.env, {
  AUTH_MODE: 'dev',
  MIMA_DEMO_MODE: 'true',
  MIMA_LOGIN_PROVIDER: 'dev',
  MIMA_REAUTH_PROVIDER: 'dev',
  MIMA_DIRECTORY_PROVIDER: 'dev',
  MIMA_API_HOST: '127.0.0.1',
  MIMA_PUBLIC_BASE_URL: 'http://127.0.0.1:4173',
  MIMA_WEB_ORIGINS: 'http://127.0.0.1:4173',
  MIMA_SESSION_COOKIE_SECURE: 'false',
});

const [{ buildStrictApp }, { buildOpenApiDocument }] = await Promise.all([
  import('../strict-app.ts'),
  import('../openapi-contract.ts'),
]);

const keyDir = mkdtempSync(join(tmpdir(), 'mima-openapi-'));
writeFileSync(join(keyDir, 'kek-v1.key'), `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });

const app = await buildStrictApp({
  logger: false,
  migrate: false,
  runtimeKeyDir: keyDir,
  auditKeyDir: keyDir,
  verifyAuditChainOnStartup: false,
});
try {
  await app.ready();
  const doc = buildOpenApiDocument(app.swagger(), 'https://mima.example.com');
  const out = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'openapi', 'openapi.json');
  mkdirSync(dirname(out), { recursive: true });
  const content = JSON.stringify(doc, null, 2) + '\n';
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== content) throw new Error('OpenAPI contract is stale; run openapi:generate');
    console.log(`OpenAPI is current: ${out}`);
  } else {
    writeFileSync(out, content);
    console.log(`OpenAPI written to ${out}`);
  }
} finally {
  await app.close();
  rmSync(keyDir, { recursive: true, force: true });
}
