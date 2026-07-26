import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { buildStrictApp } from '../../src/strict-app.ts';
import { testDbUrl } from '../integration/helpers.ts';

const databaseName = 'mima_test_log_redaction';
const databaseUrl = testDbUrl(databaseName);
const adminUrl = testDbUrl('mima');
const keyDir = mkdtempSync(join(tmpdir(), 'mima-log-redaction-keys-'));

await resetDatabase();
const admin = new pg.Client({ connectionString: adminUrl });
await admin.connect();
await admin.query(`CREATE DATABASE ${databaseName}`);
await admin.end();
writeFileSync(join(keyDir, 'kek-v1.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });

const canaries = {
  authorization: 'Bearer LOG_AUTHORIZATION_CANARY',
  code: 'LOG_OIDC_CODE_CANARY',
  cookie: 'mima_sid=LOG_COOKIE_CANARY',
  note: 'LOG_NOTE_CANARY',
  password: 'LOG_PASSWORD_CANARY',
  state: 'LOG_OIDC_STATE_CANARY',
  token: 'LOG_TOKEN_CANARY',
};

const app = await buildStrictApp({
  databaseUrl,
  runtimeKeyDir: keyDir,
  auditKeyDir: keyDir,
  logger: true,
});
app.get('/__log-redaction-canary', async () => {
  const error = new Error(`LOG_ERROR_MESSAGE_CANARY ${canaries.note}`) as Error & Record<string, unknown>;
  error.detail = canaries.password;
  error.query = canaries.token;
  throw error;
});

try {
  await app.inject({
    method: 'GET',
    url: `/__log-redaction-canary?code=${canaries.code}&state=${canaries.state}`,
    headers: { authorization: canaries.authorization, cookie: canaries.cookie },
  });
  await app.inject({
    method: 'POST',
    url: '/api/auth/oidc/callback',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `mima_oidc_tx=${canaries.cookie}`,
    },
    payload: new URLSearchParams({ code: canaries.code, state: canaries.state }).toString(),
  });
  await app.inject({
    method: 'GET',
    url: `/api/auth/feishu/callback?code=${canaries.code}&state=${canaries.state}`,
    headers: { cookie: canaries.cookie },
  });
  await app.inject({
    method: 'POST',
    url: '/api/session',
    payload: { username: 'log-canary', password: canaries.password, token: canaries.token, note: canaries.note },
  });
  await app.inject({
    method: 'POST',
    url: '/api/session',
    headers: { 'content-type': 'application/json' },
    payload: `{"password":"${canaries.password}",`,
  });
  await app.inject({
    method: 'GET',
    url: '/api/v2/events?cursor=0',
    headers: { authorization: canaries.authorization, cookie: canaries.cookie },
  });
} finally {
  await app.close();
  await resetDatabase();
  rmSync(keyDir, { recursive: true, force: true });
}

console.log('LOG_REDACTION_RUNNER_COMPLETE');

async function resetDatabase(): Promise<void> {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  } finally {
    await client.end();
  }
}
