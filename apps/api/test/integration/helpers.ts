import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/app.ts';
import { buildStrictApp } from '../../src/strict-app.ts';

const DEFAULT_ADMIN_URL = 'postgres://mima:mima_dev_pw@127.0.0.1:55432/mima';
export const TEST_API_HOST = process.env.MIMA_INTEGRATION_API_HOST ?? '127.0.0.1';

export function testDbUrl(dbName: string): string {
  const url = new URL(process.env.MIMA_INTEGRATION_DATABASE_URL ?? DEFAULT_ADMIN_URL);
  url.pathname = `/${dbName}`;
  return url.toString();
}

export function testRoleDbUrl(dbName: string, username: string, password: string): string {
  const url = new URL(testDbUrl(dbName));
  url.username = username;
  url.password = password;
  return url.toString();
}

export function testServerOrigin(port: number): string {
  const host = TEST_API_HOST.includes(':') ? `[${TEST_API_HOST}]` : TEST_API_HOST;
  return `http://${host}:${port}`;
}

const ADMIN_URL = testDbUrl('mima');

export async function freshTestApp(dbName: string): Promise<FastifyInstance> {
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const keyDir = mkdtempSync(join(tmpdir(), 'mima-test-keys-'));
  writeFileSync(join(keyDir, 'kek-v1.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
  // 审计密钥不再由运行时自动创建（只允许 keys:init），测试基建自行准备
  writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });

  return buildApp({
    databaseUrl: testDbUrl(dbName),
    masterKeyDir: keyDir,
    e2eeRequired: false,
    logger: false,
  });
}

export async function freshStrictTestApp(dbName: string): Promise<FastifyInstance> {
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const keyDir = mkdtempSync(join(tmpdir(), 'mima-strict-test-keys-'));
  writeFileSync(join(keyDir, 'kek-v1.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
  writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });

  return buildStrictApp({
    databaseUrl: testDbUrl(dbName),
    runtimeKeyDir: keyDir,
    auditKeyDir: keyDir,
    logger: false,
  });
}

export interface TestSession {
  cookie: string;
  csrf: string;
  userId: string;
}

export async function login(app: FastifyInstance, username: string): Promise<TestSession> {
  const res = await app.inject({
    method: 'POST',
    url: '/api/session',
    payload: { username, password: 'dev' },
  });
  if (res.statusCode !== 200) throw new Error(`login failed: ${res.statusCode} ${res.body}`);
  const setCookie = res.headers['set-cookie'];
  const raw = Array.isArray(setCookie) ? setCookie[0]! : (setCookie as string);
  const cookie = raw.split(';')[0]!;
  const body = res.json() as { csrfToken: string; user: { id: string } };
  return { cookie, csrf: body.csrfToken, userId: body.user.id };
}

export function authed(session: TestSession) {
  return {
    headers: { cookie: session.cookie, 'x-mima-csrf': session.csrf },
  };
}

export function key(): string {
  return randomBytes(12).toString('hex');
}
