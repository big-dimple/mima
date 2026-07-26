import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { AuthRuntime } from '../../src/auth/runtime.ts';
import type { AuthUserRecord, FeishuCallbackResult } from '../../src/auth/contracts.ts';
import { env } from '../../src/env.ts';
import { buildStrictApp } from '../../src/strict-app.ts';
import { testDbUrl } from './helpers.ts';

const databaseName = 'mima_test_feishu_callback_route';
const databaseUrl = testDbUrl(databaseName);
const adminUrl = testDbUrl('mima');
const redirectUri = 'https://mima.example.test/api/auth/feishu/callback';
const previousRedirectUri = env.feishu.redirectUri;

describe('Feishu callback route', () => {
  afterAll(async () => {
    env.feishu.redirectUri = previousRedirectUri;
    await resetDatabase();
  });

  it('allows only bounded provider parameters and prevents callback referrer propagation', async () => {
    await resetDatabase();
    await createDatabase();
    const keyDir = mkdtempSync(join(tmpdir(), 'mima-feishu-route-keys-'));
    writeFileSync(join(keyDir, 'kek-v1.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    env.feishu.redirectUri = redirectUri;
    const user: AuthUserRecord = {
      id: 'feishu-callback-user',
      username: 'feishu-user',
      displayName: 'Feishu User',
      email: 'feishu-user@example.test',
      groups: [],
      source: 'feishu',
      active: true,
    };
    const completeCallback = vi.fn<(
      callbackUrl: URL,
      browserBindingToken: string | undefined,
    ) => Promise<FeishuCallbackResult>>(async (callbackUrl) => {
      if (callbackUrl.searchParams.has('error')) throw new Error('provider denied authorization');
      return {
        identity: {
          tenantKey: 'tenant-key',
          userId: 'feishu-user-id',
          displayName: user.displayName,
          email: user.email,
        },
        startedAt: new Date('2026-07-19T00:00:00Z'),
      };
    });
    const authRuntime: AuthRuntime = {
      loginProvider: 'feishu',
      reauthProvider: 'none',
      directoryProvider: 'authentik',
      login: {
        method: 'feishu',
        beginLogin: async () => ({
          url: new URL('https://open.feishu.cn/open-apis/authen/v1/authorize'),
          browserBindingToken: 'binding',
        }),
        completeCallback,
      },
      reauth: null,
      directory: {
        source: 'oidc',
        listDirectory: async () => ({ users: [], groups: [], syncedAt: null }),
        findActiveUser: async () => user,
        findActiveOidcUser: async () => null,
        findActiveUsername: async () => user,
        resolveExternalIdentity: async () => user,
        start: () => undefined,
        stop: () => undefined,
      },
      sessions: {
        create: async () => ({
          token: 'session-token',
          info: {
            user: { ...user, isPlatformAdmin: false },
            csrfToken: 'csrf-token',
            locked: false,
            cryptoProfileInitialized: false,
            cryptoDeviceId: null,
          },
        }),
        completeReauthentication: async () => false,
        consumeOidcLogout: async () => ({ replayed: false, sessionsRevoked: 0, userIds: [] }),
      },
    };
    const app = await buildStrictApp({
      databaseUrl,
      runtimeKeyDir: keyDir,
      auditKeyDir: keyDir,
      authRuntime,
      logger: false,
    });
    const database = new pg.Client({ connectionString: databaseUrl });
    await database.connect();
    await database.query(
      `INSERT INTO users (id, username, display_name, email, source, active) VALUES ($1, $2, $3, $4, 'feishu', true)`,
      [user.id, user.username, user.displayName, user.email],
    );
    await database.end();
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/api/auth/feishu/callback?code=authorization-code&state=authorization-state',
        headers: { cookie: 'mima_feishu_tx=binding-token' },
      });
      expect(response.statusCode).toBe(303);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['referrer-policy']).toBe('no-referrer');
      expect(completeCallback).toHaveBeenCalledTimes(1);
      const [callbackUrl, bindingToken] = completeCallback.mock.calls[0]!;
      expect(callbackUrl.href).toBe(`${redirectUri}?code=authorization-code&state=authorization-state`);
      expect(bindingToken).toBe('binding-token');
      const cookies = response.headers['set-cookie'];
      const serialized = Array.isArray(cookies) ? cookies.join('\n') : String(cookies);
      expect(serialized).toContain('mima_feishu_tx=;');
      expect(serialized).toContain('SameSite=Lax');
      expect(serialized).toContain('Secure');

      const denied = await app.inject({
        method: 'GET',
        url: '/api/auth/feishu/callback?error=access_denied&state=authorization-state',
        headers: { cookie: 'mima_feishu_tx=binding-token' },
      });
      expect(denied.statusCode).toBe(303);
      expect(denied.headers.location).toContain('error=feishu_auth_failed');
      expect(denied.headers['cache-control']).toBe('no-store');
      expect(denied.headers['referrer-policy']).toBe('no-referrer');
      expect(completeCallback).toHaveBeenCalledTimes(2);

      const unexpected = await app.inject({
        method: 'GET',
        url: '/api/auth/feishu/callback?code=x&state=y&token=must-not-pass',
      });
      expect(unexpected.statusCode).toBe(400);
      expect(unexpected.headers['cache-control']).toBe('no-store');
      expect(unexpected.headers['referrer-policy']).toBe('no-referrer');
      expect(unexpected.body).not.toContain('must-not-pass');
      expect(completeCallback).toHaveBeenCalledTimes(2);

      const ambiguous = await app.inject({
        method: 'GET',
        url: '/api/auth/feishu/callback?code=x&error=access_denied&state=y',
      });
      expect(ambiguous.statusCode).toBe(400);
      expect(ambiguous.headers['cache-control']).toBe('no-store');
      expect(ambiguous.headers['referrer-policy']).toBe('no-referrer');
      expect(completeCallback).toHaveBeenCalledTimes(2);
    } finally {
      await app.close();
      rmSync(keyDir, { recursive: true, force: true });
    }
  });
});

async function createDatabase(): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${databaseName}`);
  } finally {
    await admin.end();
  }
}

async function resetDatabase(): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}
