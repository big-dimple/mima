import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { AuthRuntime } from '../../src/auth/runtime.ts';
import type { AuthUserRecord, OidcCallbackResult } from '../../src/auth/contracts.ts';
import { env } from '../../src/env.ts';
import { buildStrictApp } from '../../src/strict-app.ts';
import { testDbUrl } from './helpers.ts';

const databaseName = 'mima_test_oidc_form_post_route';
const databaseUrl = testDbUrl(databaseName);
const adminUrl = testDbUrl('mima');
const redirectUri = 'https://mima.example.test/api/auth/oidc/callback';
const previousRedirectUri = env.oidc.redirectUri;

describe('OIDC form-post route', () => {
  afterAll(async () => {
    env.oidc.redirectUri = previousRedirectUri;
    await resetDatabase();
  });

  it('consumes a form body, clears the binding cookie, and exposes no GET callback', async () => {
    await resetDatabase();
    await createDatabase();
    const keyDir = mkdtempSync(join(tmpdir(), 'mima-oidc-route-keys-'));
    writeFileSync(join(keyDir, 'kek-v1.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    env.oidc.redirectUri = redirectUri;
    const user: AuthUserRecord = {
      id: 'oidc-form-post-user',
      username: 'oidc-user',
      displayName: 'OIDC User',
      email: 'oidc-user@example.test',
      groups: [],
      source: 'oidc',
      active: true,
    };
    const completeCallback = vi.fn<(
      callbackUrl: URL,
      browserBindingToken: string | undefined,
    ) => Promise<OidcCallbackResult>>(async () => ({
      purpose: 'login' as const,
      identity: {
        issuer: 'https://auth.example.test/application/o/mima/',
        subject: 'oidc-subject',
        preferredUsername: user.username,
        displayName: user.displayName,
        email: user.email,
        sid: null,
        authTime: new Date('2026-07-19T00:00:00Z'),
      },
      sessionId: null,
      userId: null,
      previousAuthenticatedAt: null,
      startedAt: new Date('2026-07-19T00:00:00Z'),
    }));
    const authRuntime: AuthRuntime = {
      loginProvider: 'oidc',
      reauthProvider: 'none',
      directoryProvider: 'authentik',
      login: {
        method: 'oidc',
        beginLogin: async () => ({ url: new URL('https://auth.example.test/authorize'), browserBindingToken: 'binding' }),
        completeCallback,
        validateLogoutToken: async () => ({
          issuer: 'https://auth.example.test/application/o/mima/',
          subject: user.id,
          sid: null,
          jti: 'logout-jti',
          expiresAt: new Date(Date.now() + 60_000),
        }),
      },
      reauth: null,
      directory: {
        source: 'oidc',
        listDirectory: async () => ({ users: [], groups: [], syncedAt: null }),
        findActiveUser: async () => user,
        findActiveOidcUser: async () => user,
        findActiveUsername: async () => user,
        resolveExternalIdentity: async () => null,
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
      `INSERT INTO users (id, username, display_name, email, source, active) VALUES ($1, $2, $3, $4, 'oidc', true)`,
      [user.id, user.username, user.displayName, user.email],
    );
    await database.end();
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/api/auth/oidc/callback',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: 'mima_oidc_tx=binding-token',
        },
        payload: new URLSearchParams({
          code: 'authorization-code',
          state: 'authorization-state',
          session_state: 'provider-session',
        }).toString(),
      });
      expect(response.statusCode).toBe(303);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['referrer-policy']).toBe('no-referrer');
      expect(completeCallback).toHaveBeenCalledTimes(1);
      const [callbackUrl, bindingToken] = completeCallback.mock.calls[0]!;
      expect(callbackUrl.href).toBe(
        `${redirectUri}?code=authorization-code&session_state=provider-session&state=authorization-state`,
      );
      expect(bindingToken).toBe('binding-token');
      const cookies = response.headers['set-cookie'];
      const serialized = Array.isArray(cookies) ? cookies.join('\n') : String(cookies);
      expect(serialized).toContain('mima_oidc_tx=;');
      expect(serialized).toContain('SameSite=None');
      expect(serialized).toContain('mima_sid=session-token');

      const getResponse = await app.inject({ method: 'GET', url: '/api/auth/oidc/callback?code=x&state=y' });
      expect(getResponse.statusCode).toBe(404);
      expect(getResponse.headers['cache-control']).toBe('no-store');
      expect(getResponse.headers['referrer-policy']).toBe('no-referrer');
      expect(getResponse.body).not.toContain('code=x');
      expect(getResponse.body).not.toContain('state=y');
      expect(completeCallback).toHaveBeenCalledTimes(1);

      const invalid = await app.inject({
        method: 'POST',
        url: '/api/auth/oidc/callback',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({ code: 'x', error: 'access_denied', state: 'y' }).toString(),
      });
      expect(invalid.statusCode).toBe(400);
      expect(invalid.headers['cache-control']).toBe('no-store');
      expect(invalid.headers['referrer-policy']).toBe('no-referrer');
      expect(completeCallback).toHaveBeenCalledTimes(1);
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
