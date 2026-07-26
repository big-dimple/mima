import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthentikDirectoryService, oidcUserId } from '../../src/auth/directory.ts';
import { directorySyncState, userIdentities, users } from '../../src/db/schema.ts';
import { freshStrictTestApp } from './helpers.ts';

const TEST_DB_NAME = 'mima_test_authentik_identity_lookup';
const ISSUER = 'https://auth.example.test/application/o/mima/';

let app: FastifyInstance;
let tokenDirectory: string;

beforeAll(async () => {
  app = await freshStrictTestApp(TEST_DB_NAME);
  tokenDirectory = mkdtempSync(join(tmpdir(), 'mima-authentik-directory-'));
  writeFileSync(join(tokenDirectory, 'token'), 'directory-token\n', { mode: 0o600 });
});

afterAll(async () => {
  await app.close();
  rmSync(tokenDirectory, { recursive: true, force: true });
});

describe('Authentik directory identity lookup', () => {
  it('resolves an OIDC callback subject stored by the Authentik sync', async () => {
    const subject = randomUUID();
    const userId = oidcUserId(ISSUER, subject);
    await app.ctx.db.insert(users).values({
      id: userId,
      username: 'alice',
      displayName: 'Alice Example',
      email: 'alice@example.test',
      source: 'oidc',
      active: true,
    });
    await app.ctx.db.insert(userIdentities).values({
      provider: 'authentik',
      issuer: ISSUER,
      subject,
      userId,
    });
    await app.ctx.db.insert(directorySyncState).values({
      provider: 'authentik',
      lastAttemptAt: new Date(),
      lastSuccessAt: new Date(),
    });

    const directory = new AuthentikDirectoryService(app.ctx.db, {
      baseUrl: 'https://auth.example.test/',
      issuer: ISSUER,
      tokenFile: join(tokenDirectory, 'token'),
      serviceUsername: 'service-account',
      groupMapJson: '{}',
      syncIntervalMs: 60_000,
      maxStaleMs: 60_000,
      requestTimeoutMs: 1_000,
    });

    await expect(directory.findActiveOidcUser(ISSUER, subject)).resolves.toMatchObject({
      id: userId,
      username: 'alice',
      source: 'oidc',
      active: true,
    });
  });
});
