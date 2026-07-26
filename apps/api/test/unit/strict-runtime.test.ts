import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildStrictApp } from '../../src/strict-app.ts';

describe('strict zero-knowledge runtime boundary', () => {
  let app: FastifyInstance | null = null;
  let keyRoot: string | null = null;

  afterEach(async () => {
    await app?.close();
    if (keyRoot) rmSync(keyRoot, { recursive: true, force: true });
    app = null;
    keyRoot = null;
  });

  it('does not register or advertise legacy plaintext routes', async () => {
    keyRoot = mkdtempSync(join(tmpdir(), 'mima-strict-runtime-'));
    const runtimeKeyDir = join(keyRoot, 'runtime');
    const auditKeyDir = join(keyRoot, 'audit');
    mkdirSync(runtimeKeyDir);
    mkdirSync(auditKeyDir);
    writeFileSync(join(runtimeKeyDir, 'kek-v1.key'), `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
    writeFileSync(join(auditKeyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });

    app = await buildStrictApp({
      databaseUrl: 'postgres://unused:unused@127.0.0.1:1/unused',
      runtimeKeyDir,
      auditKeyDir,
      logger: false,
      migrate: false,
      verifyAuditChainOnStartup: false,
    });
    const canary = 'password-token-note-canary-must-never-be-returned';
    app.get('/__test/safe-error', { schema: { hide: true } }, async () => {
      throw new Error(canary);
    });
    await app.ready();

    for (const request of [
      { method: 'GET' as const, url: '/api/bootstrap' },
      { method: 'GET' as const, url: '/api/events' },
      { method: 'POST' as const, url: '/api/items/00000000-0000-4000-8000-000000000000/reveal' },
      { method: 'POST' as const, url: '/api/extension/items/00000000-0000-4000-8000-000000000000/reveal' },
    ]) {
      expect((await app.inject(request)).statusCode).toBe(404);
    }

    const response = await app.inject({ method: 'GET', url: '/api/openapi.json' });
    expect(response.statusCode).toBe(200);
    const paths = (response.json() as { paths: Record<string, unknown> }).paths;
    expect(paths['/api/v2/bootstrap']).toBeDefined();
    expect(paths['/api/v2/events']).toBeDefined();
    expect(paths['/api/v2/extension/bootstrap']).toBeDefined();
    expect(paths['/api/bootstrap']).toBeUndefined();
    expect(paths['/api/items/{itemId}/reveal']).toBeUndefined();
    expect(paths['/api/extension/items/{itemId}/reveal']).toBeUndefined();

    const failed = await app.inject({ method: 'GET', url: '/__test/safe-error' });
    expect(failed.statusCode).toBe(500);
    expect(failed.body).not.toContain(canary);
    expect(failed.json()).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: '服务暂时无法处理请求',
    });
  });
});
