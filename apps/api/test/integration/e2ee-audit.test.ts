import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { vaults } from '../../src/db/schema.ts';
import { toPublicAuditEvent } from '../../src/routes/e2ee-audit.ts';
import { auditStandalone } from '../../src/services/audit.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let session: TestSession;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_e2ee_audit');
  session = await login(app, 'bob');
});

afterAll(async () => {
  await app.close();
});

describe('zero-knowledge audit boundary', () => {
  it('does not expose legacy audit details before cutover', async () => {
    const vault = (await app.ctx.db.select().from(vaults)
      .where(eq(vaults.ownerUserId, session.userId)).limit(1))[0]!;
    const canary = 'legacy-title-canary-must-not-leave-the-api';
    await auditStandalone(app.ctx.db, app.ctx.audit, {
      actorUserId: session.userId,
      action: 'legacy.audit.canary',
      vaultId: vault.id,
      success: true,
      details: { title: canary },
    });

    const response = await app.inject({
      method: 'GET',
      url: `/api/vaults/${vault.id}/audit`,
      ...authed(session),
    });

    expect(response.statusCode).toBe(423);
    expect(response.body).not.toContain(canary);
    expect(response.json()).toMatchObject({
      error: 'Locked',
      message: '密码库完成零知识迁移后才能查看审计记录',
    });
  });

  it('redacts all audit details from the public zero-knowledge response', () => {
    const canary = 'post-cutover-canary-must-not-leave-the-api';
    const response = toPublicAuditEvent({
      id: 1,
      ts: new Date('2026-07-18T00:00:00.000Z'),
      actorUserId: session.userId,
      action: 'item.e2ee.create',
      vaultId: '00000000-0000-4000-8000-000000000001',
      itemId: null,
      success: true,
      details: { title: canary, nested: { token: canary } },
      prevHash: 'previous',
      hash: 'current',
    });

    expect(response.details).toEqual({});
    expect(JSON.stringify(response)).not.toContain(canary);
  });
});
