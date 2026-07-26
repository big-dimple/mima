import { desc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { ZeroKnowledgeApiErrorSchema, ZeroKnowledgeAuditEventSchema } from '@mima/contracts';
import { canReadAudit } from '@mima/domain';
import { auditEvents, vaultCryptoStates } from '../db/schema.ts';
import { getVaultAccess } from '../services/access.ts';
import { auditStandalone } from '../services/audit.ts';

const VaultParams = z.object({ vaultId: z.string().uuid() });

export function registerE2eeAuditRoutes(app: FastifyInstance): void {
  const { db } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();

  r.get('/api/vaults/:vaultId/audit', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['audit'],
      params: VaultParams,
      response: { 200: z.array(ZeroKnowledgeAuditEventSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || !canReadAudit(access.role, req.user.isPlatformAdmin)) {
      await auditStandalone(db, app.ctx.audit, {
        actorUserId: req.user.id,
        action: 'audit.read',
        vaultId: req.params.vaultId,
        success: false,
        details: { reason: 'access_denied' },
      });
      return reply.code(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: '没有执行该操作的权限',
      } as never);
    }
    const state = (await db
      .select({ storageMode: vaultCryptoStates.storageMode })
      .from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, req.params.vaultId))
      .limit(1))[0];
    if (state?.storageMode !== 'e2ee') {
      await auditStandalone(db, app.ctx.audit, {
        actorUserId: req.user.id,
        action: 'audit.read',
        vaultId: req.params.vaultId,
        success: false,
        details: { reason: 'migration_incomplete' },
      });
      return reply.code(423).send({
        statusCode: 423,
        error: 'Locked',
        message: '密码库完成零知识迁移后才能查看审计记录',
      } as never);
    }
    reply.header('cache-control', 'no-store');
    const rows = await db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.vaultId, req.params.vaultId))
      .orderBy(desc(auditEvents.id))
      .limit(200);
    return rows.map(toPublicAuditEvent);
  });
}

export function toPublicAuditEvent(row: typeof auditEvents.$inferSelect) {
  return { ...row, ts: row.ts.toISOString(), details: {} };
}
