import { and, eq } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import {
  ZeroKnowledgeApiErrorSchema,
  ApproveLegacyKeyRetirementRequestSchema,
  CompleteLegacyKeyRetirementRequestSchema,
  CreateLegacyKeyRetirementRequestSchema,
  LegacyKeyRetirementResponseSchema,
  type LegacyKeyRetirementResponse,
} from '@mima/contracts';
import { canonicalJson } from '@mima/e2ee';
import {
  legacyKeyRetirementApprovals,
  legacyKeyRetirementPlans,
  legacyMigrationEvidence,
  legacyMigrationJobs,
  vaultCryptoStates,
} from '../db/schema.ts';
import { env } from '../env.ts';
import { appendAudit, type DbOrTx } from '../services/audit.ts';
import { runCommand } from '../services/commands.ts';
import {
  decodeBase64Url,
  encodeBase64Url,
  getActiveDevice,
  sha256,
  verifyCommandSignature,
} from '../services/e2ee.ts';

class RetirementConflictError extends Error {}

export function registerE2eeLegacyKeyRetirementRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.get('/api/v2/legacy-key-retirement', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee-migration'],
      response: { 200: LegacyKeyRetirementResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async () => retirementDto(db, await currentPlan(db)));

  r.post('/api/v2/legacy-key-retirement', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-migration'],
      body: CreateLegacyKeyRetirementRequestSchema,
      response: { 201: LegacyKeyRetirementResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!req.user.isPlatformAdmin) return forbidden(reply, '只有系统管理员可以登记旧密钥退役计划');
    const actor = await activeUnlockedAdminDevice(app, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const unsigned = withoutSignature(req.body);
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'legacy_key_retirement.create',
      { userId: req.user.id, request: unsigned },
    )) return unauthorized(reply, '旧密钥退役计划设备签名无效');

    const retireBy = req.body.retireBy ? new Date(req.body.retireBy) : null;
    if (retireBy && retireBy.getTime() <= Date.now()) return badRequest(reply, '旧密钥退役期限必须晚于当前时间');
    let copyInventoryDigest: Buffer;
    let copyManifestDigest: Buffer;
    let kekFingerprintDigest: Buffer | null;
    let planSignature: Buffer;
    try {
      copyInventoryDigest = decodeBase64Url(req.body.copyInventoryDigest, { exact: 32 });
      copyManifestDigest = decodeBase64Url(req.body.copyManifestDigest, { exact: 32 });
      kekFingerprintDigest = req.body.kekFingerprintDigest
        ? decodeBase64Url(req.body.kekFingerprintDigest, { exact: 32 })
        : null;
      planSignature = decodeBase64Url(req.body.signature, { exact: 64 });
    } catch {
      return badRequest(reply, '旧密钥退役摘要或签名格式无效');
    }
    const planDigest = retirementPlanDigest({
      deploymentId: env.deploymentId,
      reasonCode: req.body.reasonCode,
      retireBy: req.body.retireBy,
      copyInventoryDigest: req.body.copyInventoryDigest,
      copyManifestDigest: req.body.copyManifestDigest,
      kekFingerprintDigest: req.body.kekFingerprintDigest,
    });

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const row = (await tx.insert(legacyKeyRetirementPlans).values({
          deploymentId: env.deploymentId,
          reasonCode: req.body.reasonCode,
          retireBy,
          copyInventoryDigest,
          copyManifestDigest,
          kekFingerprintDigest,
          planDigest,
          createdByUserId: req.user.id,
          createdByDeviceId: actor.id,
          planSignature,
        }).returning())[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'migration.legacy_key_retirement.create',
          success: true,
          details: { reasonCode: row.reasonCode },
        });
        return { statusCode: 201, response: await retirementDto(tx, row) };
      });
      return reply.code(201).send(result.response);
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '当前部署已经登记旧密钥退役计划');
      if (isDatabaseStateViolation(error)) {
        return conflict(reply, '当前部署状态不允许登记这份旧密钥退役计划');
      }
      throw error;
    }
  });

  r.post('/api/v2/legacy-key-retirement/approve', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-migration'],
      body: ApproveLegacyKeyRetirementRequestSchema,
      response: { 200: LegacyKeyRetirementResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!req.user.isPlatformAdmin) return forbidden(reply, '只有系统管理员可以审批旧密钥退役计划');
    const actor = await activeUnlockedAdminDevice(app, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const plan = await currentPlan(db);
    if (!plan) return conflict(reply, '当前部署尚未登记旧密钥退役计划');
    let planDigest: Buffer;
    let evidenceDigest: Buffer;
    let signature: Buffer;
    try {
      planDigest = decodeBase64Url(req.body.planDigest, { exact: 32 });
      evidenceDigest = decodeBase64Url(req.body.evidenceDigest, { exact: 32 });
      signature = decodeBase64Url(req.body.signature, { exact: 64 });
    } catch {
      return badRequest(reply, '旧密钥退役审批摘要或签名格式无效');
    }
    if (!Buffer.from(plan.planDigest).equals(planDigest)) return conflict(reply, '旧密钥退役计划摘要不匹配');
    const unsigned = withoutSignature(req.body);
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'legacy_key_retirement.approve',
      { userId: req.user.id, request: unsigned },
    )) return unauthorized(reply, '旧密钥退役审批设备签名无效');

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await tx.insert(legacyKeyRetirementApprovals).values({
          planId: plan.id,
          approverUserId: req.user.id,
          approverDeviceId: actor.id,
          planDigest,
          evidenceDigest,
          signature,
        });
        const updated = (await tx.select().from(legacyKeyRetirementPlans)
          .where(eq(legacyKeyRetirementPlans.id, plan.id)).limit(1))[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'migration.legacy_key_retirement.approve',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await retirementDto(tx, updated) };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '你已经审批过这份计划');
      if (isDatabaseStateViolation(error)) {
        return conflict(reply, '审批必须绑定两名管理员共同核对的同一份销毁与副本清点证据');
      }
      throw error;
    }
  });

  r.post('/api/v2/legacy-key-retirement/complete', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-migration'],
      body: CompleteLegacyKeyRetirementRequestSchema,
      response: { 200: LegacyKeyRetirementResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!req.user.isPlatformAdmin) return forbidden(reply, '只有系统管理员可以完成旧密钥退役');
    const actor = await activeUnlockedAdminDevice(app, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const plan = await currentPlan(db);
    if (!plan) return conflict(reply, '当前部署尚未登记旧密钥退役计划');
    let planDigest: Buffer;
    let completionEvidenceDigest: Buffer;
    let signature: Buffer;
    try {
      planDigest = decodeBase64Url(req.body.planDigest, { exact: 32 });
      completionEvidenceDigest = decodeBase64Url(req.body.completionEvidenceDigest, { exact: 32 });
      signature = decodeBase64Url(req.body.signature, { exact: 64 });
    } catch {
      return badRequest(reply, '旧密钥退役完成摘要或签名格式无效');
    }
    if (!Buffer.from(plan.planDigest).equals(planDigest)) return conflict(reply, '旧密钥退役计划摘要不匹配');
    const unsigned = withoutSignature(req.body);
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'legacy_key_retirement.complete',
      { userId: req.user.id, request: unsigned },
    )) return unauthorized(reply, '旧密钥退役完成设备签名无效');

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const lockedPlan = (await tx.select().from(legacyKeyRetirementPlans)
          .where(eq(legacyKeyRetirementPlans.id, plan.id)).for('update').limit(1))[0];
        if (!lockedPlan || lockedPlan.status !== 'approved' || !Buffer.from(lockedPlan.planDigest).equals(planDigest)) {
          throw new RetirementConflictError('旧密钥退役尚未获得两名管理员审批');
        }
        const jobs = await tx.select().from(legacyMigrationJobs);
        const vaultStates = await tx.select().from(vaultCryptoStates);
        const approvals = await tx.select().from(legacyKeyRetirementApprovals)
          .where(eq(legacyKeyRetirementApprovals.planId, lockedPlan.id)).for('update');
        if (
          approvals.length < 2
          || approvals.some((approval) => (
            !Buffer.from(approval.planDigest).equals(planDigest)
            || !Buffer.from(approval.evidenceDigest).equals(completionEvidenceDigest)
          ))
        ) {
          throw new RetirementConflictError('两名管理员必须先批准同一份销毁与副本清点证据');
        }
        const completedJobs = jobs.filter((job) => job.state === 'e2ee' && job.completedAt);
        const activeJobs = jobs.filter((job) => ['preparing', 'frozen', 'encrypting', 'verifying', 'cutover'].includes(job.state));
        const targetStatus = lockedPlan.reasonCode === 'fresh_install' ? 'not_applicable' as const : 'completed' as const;
        if (targetStatus === 'not_applicable') {
          if (jobs.length > 0) throw new RetirementConflictError('存在旧数据迁移记录，不能标记为新安装不适用');
        } else if (
          completedJobs.length === 0
          || activeJobs.length > 0
          || vaultStates.some((state) => state.storageMode !== 'e2ee')
        ) {
          throw new RetirementConflictError('仍有密码库或迁移任务未完成，不能确认旧密钥退役');
        }
        if (completedJobs.length > 0) {
          await tx.insert(legacyMigrationEvidence).values(completedJobs.map((job) => ({
            jobId: job.id,
            evidenceType: 'legacy_key_retirement' as const,
            stage: 'e2ee' as const,
            subjectKind: 'deployment' as const,
            subjectId: env.deploymentId,
            recordCount: 1,
            digest: retirementJobEvidenceDigest({
              completionEvidenceDigest: req.body.completionEvidenceDigest,
              deploymentId: env.deploymentId,
              jobId: job.id,
              planDigest: req.body.planDigest,
              sourceDigest: job.sourceSnapshotHash ? encodeBase64Url(job.sourceSnapshotHash) : null,
            }),
            retirementManifestDigest: completionEvidenceDigest,
            signerDeviceId: actor.id,
            signature,
          })));
        }
        const now = new Date();
        const updated = (await tx.update(legacyKeyRetirementPlans).set({
          status: targetStatus,
          completionEvidenceDigest,
          completedAt: now,
        }).where(and(
          eq(legacyKeyRetirementPlans.id, lockedPlan.id),
          eq(legacyKeyRetirementPlans.status, 'approved'),
        )).returning())[0];
        if (!updated) throw new RetirementConflictError('旧密钥退役计划已经变化');
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'migration.legacy_key_retirement.complete',
          success: true,
          details: { status: targetStatus, migratedJobCount: completedJobs.length },
        });
        return { statusCode: 200, response: await retirementDto(tx, updated) };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof RetirementConflictError || isUniqueViolation(error)) {
        return conflict(reply, error instanceof Error ? error.message : '旧密钥退役证据已经存在');
      }
      if (isDatabaseStateViolation(error)) return conflict(reply, '旧密钥退役完成门禁未通过');
      throw error;
    }
  });
}

async function activeUnlockedAdminDevice(
  app: FastifyInstance,
  userId: string,
  session: { locked: boolean; unlockedDeviceId: string | null },
  actorDeviceId: string,
  reply: FastifyReply,
) {
  if (session.locked || session.unlockedDeviceId !== actorDeviceId) {
    forbidden(reply, '请先用当前管理员设备解锁工作台');
    return null;
  }
  const actor = await getActiveDevice(app.ctx.db, userId, actorDeviceId);
  if (!actor) {
    forbidden(reply, '当前管理员设备未授权或已经撤销');
    return null;
  }
  return actor;
}

async function currentPlan(db: DbOrTx) {
  return (await db.select().from(legacyKeyRetirementPlans)
    .where(eq(legacyKeyRetirementPlans.deploymentId, env.deploymentId)).limit(1))[0] ?? null;
}

async function retirementDto(
  db: DbOrTx,
  row: typeof legacyKeyRetirementPlans.$inferSelect | null,
): Promise<LegacyKeyRetirementResponse> {
  const completedJobs = await db.select({ id: legacyMigrationJobs.id }).from(legacyMigrationJobs)
    .where(eq(legacyMigrationJobs.state, 'e2ee'));
  const evidenceJobs = await db.select({ jobId: legacyMigrationEvidence.jobId }).from(legacyMigrationEvidence)
    .where(and(
      eq(legacyMigrationEvidence.evidenceType, 'legacy_key_retirement'),
      eq(legacyMigrationEvidence.subjectKind, 'deployment'),
      eq(legacyMigrationEvidence.subjectId, env.deploymentId),
    ));
  if (!row) {
    return {
      deploymentId: env.deploymentId,
      status: 'unplanned',
      reasonCode: null,
      retireBy: null,
      copyInventoryDigest: null,
      copyManifestDigest: null,
      kekFingerprintDigest: null,
      planDigest: null,
      approvalCount: 0,
      approvalUserIds: [],
      approvalEvidenceDigest: null,
      migratedJobCount: completedJobs.length,
      evidenceJobCount: evidenceJobs.length,
      legacyKeyState: 'unknown',
      overdue: false,
      createdAt: null,
      approvedAt: null,
      completedAt: null,
    };
  }
  const approvals = await db.select({
    userId: legacyKeyRetirementApprovals.approverUserId,
    evidenceDigest: legacyKeyRetirementApprovals.evidenceDigest,
  })
    .from(legacyKeyRetirementApprovals)
    .where(eq(legacyKeyRetirementApprovals.planId, row.id));
  const legacyKeyState = row.status === 'completed'
    ? 'retired' as const
    : row.status === 'not_applicable'
      ? 'not_applicable' as const
      : completedJobs.length > 0
        ? 'retained' as const
        : 'unknown' as const;
  return {
    deploymentId: row.deploymentId,
    status: row.status,
    reasonCode: row.reasonCode,
    retireBy: row.retireBy?.toISOString() ?? null,
    copyInventoryDigest: encodeBase64Url(row.copyInventoryDigest),
    copyManifestDigest: encodeBase64Url(row.copyManifestDigest),
    kekFingerprintDigest: row.kekFingerprintDigest ? encodeBase64Url(row.kekFingerprintDigest) : null,
    planDigest: encodeBase64Url(row.planDigest),
    approvalCount: approvals.length,
    approvalUserIds: approvals.map((approval) => approval.userId),
    approvalEvidenceDigest: approvals[0] ? encodeBase64Url(approvals[0].evidenceDigest) : null,
    migratedJobCount: completedJobs.length,
    evidenceJobCount: evidenceJobs.length,
    legacyKeyState,
    overdue: legacyKeyState === 'retained' && Boolean(row.retireBy && row.retireBy.getTime() < Date.now()),
    createdAt: row.createdAt.toISOString(),
    approvedAt: row.approvedAt?.toISOString() ?? null,
    completedAt: row.completedAt?.toISOString() ?? null,
  };
}

function retirementPlanDigest(input: {
  deploymentId: string;
  reasonCode: string;
  retireBy: string | null;
  copyInventoryDigest: string;
  copyManifestDigest: string;
  kekFingerprintDigest: string | null;
}) {
  return sha256(canonicalJson({
    kind: 'legacy-key-retirement-plan',
    protocol: 'lm-e2ee-v1',
    ...input,
  }));
}

function retirementJobEvidenceDigest(input: {
  completionEvidenceDigest: string;
  deploymentId: string;
  jobId: string;
  planDigest: string;
  sourceDigest: string | null;
}) {
  return sha256(canonicalJson({
    kind: 'legacy-key-retirement-evidence',
    protocol: 'lm-e2ee-v1',
    ...input,
  }));
}

function withoutSignature<T extends { signature: string }>(value: T): Omit<T, 'signature'> {
  const { signature: _signature, ...unsigned } = value;
  return unsigned;
}

function badRequest(reply: FastifyReply, message: string) {
  return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message });
}

function unauthorized(reply: FastifyReply, message: string) {
  return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message });
}

function forbidden(reply: FastifyReply, message: string) {
  return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message });
}

function conflict(reply: FastifyReply, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', message });
}

function isUniqueViolation(error: unknown): boolean {
  return databaseErrorCode(error) === '23505';
}

function isDatabaseStateViolation(error: unknown): boolean {
  return ['P0001', '23502', '23503', '23514'].includes(databaseErrorCode(error) ?? '');
}

function databaseErrorCode(error: unknown): string | null {
  let current = error;
  for (let depth = 0; depth < 4; depth += 1) {
    if (!current || typeof current !== 'object') return null;
    if ('code' in current && typeof current.code === 'string') return current.code;
    current = 'cause' in current ? current.cause : null;
  }
  return null;
}
