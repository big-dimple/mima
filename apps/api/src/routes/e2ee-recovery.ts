import { randomUUID } from 'node:crypto';
import { and, asc, desc, eq, inArray, isNotNull, lte } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  ActivateEnterpriseRecoveryKeyRequestSchema,
  ApproveEnterpriseRecoveryKeyRequestSchema,
  ApproveEnterpriseRecoveryRequestSchema,
  CancelEnterpriseRecoveryKeyRequestSchema,
  CancelEnterpriseRecoveryRequestSchema,
  CompleteEnterpriseRecoveryRequestSchema,
  CreateEnterpriseRecoveryRequestSchema,
  DistributeEnterpriseRecoveryEnvelopeRequestSchema,
  DistributeEnterpriseRecoveryEnvelopeResponseSchema,
  EnterpriseRecoveryCandidateSchema,
  EnterpriseRecoveryCoverageSchema,
  EnterpriseRecoveryCustodyShareSchema,
  EnterpriseRecoveryKeySchema,
  EnterpriseRecoveryReadinessSchema,
  EnterpriseRecoveryRequestSchema,
  EnterpriseRecoveryWorkspaceSchema,
  RegisterManagedEnterpriseRecoveryKeyRequestSchema,
  RegisterEnterpriseRecoveryKeyRequestSchema,
} from '@mima/contracts';
import {
  accountCryptoResetRequests,
  accountCryptoResetVaults,
  encryptedVaultHeaders,
  enterpriseRecoveryApprovals,
  enterpriseRecoveryCases,
  enterpriseRecoveryCustodyShares,
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryKeys,
  enterpriseRecoveryRequests,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultMemberships,
  vaults,
} from '../db/schema.ts';
import { appendAudit, recordAnchor } from '../services/audit.ts';
import type { DbOrTx } from '../services/audit.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import { getVaultAccess, listPersonalVaultRecoveryCandidates } from '../services/access.ts';
import {
  decodeBase64Url,
  encodeCipherBlob,
  encodeBase64Url,
  getActiveDevice,
  getCryptoProfile,
  publicKeyFingerprint,
  sha256,
  toEnvelopeDto,
  verifyCommandSignature,
  verifyVaultEnvelope,
} from '../services/e2ee.ts';
import { canonicalJson, enterpriseRecoveryCeremonyDigest } from '@mima/e2ee';
import {
  ensureMembershipRekeyTask,
  resolveAuthorizedVaultCapability,
} from '../services/vault-envelope-tasks.ts';
import { hasLocalPlatformAdminRole } from '../services/system-roles.ts';
import { listEnterpriseRecoveryCases } from './e2ee-recovery-cases.ts';
import {
  lockEnterpriseRecoveryAdministration,
  lockEnterpriseRecoveryCoverage,
  lockRecipientSets,
} from '../services/recipient-set-lock.ts';

const RecoveryParams = z.object({ requestId: z.string().uuid() });
const RecoveryKeyParams = z.object({ keyId: z.string().uuid() });
const RecoveryKeyVaultParams = z.object({ keyId: z.string().uuid(), vaultId: z.string().uuid() });
class RecoveryKeyConflictError extends Error {}

class RecoveryRequestError extends Error {
  constructor(
    readonly statusCode: 400 | 401 | 403 | 404 | 409,
    message: string,
  ) {
    super(message);
  }
}

export function registerE2eeRecoveryRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];
  const requireLocalRecoveryAdmin = async (req: FastifyRequest, reply: FastifyReply) => {
    if (!await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '企业恢复公钥只能由本地授权的系统管理员操作');
    }
  };
  const recoveryKeyWriteGuard = [...writeGuard, requireLocalRecoveryAdmin];

  r.get('/api/v2/recovery/key', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-recovery'], response: { 200: EnterpriseRecoveryKeySchema.nullable(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async () => {
    const row = (await db.select().from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1))[0];
    return row ? recoveryKeyDto(db, row) : null;
  });

  r.get('/api/v2/recovery/keys', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-recovery'], response: { 200: z.array(EnterpriseRecoveryKeySchema), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req) => {
    const rows = req.user.isLocalPlatformAdmin
      ? await db.select().from(enterpriseRecoveryKeys).orderBy(desc(enterpriseRecoveryKeys.createdAt))
      : await db.select().from(enterpriseRecoveryKeys)
          .where(inArray(enterpriseRecoveryKeys.status, ['staged', 'active']))
          .orderBy(desc(enterpriseRecoveryKeys.createdAt));
    return Promise.all(rows.map((row) => recoveryKeyDto(db, row)));
  });

  r.get('/api/v2/recovery/readiness', {
    preHandler: [app.requireSession, requireLocalRecoveryAdmin],
    schema: {
      tags: ['e2ee-recovery'],
      response: { 200: EnterpriseRecoveryReadinessSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (_req, reply) => {
    reply.header('cache-control', 'no-store');
    return enterpriseRecoveryReadinessDto(db);
  });

  r.get('/api/v2/recovery/workspace', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee-recovery'],
      response: { 200: EnterpriseRecoveryWorkspaceSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await expireEnterpriseRecoveryRequests(db);
    const canManage = await hasLocalPlatformAdminRole(db, req.user.id);
    const keys = canManage
      ? await db.select().from(enterpriseRecoveryKeys).orderBy(desc(enterpriseRecoveryKeys.createdAt))
      : await db.select().from(enterpriseRecoveryKeys)
          .where(inArray(enterpriseRecoveryKeys.status, ['staged', 'active']))
          .orderBy(desc(enterpriseRecoveryKeys.createdAt));
    const workflowKey = keys.find((key) => key.status === 'pending' || key.status === 'staged')
      ?? keys.find((key) => key.status === 'active')
      ?? null;
    const requestRows = canManage
      ? await db.select().from(enterpriseRecoveryRequests).orderBy(desc(enterpriseRecoveryRequests.createdAt))
      : await db.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.targetUserId, req.user.id))
          .orderBy(desc(enterpriseRecoveryRequests.createdAt));
    const [readiness, coverage, candidates, cases] = await Promise.all([
      canManage ? enterpriseRecoveryReadinessDto(db) : Promise.resolve(null),
      workflowKey && ['staged', 'active'].includes(workflowKey.status)
        ? enterpriseRecoveryCoverageDto(db, workflowKey.id, req.user.id, canManage)
        : Promise.resolve(null),
      canManage ? listPersonalVaultRecoveryCandidates(db) : Promise.resolve([]),
      listEnterpriseRecoveryCases(db, req.user.id, canManage),
    ]);
    reply.header('cache-control', 'no-store');
    return {
      refreshedAt: new Date().toISOString(),
      keys: await Promise.all(keys.map((key) => recoveryKeyDto(db, key))),
      readiness,
      coverage,
      requests: await Promise.all(requestRows.map((request) => recoveryRequestDto(db, request))),
      cases,
      candidates: candidates.map((candidate) => ({
        vaultId: candidate.vault.id,
        targetUserId: candidate.user.id,
        targetDisplayName: candidate.user.displayName,
        targetUsername: candidate.user.username,
        targetDeviceId: candidate.targetDevice.id,
        targetEncryptionPublicKey: encodeBase64Url(candidate.profile.publicEncryptionKey),
        targetKeyVersion: candidate.profile.cryptoGeneration,
        targetCapability: 'full' as const,
        reason: 'personal_owner_missing_current_full_envelope' as const,
      })),
    };
  });

  r.get('/api/v2/recovery/keys/:keyId/coverage', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee-recovery'],
      params: RecoveryKeyParams,
      response: { 200: EnterpriseRecoveryCoverageSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const key = (await db.select({ id: enterpriseRecoveryKeys.id }).from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).limit(1))[0];
    if (!key) return reply.code(404).send(notFoundBody('企业恢复公钥不存在') as never);
    const canSeeAll = await hasLocalPlatformAdminRole(db, req.user.id);
    reply.header('cache-control', 'no-store');
    return enterpriseRecoveryCoverageDto(db, key.id, req.user.id, canSeeAll);
  });

  r.post('/api/v2/recovery/key', {
    preHandler: recoveryKeyWriteGuard,
    schema: { tags: ['e2ee-recovery'], body: RegisterEnterpriseRecoveryKeyRequestSchema, response: { 201: EnterpriseRecoveryKeySchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    let publicKey; let evidenceDigest;
    try {
      publicKey = decodeBase64Url(req.body.publicEncryptionKey, { exact: 32 });
      evidenceDigest = decodeBase64Url(req.body.ceremonyEvidenceDigest, { exact: 32 });
    } catch { return badRequest(reply, '企业恢复公钥格式无效'); }
    if (publicKeyFingerprint(req.body.publicEncryptionKey) !== req.body.keyFingerprint) {
      return badRequest(reply, '企业恢复公钥指纹不匹配');
    }
      const expectedCeremonyDigest = await enterpriseRecoveryCeremonyDigest({
        ceremonyId: req.body.ceremonyId,
        publicKey: req.body.publicEncryptionKey,
        publicKeyFingerprint: req.body.keyFingerprint,
        shareCount: req.body.shareCount,
    });
    if (expectedCeremonyDigest !== req.body.ceremonyEvidenceDigest) {
      return badRequest(reply, '企业恢复仪式证据摘要不匹配');
    }
    try {
      const committed = await db.transaction(async (tx) => {
        const row = (await tx.insert(enterpriseRecoveryKeys).values({
          ceremonyId: req.body.ceremonyId,
          keyFingerprint: req.body.keyFingerprint,
          publicEncryptionKey: publicKey,
          threshold: 2,
          shareCount: req.body.shareCount,
          ceremonyEvidenceDigest: evidenceDigest,
          createdByUserId: req.user.id,
        }).returning())[0]!;
        const head = await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.key.register',
          success: true,
          details: {},
        });
        return { row, head };
      });
      recordAnchor(audit, committed.head);
      return reply.code(201).send(await recoveryKeyDto(db, committed.row));
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '已经存在有效的企业恢复公钥');
      throw error;
    }
  });

  r.post('/api/v2/recovery/custody', {
    preHandler: recoveryKeyWriteGuard,
    schema: {
      tags: ['e2ee-recovery'],
      body: RegisterManagedEnterpriseRecoveryKeyRequestSchema,
      response: { 201: EnterpriseRecoveryKeySchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== req.body.actorDeviceId) {
      return forbidden(reply, '请先用当前设备解锁工作台');
    }
    const validation = await validateManagedCustodyRequest(db, req.user.id, req.body);
    if (validation instanceof RecoveryRequestError) return sendRecoveryRequestError(reply, validation);
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryCoverage(tx);
        await lockEnterpriseRecoveryAdministration(tx);
        const locked = await validateManagedCustodyRequest(tx, req.user.id, req.body);
        if (locked instanceof RecoveryRequestError) throw locked;
        const row = (await tx.insert(enterpriseRecoveryKeys).values({
          ceremonyId: req.body.key.ceremonyId,
          keyFingerprint: req.body.key.keyFingerprint,
          publicEncryptionKey: locked.publicKey,
          threshold: 2,
          shareCount: req.body.key.shareCount,
          custodyMode: 'administrator_accounts',
          ceremonyEvidenceDigest: locked.evidenceDigest,
          createdByUserId: req.user.id,
        }).returning())[0]!;
        for (const share of locked.shares) {
          await tx.insert(enterpriseRecoveryCustodyShares).values({
            recoveryKeyId: row.id,
            administratorUserId: share.administratorUserId,
            administratorKeyVersion: share.administratorKeyVersion,
            administratorEncryptionPublicKey: share.administratorEncryptionPublicKey,
            shareIndex: share.shareIndex,
            sealedShareCiphertext: share.sealedShareCiphertext,
            sealedShareDigest: share.sealedShareDigest,
            registeredByUserId: req.user.id,
          });
        }
        const ownShare = locked.shares.find((share) => share.administratorUserId === req.user.id)!;
        await tx.insert(enterpriseRecoveryKeyApprovals).values({
          recoveryKeyId: row.id,
          approverUserId: req.user.id,
          ceremonyEvidenceDigest: locked.evidenceDigest,
          actorDeviceId: req.body.actorDeviceId,
          sealedShareDigest: ownShare.sealedShareDigest,
          approvalSignature: locked.signature,
        });
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.custody.register',
          success: true,
          details: { administratorCount: locked.shares.length },
        });
        return { statusCode: 201, response: await recoveryKeyDto(tx, row) };
      }, commandIdentity('recovery.custody.register', req.body));
      return reply.code(201).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryRequestError) return sendRecoveryRequestError(reply, error);
      if (isUniqueViolation(error)) return conflict(reply, '已经存在正在准备的企业恢复设置');
      throw error;
    }
  });

  r.get('/api/v2/recovery/keys/:keyId/custody/share', {
    preHandler: [app.requireSession, requireLocalRecoveryAdmin],
    schema: {
      tags: ['e2ee-recovery'],
      params: RecoveryKeyParams,
      response: { 200: EnterpriseRecoveryCustodyShareSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const [key, share, profile] = await Promise.all([
      db.select().from(enterpriseRecoveryKeys)
        .where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).limit(1),
      db.select().from(enterpriseRecoveryCustodyShares).where(and(
        eq(enterpriseRecoveryCustodyShares.recoveryKeyId, req.params.keyId),
        eq(enterpriseRecoveryCustodyShares.administratorUserId, req.user.id),
      )).limit(1),
      getCryptoProfile(db, req.user.id),
    ]);
    if (!key[0] || key[0].custodyMode !== 'administrator_accounts' || !share[0]) {
      return reply.code(404).send(notFoundBody('当前账号没有这套企业恢复设置') as never);
    }
    if (!profile
      || profile.cryptoGeneration !== share[0].administratorKeyVersion
      || !Buffer.from(profile.publicEncryptionKey).equals(share[0].administratorEncryptionPublicKey)
    ) return conflict(reply, '当前管理员的账号安全信息已更新，请重新准备企业恢复');
    reply.header('cache-control', 'no-store');
    return custodyShareDto(share[0]);
  });

  r.post('/api/v2/recovery/keys/:keyId/approve', {
    preHandler: recoveryKeyWriteGuard,
    schema: {
      tags: ['e2ee-recovery'], params: RecoveryKeyParams, body: ApproveEnterpriseRecoveryKeyRequestSchema,
      response: { 200: EnterpriseRecoveryKeySchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    let evidenceDigest;
    try { evidenceDigest = decodeBase64Url(req.body.ceremonyEvidenceDigest, { exact: 32 }); }
    catch { return badRequest(reply, '企业恢复仪式证据摘要格式无效'); }
    const key = (await db.select().from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).limit(1))[0];
    if (!key) return reply.code(404).send(notFoundBody('企业恢复公钥不存在') as never);
    if (!Buffer.from(key.ceremonyEvidenceDigest).equals(evidenceDigest)) {
      return conflict(reply, '企业恢复仪式证据摘要不匹配');
    }
    if (!['pending', 'staged'].includes(key.status)) return conflict(reply, '该企业恢复公钥不再接受审批');
    let managedApproval: {
      actorDeviceId: string;
      sealedShareDigest: Buffer;
      signature: Buffer;
    } | null = null;
    if (key.custodyMode === 'administrator_accounts') {
      if (!req.body.actorDeviceId
        || req.sessionRow.locked
        || req.sessionRow.unlockedDeviceId !== req.body.actorDeviceId
      ) return forbidden(reply, '请先用当前设备解锁工作台');
      const validation = await validateManagedCustodyApproval(db, req.user.id, key.id, req.body);
      if (validation instanceof RecoveryRequestError) {
        return sendRecoveryRequestError(reply, validation);
      }
      managedApproval = validation;
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockEnterpriseRecoveryCoverage(tx);
        await lockEnterpriseRecoveryAdministration(tx);
        const lockedKey = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, key.id)).for('update').limit(1))[0];
        if (!lockedKey || !['pending', 'staged'].includes(lockedKey.status)) {
          throw new RecoveryRequestError(409, '这份公开清单已经结束，请刷新查看最新状态');
        }
        if (lockedKey.custodyMode === 'administrator_accounts') {
          const lockedApproval = await validateManagedCustodyApproval(
            tx,
            req.user.id,
            lockedKey.id,
            req.body,
          );
          if (!lockedApproval || lockedApproval instanceof RecoveryRequestError) {
          throw lockedApproval ?? new RecoveryRequestError(409, '当前管理员账号中的恢复权限不可用');
          }
          managedApproval = lockedApproval;
        }
        const approvals = await tx.select({ userId: enterpriseRecoveryKeyApprovals.approverUserId })
          .from(enterpriseRecoveryKeyApprovals)
          .where(eq(enterpriseRecoveryKeyApprovals.recoveryKeyId, lockedKey.id));
        if (approvals.some((approval) => approval.userId === req.user.id)) {
          throw new RecoveryRequestError(409, '你已经确认过这份公开清单，无需重复操作');
        }
        if (approvals.length >= 2) {
          throw new RecoveryRequestError(409, '这份公开清单已完成两人确认，请刷新后进入下一步');
        }
        await tx.insert(enterpriseRecoveryKeyApprovals).values({
          recoveryKeyId: lockedKey.id,
          approverUserId: req.user.id,
          ceremonyEvidenceDigest: evidenceDigest,
          actorDeviceId: managedApproval?.actorDeviceId ?? null,
          sealedShareDigest: managedApproval?.sealedShareDigest ?? null,
          approvalSignature: managedApproval?.signature ?? null,
        });
        let automaticallyActivated = false;
        if (approvals.length === 1) {
          const states = await tx.select({ vaultId: vaultCryptoStates.vaultId })
            .from(vaultCryptoStates)
            .where(eq(vaultCryptoStates.storageMode, 'e2ee'))
            .orderBy(asc(vaultCryptoStates.vaultId));
          for (const state of states) {
            collect(await recordSyncEvent(tx, {
              type: 'vault.crypto_changed',
              vaultId: state.vaultId,
              itemId: null,
              payload: { recoveryCoverageRequested: true },
            }));
          }
          const activeKey = (await tx.select({ id: enterpriseRecoveryKeys.id })
            .from(enterpriseRecoveryKeys)
            .where(eq(enterpriseRecoveryKeys.status, 'active'))
            .orderBy(asc(enterpriseRecoveryKeys.id)).for('update').limit(1))[0];
          if (!activeKey && (await enterpriseRecoveryReadinessDto(tx)).ready) {
            automaticallyActivated = Boolean((await tx.update(enterpriseRecoveryKeys)
              .set({ status: 'active' })
              .where(and(
                eq(enterpriseRecoveryKeys.id, lockedKey.id),
                eq(enterpriseRecoveryKeys.status, 'staged'),
              ))
              .returning({ id: enterpriseRecoveryKeys.id }))[0]);
          }
        }
        const updated = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, lockedKey.id)).limit(1))[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.key.approve',
          success: true,
          details: {},
        });
        if (automaticallyActivated) {
          await appendAudit(tx, audit, {
            actorUserId: req.user.id,
            action: 'recovery.key.activate',
            success: true,
            details: { automatic: true, initialSetup: true },
          });
        }
        return { statusCode: 200, response: await recoveryKeyDto(tx, updated) };
      }, commandIdentity('recovery.key.approve', { keyId: req.params.keyId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryRequestError) return sendRecoveryRequestError(reply, error);
      if (isUniqueViolation(error)) return conflict(reply, '你已经审批过该企业恢复公钥');
      throw error;
    }
  });

  r.post('/api/v2/recovery/keys/:keyId/cancel', {
    preHandler: recoveryKeyWriteGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: RecoveryKeyParams,
      body: CancelEnterpriseRecoveryKeyRequestSchema,
      response: { 200: EnterpriseRecoveryKeySchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    let evidenceDigest;
    try { evidenceDigest = decodeBase64Url(req.body.ceremonyEvidenceDigest, { exact: 32 }); }
    catch { return badRequest(reply, '公开清单摘要格式无效'); }
    try {
      const result = await runCommand(
        db,
        bus,
        audit,
        req.user.id,
        req.body.idempotencyKey,
        async (tx) => {
          const key = (await tx.select().from(enterpriseRecoveryKeys)
            .where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).for('update').limit(1))[0];
          if (!key) throw new RecoveryRequestError(404, '企业恢复公开清单不存在');
          if (!['pending', 'staged'].includes(key.status)) {
            throw new RecoveryRequestError(409, '这份公开清单已经结束，刷新后可查看最新状态');
          }
          if (!Buffer.from(key.ceremonyEvidenceDigest).equals(evidenceDigest)) {
            throw new RecoveryRequestError(409, '公开清单摘要不匹配，请重新导入原文件');
          }
          const cancelled = (await tx.update(enterpriseRecoveryKeys).set({
            status: 'cancelled',
            cancelledAt: new Date(),
          }).where(eq(enterpriseRecoveryKeys.id, key.id)).returning())[0]!;
          await appendAudit(tx, audit, {
            actorUserId: req.user.id,
            action: 'recovery.key.cancel',
            success: true,
            details: {},
          });
          return { statusCode: 200, response: await recoveryKeyDto(tx, cancelled) };
        },
        commandIdentity('recovery.key.cancel', { keyId: req.params.keyId, ...req.body }),
      );
      return reply.code(200).send(result.response);
    } catch (error) {
      return sendRecoveryRequestError(reply, error);
    }
  });

  r.post('/api/v2/recovery/keys/:keyId/vaults/:vaultId/envelope', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: RecoveryKeyVaultParams,
      body: DistributeEnterpriseRecoveryEnvelopeRequestSchema,
      response: { 201: DistributeEnterpriseRecoveryEnvelopeResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以分发企业恢复密钥');
    if (req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== req.body.actorDeviceId) {
      return forbidden(reply, '请先用当前设备解锁工作台');
    }
    const [actor, profile, key, state] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.actorDeviceId),
      getCryptoProfile(db, req.user.id),
      db.select().from(enterpriseRecoveryKeys).where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).limit(1),
      db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).limit(1),
    ]);
    if (!actor || !profile) return forbidden(reply, '当前设备未授权');
    if (!key[0] || !['staged', 'active'].includes(key[0].status)) {
      return conflict(reply, '企业恢复公开清单尚未完成两人确认，或已不再接受保护更新');
    }
    if (!state[0] || state[0].storageMode !== 'e2ee' || !state[0].activeEpoch) {
      return conflict(reply, '该密码库尚未启用零知识加密');
    }
    const envelope = req.body.envelope;
    if (
      envelope.vaultId !== req.params.vaultId || envelope.epoch !== state[0].activeEpoch ||
      envelope.recipientKind !== 'recovery' ||
      ![key[0].id, key[0].keyFingerprint].includes(envelope.recipientId) ||
      envelope.recipientKeyVersion !== 1 || envelope.capability !== 'recovery' ||
      envelope.signerUserId !== req.user.id || envelope.signerKeyVersion !== profile.cryptoGeneration ||
      !await verifyVaultEnvelope(envelope, encodeBase64Url(profile.publicSigningKey))
    ) return badRequest(reply, '企业恢复 envelope 的绑定或签名无效');
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'recovery.key.distribute', {
      userId: req.user.id,
      vaultId: req.params.vaultId,
      request: without(req.body, 'signature'),
    })) return unauthorized(reply, '恢复密钥分发签名无效');
    let ciphertext; let envelopeSignature;
    try {
      ciphertext = decodeBase64Url(envelope.sealedKeyBundle, { min: 49, max: 10_000 });
      envelopeSignature = decodeBase64Url(envelope.signature, { exact: 64 });
    } catch { return badRequest(reply, '企业恢复 envelope 格式无效'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryCoverage(tx);
        await lockRecipientSets(tx, [req.user.id]);
        const [lockedAccess, lockedActor, lockedProfile] = await Promise.all([
          getVaultAccess(tx, req.user, req.params.vaultId),
          getActiveDevice(tx, req.user.id, req.body.actorDeviceId),
          getCryptoProfile(tx, req.user.id),
        ]);
        const lockedKey = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).for('share').limit(1))[0];
        const lockedState = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (!lockedAccess || lockedAccess.role !== 'owner') {
          throw new RecoveryRequestError(403, '你已不是该密码库的拥有者，请刷新后核对权限');
        }
        if (!lockedActor || !lockedProfile) {
          throw new RecoveryRequestError(403, '当前设备授权已经变化，请重新解锁后重试');
        }
        if (!lockedKey || !['staged', 'active'].includes(lockedKey.status)) {
          throw new RecoveryRequestError(409, '企业恢复公开清单尚未完成两人确认，或已不再接受保护更新');
        }
        if (!lockedState?.activeEpoch || lockedState.storageMode !== 'e2ee') {
          throw new RecoveryRequestError(409, '密码库安全状态已经变化，请刷新后重试');
        }
        if (
          envelope.epoch !== lockedState.activeEpoch
          || envelope.signerKeyVersion !== lockedProfile.cryptoGeneration
          || !Buffer.from(lockedProfile.publicSigningKey).equals(profile.publicSigningKey)
          || !await verifyVaultEnvelope(envelope, encodeBase64Url(lockedProfile.publicSigningKey))
        ) throw new RecoveryRequestError(409, '密码库密钥或账号安全信息已经变化，请刷新后重新添加保护');
        const existing = (await tx.select().from(vaultKeyEnvelopes).where(and(
          eq(vaultKeyEnvelopes.vaultId, req.params.vaultId),
          eq(vaultKeyEnvelopes.keyEpoch, lockedState.activeEpoch),
          eq(vaultKeyEnvelopes.recipientRecoveryKeyId, lockedKey.id),
          eq(vaultKeyEnvelopes.accessScope, 'recovery'),
          eq(vaultKeyEnvelopes.authorizationKind, 'recovery'),
        )).for('update').limit(1))[0];
        const alreadyCovered = Boolean(
          existing?.status === 'active'
          && existing.signerUserId
          && existing.signerKeyVersion
          && existing.signerPublicKey,
        );
        if (!alreadyCovered) {
          const values = {
            ciphertext,
            ciphertextDigest: sha256(ciphertext),
            senderDeviceId: lockedActor.id,
            signerUserId: req.user.id,
            signerKeyVersion: lockedProfile.cryptoGeneration,
            signerPublicKey: lockedProfile.publicSigningKey,
            signature: envelopeSignature,
            status: 'active' as const,
            activatedAt: new Date(),
            revokedAt: null,
            revocationReason: null,
          };
          if (existing) {
            await tx.update(vaultKeyEnvelopes).set(values).where(eq(vaultKeyEnvelopes.id, existing.id));
          } else {
            await tx.insert(vaultKeyEnvelopes).values({
              vaultId: req.params.vaultId,
              keyEpoch: lockedState.activeEpoch,
              recipientKind: 'enterprise_recovery',
              accessScope: 'recovery',
              recipientRecoveryKeyId: lockedKey.id,
              recipientKeyFingerprint: lockedKey.keyFingerprint,
              authorizationKind: 'recovery',
              authorizationRef: lockedKey.ceremonyId,
              envelopeVersion: 1,
              ...values,
            });
          }
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.key.distribute',
          vaultId: req.params.vaultId,
          success: true,
          details: {},
        });
        return {
          statusCode: 201,
          response: { ok: true as const, alreadyCovered },
        };
      }, commandIdentity('recovery.key.distribute', {
        keyId: req.params.keyId,
        vaultId: req.params.vaultId,
        ...req.body,
      }));
      return reply.code(201).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryRequestError) return sendRecoveryRequestError(reply, error);
      if (isUniqueViolation(error)) return conflict(reply, '该密码库的企业恢复保护已经由其他操作更新，请刷新查看');
      throw error;
    }
  });

  r.post('/api/v2/recovery/keys/:keyId/activate', {
    preHandler: recoveryKeyWriteGuard,
    schema: {
      tags: ['e2ee-recovery'], params: RecoveryKeyParams, body: ActivateEnterpriseRecoveryKeyRequestSchema,
      response: { 200: EnterpriseRecoveryKeySchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    let evidenceDigest;
    try { evidenceDigest = decodeBase64Url(req.body.ceremonyEvidenceDigest, { exact: 32 }); }
    catch { return badRequest(reply, '企业恢复仪式证据摘要格式无效'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockEnterpriseRecoveryCoverage(tx);
        await lockEnterpriseRecoveryAdministration(tx);
        const key = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, req.params.keyId)).for('update').limit(1))[0];
        if (!key || key.status !== 'staged') throw new RecoveryKeyConflictError('企业恢复公钥尚未完成双人审批');
        if (!Buffer.from(key.ceremonyEvidenceDigest).equals(evidenceDigest)) {
          throw new RecoveryKeyConflictError('企业恢复仪式证据摘要不匹配');
        }
        const readiness = await enterpriseRecoveryReadinessDto(tx);
        if (!readiness.ready) {
            throw new RecoveryKeyConflictError('至少需要两名已准备的实名 OIDC 管理员才能启用企业恢复');
        }
        const previous = await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.status, 'active'))
          .orderBy(asc(enterpriseRecoveryKeys.id)).for('update');
        const previousIds = previous.map((row) => row.id);
        const now = new Date();
        if (previousIds.length) {
          await tx.select({ id: enterpriseRecoveryRequests.id }).from(enterpriseRecoveryRequests)
            .where(and(
              inArray(enterpriseRecoveryRequests.recoveryKeyId, previousIds),
              inArray(enterpriseRecoveryRequests.status, ['pending', 'approved']),
            ))
            .orderBy(asc(enterpriseRecoveryRequests.id)).for('update');
          await tx.update(enterpriseRecoveryRequests).set({
            status: 'cancelled', cancelledAt: now, lastErrorCode: 'recovery_key_rotated',
          }).where(and(
            inArray(enterpriseRecoveryRequests.recoveryKeyId, previousIds),
            inArray(enterpriseRecoveryRequests.status, ['pending', 'approved']),
          ));
          const previousCases = await tx.select({
            id: enterpriseRecoveryCases.id,
            accountResetRequestId: enterpriseRecoveryCases.accountResetRequestId,
          }).from(enterpriseRecoveryCases).where(and(
            inArray(enterpriseRecoveryCases.recoveryKeyId, previousIds),
            inArray(enterpriseRecoveryCases.status, [
              'waiting_for_target',
              'pending_approval',
              'approved',
              'processing',
            ]),
          )).orderBy(asc(enterpriseRecoveryCases.id)).for('update');
          const resetIds = previousCases
            .map((recoveryCase) => recoveryCase.accountResetRequestId)
            .filter((requestId): requestId is string => Boolean(requestId));
          if (resetIds.length) {
            await tx.update(accountCryptoResetRequests).set({
              status: 'cancelled',
              cancelledAt: now,
              lastErrorCode: 'recovery_key_rotated',
            }).where(and(
              inArray(accountCryptoResetRequests.id, resetIds),
              inArray(accountCryptoResetRequests.status, ['pending', 'approved']),
            ));
          }
          if (previousCases.length) {
            await tx.update(enterpriseRecoveryCases).set({
              status: 'cancelled',
              cancelledAt: now,
              lastErrorCode: 'recovery_key_rotated',
            }).where(inArray(enterpriseRecoveryCases.id, previousCases.map((recoveryCase) => recoveryCase.id)));
          }
        }
        const states = await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.storageMode, 'e2ee'))
          .orderBy(asc(vaultCryptoStates.vaultId)).for('update');
        const coveredRows = states.length ? await tx.select({
          vaultId: vaultKeyEnvelopes.vaultId,
          keyEpoch: vaultKeyEnvelopes.keyEpoch,
        })
          .from(vaultKeyEnvelopes)
          .where(and(
            inArray(vaultKeyEnvelopes.vaultId, states.map((state) => state.vaultId)),
            eq(vaultKeyEnvelopes.recipientRecoveryKeyId, key.id),
            eq(vaultKeyEnvelopes.status, 'active'),
            isNotNull(vaultKeyEnvelopes.signerUserId),
          )) : [];
        const coveredEpochs = new Set(coveredRows.map((row) => `${row.vaultId}:${row.keyEpoch}`));
        if (previousIds.length > 0 && states.some((state) => (
          !state.activeEpoch || !coveredEpochs.has(`${state.vaultId}:${state.activeEpoch}`)
        ))) {
          throw new RecoveryKeyConflictError('仍有密码库尚未分发新的企业恢复公钥');
        }
        for (const row of previous) {
          await tx.update(enterpriseRecoveryKeys).set({ status: 'retired', retiredAt: now })
            .where(eq(enterpriseRecoveryKeys.id, row.id));
        }
        const activated = (await tx.update(enterpriseRecoveryKeys).set({ status: 'active' })
          .where(and(eq(enterpriseRecoveryKeys.id, key.id), eq(enterpriseRecoveryKeys.status, 'staged')))
          .returning())[0];
        if (!activated) throw new RecoveryKeyConflictError('企业恢复公钥状态已经变化');
        if (previousIds.length) {
          await tx.update(vaultKeyEnvelopes).set({
            status: 'revoked', revokedAt: now, revocationReason: 'recovery_key_rotated',
          }).where(and(
            inArray(vaultKeyEnvelopes.recipientRecoveryKeyId, previousIds),
            eq(vaultKeyEnvelopes.status, 'active'),
          ));
        }
        if (previousIds.length) {
          for (const state of states) {
            const rekey = await ensureMembershipRekeyTask(
              tx,
              state.vaultId,
              req.user.id,
              null,
              now,
              'device_compromise',
            );
            collect(await recordSyncEvent(tx, {
              type: 'vault.rekey_required',
              vaultId: state.vaultId,
              itemId: null,
              payload: { pendingEpoch: rekey.toEpoch, taskId: rekey.id },
            }));
          }
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.key.activate',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryKeyDto(tx, activated) };
      }, commandIdentity('recovery.key.activate', { keyId: req.params.keyId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryKeyConflictError) return conflict(reply, error.message);
      throw error;
    }
  });

  r.get('/api/v2/recovery/requests', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-recovery'], response: { 200: z.array(EnterpriseRecoveryRequestSchema), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req) => {
    await expireEnterpriseRecoveryRequests(db);
    const rows = req.user.isLocalPlatformAdmin
      ? await db.select().from(enterpriseRecoveryRequests).orderBy(desc(enterpriseRecoveryRequests.createdAt))
      : await db.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.targetUserId, req.user.id))
          .orderBy(desc(enterpriseRecoveryRequests.createdAt));
    return Promise.all(rows.map((row) => recoveryRequestDto(db, row)));
  });

  r.post('/api/v2/recovery/requests/:requestId/cancel', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: RecoveryParams,
      body: CancelEnterpriseRecoveryRequestSchema,
      response: { 200: EnterpriseRecoveryRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    let requestDigest;
    try { requestDigest = decodeBase64Url(req.body.requestDigest, { exact: 32 }); }
    catch { return badRequest(reply, '恢复请求摘要格式无效'); }
    try {
      const result = await runCommand(
        db,
        bus,
        audit,
        req.user.id,
        req.body.idempotencyKey,
        async (tx) => {
          await expireEnterpriseRecoveryRequests(tx);
          const request = (await tx.select().from(enterpriseRecoveryRequests)
            .where(eq(enterpriseRecoveryRequests.id, req.params.requestId)).for('update').limit(1))[0];
          if (!request) throw new RecoveryRequestError(404, '恢复请求不存在');
          const canCancel = request.targetUserId === req.user.id
            || request.createdByUserId === req.user.id
            || await hasLocalPlatformAdminRole(tx, req.user.id);
          if (!canCancel) throw new RecoveryRequestError(403, '你没有取消这次恢复申请的权限');
          if (!Buffer.from(request.requestDigest).equals(requestDigest)) {
            throw new RecoveryRequestError(409, '恢复请求已经变化，请刷新后重试');
          }
          if (!['pending', 'approved'].includes(request.status)) {
            throw new RecoveryRequestError(409, '这次恢复申请已经结束，刷新后可查看最新状态');
          }
          const cancelled = (await tx.update(enterpriseRecoveryRequests).set({
            status: 'cancelled',
            cancelledAt: new Date(),
            lastErrorCode: 'cancelled_by_user',
          }).where(eq(enterpriseRecoveryRequests.id, request.id)).returning())[0]!;
          await appendAudit(tx, audit, {
            actorUserId: req.user.id,
            action: 'recovery.request.cancel',
            vaultId: request.vaultId,
            success: true,
            details: {},
          });
          return { statusCode: 200, response: await recoveryRequestDto(tx, cancelled) };
        },
        commandIdentity('recovery.request.cancel', { requestId: req.params.requestId, ...req.body }),
      );
      return reply.code(200).send(result.response);
    } catch (error) {
      return sendRecoveryRequestError(reply, error);
    }
  });

  r.get('/api/v2/recovery/candidates', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee-recovery'],
      response: { 200: z.array(EnterpriseRecoveryCandidateSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!req.user.isLocalPlatformAdmin) return forbidden(reply, '只有本地授权的系统管理员可以查看企业恢复候选');
    const candidates = await listPersonalVaultRecoveryCandidates(db);
    reply.header('cache-control', 'no-store');
    return candidates.map((candidate) => ({
      vaultId: candidate.vault.id,
      targetUserId: candidate.user.id,
      targetDisplayName: candidate.user.displayName,
      targetUsername: candidate.user.username,
      targetDeviceId: candidate.targetDevice.id,
      targetEncryptionPublicKey: encodeBase64Url(candidate.profile.publicEncryptionKey),
      targetKeyVersion: candidate.profile.cryptoGeneration,
      targetCapability: 'full' as const,
      reason: 'personal_owner_missing_current_full_envelope' as const,
    }));
  });

  r.get('/api/v2/recovery/requests/:requestId', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-recovery'], params: RecoveryParams, response: { 200: EnterpriseRecoveryRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    await expireEnterpriseRecoveryRequests(db);
    const row = (await db.select().from(enterpriseRecoveryRequests)
      .where(eq(enterpriseRecoveryRequests.id, req.params.requestId)).limit(1))[0];
    if (!row) return reply.code(404).send(notFoundBody('恢复请求不存在') as never);
    if (!req.user.isLocalPlatformAdmin && row.targetUserId !== req.user.id) return forbidden(reply, '没有查看该恢复请求的权限');
    return recoveryRequestDto(db, row);
  });

  r.get('/api/v2/recovery/requests/:requestId/package', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-recovery'], params: RecoveryParams, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    await expireEnterpriseRecoveryRequests(db);
    const request = (await db.select().from(enterpriseRecoveryRequests)
      .where(eq(enterpriseRecoveryRequests.id, req.params.requestId)).limit(1))[0];
    if (!request) return reply.code(404).send(notFoundBody('恢复请求不存在') as never);
    if (!req.user.isLocalPlatformAdmin && request.targetUserId !== req.user.id) {
      return forbidden(reply, '没有下载该恢复请求包的权限');
    }
    if (request.status !== 'approved') {
      return conflict(reply, request.status === 'expired'
        ? '这次恢复申请已过期，请联系管理员重新发起'
        : '恢复申请尚未完成两人确认，或已经结束');
    }
    const currentCapability = await resolveAuthorizedVaultCapability(
      db,
      request.vaultId,
      request.targetUserId,
    );
    if (!recoveryCapabilityStillAuthorized(request.targetCapability, currentCapability)) {
      return conflict(reply, '目标用户当前已无权恢复该范围，请重新核对成员权限');
    }
    const [state, recoveryKey, targetProfile] = await Promise.all([
      db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, request.vaultId)).limit(1),
      db.select().from(enterpriseRecoveryKeys).where(eq(enterpriseRecoveryKeys.id, request.recoveryKeyId)).limit(1),
      getCryptoProfile(db, request.targetUserId),
    ]);
    if (
      !state[0]?.activeEpoch
      || state[0].activeEpoch !== request.keyEpoch
      || !recoveryKey[0]
      || !targetProfile
    ) return conflict(reply, '密码库密钥或恢复对象已经变化，请重新发起本次恢复');
    const header = (await db.select().from(encryptedVaultHeaders).where(and(
      eq(encryptedVaultHeaders.vaultId, request.vaultId),
      eq(encryptedVaultHeaders.keyEpoch, request.keyEpoch),
      eq(encryptedVaultHeaders.headerVersion, state[0].activeHeaderVersion),
    )).limit(1))[0];
    if (!header) return conflict(reply, '当前密码库缺少绑定到活动密钥版本的加密头');
    const envelopeRow = (await db.select({
      envelope: vaultKeyEnvelopes,
    }).from(vaultKeyEnvelopes)
      .where(and(
        eq(vaultKeyEnvelopes.vaultId, request.vaultId),
        eq(vaultKeyEnvelopes.keyEpoch, request.keyEpoch),
        eq(vaultKeyEnvelopes.recipientRecoveryKeyId, recoveryKey[0].id),
        eq(vaultKeyEnvelopes.status, 'active'),
        isNotNull(vaultKeyEnvelopes.signerUserId),
      )).limit(1))[0];
    if (!envelopeRow?.envelope.signerUserId
      || !envelopeRow.envelope.signerKeyVersion
      || !envelopeRow.envelope.signerPublicKey
    ) return conflict(reply, '该密码库的恢复保护版本较旧，请由拥有者刷新保护后再试');
    return {
      protocol: 'lm-e2ee-v1',
      kind: 'enterprise-recovery-request-package',
      request: await recoveryRequestDto(db, request),
      activeEpoch: request.keyEpoch,
      recoveryKey: await recoveryKeyDto(db, recoveryKey[0]),
      recoveryEnvelope: toEnvelopeDto(envelopeRow.envelope, {
        userId: envelopeRow.envelope.signerUserId,
        keyVersion: envelopeRow.envelope.signerKeyVersion,
      }),
      trustedSigner: {
        userId: envelopeRow.envelope.signerUserId,
        keyVersion: envelopeRow.envelope.signerKeyVersion,
        signingPublicKey: encodeBase64Url(envelopeRow.envelope.signerPublicKey),
      },
      encryptedHeader: {
        vaultId: header.vaultId,
        version: header.headerVersion,
        keyEpoch: header.keyEpoch,
        blob: encodeCipherBlob(header.nonce, header.ciphertext),
        signature: encodeBase64Url(header.signature),
        updatedAt: header.createdAt.toISOString(),
        updatedBy: header.createdByDeviceId,
      },
      targetProfile: {
        userId: targetProfile.userId,
        keyVersion: targetProfile.cryptoGeneration,
        encryptionPublicKey: encodeBase64Url(targetProfile.publicEncryptionKey),
        signingPublicKey: encodeBase64Url(targetProfile.publicSigningKey),
      },
    };
  });

  r.post('/api/v2/recovery/requests', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-recovery'], body: CreateEnterpriseRecoveryRequestSchema, response: { 201: EnterpriseRecoveryRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    if (!req.user.isLocalPlatformAdmin) return forbidden(reply, '只有本地授权的系统管理员可以发起企业恢复');
    const [recoveryKey, state, targetDevice, targetProfile, resetProvenance, targetCapability] = await Promise.all([
      db.select().from(enterpriseRecoveryKeys).where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1),
      db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, req.body.vaultId)).limit(1),
      getActiveDevice(db, req.body.targetUserId, req.body.targetDeviceId),
      getCryptoProfile(db, req.body.targetUserId),
      req.body.reason === 'account_reset' && req.body.accountResetRequestId
        ? db.select({ request: accountCryptoResetRequests, vaultId: accountCryptoResetVaults.vaultId })
            .from(accountCryptoResetRequests)
            .innerJoin(accountCryptoResetVaults, eq(
              accountCryptoResetVaults.requestId,
              accountCryptoResetRequests.id,
            ))
            .where(and(
              eq(accountCryptoResetRequests.id, req.body.accountResetRequestId),
              eq(accountCryptoResetRequests.targetUserId, req.body.targetUserId),
              eq(accountCryptoResetRequests.status, 'activated'),
              eq(accountCryptoResetVaults.vaultId, req.body.vaultId),
            )).limit(1)
        : Promise.resolve([]),
      resolveAuthorizedVaultCapability(db, req.body.vaultId, req.body.targetUserId),
    ]);
    if (!recoveryKey[0]) return conflict(reply, '尚未登记企业恢复公钥');
    if (!state[0] || state[0].storageMode !== 'e2ee' || !state[0].activeEpoch) return conflict(reply, '该密码库尚未启用零知识加密');
    const reset = resetProvenance[0]?.request;
    const hasValidResetProvenance = req.body.reason === 'account_reset'
      && reset
      && reset.candidateDeviceId === req.body.targetDeviceId
      && reset.newCryptoGeneration === req.body.targetKeyVersion;
    if (!targetDevice || !targetProfile || !targetCapability ||
      (req.body.reason === 'account_reset' && !hasValidResetProvenance)) {
      return badRequest(reply, '目标用户、目标设备、当前成员权限或账户重置凭据不具备该密码库的恢复资格');
    }
    let targetEncryptionPublicKey;
    try { targetEncryptionPublicKey = decodeBase64Url(req.body.targetEncryptionPublicKey, { exact: 32 }); }
    catch { return badRequest(reply, '目标设备公钥格式无效'); }
    if (!Buffer.from(targetProfile.publicEncryptionKey).equals(targetEncryptionPublicKey)) {
      return badRequest(reply, '目标用户加密公钥已经变化');
    }
    const id = randomUUID();
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + 24 * 60 * 60_000);
    const requestDigest = recoveryRequestDigest({
      id,
      vaultId: req.body.vaultId,
      activeEpoch: state[0].activeEpoch,
      recoveryKeyId: recoveryKey[0].id,
      recoveryKeyFingerprint: recoveryKey[0].keyFingerprint,
      recoveryKeyCreatedAt: recoveryKey[0].createdAt.toISOString(),
      targetUserId: req.body.targetUserId,
      targetDeviceId: req.body.targetDeviceId,
      targetEncryptionPublicKey: req.body.targetEncryptionPublicKey,
      targetKeyVersion: targetProfile.cryptoGeneration,
      targetCapability,
      reason: req.body.reason,
      accountResetRequestId: req.body.accountResetRequestId ?? null,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    });
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryCoverage(tx);
        await lockEnterpriseRecoveryAdministration(tx);
        await lockRecipientSets(tx, [req.body.targetUserId]);
        await expireEnterpriseRecoveryRequests(tx);
        if (!await hasLocalPlatformAdminRole(tx, req.user.id)) {
          throw new RecoveryRequestError(403, '你已不再是企业恢复管理员，请刷新页面');
        }
        const lockedKey = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.status, 'active')).for('share').limit(1))[0];
        const lockedState = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.body.vaultId)).for('update').limit(1))[0];
        const [lockedDevice, lockedProfile, lockedCapability] = await Promise.all([
          getActiveDevice(tx, req.body.targetUserId, req.body.targetDeviceId),
          getCryptoProfile(tx, req.body.targetUserId),
          resolveAuthorizedVaultCapability(tx, req.body.vaultId, req.body.targetUserId),
        ]);
        const lockedReset = req.body.reason === 'account_reset' && req.body.accountResetRequestId
          ? (await tx.select({ request: accountCryptoResetRequests })
              .from(accountCryptoResetRequests)
              .innerJoin(accountCryptoResetVaults, eq(
                accountCryptoResetVaults.requestId,
                accountCryptoResetRequests.id,
              ))
              .where(and(
                eq(accountCryptoResetRequests.id, req.body.accountResetRequestId),
                eq(accountCryptoResetRequests.targetUserId, req.body.targetUserId),
                eq(accountCryptoResetRequests.status, 'activated'),
                eq(accountCryptoResetVaults.vaultId, req.body.vaultId),
              )).limit(1))[0]?.request
          : null;
        const lockedResetValid = req.body.reason !== 'account_reset' || Boolean(
          lockedReset
          && lockedReset.candidateDeviceId === req.body.targetDeviceId
          && lockedReset.newCryptoGeneration === req.body.targetKeyVersion,
        );
        if (
          !lockedKey
          || lockedKey.id !== recoveryKey[0]!.id
          || !lockedState?.activeEpoch
          || lockedState.storageMode !== 'e2ee'
          || lockedState.activeEpoch !== state[0]!.activeEpoch
          || !lockedDevice
          || !lockedProfile
          || lockedProfile.cryptoGeneration !== targetProfile.cryptoGeneration
          || !Buffer.from(lockedProfile.publicEncryptionKey).equals(targetEncryptionPublicKey)
          || lockedCapability !== targetCapability
          || !lockedResetValid
        ) throw new RecoveryRequestError(409, '恢复对象、权限或密码库密钥刚刚发生变化，请刷新后重新发起');
        const row = (await tx.insert(enterpriseRecoveryRequests).values({
          id,
          vaultId: req.body.vaultId,
          recoveryKeyId: recoveryKey[0]!.id,
          keyEpoch: state[0]!.activeEpoch!,
          targetUserId: req.body.targetUserId,
          targetDeviceId: req.body.targetDeviceId,
          targetEncryptionPublicKey,
          targetKeyVersion: targetProfile.cryptoGeneration,
          targetCapability,
          reason: req.body.reason,
          accountResetRequestId: req.body.accountResetRequestId ?? null,
          requestDigest,
          createdByUserId: req.user.id,
          createdAt,
          expiresAt,
        }).returning())[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.request.create',
          vaultId: row.vaultId,
          success: true,
          details: {},
        });
        return { statusCode: 201, response: await recoveryRequestDto(tx, row) };
      }, commandIdentity('recovery.request.create', req.body));
      return reply.code(201).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryRequestError) return sendRecoveryRequestError(reply, error);
      if (isUniqueViolation(error)) return conflict(reply, '该用户已有进行中的恢复请求');
      throw error;
    }
  });

  r.post('/api/v2/recovery/requests/:requestId/approve', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-recovery'], params: RecoveryParams, body: ApproveEnterpriseRecoveryRequestSchema, response: { 200: EnterpriseRecoveryRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    if (!req.user.isLocalPlatformAdmin) return forbidden(reply, '只有本地授权的系统管理员可以审批企业恢复');
    let requestDigest;
    try { requestDigest = decodeBase64Url(req.body.requestDigest, { exact: 32 }); }
    catch { return badRequest(reply, '恢复请求摘要格式无效'); }
    const request = (await db.select().from(enterpriseRecoveryRequests)
      .where(eq(enterpriseRecoveryRequests.id, req.params.requestId)).limit(1))[0];
    if (!request) return reply.code(404).send(notFoundBody('恢复请求不存在') as never);
    if (!Buffer.from(request.requestDigest).equals(requestDigest)) return conflict(reply, '恢复请求摘要不匹配');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await expireEnterpriseRecoveryRequests(tx);
        const lockedRequest = (await tx.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.id, request.id)).for('update').limit(1))[0];
        if (!lockedRequest || !['pending', 'approved'].includes(lockedRequest.status)) {
          throw new RecoveryRequestError(409, lockedRequest?.status === 'expired'
            ? '这次恢复申请已过期，请重新发起新的申请'
            : '这次恢复申请已经结束，请刷新查看最新状态');
        }
        if (!Buffer.from(lockedRequest.requestDigest).equals(requestDigest)) {
          throw new RecoveryRequestError(409, '恢复请求摘要不匹配，请刷新后重试');
        }
        const existingApprovals = await tx.select({ userId: enterpriseRecoveryApprovals.approverUserId })
          .from(enterpriseRecoveryApprovals)
          .where(eq(enterpriseRecoveryApprovals.requestId, lockedRequest.id));
        if (existingApprovals.some((approval) => approval.userId === req.user.id)) {
          throw new RecoveryRequestError(409, '你已经确认过这次恢复申请，无需重复操作');
        }
        if (existingApprovals.length >= 2) {
          throw new RecoveryRequestError(409, '这次恢复申请已完成两人确认，请刷新后进入下一步');
        }
        await tx.insert(enterpriseRecoveryApprovals).values({
          requestId: lockedRequest.id,
          approverUserId: req.user.id,
          requestDigest,
        });
        const updated = (await tx.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.id, lockedRequest.id)).limit(1))[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.request.approve',
          vaultId: lockedRequest.vaultId,
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryRequestDto(tx, updated) };
      }, commandIdentity('recovery.request.approve', { requestId: req.params.requestId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryRequestError) return sendRecoveryRequestError(reply, error);
      if (isUniqueViolation(error)) return conflict(reply, '你已经审批过该恢复请求');
      throw error;
    }
  });

  r.post('/api/v2/recovery/requests/:requestId/complete', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-recovery'], params: RecoveryParams, body: CompleteEnterpriseRecoveryRequestSchema, response: { 200: EnterpriseRecoveryRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    let requestDigest; let toolEvidenceDigest;
    try {
      requestDigest = decodeBase64Url(req.body.requestDigest, { exact: 32 });
      toolEvidenceDigest = decodeBase64Url(req.body.toolEvidenceDigest, { exact: 32 });
    } catch { return badRequest(reply, '恢复证据摘要格式无效'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockRecipientSets(tx, [req.user.id]);
        await expireEnterpriseRecoveryRequests(tx);
        const request = (await tx.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.id, req.params.requestId)).for('update').limit(1))[0];
        if (!request) throw new RecoveryRequestError(404, '恢复请求不存在');
        if (request.targetUserId !== req.user.id) {
          throw new RecoveryRequestError(403, '只有目标用户可以确认恢复完成');
        }
        if (request.status !== 'approved') {
          throw new RecoveryRequestError(409, request.status === 'expired'
            ? '这次恢复申请已过期，请联系管理员重新发起'
            : '恢复申请尚未完成两人确认，或已经结束');
        }
        if (!Buffer.from(request.requestDigest).equals(requestDigest)) {
          throw new RecoveryRequestError(409, '恢复请求摘要不匹配');
        }
        const actor = await getActiveDevice(tx, req.user.id, req.body.actorDeviceId);
        const stateRows = await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, request.vaultId)).for('update').limit(1);
        const profile = await getCryptoProfile(tx, req.user.id);
        const currentCapability = await resolveAuthorizedVaultCapability(
          tx,
          request.vaultId,
          req.user.id,
        );
        if (!actor || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== actor.id) {
          throw new RecoveryRequestError(403, '请先用新主密码解锁后再继续');
        }
        if (request.caseId === null && actor.id !== request.targetDeviceId) {
          throw new RecoveryRequestError(403, '这次旧版恢复申请需要在发起时使用的页面完成');
        }
        const state = stateRows[0];
        const envelope = req.body.recoveredEnvelope;
        if (!state?.activeEpoch || state.activeEpoch !== request.keyEpoch || !profile ||
          !recoveryCapabilityStillAuthorized(request.targetCapability, currentCapability) ||
          profile.cryptoGeneration !== request.targetKeyVersion ||
          !Buffer.from(profile.publicEncryptionKey).equals(request.targetEncryptionPublicKey) ||
          envelope.vaultId !== request.vaultId || envelope.epoch !== request.keyEpoch ||
          envelope.recipientKind !== 'user' || envelope.recipientId !== req.user.id ||
          envelope.recipientKeyVersion !== profile.cryptoGeneration || envelope.capability !== request.targetCapability ||
          envelope.signerUserId !== req.user.id || envelope.signerKeyVersion !== profile.cryptoGeneration ||
          !await verifyVaultEnvelope(envelope, encodeBase64Url(profile.publicSigningKey))
        ) throw new RecoveryRequestError(400, '恢复 envelope 的绑定或签名无效');
        if (!await verifyCommandSignature(req.body.targetConfirmationSignature, encodeBase64Url(actor.publicSigningKey), 'recovery.complete', {
          userId: req.user.id,
          vaultId: request.vaultId,
          request: { requestId: request.id, ...without(req.body, 'targetConfirmationSignature') },
        })) throw new RecoveryRequestError(401, '当前登录确认失败，请重新登录后重试');
        let ciphertext; let signature;
        try {
          ciphertext = decodeBase64Url(envelope.sealedKeyBundle, { min: 49, max: 10_000 });
          signature = decodeBase64Url(envelope.signature, { exact: 64 });
        } catch {
          throw new RecoveryRequestError(400, '恢复 envelope 格式无效');
        }
        const now = new Date();
        const insertedEnvelope = (await tx.insert(vaultKeyEnvelopes).values({
          vaultId: request.vaultId,
          keyEpoch: request.keyEpoch,
          recipientKind: 'user',
          accessScope: request.targetCapability,
          recipientUserId: req.user.id,
          recipientKeyFingerprint: publicKeyFingerprint(encodeBase64Url(profile.publicEncryptionKey)),
          authorizationKind: 'recovery',
          authorizationRef: request.id,
          envelopeVersion: profile.cryptoGeneration,
          ciphertext,
          ciphertextDigest: sha256(ciphertext),
          senderDeviceId: actor.id,
          signerUserId: req.user.id,
          signerKeyVersion: profile.cryptoGeneration,
          signerPublicKey: profile.publicSigningKey,
          signature,
          status: 'active',
          activatedAt: now,
        }).returning())[0]!;
        const completed = (await tx.update(enterpriseRecoveryRequests).set({
          status: 'completed',
          completedEnvelopeId: insertedEnvelope.id,
          toolEvidenceDigest,
          completedAt: now,
        }).where(and(
          eq(enterpriseRecoveryRequests.id, request.id),
          eq(enterpriseRecoveryRequests.status, 'approved'),
        )).returning())[0];
        if (!completed) throw new Error('recovery request changed');
        if (request.targetCapability === 'full') {
          const rekey = await ensureMembershipRekeyTask(
            tx,
            state.vaultId,
            req.user.id,
            actor.id,
            now,
            'device_compromise',
          );
          collect(await recordSyncEvent(tx, {
            type: 'vault.rekey_required',
            vaultId: request.vaultId,
            itemId: null,
            payload: { pendingEpoch: rekey.toEpoch, taskId: rekey.id },
          }));
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.request.complete',
          vaultId: request.vaultId,
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryRequestDto(tx, completed) };
      }, commandIdentity('recovery.request.complete', { requestId: req.params.requestId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof RecoveryRequestError) {
        if (error.statusCode === 400) return badRequest(reply, error.message);
        if (error.statusCode === 401) return unauthorized(reply, error.message);
        if (error.statusCode === 403) return forbidden(reply, error.message);
        if (error.statusCode === 404) return reply.code(404).send(notFoundBody(error.message) as never);
        return conflict(reply, error.message);
      }
      if (isUniqueViolation(error)) return conflict(reply, '目标用户已经持有当前密钥 envelope');
      throw error;
    }
  });
}

async function recoveryKeyDto(db: DbOrTx, row: typeof enterpriseRecoveryKeys.$inferSelect) {
  const [approvals, custody] = await Promise.all([
    db.select({ userId: enterpriseRecoveryKeyApprovals.approverUserId })
      .from(enterpriseRecoveryKeyApprovals)
      .where(eq(enterpriseRecoveryKeyApprovals.recoveryKeyId, row.id))
      .orderBy(asc(enterpriseRecoveryKeyApprovals.approvedAt)),
    db.select({ userId: enterpriseRecoveryCustodyShares.administratorUserId })
      .from(enterpriseRecoveryCustodyShares)
      .where(eq(enterpriseRecoveryCustodyShares.recoveryKeyId, row.id))
      .orderBy(asc(enterpriseRecoveryCustodyShares.shareIndex)),
  ]);
  return {
    id: row.id,
    ceremonyId: row.ceremonyId,
    keyFingerprint: row.keyFingerprint,
    publicEncryptionKey: encodeBase64Url(row.publicEncryptionKey),
    threshold: 2 as const,
    shareCount: row.shareCount,
    custodyMode: row.custodyMode,
    custodyUserIds: custody.map((entry) => entry.userId),
    status: row.status,
    ceremonyEvidenceDigest: encodeBase64Url(row.ceremonyEvidenceDigest),
    approvalUserIds: approvals.map((approval) => approval.userId),
    createdAt: row.createdAt.toISOString(),
    retiredAt: row.retiredAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
  };
}

async function enterpriseRecoveryReadinessDto(db: DbOrTx) {
  const assignments = await db.select({
    userId: systemRoleAssignments.userId,
    username: users.username,
    displayName: users.displayName,
    identitySource: users.source,
    active: users.active,
  }).from(systemRoleAssignments)
    .innerJoin(users, eq(users.id, systemRoleAssignments.userId))
    .where(eq(systemRoleAssignments.role, 'platform-admin'))
    .orderBy(asc(users.username), asc(users.id));
  const userIds = assignments.map((assignment) => assignment.userId);
  const [profiles, devices] = userIds.length > 0
    ? await Promise.all([
        db.select({
          userId: userCryptoProfiles.userId,
          generation: userCryptoProfiles.cryptoGeneration,
          encryptionPublicKey: userCryptoProfiles.publicEncryptionKey,
        })
          .from(userCryptoProfiles).where(inArray(userCryptoProfiles.userId, userIds)),
        db.select({
          userId: userDevices.userId,
          generation: userDevices.deviceGeneration,
        }).from(userDevices).where(and(
          inArray(userDevices.userId, userIds),
          eq(userDevices.status, 'active'),
        )),
      ])
    : [[], []];
  const profileByUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  const activeDeviceCountByUser = new Map<string, number>();
  for (const device of devices) {
    if (device.generation !== profileByUser.get(device.userId)?.generation) continue;
    activeDeviceCountByUser.set(device.userId, (activeDeviceCountByUser.get(device.userId) ?? 0) + 1);
  }
  const administrators = assignments.map((assignment) => {
    const profile = profileByUser.get(assignment.userId);
    const hasCryptoProfile = Boolean(profile);
    const activeDeviceCount = activeDeviceCountByUser.get(assignment.userId) ?? 0;
    const ready = assignment.active
      && assignment.identitySource === 'oidc'
      && hasCryptoProfile
      && activeDeviceCount > 0;
    return {
      ...assignment,
      hasCryptoProfile,
      activeDeviceCount,
      cryptoGeneration: profile?.generation ?? null,
      encryptionPublicKey: profile ? encodeBase64Url(profile.encryptionPublicKey) : null,
      ready,
    };
  });
  const readyAdministratorCount = administrators.filter((administrator) => administrator.ready).length;
  return {
    requiredAdministratorCount: 2 as const,
    maximumAdministratorCount: 6 as const,
    administratorCount: administrators.length,
    readyAdministratorCount,
    ready: administrators.length >= 2
      && administrators.length <= 6
      && readyAdministratorCount === administrators.length,
    administrators,
  };
}

function custodyShareDto(row: typeof enterpriseRecoveryCustodyShares.$inferSelect) {
  return {
    recoveryKeyId: row.recoveryKeyId,
    administratorUserId: row.administratorUserId,
    administratorKeyVersion: row.administratorKeyVersion,
    shareIndex: row.shareIndex,
    sealedShare: encodeBase64Url(row.sealedShareCiphertext),
    sealedShareDigest: encodeBase64Url(row.sealedShareDigest),
  };
}

async function validateManagedCustodyRequest(
  db: DbOrTx,
  userId: string,
  request: z.infer<typeof RegisterManagedEnterpriseRecoveryKeyRequestSchema>,
) {
  const readiness = await enterpriseRecoveryReadinessDto(db);
  if (!readiness.ready) {
    return new RecoveryRequestError(409, '请先准备两至六名已设置主密码的企业恢复管理员');
  }
  if (request.key.shareCount !== readiness.administratorCount
    || request.shares.length !== readiness.administratorCount
  ) return new RecoveryRequestError(409, '管理员名单已经变化，请刷新后重新准备');
  const expectedUsers = new Set(readiness.administrators.map((entry) => entry.userId));
  const submittedUsers = new Set(request.shares.map((entry) => entry.administratorUserId));
  const submittedIndexes = new Set(request.shares.map((entry) => entry.shareIndex));
  if (submittedUsers.size !== request.shares.length
    || submittedIndexes.size !== request.shares.length
    || [...expectedUsers].some((entry) => !submittedUsers.has(entry))
    || !expectedUsers.has(userId)
  ) return new RecoveryRequestError(409, '管理员名单已经变化，请刷新后重新准备');

  let publicKey: Buffer;
  let evidenceDigest: Buffer;
  let signature: Buffer;
  try {
    publicKey = decodeBase64Url(request.key.publicEncryptionKey, { exact: 32 });
    evidenceDigest = decodeBase64Url(request.key.ceremonyEvidenceDigest, { exact: 32 });
    signature = decodeBase64Url(request.signature, { exact: 64 });
  } catch {
    return new RecoveryRequestError(400, '企业恢复设置格式不正确');
  }
  if (publicKeyFingerprint(request.key.publicEncryptionKey) !== request.key.keyFingerprint) {
    return new RecoveryRequestError(400, '企业恢复公钥指纹不匹配');
  }
  const expectedDigest = await enterpriseRecoveryCeremonyDigest({
    ceremonyId: request.key.ceremonyId,
    publicKey: request.key.publicEncryptionKey,
    publicKeyFingerprint: request.key.keyFingerprint,
    shareCount: request.key.shareCount,
  });
  if (expectedDigest !== request.key.ceremonyEvidenceDigest) {
    return new RecoveryRequestError(400, '企业恢复设置校验失败');
  }
  const [actor, profile] = await Promise.all([
    getActiveDevice(db, userId, request.actorDeviceId),
    getCryptoProfile(db, userId),
  ]);
  if (!actor || !profile || !await verifyCommandSignature(
    request.signature,
    encodeBase64Url(actor.publicSigningKey),
    'recovery.custody.register',
    { userId, request: without(request, 'signature') },
  )) return new RecoveryRequestError(401, '当前管理员的安全确认无效，请重新解锁后再试');

  const administratorById = new Map(readiness.administrators.map((entry) => [entry.userId, entry]));
  const shares = [];
  for (const share of request.shares) {
    const administrator = administratorById.get(share.administratorUserId);
    if (!administrator?.ready
      || administrator.cryptoGeneration !== share.administratorKeyVersion
      || !administrator.encryptionPublicKey
    ) return new RecoveryRequestError(409, '管理员账号安全信息已经变化，请刷新后重新准备');
    let sealedShareCiphertext: Buffer;
    let sealedShareDigest: Buffer;
    let administratorEncryptionPublicKey: Buffer;
    try {
      sealedShareCiphertext = decodeBase64Url(share.sealedShare, { min: 49, max: 20_000 });
      sealedShareDigest = decodeBase64Url(share.sealedShareDigest, { exact: 32 });
      administratorEncryptionPublicKey = decodeBase64Url(administrator.encryptionPublicKey, { exact: 32 });
    } catch {
      return new RecoveryRequestError(400, '管理员恢复材料格式不正确');
    }
    if (!sha256(sealedShareCiphertext).equals(sealedShareDigest)) {
      return new RecoveryRequestError(400, '管理员恢复材料校验失败');
    }
    shares.push({
      administratorUserId: share.administratorUserId,
      administratorKeyVersion: share.administratorKeyVersion,
      administratorEncryptionPublicKey,
      shareIndex: share.shareIndex,
      sealedShareCiphertext,
      sealedShareDigest,
    });
  }
  return { publicKey, evidenceDigest, signature, shares };
}

async function validateManagedCustodyApproval(
  db: DbOrTx,
  userId: string,
  keyId: string,
  request: z.infer<typeof ApproveEnterpriseRecoveryKeyRequestSchema>,
) {
  if (!request.actorDeviceId || !request.sealedShareDigest || !request.signature) {
    return new RecoveryRequestError(400, '请先在当前浏览器核对自己的恢复材料');
  }
  const [share, actor, profile] = await Promise.all([
    db.select().from(enterpriseRecoveryCustodyShares).where(and(
      eq(enterpriseRecoveryCustodyShares.recoveryKeyId, keyId),
      eq(enterpriseRecoveryCustodyShares.administratorUserId, userId),
    )).limit(1),
    getActiveDevice(db, userId, request.actorDeviceId),
    getCryptoProfile(db, userId),
  ]);
  if (!share[0] || !actor || !profile
    || profile.cryptoGeneration !== share[0].administratorKeyVersion
    || !Buffer.from(profile.publicEncryptionKey).equals(share[0].administratorEncryptionPublicKey)
  ) return new RecoveryRequestError(409, '当前管理员的恢复材料已失效，请重新准备企业恢复');
  let sealedShareDigest: Buffer;
  let signature: Buffer;
  try {
    sealedShareDigest = decodeBase64Url(request.sealedShareDigest, { exact: 32 });
    signature = decodeBase64Url(request.signature, { exact: 64 });
  } catch {
    return new RecoveryRequestError(400, '管理员恢复材料确认格式不正确');
  }
  if (!Buffer.from(share[0].sealedShareDigest).equals(sealedShareDigest)) {
    return new RecoveryRequestError(409, '管理员恢复材料已经变化，请刷新后重试');
  }
  if (!await verifyCommandSignature(
    request.signature,
    encodeBase64Url(actor.publicSigningKey),
    'recovery.custody.approve',
    { userId, request: { keyId, ...without(request, 'signature') } },
  )) return new RecoveryRequestError(401, '当前管理员的安全确认无效，请重新解锁后再试');
  return {
    actorDeviceId: request.actorDeviceId,
    sealedShareDigest,
    signature,
  };
}

async function enterpriseRecoveryCoverageDto(
  db: DbOrTx,
  keyId: string,
  userId: string,
  canSeeAll: boolean,
) {
  const states = await db.select({
    vaultId: vaultCryptoStates.vaultId,
    epoch: vaultCryptoStates.activeEpoch,
  }).from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.storageMode, 'e2ee'))
    .orderBy(asc(vaultCryptoStates.vaultId));
  if (states.length === 0) {
    return {
      keyId,
      totalVaultCount: 0,
      coveredVaultCount: 0,
      complete: true,
      vaults: [],
    };
  }
  const vaultIds = states.map((state) => state.vaultId);
  const [vaultRows, ownerRows, coveredRows] = await Promise.all([
    db.select({ id: vaults.id, kind: vaults.kind, ownerUserId: vaults.ownerUserId })
      .from(vaults).where(inArray(vaults.id, vaultIds)),
    db.select({ vaultId: vaultMemberships.vaultId, userId: vaultMemberships.subjectId })
      .from(vaultMemberships).where(and(
        inArray(vaultMemberships.vaultId, vaultIds),
        eq(vaultMemberships.subjectKind, 'user'),
        eq(vaultMemberships.role, 'owner'),
      )),
    db.select({ vaultId: vaultKeyEnvelopes.vaultId, epoch: vaultKeyEnvelopes.keyEpoch })
      .from(vaultKeyEnvelopes).where(and(
        inArray(vaultKeyEnvelopes.vaultId, vaultIds),
        eq(vaultKeyEnvelopes.recipientRecoveryKeyId, keyId),
        eq(vaultKeyEnvelopes.status, 'active'),
        isNotNull(vaultKeyEnvelopes.signerUserId),
      )),
  ]);
  const ownersByVault = new Map<string, string[]>();
  for (const vault of vaultRows) {
    if (vault.kind === 'personal' && vault.ownerUserId) ownersByVault.set(vault.id, [vault.ownerUserId]);
  }
  for (const owner of ownerRows) {
    const ownerUserIds = ownersByVault.get(owner.vaultId) ?? [];
    if (!ownerUserIds.includes(owner.userId)) ownerUserIds.push(owner.userId);
    ownersByVault.set(owner.vaultId, ownerUserIds);
  }
  for (const ownerUserIds of ownersByVault.values()) ownerUserIds.sort();
  const covered = new Set(coveredRows.map((row) => `${row.vaultId}:${row.epoch}`));
  const visibleVaults = states.map((state) => {
    const ownerUserIds = ownersByVault.get(state.vaultId) ?? [];
    return {
      vaultId: state.vaultId,
      epoch: state.epoch,
      covered: state.epoch !== null && covered.has(`${state.vaultId}:${state.epoch}`),
      canManage: ownerUserIds.includes(userId),
      ownerUserIds,
    };
  }).filter((vault) => canSeeAll || vault.canManage);
  const coveredVaultCount = visibleVaults.filter((vault) => vault.covered).length;
  return {
    keyId,
    totalVaultCount: visibleVaults.length,
    coveredVaultCount,
    complete: coveredVaultCount === visibleVaults.length,
    vaults: visibleVaults,
  };
}

async function recoveryRequestDto(
  db: DbOrTx,
  row: typeof enterpriseRecoveryRequests.$inferSelect,
) {
  const approvals = await db.select({ userId: enterpriseRecoveryApprovals.approverUserId })
    .from(enterpriseRecoveryApprovals)
    .where(eq(enterpriseRecoveryApprovals.requestId, row.id));
  return {
    id: row.id,
    caseId: row.caseId,
    vaultId: row.vaultId,
    recoveryKeyId: row.recoveryKeyId,
    keyEpoch: row.keyEpoch,
    targetUserId: row.targetUserId,
    targetDeviceId: row.targetDeviceId,
    targetEncryptionPublicKey: encodeBase64Url(row.targetEncryptionPublicKey),
    targetKeyVersion: row.targetKeyVersion,
    targetCapability: row.targetCapability,
    accountResetRequestId: row.accountResetRequestId,
    requestDigest: encodeBase64Url(row.requestDigest),
    status: row.status,
    approvalUserIds: approvals.map((approval) => approval.userId),
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    completedAt: row.completedAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
    expiredAt: row.expiredAt?.toISOString() ?? null,
    lastErrorCode: row.lastErrorCode,
  };
}

function recoveryRequestDigest(value: unknown) {
  return sha256(canonicalJson(value as never));
}

function commandIdentity(commandName: string, request: unknown) {
  return { commandName, requestDigest: recoveryRequestDigest(request) };
}

async function expireEnterpriseRecoveryRequests(db: DbOrTx): Promise<void> {
  await db.update(enterpriseRecoveryRequests).set({
    status: 'expired',
    expiredAt: new Date(),
    lastErrorCode: 'request_expired',
  }).where(and(
    inArray(enterpriseRecoveryRequests.status, ['pending', 'approved']),
    lte(enterpriseRecoveryRequests.expiresAt, new Date()),
  ));
}

export function recoveryCapabilityStillAuthorized(
  requested: 'metadata' | 'full',
  current: 'metadata' | 'full' | null,
): boolean {
  return requested === 'metadata' ? current !== null : current === 'full';
}

function without<T extends Record<string, unknown>, K extends keyof T>(input: T, key: K): Omit<T, K> {
  const copy = { ...input };
  delete copy[key];
  return copy;
}

function isUniqueViolation(error: unknown): boolean {
  let current = error;
  const seen = new Set<unknown>();
  while (current && typeof current === 'object' && !seen.has(current)) {
    if ('code' in current && current.code === '23505') return true;
    seen.add(current);
    current = 'cause' in current ? current.cause : null;
  }
  return false;
}

function badRequest(reply: FastifyReply, message: string) {
  return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message } as never);
}

function unauthorized(reply: FastifyReply, message: string) {
  return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message } as never);
}

function forbidden(reply: FastifyReply, message: string) {
  return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message } as never);
}

function conflict(reply: FastifyReply, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', message } as never);
}

function sendRecoveryRequestError(reply: FastifyReply, error: unknown) {
  if (!(error instanceof RecoveryRequestError)) throw error;
  if (error.statusCode === 400) return badRequest(reply, error.message);
  if (error.statusCode === 401) return unauthorized(reply, error.message);
  if (error.statusCode === 403) return forbidden(reply, error.message);
  if (error.statusCode === 404) return reply.code(404).send(notFoundBody(error.message) as never);
  return conflict(reply, error.message);
}

function notFoundBody(message: string) {
  return { statusCode: 404, error: 'Not Found', message };
}
