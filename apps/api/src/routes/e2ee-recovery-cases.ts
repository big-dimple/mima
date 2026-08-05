import { randomUUID } from 'node:crypto';
import { and, asc, desc, eq, inArray, isNotNull, lte } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ApproveEnterpriseRecoveryCaseRequestSchema,
  CancelEnterpriseRecoveryCaseRequestSchema,
  CreateEnterpriseRecoveryCaseRequestSchema,
  EnterpriseRecoveryCasePackageSchema,
  EnterpriseRecoveryCaseSchema,
  EnterpriseRecoveryCaseTransferSchema,
  FinalizeEnterpriseRecoveryCaseRequestSchema,
  UploadEnterpriseRecoveryCaseTransferRequestSchema,
  ZeroKnowledgeApiErrorSchema,
} from '@mima/contracts';
import {
  canonicalJson,
  enterpriseRecoveryTransferEvidenceDigest,
} from '@mima/e2ee';
import {
  accountCryptoResetApprovals,
  accountCryptoResetRequests,
  enterpriseRecoveryApprovals,
  enterpriseRecoveryCaseApprovals,
  enterpriseRecoveryCases,
  enterpriseRecoveryCaseTransfers,
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryKeys,
  enterpriseRecoveryRequests,
  users,
  vaultCryptoStates,
  vaultKeyEnvelopes,
} from '../db/schema.ts';
import { appendAudit, type DbOrTx } from '../services/audit.ts';
import { runCommand } from '../services/commands.ts';
import { userFromRow } from '../plugins/auth.ts';
import {
  applyApprovedAccountCryptoReset,
  AccountCryptoResetActivationConflictError,
} from '../services/account-crypto-reset-activation.ts';
import {
  decodeBase64Url,
  encodeBase64Url,
  getActiveDevice,
  getCryptoProfile,
  sha256,
  toEnvelopeDto,
  verifyCommandSignature,
} from '../services/e2ee.ts';
import {
  lockEnterpriseRecoveryAdministration,
  lockRecipientSets,
} from '../services/recipient-set-lock.ts';
import { hasLocalPlatformAdminRole } from '../services/system-roles.ts';
import { resolveAuthorizedVaultCapability } from '../services/vault-envelope-tasks.ts';

const CaseParams = z.object({ caseId: z.string().uuid() });
const ACTIVE_CASE_STATUSES = [
  'waiting_for_target',
  'pending_approval',
  'approved',
  'processing',
] as const;
const OPEN_ITEM_STATUSES = ['pending', 'approved'] as const;
const TERMINAL_ITEM_STATUSES = [
  'satisfied',
  'completed',
  'cancelled',
  'expired',
  'failed',
] as const;

class RecoveryCaseError extends Error {
  constructor(public statusCode: 400 | 401 | 403 | 404 | 409, message: string) {
    super(message);
  }
}

export function registerE2eeRecoveryCaseRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const readGuard = [app.requireSession];
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.get('/api/v2/recovery/cases', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-recovery'],
      response: { 200: z.array(EnterpriseRecoveryCaseSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await reconcileRecoveryCases(db);
    const canSeeAll = await hasLocalPlatformAdminRole(db, req.user.id);
    const rows = canSeeAll
      ? await db.select().from(enterpriseRecoveryCases).orderBy(desc(enterpriseRecoveryCases.createdAt))
      : await db.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.targetUserId, req.user.id))
          .orderBy(desc(enterpriseRecoveryCases.createdAt));
    reply.header('cache-control', 'no-store');
    return Promise.all(rows.map((row) => recoveryCaseDto(db, row)));
  });

  r.get('/api/v2/recovery/cases/:caseId', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      response: { 200: EnterpriseRecoveryCaseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await reconcileRecoveryCases(db, [req.params.caseId]);
    const row = (await db.select().from(enterpriseRecoveryCases)
      .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).limit(1))[0];
    if (!row) return notFound(reply, '这次恢复协助不存在');
    if (row.targetUserId !== req.user.id && !await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '没有查看这次恢复协助的权限');
    }
    reply.header('cache-control', 'no-store');
    return recoveryCaseDto(db, row);
  });

  r.post('/api/v2/recovery/cases', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      body: CreateEnterpriseRecoveryCaseRequestSchema,
      response: { 201: EnterpriseRecoveryCaseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '只有企业恢复管理员可以发起协助');
    }
    const [target, recoveryKey, profile] = await Promise.all([
      db.select().from(users).where(and(
        eq(users.id, req.body.targetUserId),
        eq(users.active, true),
      )).limit(1),
      db.select().from(enterpriseRecoveryKeys)
        .where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1),
      getCryptoProfile(db, req.body.targetUserId),
    ]);
    if (!target[0]) return badRequest(reply, '没有找到这位在职用户');
    if (!profile) return conflict(reply, '这位用户尚未设置主密码，不需要走恢复流程');
    if (!recoveryKey[0]) return conflict(reply, '公司恢复能力尚未准备完成');
    const now = new Date();
    const row = {
      id: randomUUID(),
      kind: req.body.kind,
      targetUserId: req.body.targetUserId,
      recoveryKeyId: recoveryKey[0].id,
      createdByUserId: req.user.id,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 24 * 60 * 60_000),
    };
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryAdministration(tx);
        await expireRecoveryCases(tx);
        if (!await hasLocalPlatformAdminRole(tx, req.user.id)) {
          throw new RecoveryCaseError(403, '你已不再是企业恢复管理员，请刷新页面');
        }
        const currentKey = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.status, 'active')).for('share').limit(1))[0];
        const currentTarget = (await tx.select().from(users).where(and(
          eq(users.id, row.targetUserId),
          eq(users.active, true),
        )).for('share').limit(1))[0];
        if (!currentKey || currentKey.id !== row.recoveryKeyId || !currentTarget) {
          throw new RecoveryCaseError(409, '恢复对象或公司恢复能力已经变化，请刷新后重试');
        }
        const created = (await tx.insert(enterpriseRecoveryCases).values(row).returning())[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.case.create',
          success: true,
          details: {},
        });
        return { statusCode: 201, response: await recoveryCaseDto(tx, created) };
      }, commandIdentity('recovery.case.create', req.body));
      reply.header('cache-control', 'no-store');
      return reply.code(201).send(result.response);
    } catch (error) {
      return sendCaseError(reply, error, '这位用户已有进行中的恢复协助');
    }
  });

  r.post('/api/v2/recovery/cases/:caseId/target', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      body: FinalizeEnterpriseRecoveryCaseRequestSchema,
      response: { 200: EnterpriseRecoveryCaseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const existing = (await db.select().from(enterpriseRecoveryCases)
      .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).limit(1))[0];
    if (!existing) return notFound(reply, '这次恢复协助不存在');
    if (existing.targetUserId !== req.user.id) return forbidden(reply, '只能为自己的恢复协助设置新主密码');
    if (existing.kind !== req.body.kind) return conflict(reply, '恢复场景已经变化，请刷新后重试');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryAdministration(tx);
        await expireRecoveryCases(tx);
        const recoveryCase = (await tx.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).for('update').limit(1))[0];
        if (!recoveryCase) throw new RecoveryCaseError(404, '这次恢复协助不存在');
        if (recoveryCase.targetUserId !== req.user.id || recoveryCase.kind !== req.body.kind) {
          throw new RecoveryCaseError(403, '这次恢复协助不属于当前账号');
        }
        if (recoveryCase.status !== 'waiting_for_target' || recoveryCase.expiresAt <= new Date()) {
          throw new RecoveryCaseError(409, '这次恢复协助已经进入下一步或已经结束');
        }
        const recoveryKey = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, recoveryCase.recoveryKeyId)).for('share').limit(1))[0];
        if (!recoveryKey || recoveryKey.status !== 'active') {
          throw new RecoveryCaseError(409, '公司恢复能力已经更新，请让管理员重新发起');
        }

        let targetDeviceId: string;
        let targetEncryptionPublicKey: Buffer;
        let targetKeyVersion: number;
        let accountResetRequestId: string | null = null;
        let accountResetDigest: string | null = null;

        if (req.body.kind === 'forgot_password') {
          const reset = (await tx.select().from(accountCryptoResetRequests).where(and(
            eq(accountCryptoResetRequests.id, req.body.accountResetRequestId),
            eq(accountCryptoResetRequests.targetUserId, req.user.id),
            eq(accountCryptoResetRequests.status, 'pending'),
          )).for('update').limit(1))[0];
          if (!reset || reset.caseId !== null) {
            throw new RecoveryCaseError(409, '新主密码准备信息不存在或已用于其他恢复协助');
          }
          const activationPayload = {
            idempotencyKey: req.body.activation.idempotencyKey,
            requestId: reset.id,
            requestDigest: req.body.activation.requestDigest,
          };
          if (req.body.activation.requestDigest !== encodeBase64Url(reset.requestDigest)
            || !await verifyCommandSignature(
              req.body.activation.candidateDevicePossessionSignature,
              encodeBase64Url(reset.candidateDeviceSigningPublicKey),
              'crypto.account_reset.activate.device',
              { userId: req.user.id, request: activationPayload },
            )
            || !await verifyCommandSignature(
              req.body.activation.candidateUserSignature,
              encodeBase64Url(reset.publicSigningKey),
              'crypto.account_reset.activate.user',
              { userId: req.user.id, request: activationPayload },
            )
          ) throw new RecoveryCaseError(401, '新主密码自动启用授权无效，请重新设置');
          let activationDeviceSignature: Buffer;
          let activationUserSignature: Buffer;
          try {
            activationDeviceSignature = decodeBase64Url(
              req.body.activation.candidateDevicePossessionSignature,
              { exact: 64 },
            );
            activationUserSignature = decodeBase64Url(
              req.body.activation.candidateUserSignature,
              { exact: 64 },
            );
          } catch {
            throw new RecoveryCaseError(400, '新主密码自动启用授权格式不正确');
          }
          await tx.update(accountCryptoResetRequests).set({
            caseId: recoveryCase.id,
            recoveryActivationIdempotencyKey: req.body.activation.idempotencyKey,
            recoveryActivationDeviceSignature: activationDeviceSignature,
            recoveryActivationUserSignature: activationUserSignature,
          })
            .where(eq(accountCryptoResetRequests.id, reset.id));
          targetDeviceId = reset.candidateDeviceId;
          targetEncryptionPublicKey = Buffer.from(reset.publicEncryptionKey);
          targetKeyVersion = reset.newCryptoGeneration;
          accountResetRequestId = reset.id;
          accountResetDigest = encodeBase64Url(reset.requestDigest);
        } else {
          let submittedKey: Buffer;
          try { submittedKey = decodeBase64Url(req.body.targetEncryptionPublicKey, { exact: 32 }); }
          catch { throw new RecoveryCaseError(400, '账号安全信息格式不正确'); }
          const [profile, device] = await Promise.all([
            getCryptoProfile(tx, req.user.id),
            getActiveDevice(tx, req.user.id, req.body.targetDeviceId),
          ]);
          if (!profile || !device
            || profile.cryptoGeneration !== req.body.targetKeyVersion
            || !Buffer.from(profile.publicEncryptionKey).equals(submittedKey)
            || device.deviceGeneration !== req.body.targetKeyVersion
          ) throw new RecoveryCaseError(409, '账号安全信息已经变化，请重新登录后再试');
          const unsigned = without(req.body, 'targetSignature');
          if (!await verifyCommandSignature(
            req.body.targetSignature,
            encodeBase64Url(device.publicSigningKey),
            'recovery.case.target',
            { userId: req.user.id, request: { caseId: recoveryCase.id, ...unsigned } },
          )) throw new RecoveryCaseError(401, '账号安全确认失败，请重新登录后再试');
          targetDeviceId = device.id;
          targetEncryptionPublicKey = submittedKey;
          targetKeyVersion = profile.cryptoGeneration;
        }

        await tx.update(enterpriseRecoveryCases).set({
          targetDeviceId,
          targetEncryptionPublicKey,
          targetKeyVersion,
          accountResetRequestId,
        }).where(eq(enterpriseRecoveryCases.id, recoveryCase.id));

        const states = await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.storageMode, 'e2ee'))
          .orderBy(asc(vaultCryptoStates.vaultId));
        const createdAt = new Date();
        const itemDigests: string[] = [];
        for (const state of states) {
          if (!state.activeEpoch) continue;
          const capability = await resolveAuthorizedVaultCapability(tx, state.vaultId, req.user.id);
          if (!capability) continue;
          const id = randomUUID();
          const requestDigest = recoveryRequestDigest({
            id,
            caseId: recoveryCase.id,
            vaultId: state.vaultId,
            activeEpoch: state.activeEpoch,
            recoveryKeyId: recoveryKey.id,
            recoveryKeyFingerprint: recoveryKey.keyFingerprint,
            recoveryKeyCreatedAt: recoveryKey.createdAt.toISOString(),
            targetUserId: req.user.id,
            targetDeviceId,
            targetEncryptionPublicKey: encodeBase64Url(targetEncryptionPublicKey),
            targetKeyVersion,
            targetCapability: capability,
            reason: req.body.kind === 'forgot_password' ? 'account_reset' : 'lost_all_devices',
            accountResetRequestId,
            createdAt: createdAt.toISOString(),
            expiresAt: recoveryCase.expiresAt.toISOString(),
          });
          await tx.insert(enterpriseRecoveryRequests).values({
            id,
            caseId: recoveryCase.id,
            vaultId: state.vaultId,
            recoveryKeyId: recoveryKey.id,
            keyEpoch: state.activeEpoch,
            targetUserId: req.user.id,
            targetDeviceId,
            targetEncryptionPublicKey,
            targetKeyFingerprint: encodeBase64Url(sha256(targetEncryptionPublicKey)),
            targetKeyVersion,
            targetCapability: capability,
            reason: req.body.kind === 'forgot_password' ? 'account_reset' : 'lost_all_devices',
            accountResetRequestId,
            requestDigest,
            createdByUserId: recoveryCase.createdByUserId,
            createdAt,
            expiresAt: recoveryCase.expiresAt,
          });
          itemDigests.push(encodeBase64Url(requestDigest));
        }
        if (itemDigests.length === 0) {
          throw new RecoveryCaseError(409, '当前没有可恢复的既有密码库权限');
        }
        const finalizedAt = new Date();
        const caseDigest = sha256(canonicalJson({
          accountResetDigest,
          caseId: recoveryCase.id,
          expiresAt: recoveryCase.expiresAt.toISOString(),
          itemRequestDigests: [...itemDigests].sort(),
          kind: recoveryCase.kind,
          protocol: 'mima-e2ee-v2',
          recoveryKey: {
            createdAt: recoveryKey.createdAt.toISOString(),
            fingerprint: recoveryKey.keyFingerprint,
            id: recoveryKey.id,
          },
          target: {
            deviceId: targetDeviceId,
            encryptionPublicKey: encodeBase64Url(targetEncryptionPublicKey),
            keyVersion: targetKeyVersion,
            userId: req.user.id,
          },
        } as never));
        const finalized = (await tx.update(enterpriseRecoveryCases).set({
          status: 'pending_approval',
          caseDigest,
          finalizedAt,
        }).where(and(
          eq(enterpriseRecoveryCases.id, recoveryCase.id),
          eq(enterpriseRecoveryCases.status, 'waiting_for_target'),
        )).returning())[0];
        if (!finalized) throw new RecoveryCaseError(409, '这次恢复协助已经变化，请刷新后重试');
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.case.target_finalize',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryCaseDto(tx, finalized) };
      }, commandIdentity('recovery.case.target_finalize', { caseId: req.params.caseId, ...req.body }));
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(result.response);
    } catch (error) {
      return sendCaseError(reply, error, '恢复准备信息已经变化，请刷新后重试');
    }
  });

  r.post('/api/v2/recovery/cases/:caseId/approve', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      body: ApproveEnterpriseRecoveryCaseRequestSchema,
      response: { 200: EnterpriseRecoveryCaseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '只有企业恢复管理员可以确认恢复协助');
    }
    let caseDigest: Buffer;
    try { caseDigest = decodeBase64Url(req.body.caseDigest, { exact: 32 }); }
    catch { return badRequest(reply, '恢复协助信息格式不正确'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockEnterpriseRecoveryAdministration(tx);
        await expireRecoveryCases(tx);
        const recoveryCase = (await tx.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).for('update').limit(1))[0];
        if (!recoveryCase) throw new RecoveryCaseError(404, '这次恢复协助不存在');
        if (!await hasLocalPlatformAdminRole(tx, req.user.id)) {
          throw new RecoveryCaseError(403, '你已不再是企业恢复管理员，请刷新页面');
        }
        if (recoveryCase.targetUserId === req.user.id) {
          throw new RecoveryCaseError(403, '不能确认自己的恢复协助');
        }
        if (recoveryCase.status !== 'pending_approval'
          || !recoveryCase.caseDigest
          || !Buffer.from(recoveryCase.caseDigest).equals(caseDigest)
        ) throw new RecoveryCaseError(409, '这次恢复协助已经变化或不再等待确认');

        const items = await tx.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.caseId, recoveryCase.id))
          .orderBy(asc(enterpriseRecoveryRequests.vaultId));
        for (const item of items.filter((entry) => OPEN_ITEM_STATUSES.includes(entry.status as never))) {
          const [state, capability] = await Promise.all([
            tx.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, item.vaultId)).limit(1),
            resolveAuthorizedVaultCapability(tx, item.vaultId, item.targetUserId),
          ]);
          if (!capability || (item.targetCapability === 'full' && capability !== 'full')) {
            await tx.update(enterpriseRecoveryRequests).set({
              status: 'cancelled',
              cancelledAt: new Date(),
              lastErrorCode: 'authorization_changed',
            }).where(eq(enterpriseRecoveryRequests.id, item.id));
          } else if (!state[0]?.activeEpoch || state[0].activeEpoch !== item.keyEpoch) {
            await tx.update(enterpriseRecoveryRequests).set({
              status: 'expired',
              expiredAt: new Date(),
              lastErrorCode: 'vault_key_changed',
            }).where(eq(enterpriseRecoveryRequests.id, item.id));
          }
        }

        const existingApprovals = await tx.select().from(enterpriseRecoveryCaseApprovals)
          .where(eq(enterpriseRecoveryCaseApprovals.caseId, recoveryCase.id));
        if (existingApprovals.some((entry) => entry.approverUserId === req.user.id)) {
          throw new RecoveryCaseError(409, '你已经确认过这次恢复协助');
        }
        if (existingApprovals.length >= 2) {
          throw new RecoveryCaseError(409, '这次恢复协助已经完成两人确认');
        }
        await tx.insert(enterpriseRecoveryCaseApprovals).values({
          caseId: recoveryCase.id,
          approverUserId: req.user.id,
          caseDigest,
        });

        if (recoveryCase.accountResetRequestId) {
          const reset = (await tx.select().from(accountCryptoResetRequests)
            .where(eq(accountCryptoResetRequests.id, recoveryCase.accountResetRequestId))
            .for('update').limit(1))[0];
          if (!reset || !OPEN_ITEM_STATUSES.includes(reset.status as never)
            || reset.caseId !== recoveryCase.id
          ) throw new RecoveryCaseError(409, '用户的新主密码准备信息已经变化，请重新发起');
          await tx.insert(accountCryptoResetApprovals).values({
            requestId: reset.id,
            approverUserId: req.user.id,
            requestDigest: reset.requestDigest,
          });
          const approvedReset = (await tx.select().from(accountCryptoResetRequests)
            .where(eq(accountCryptoResetRequests.id, reset.id)).limit(1))[0]!;
          if (approvedReset.status === 'approved') {
            if (!approvedReset.recoveryActivationIdempotencyKey
              || !approvedReset.recoveryActivationDeviceSignature
              || !approvedReset.recoveryActivationUserSignature
            ) throw new RecoveryCaseError(409, '新主密码自动启用授权不完整，请重新发起');
            const activationRequestDigest = encodeBase64Url(approvedReset.requestDigest);
            const activationPayload = {
              idempotencyKey: approvedReset.recoveryActivationIdempotencyKey,
              requestId: approvedReset.id,
              requestDigest: activationRequestDigest,
            };
            if (!await verifyCommandSignature(
              encodeBase64Url(approvedReset.recoveryActivationDeviceSignature),
              encodeBase64Url(approvedReset.candidateDeviceSigningPublicKey),
              'crypto.account_reset.activate.device',
              { userId: recoveryCase.targetUserId, request: activationPayload },
            ) || !await verifyCommandSignature(
              encodeBase64Url(approvedReset.recoveryActivationUserSignature),
              encodeBase64Url(approvedReset.publicSigningKey),
              'crypto.account_reset.activate.user',
              { userId: recoveryCase.targetUserId, request: activationPayload },
            )) throw new RecoveryCaseError(409, '新主密码自动启用授权校验失败，请重新发起');
            const target = (await tx.select().from(users).where(and(
              eq(users.id, recoveryCase.targetUserId),
              eq(users.active, true),
            )).limit(1))[0];
            if (!target) throw new RecoveryCaseError(409, '恢复用户已经停用或不存在');
            try {
              await applyApprovedAccountCryptoReset(tx, collect, {
                requestId: approvedReset.id,
                targetUser: userFromRow(target),
              });
            } catch (error) {
              if (error instanceof AccountCryptoResetActivationConflictError) {
                throw new RecoveryCaseError(409, error.message);
              }
              throw error;
            }
            await appendAudit(tx, audit, {
              actorUserId: recoveryCase.targetUserId,
              action: 'crypto.account_reset.activate',
              success: true,
              details: { automatic: true },
            });
          }
        }
        const approvableItems = await tx.select().from(enterpriseRecoveryRequests).where(and(
          eq(enterpriseRecoveryRequests.caseId, recoveryCase.id),
          inArray(enterpriseRecoveryRequests.status, OPEN_ITEM_STATUSES),
        ));
        for (const item of approvableItems) {
          await tx.insert(enterpriseRecoveryApprovals).values({
            requestId: item.id,
            approverUserId: req.user.id,
            requestDigest: item.requestDigest,
          });
        }
        const updated = (await tx.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.id, recoveryCase.id)).limit(1))[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.case.approve',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryCaseDto(tx, updated) };
      }, commandIdentity('recovery.case.approve', { caseId: req.params.caseId, ...req.body }));
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(result.response);
    } catch (error) {
      return sendCaseError(reply, error, '这次恢复协助已经变化或你已经确认过');
    }
  });

  r.post('/api/v2/recovery/cases/:caseId/cancel', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      body: CancelEnterpriseRecoveryCaseRequestSchema,
      response: { 200: EnterpriseRecoveryCaseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryAdministration(tx);
        const recoveryCase = (await tx.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).for('update').limit(1))[0];
        if (!recoveryCase) throw new RecoveryCaseError(404, '这次恢复协助不存在');
        const administrator = await hasLocalPlatformAdminRole(tx, req.user.id);
        if (recoveryCase.targetUserId !== req.user.id && !administrator) {
          throw new RecoveryCaseError(403, '没有取消这次恢复协助的权限');
        }
        if (!ACTIVE_CASE_STATUSES.includes(recoveryCase.status as never)) {
          throw new RecoveryCaseError(409, '这次恢复协助已经结束');
        }
        if (recoveryCase.caseDigest) {
          if (!req.body.caseDigest) throw new RecoveryCaseError(409, '请刷新后再取消这次恢复协助');
          const submitted = decodeBase64Url(req.body.caseDigest, { exact: 32 });
          if (!Buffer.from(recoveryCase.caseDigest).equals(submitted)) {
            throw new RecoveryCaseError(409, '这次恢复协助已经变化，请刷新后重试');
          }
        }
        const now = new Date();
        await tx.update(enterpriseRecoveryRequests).set({
          status: 'cancelled',
          cancelledAt: now,
          lastErrorCode: 'case_cancelled',
        }).where(and(
          eq(enterpriseRecoveryRequests.caseId, recoveryCase.id),
          inArray(enterpriseRecoveryRequests.status, OPEN_ITEM_STATUSES),
        ));
        if (recoveryCase.accountResetRequestId) {
          await tx.update(accountCryptoResetRequests).set({
            status: 'cancelled',
            cancelledAt: now,
            lastErrorCode: 'case_cancelled',
          }).where(and(
            eq(accountCryptoResetRequests.id, recoveryCase.accountResetRequestId),
            inArray(accountCryptoResetRequests.status, OPEN_ITEM_STATUSES),
          ));
        }
        const cancelled = (await tx.update(enterpriseRecoveryCases).set({
          status: 'cancelled',
          cancelledAt: now,
          lastErrorCode: 'case_cancelled',
        }).where(eq(enterpriseRecoveryCases.id, recoveryCase.id)).returning())[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.case.cancel',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryCaseDto(tx, cancelled) };
      }, commandIdentity('recovery.case.cancel', { caseId: req.params.caseId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      return sendCaseError(reply, error, '这次恢复协助已经变化或已经结束');
    }
  });

  r.get('/api/v2/recovery/cases/:caseId/package', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      response: { 200: EnterpriseRecoveryCasePackageSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '只有企业恢复管理员可以下载离线处理包');
    }
    await reconcileRecoveryCases(db, [req.params.caseId]);
    const recoveryCase = (await db.select().from(enterpriseRecoveryCases)
      .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).limit(1))[0];
    if (!recoveryCase) return notFound(reply, '这次恢复协助不存在');
    if (!['approved', 'processing'].includes(recoveryCase.status) || !recoveryCase.caseDigest) {
      return conflict(reply, '这次恢复协助尚未完成两人确认，或已经结束');
    }
    const [recoveryKey, targetProfile, items] = await Promise.all([
      db.select().from(enterpriseRecoveryKeys)
        .where(eq(enterpriseRecoveryKeys.id, recoveryCase.recoveryKeyId)).limit(1),
      getCryptoProfile(db, recoveryCase.targetUserId),
      db.select().from(enterpriseRecoveryRequests).where(and(
        eq(enterpriseRecoveryRequests.caseId, recoveryCase.id),
        eq(enterpriseRecoveryRequests.status, 'approved'),
      )).orderBy(asc(enterpriseRecoveryRequests.vaultId)),
    ]);
    if (!recoveryKey[0] || recoveryKey[0].status !== 'active' || !targetProfile
      || targetProfile.cryptoGeneration !== recoveryCase.targetKeyVersion
      || !recoveryCase.targetEncryptionPublicKey
      || !Buffer.from(targetProfile.publicEncryptionKey).equals(recoveryCase.targetEncryptionPublicKey)
    ) return conflict(reply, '正在等待用户的新主密码准备完成，请稍后刷新');

    const packageItems = [];
    for (const item of items) {
      const currentCapability = await resolveAuthorizedVaultCapability(db, item.vaultId, item.targetUserId);
      if (!currentCapability || (item.targetCapability === 'full' && currentCapability !== 'full')) continue;
      const state = (await db.select().from(vaultCryptoStates)
        .where(eq(vaultCryptoStates.vaultId, item.vaultId)).limit(1))[0];
      if (!state?.activeEpoch || state.activeEpoch !== item.keyEpoch) continue;
      const envelope = (await db.select().from(vaultKeyEnvelopes).where(and(
        eq(vaultKeyEnvelopes.vaultId, item.vaultId),
        eq(vaultKeyEnvelopes.keyEpoch, item.keyEpoch),
        eq(vaultKeyEnvelopes.recipientRecoveryKeyId, recoveryCase.recoveryKeyId),
        eq(vaultKeyEnvelopes.status, 'active'),
        isNotNull(vaultKeyEnvelopes.signerUserId),
      )).limit(1))[0];
      if (!envelope?.signerUserId || !envelope.signerKeyVersion || !envelope.signerPublicKey) continue;
      packageItems.push({
        request: await recoveryRequestDto(db, item),
        activeEpoch: item.keyEpoch,
        recoveryEnvelope: toEnvelopeDto(envelope, {
          userId: envelope.signerUserId,
          keyVersion: envelope.signerKeyVersion,
        }),
        trustedSigner: {
          userId: envelope.signerUserId,
          keyVersion: envelope.signerKeyVersion,
          signingPublicKey: encodeBase64Url(envelope.signerPublicKey),
        },
        targetProfile: {
          userId: targetProfile.userId,
          keyVersion: targetProfile.cryptoGeneration,
          encryptionPublicKey: encodeBase64Url(targetProfile.publicEncryptionKey),
          signingPublicKey: encodeBase64Url(targetProfile.publicSigningKey),
        },
      });
    }
    if (packageItems.length !== items.length) {
      return conflict(reply, '系统仍在等待密码库拥有者自动补齐；暂时没有需要离线处理的内容');
    }
    reply.header('cache-control', 'no-store');
    return {
      protocol: 'mima-e2ee-v2' as const,
      kind: 'enterprise-recovery-case-package' as const,
      caseId: recoveryCase.id,
      caseDigest: encodeBase64Url(recoveryCase.caseDigest),
      recoveryKey: await recoveryKeyDto(db, recoveryKey[0]),
      items: packageItems,
    };
  });

  r.post('/api/v2/recovery/cases/:caseId/transfers', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      body: UploadEnterpriseRecoveryCaseTransferRequestSchema,
      response: { 200: EnterpriseRecoveryCaseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '只有企业恢复管理员可以提交离线处理结果');
    }
    let caseDigest: Buffer;
    try { caseDigest = decodeBase64Url(req.body.caseDigest, { exact: 32 }); }
    catch { return badRequest(reply, '离线处理结果与当前恢复协助不匹配'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await lockEnterpriseRecoveryAdministration(tx);
        await expireRecoveryCases(tx);
        const recoveryCase = (await tx.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).for('update').limit(1))[0];
        if (!recoveryCase) throw new RecoveryCaseError(404, '这次恢复协助不存在');
        if (!await hasLocalPlatformAdminRole(tx, req.user.id)) {
          throw new RecoveryCaseError(403, '你已不再是企业恢复管理员，请刷新页面');
        }
        if (!recoveryCase.caseDigest
          || !Buffer.from(recoveryCase.caseDigest).equals(caseDigest)
          || req.body.transfer.caseId !== recoveryCase.id
          || req.body.transfer.caseDigest !== req.body.caseDigest
          || !['approved', 'processing'].includes(recoveryCase.status)
        ) throw new RecoveryCaseError(409, '离线处理结果与当前恢复协助不匹配');

        const items = await tx.select().from(enterpriseRecoveryRequests)
          .where(eq(enterpriseRecoveryRequests.caseId, recoveryCase.id));
        const recoveryKey = (await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, recoveryCase.recoveryKeyId)).limit(1))[0];
        if (!recoveryKey || recoveryKey.status !== 'active') {
          throw new RecoveryCaseError(409, '公司恢复能力已经更新，请重新发起');
        }
        const byId = new Map(items.map((item) => [item.id, item]));
        const approvedItems = items.filter((item) => item.status === 'approved');
        const seen = new Set<string>();
        for (const offlineResult of req.body.transfer.results) {
          const item = byId.get(offlineResult.requestId);
          if (!item || seen.has(item.id) || item.status !== 'approved'
            || offlineResult.requestDigest !== encodeBase64Url(item.requestDigest)
            || offlineResult.vaultId !== item.vaultId
            || offlineResult.epoch !== item.keyEpoch
            || offlineResult.recoveryKeyId !== item.recoveryKeyId
            || offlineResult.ceremonyId !== recoveryKey.ceremonyId
            || offlineResult.recoveryCeremonyDigest !== encodeBase64Url(recoveryKey.ceremonyEvidenceDigest)
            || offlineResult.targetUserId !== item.targetUserId
            || offlineResult.targetCapability !== item.targetCapability
            || offlineResult.recoveredEnvelope.vaultId !== item.vaultId
            || offlineResult.recoveredEnvelope.epoch !== item.keyEpoch
            || offlineResult.recoveredEnvelope.recipientKind !== 'user'
            || offlineResult.recoveredEnvelope.recipientId !== item.targetUserId
            || offlineResult.recoveredEnvelope.recipientKeyVersion !== item.targetKeyVersion
            || offlineResult.recoveredEnvelope.capability !== item.targetCapability
            || offlineResult.recoveredEnvelope.signerUserId !== item.targetUserId
            || offlineResult.recoveredEnvelope.signerKeyVersion !== item.targetKeyVersion
          ) throw new RecoveryCaseError(409, '离线处理结果包含过期、重复或不属于本次协助的内容');
          const expectedEvidence = await enterpriseRecoveryTransferEvidenceDigest({
            requestId: offlineResult.requestId,
            requestDigest: offlineResult.requestDigest,
            vaultId: offlineResult.vaultId,
            epoch: offlineResult.epoch,
            recoveryKeyId: offlineResult.recoveryKeyId,
            ceremonyId: offlineResult.ceremonyId,
            recoveryCeremonyDigest: offlineResult.recoveryCeremonyDigest,
            targetUserId: offlineResult.targetUserId,
            targetCapability: offlineResult.targetCapability,
            recoveredEnvelope: offlineResult.recoveredEnvelope,
          });
          if (expectedEvidence !== offlineResult.toolEvidenceDigest) {
            throw new RecoveryCaseError(400, '离线处理结果校验失败，请重新处理');
          }
          seen.add(item.id);
        }
        if (seen.size !== approvedItems.length) {
          throw new RecoveryCaseError(409, '离线处理结果不完整，请重新下载处理包后一次完成');
        }
        const transferDigest = sha256(canonicalJson(req.body.transfer as never));
        const existingTransfer = (await tx.select().from(enterpriseRecoveryCaseTransfers)
          .where(eq(enterpriseRecoveryCaseTransfers.caseId, recoveryCase.id)).limit(1))[0];
        if (existingTransfer) {
          if (!Buffer.from(existingTransfer.transferDigest).equals(transferDigest)) {
            throw new RecoveryCaseError(409, '本次协助已经提交过另一份离线处理结果');
          }
        } else {
          await tx.insert(enterpriseRecoveryCaseTransfers).values({
            caseId: recoveryCase.id,
            caseDigest,
            transferDigest,
            transferPayload: req.body.transfer,
            uploadedByUserId: req.user.id,
          });
        }
        if (recoveryCase.status === 'approved') {
          await tx.update(enterpriseRecoveryCases).set({
            status: 'processing',
            processingAt: new Date(),
          }).where(eq(enterpriseRecoveryCases.id, recoveryCase.id));
        }
        const updated = (await tx.select().from(enterpriseRecoveryCases)
          .where(eq(enterpriseRecoveryCases.id, recoveryCase.id)).limit(1))[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'recovery.case.transfer_upload',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await recoveryCaseDto(tx, updated) };
      }, commandIdentity('recovery.case.transfer_upload', { caseId: req.params.caseId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      return sendCaseError(reply, error, '离线处理结果已经提交或不再适用');
    }
  });

  r.get('/api/v2/recovery/cases/:caseId/transfer', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      response: {
        200: EnterpriseRecoveryCaseTransferSchema.nullable(),
        '4xx': ZeroKnowledgeApiErrorSchema,
      },
    },
  }, async (req, reply) => {
    const transfer = await db.transaction(async (tx) => {
      await lockRecipientSets(tx, [req.user.id]);
      await reconcileRecoveryCases(tx, [req.params.caseId]);
      const recoveryCase = (await tx.select().from(enterpriseRecoveryCases)
        .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).for('share').limit(1))[0];
      if (!recoveryCase) throw new RecoveryCaseError(404, '这次恢复协助不存在');
      if (recoveryCase.targetUserId !== req.user.id) {
        throw new RecoveryCaseError(403, '只有接受帮助的用户可以领取恢复结果');
      }
      if (recoveryCase.status !== 'processing') return null;
      const stored = (await tx.select().from(enterpriseRecoveryCaseTransfers)
        .where(eq(enterpriseRecoveryCaseTransfers.caseId, recoveryCase.id)).limit(1))[0];
      if (!stored) return null;
      const approvedItems = await tx.select({ id: enterpriseRecoveryRequests.id })
        .from(enterpriseRecoveryRequests).where(and(
          eq(enterpriseRecoveryRequests.caseId, recoveryCase.id),
          eq(enterpriseRecoveryRequests.status, 'approved'),
        ));
      const approvedIds = new Set(approvedItems.map((item) => item.id));
      const parsed = EnterpriseRecoveryCaseTransferSchema.parse(stored.transferPayload);
      const results = parsed.results.filter((result) => approvedIds.has(result.requestId));
      return results.length > 0 ? { ...parsed, results } : null;
    }).catch((error) => {
      if (error instanceof RecoveryCaseError) return error;
      throw error;
    });
    if (transfer instanceof RecoveryCaseError) {
      return sendCaseError(reply, transfer, '这次恢复协助已经变化');
    }
    reply.header('cache-control', 'no-store');
    return transfer;
  });
}

export async function listEnterpriseRecoveryCases(
  db: DbOrTx,
  userId: string,
  canSeeAll: boolean,
) {
  await reconcileRecoveryCases(db);
  const rows = canSeeAll
    ? await db.select().from(enterpriseRecoveryCases).orderBy(desc(enterpriseRecoveryCases.createdAt))
    : await db.select().from(enterpriseRecoveryCases)
        .where(eq(enterpriseRecoveryCases.targetUserId, userId))
        .orderBy(desc(enterpriseRecoveryCases.createdAt));
  return Promise.all(rows.map((row) => recoveryCaseDto(db, row)));
}

async function reconcileRecoveryCases(db: DbOrTx, caseIds?: string[]): Promise<void> {
  await expireRecoveryCases(db);
  const filters = [inArray(enterpriseRecoveryCases.status, ['approved', 'processing'])];
  if (caseIds?.length) filters.push(inArray(enterpriseRecoveryCases.id, caseIds));
  const cases = await db.select().from(enterpriseRecoveryCases).where(and(...filters));
  for (const recoveryCase of cases) {
    if (recoveryCase.accountResetRequestId) {
      const reset = (await db.select().from(accountCryptoResetRequests)
        .where(eq(accountCryptoResetRequests.id, recoveryCase.accountResetRequestId)).limit(1))[0];
      if (!reset || ['cancelled', 'expired', 'failed'].includes(reset.status)) {
        await db.update(enterpriseRecoveryCases).set({
          status: reset?.status === 'expired' ? 'expired' : 'cancelled',
          expiredAt: reset?.status === 'expired' ? new Date() : null,
          cancelledAt: reset?.status === 'expired' ? null : new Date(),
          lastErrorCode: 'account_reset_unavailable',
        }).where(and(
          eq(enterpriseRecoveryCases.id, recoveryCase.id),
          inArray(enterpriseRecoveryCases.status, ['approved', 'processing']),
        ));
        continue;
      }
      if (reset.status !== 'activated') continue;
    }
    if (recoveryCase.status === 'approved') {
      await db.update(enterpriseRecoveryCases).set({
        status: 'processing',
        processingAt: new Date(),
      }).where(and(
        eq(enterpriseRecoveryCases.id, recoveryCase.id),
        eq(enterpriseRecoveryCases.status, 'approved'),
      ));
    }
    const items = await db.select().from(enterpriseRecoveryRequests)
      .where(eq(enterpriseRecoveryRequests.caseId, recoveryCase.id));
    for (const item of items.filter((entry) => entry.status === 'approved')) {
      const [state, capability, profile, key] = await Promise.all([
        db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, item.vaultId)).limit(1),
        resolveAuthorizedVaultCapability(db, item.vaultId, item.targetUserId),
        getCryptoProfile(db, item.targetUserId),
        db.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, item.recoveryKeyId)).limit(1),
      ]);
      if (!capability || (item.targetCapability === 'full' && capability !== 'full')) {
        await db.update(enterpriseRecoveryRequests).set({
          status: 'cancelled',
          cancelledAt: new Date(),
          lastErrorCode: 'authorization_changed',
        }).where(and(
          eq(enterpriseRecoveryRequests.id, item.id),
          eq(enterpriseRecoveryRequests.status, 'approved'),
        ));
        continue;
      }
      if (!state[0]?.activeEpoch || state[0].activeEpoch !== item.keyEpoch || key[0]?.status !== 'active') {
        await db.update(enterpriseRecoveryRequests).set({
          status: 'expired',
          expiredAt: new Date(),
          lastErrorCode: 'cryptographic_context_changed',
        }).where(and(
          eq(enterpriseRecoveryRequests.id, item.id),
          eq(enterpriseRecoveryRequests.status, 'approved'),
        ));
        continue;
      }
      if (!profile || profile.cryptoGeneration !== item.targetKeyVersion
        || !Buffer.from(profile.publicEncryptionKey).equals(item.targetEncryptionPublicKey)
      ) {
        await db.update(enterpriseRecoveryRequests).set({
          status: 'expired',
          expiredAt: new Date(),
          lastErrorCode: 'recipient_key_changed',
        }).where(and(
          eq(enterpriseRecoveryRequests.id, item.id),
          eq(enterpriseRecoveryRequests.status, 'approved'),
        ));
        continue;
      }
      const delivered = (await db.select({ id: vaultKeyEnvelopes.id }).from(vaultKeyEnvelopes).where(and(
        eq(vaultKeyEnvelopes.vaultId, item.vaultId),
        eq(vaultKeyEnvelopes.keyEpoch, item.keyEpoch),
        eq(vaultKeyEnvelopes.recipientKind, 'user'),
        eq(vaultKeyEnvelopes.recipientUserId, item.targetUserId),
        eq(vaultKeyEnvelopes.envelopeVersion, item.targetKeyVersion),
        eq(vaultKeyEnvelopes.accessScope, item.targetCapability),
        eq(vaultKeyEnvelopes.status, 'active'),
      )).limit(1))[0];
      if (delivered) {
        await db.update(enterpriseRecoveryRequests).set({
          status: 'satisfied',
          completedEnvelopeId: delivered.id,
          completedAt: new Date(),
          lastErrorCode: null,
        }).where(and(
          eq(enterpriseRecoveryRequests.id, item.id),
          eq(enterpriseRecoveryRequests.status, 'approved'),
        ));
      }
    }
    const latestItems = await db.select().from(enterpriseRecoveryRequests)
      .where(eq(enterpriseRecoveryRequests.caseId, recoveryCase.id));
    if (latestItems.length > 0 && latestItems.every((item) => TERMINAL_ITEM_STATUSES.includes(item.status as never))) {
      const skipped = latestItems.some((item) => ['cancelled', 'expired', 'failed'].includes(item.status));
      await db.update(enterpriseRecoveryCases).set({
        status: skipped ? 'completed_with_skips' : 'completed',
        completedAt: new Date(),
      }).where(and(
        eq(enterpriseRecoveryCases.id, recoveryCase.id),
        inArray(enterpriseRecoveryCases.status, ['approved', 'processing']),
      ));
      const transfer = (await db.select().from(enterpriseRecoveryCaseTransfers)
        .where(eq(enterpriseRecoveryCaseTransfers.caseId, recoveryCase.id)).limit(1))[0];
      if (transfer && !transfer.consumedAt) {
        await db.update(enterpriseRecoveryCaseTransfers).set({ consumedAt: new Date() })
          .where(eq(enterpriseRecoveryCaseTransfers.caseId, recoveryCase.id));
      }
    }
  }
}

async function expireRecoveryCases(db: DbOrTx): Promise<void> {
  const now = new Date();
  await db.update(enterpriseRecoveryCases).set({
    status: 'expired',
    expiredAt: now,
    lastErrorCode: 'case_expired',
  }).where(and(
    inArray(enterpriseRecoveryCases.status, ACTIVE_CASE_STATUSES),
    lte(enterpriseRecoveryCases.expiresAt, now),
  ));
  await db.update(enterpriseRecoveryRequests).set({
    status: 'expired',
    expiredAt: now,
    lastErrorCode: 'case_expired',
  }).where(and(
    isNotNull(enterpriseRecoveryRequests.caseId),
    inArray(enterpriseRecoveryRequests.status, OPEN_ITEM_STATUSES),
    lte(enterpriseRecoveryRequests.expiresAt, now),
  ));
}

async function recoveryCaseDto(db: DbOrTx, row: typeof enterpriseRecoveryCases.$inferSelect) {
  const [target, approvals, items, transfers] = await Promise.all([
    db.select({ username: users.username, displayName: users.displayName })
      .from(users).where(eq(users.id, row.targetUserId)).limit(1),
    db.select({ userId: enterpriseRecoveryCaseApprovals.approverUserId })
      .from(enterpriseRecoveryCaseApprovals)
      .where(eq(enterpriseRecoveryCaseApprovals.caseId, row.id))
      .orderBy(asc(enterpriseRecoveryCaseApprovals.approvedAt)),
    db.select().from(enterpriseRecoveryRequests)
      .where(eq(enterpriseRecoveryRequests.caseId, row.id))
      .orderBy(asc(enterpriseRecoveryRequests.vaultId)),
    db.select({ caseId: enterpriseRecoveryCaseTransfers.caseId })
      .from(enterpriseRecoveryCaseTransfers)
      .where(eq(enterpriseRecoveryCaseTransfers.caseId, row.id)).limit(1),
  ]);
  const itemDtos = await Promise.all(items.map((item) => recoveryRequestDto(db, item)));
  return {
    id: row.id,
    kind: row.kind,
    targetUserId: row.targetUserId,
    targetUsername: target[0]?.username ?? row.targetUserId,
    targetDisplayName: target[0]?.displayName ?? row.targetUserId,
    recoveryKeyId: row.recoveryKeyId,
    status: row.status,
    caseDigest: row.caseDigest ? encodeBase64Url(row.caseDigest) : null,
    targetDeviceId: row.targetDeviceId,
    targetKeyVersion: row.targetKeyVersion,
    accountResetRequestId: row.accountResetRequestId,
    approvalUserIds: approvals.map((approval) => approval.userId),
    items: itemDtos,
    resolvedItemCount: items.filter((item) => ['satisfied', 'completed'].includes(item.status)).length,
    skippedItemCount: items.filter((item) => ['cancelled', 'expired', 'failed'].includes(item.status)).length,
    hasOfflineResult: transfers.length > 0,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    finalizedAt: row.finalizedAt?.toISOString() ?? null,
    approvedAt: row.approvedAt?.toISOString() ?? null,
    processingAt: row.processingAt?.toISOString() ?? null,
    completedAt: row.completedAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
    expiredAt: row.expiredAt?.toISOString() ?? null,
    lastErrorCode: row.lastErrorCode,
  };
}

async function recoveryRequestDto(db: DbOrTx, row: typeof enterpriseRecoveryRequests.$inferSelect) {
  const approvals = await db.select({ userId: enterpriseRecoveryApprovals.approverUserId })
    .from(enterpriseRecoveryApprovals)
    .where(eq(enterpriseRecoveryApprovals.requestId, row.id))
    .orderBy(asc(enterpriseRecoveryApprovals.approvedAt));
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

async function recoveryKeyDto(db: DbOrTx, row: typeof enterpriseRecoveryKeys.$inferSelect) {
  const approvals = await db.select({ userId: enterpriseRecoveryKeyApprovals.approverUserId })
    .from(enterpriseRecoveryKeyApprovals)
    .where(eq(enterpriseRecoveryKeyApprovals.recoveryKeyId, row.id))
    .orderBy(asc(enterpriseRecoveryKeyApprovals.approvedAt));
  return {
    id: row.id,
    ceremonyId: row.ceremonyId,
    keyFingerprint: row.keyFingerprint,
    publicEncryptionKey: encodeBase64Url(row.publicEncryptionKey),
    threshold: 2 as const,
    shareCount: 3 as const,
    status: row.status,
    ceremonyEvidenceDigest: encodeBase64Url(row.ceremonyEvidenceDigest),
    approvalUserIds: approvals.map((approval) => approval.userId),
    createdAt: row.createdAt.toISOString(),
    retiredAt: row.retiredAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
  };
}

function recoveryRequestDigest(value: unknown): Buffer {
  return sha256(canonicalJson(value as never));
}

function commandIdentity(commandName: string, request: unknown) {
  return { commandName, requestDigest: sha256(canonicalJson(request as never)) };
}

function without<T extends Record<string, unknown>, K extends keyof T>(input: T, key: K): Omit<T, K> {
  const copy = { ...input };
  delete copy[key];
  return copy;
}

function sendCaseError(reply: FastifyReply, error: unknown, uniqueMessage: string) {
  if (error instanceof RecoveryCaseError) {
    if (error.statusCode === 400) return badRequest(reply, error.message);
    if (error.statusCode === 401) return unauthorized(reply, error.message);
    if (error.statusCode === 403) return forbidden(reply, error.message);
    if (error.statusCode === 404) return notFound(reply, error.message);
    return conflict(reply, error.message);
  }
  if (hasPgCode(error, '23505')) return conflict(reply, uniqueMessage);
  if (hasPgCode(error, '23514') || hasPgCode(error, 'P0001')) {
    return conflict(reply, '恢复状态已经变化，请刷新后重试');
  }
  throw error;
}

function hasPgCode(error: unknown, code: string): boolean {
  let current = error;
  const seen = new Set<unknown>();
  while (current && typeof current === 'object' && !seen.has(current)) {
    if ('code' in current && current.code === code) return true;
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

function notFound(reply: FastifyReply, message: string) {
  return reply.code(404).send({ statusCode: 404, error: 'Not Found', message } as never);
}
