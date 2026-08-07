import { randomUUID } from 'node:crypto';
import { and, asc, desc, eq, inArray, isNotNull, lte, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ApproveEnterpriseRecoveryCaseRequestSchema,
  CancelEnterpriseRecoveryCaseRequestSchema,
  CreateEnterpriseRecoveryCaseRequestSchema,
  EnterpriseRecoveryCasePackageSchema,
  EnterpriseRecoveryCaseApprovalMaterialSchema,
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
  enterpriseRecoveryCaseShareRelays,
  enterpriseRecoveryCases,
  enterpriseRecoveryCaseTransfers,
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryCustodyShares,
  enterpriseRecoveryKeys,
  enterpriseRecoveryRequests,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  users,
  vaults,
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
type RecoveryCaseApprovalRequest = z.infer<typeof ApproveEnterpriseRecoveryCaseRequestSchema>;
type ManagedRecoveryCaseApprovalRequest = Extract<RecoveryCaseApprovalRequest, {
  actorDeviceId: string;
}>;

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
    if (recoveryKey[0].custodyMode === 'administrator_accounts'
      && !await managedRecoveryCustodyIsCurrent(db, recoveryKey[0].id)
    ) return conflict(reply, '管理员名单或恢复保护已经更新，请先在“准备恢复”完成自动设置');
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
        if (!currentKey
          || currentKey.id !== row.recoveryKeyId
          || (currentKey.custodyMode === 'administrator_accounts'
            && !await managedRecoveryCustodyIsCurrent(tx, currentKey.id))
          || !currentTarget
        ) {
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

        if (recoveryKey.custodyMode === 'administrator_accounts'
          && !await managedRecoveryCustodyIsCurrent(tx, recoveryKey.id)
        ) throw new RecoveryCaseError(409, '管理员名单或恢复保护已经更新，请让管理员重新准备');

        const states = await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.storageMode, 'e2ee'))
          .orderBy(asc(vaultCryptoStates.vaultId));
        const createdAt = new Date();
        const recoverable: Array<{
          state: typeof vaultCryptoStates.$inferSelect;
          activeEpoch: number;
          capability: 'metadata' | 'full';
        }> = [];
        for (const state of states) {
          const activeEpoch = state.activeEpoch;
          if (!activeEpoch) continue;
          const capability = await resolveAuthorizedVaultCapability(tx, state.vaultId, req.user.id);
          if (capability) recoverable.push({ state, activeEpoch, capability });
        }
        let resolutionKind: 'recover_access' | 'replace_empty_personal' = 'recover_access';
        let abandonedVaultId: string | null = null;
        let replacementVaultId: string | null = null;
        let emptyVaultWitnessDigest: Buffer | null = null;
        if (req.body.kind === 'forgot_password' && recoverable.length === 1) {
          const witness = await emptyPersonalVaultWitness(
            tx,
            recoverable[0]!.state.vaultId,
            req.user.id,
            true,
          );
          if (witness) {
            resolutionKind = 'replace_empty_personal';
            abandonedVaultId = recoverable[0]!.state.vaultId;
            replacementVaultId = randomUUID();
            emptyVaultWitnessDigest = witness;
          }
        }
        const itemDigests: string[] = [];
        for (const { state, activeEpoch, capability } of resolutionKind === 'recover_access' ? recoverable : []) {
          const id = randomUUID();
          const requestDigest = recoveryRequestDigest({
            id,
            caseId: recoveryCase.id,
            vaultId: state.vaultId,
            activeEpoch,
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
            keyEpoch: activeEpoch,
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
        if (itemDigests.length === 0 && resolutionKind === 'recover_access') {
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
          resolution: resolutionKind === 'replace_empty_personal' ? {
            kind: resolutionKind,
            abandonedVaultId,
            replacementVaultId,
            witnessDigest: encodeBase64Url(emptyVaultWitnessDigest!),
          } : { kind: resolutionKind },
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
          resolutionKind,
          abandonedVaultId,
          replacementVaultId,
          emptyVaultWitnessDigest,
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

  r.get('/api/v2/recovery/cases/:caseId/approval-material', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-recovery'],
      params: CaseParams,
      response: { 200: EnterpriseRecoveryCaseApprovalMaterialSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!await hasLocalPlatformAdminRole(db, req.user.id)) {
      return forbidden(reply, '只有企业恢复管理员可以确认恢复协助');
    }
    const material = await db.transaction(async (tx) => {
      await lockEnterpriseRecoveryAdministration(tx);
      await expireRecoveryCases(tx);
      const recoveryCase = (await tx.select().from(enterpriseRecoveryCases)
        .where(eq(enterpriseRecoveryCases.id, req.params.caseId)).for('share').limit(1))[0];
      if (!recoveryCase) throw new RecoveryCaseError(404, '这次恢复协助不存在');
      if (recoveryCase.targetUserId === req.user.id) {
        throw new RecoveryCaseError(403, '不能确认自己的恢复协助');
      }
      if (recoveryCase.status !== 'pending_approval' || !recoveryCase.caseDigest) {
        throw new RecoveryCaseError(409, '这次恢复协助已经变化或不再等待确认');
      }
      const recoveryKey = (await tx.select().from(enterpriseRecoveryKeys)
        .where(eq(enterpriseRecoveryKeys.id, recoveryCase.recoveryKeyId)).limit(1))[0];
      if (!recoveryKey
        || recoveryKey.status !== 'active'
        || recoveryKey.custodyMode !== 'administrator_accounts'
        || !await managedRecoveryCustodyIsCurrent(tx, recoveryKey.id)
      ) throw new RecoveryCaseError(409, '管理员名单或恢复保护已经更新，请重新发起');
      const approvals = await tx.select().from(enterpriseRecoveryCaseApprovals)
        .where(eq(enterpriseRecoveryCaseApprovals.caseId, recoveryCase.id))
        .orderBy(asc(enterpriseRecoveryCaseApprovals.approvedAt));
      if (approvals.some((entry) => entry.approverUserId === req.user.id)) {
        throw new RecoveryCaseError(409, '你已经确认过这次恢复协助');
      }
      if (approvals.length >= 2) throw new RecoveryCaseError(409, '这次恢复协助已经完成两人确认');
      const [ownShare, profile] = await Promise.all([
        tx.select().from(enterpriseRecoveryCustodyShares).where(and(
          eq(enterpriseRecoveryCustodyShares.recoveryKeyId, recoveryKey.id),
          eq(enterpriseRecoveryCustodyShares.administratorUserId, req.user.id),
        )).limit(1),
        getCryptoProfile(tx, req.user.id),
      ]);
      if (!ownShare[0] || !profile
        || profile.cryptoGeneration !== ownShare[0].administratorKeyVersion
        || !Buffer.from(profile.publicEncryptionKey).equals(ownShare[0].administratorEncryptionPublicKey)
      ) throw new RecoveryCaseError(409, '当前管理员账号中的恢复权限已失效，请重新准备企业恢复');

      const firstApproval = approvals[0] ?? null;
      const relay = firstApproval ? (await tx.select().from(enterpriseRecoveryCaseShareRelays).where(and(
        eq(enterpriseRecoveryCaseShareRelays.caseId, recoveryCase.id),
        eq(enterpriseRecoveryCaseShareRelays.fromUserId, firstApproval.approverUserId),
        eq(enterpriseRecoveryCaseShareRelays.toUserId, req.user.id),
      )).limit(1))[0] : null;
      if (firstApproval
        && recoveryCase.resolutionKind === 'recover_access'
        && (!relay || relay.expiresAt <= new Date() || relay.consumedAt)
      ) {
        throw new RecoveryCaseError(409, '第一位管理员的确认已经失效，请重新发起');
      }
      const recipientRows = firstApproval || recoveryCase.resolutionKind === 'replace_empty_personal'
        ? []
        : await tx.select().from(enterpriseRecoveryCustodyShares).where(and(
            eq(enterpriseRecoveryCustodyShares.recoveryKeyId, recoveryKey.id),
            sql`${enterpriseRecoveryCustodyShares.administratorUserId} <> ${req.user.id}`,
          )).orderBy(asc(enterpriseRecoveryCustodyShares.shareIndex));
      const packageValue = recoveryCase.resolutionKind === 'replace_empty_personal'
        ? null
        : await buildRecoveryCasePackage(tx, recoveryCase, recoveryKey, ['pending', 'approved']);
      return {
        case: await recoveryCaseDto(tx, recoveryCase),
        recoveryKey: await recoveryKeyDto(tx, recoveryKey),
        ownShare: custodyShareDto(ownShare[0]),
        firstApprovalRelay: relay ? {
          fromUserId: relay.fromUserId,
          toUserId: relay.toUserId,
          toKeyVersion: relay.toKeyVersion,
          sealedShare: encodeBase64Url(relay.sealedShareCiphertext),
          sealedShareDigest: encodeBase64Url(relay.sealedShareDigest),
          expiresAt: relay.expiresAt.toISOString(),
        } : null,
        recipients: recipientRows.map((entry) => ({
          userId: entry.administratorUserId,
          keyVersion: entry.administratorKeyVersion,
          encryptionPublicKey: encodeBase64Url(entry.administratorEncryptionPublicKey),
        })),
        package: packageValue,
      };
    }).catch((error) => error instanceof RecoveryCaseError ? error : Promise.reject(error));
    if (material instanceof RecoveryCaseError) return sendCaseError(reply, material, '恢复确认材料不可用');
    reply.header('cache-control', 'no-store');
    return material;
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
    const managedBody = isManagedRecoveryCaseApprovalRequest(req.body) ? req.body : null;
    if (managedBody) {
      if (req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== managedBody.actorDeviceId) {
        return forbidden(reply, '请先用当前设备解锁工作台');
      }
      const actor = await getActiveDevice(db, req.user.id, managedBody.actorDeviceId);
      if (!actor || !await verifyCommandSignature(
        managedBody.signature,
        encodeBase64Url(actor.publicSigningKey),
        'recovery.case.approve',
        { userId: req.user.id, request: { caseId: req.params.caseId, ...without(managedBody, 'signature') } },
      )) return unauthorized(reply, '当前管理员的安全确认无效，请重新解锁后再试');
    }
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
        const recoveryKey = await tx.select().from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.id, recoveryCase.recoveryKeyId)).limit(1);
        if (!recoveryKey[0] || recoveryKey[0].status !== 'active') {
          throw new RecoveryCaseError(409, '企业恢复保护已经更新，请重新发起');
        }
        const managedCase = recoveryKey[0].custodyMode === 'administrator_accounts';
        if (managedCase !== Boolean(managedBody)) {
          throw new RecoveryCaseError(409, '恢复确认方式已经更新，请刷新后重试');
        }
        if (managedCase) {
          if (!managedBody) throw new RecoveryCaseError(409, '请刷新后重新确认这次恢复协助');
          if (!await managedRecoveryCustodyIsCurrent(tx, recoveryKey[0].id)) {
            throw new RecoveryCaseError(409, '管理员名单或恢复保护已经更新，请重新发起');
          }
          const lockedActor = await getActiveDevice(tx, req.user.id, managedBody.actorDeviceId);
          if (!lockedActor || !await verifyCommandSignature(
            managedBody.signature,
            encodeBase64Url(lockedActor.publicSigningKey),
            'recovery.case.approve',
            { userId: req.user.id, request: { caseId: recoveryCase.id, ...without(managedBody, 'signature') } },
          )) throw new RecoveryCaseError(401, '当前管理员的安全确认无效，请重新解锁后再试');
        }

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
        const firstApproval = existingApprovals.length === 0;
        if (managedCase && recoveryCase.resolutionKind === 'replace_empty_personal') {
          if (!managedBody?.replaceEmptyPersonal || managedBody.relays || managedBody.transfer) {
            throw new RecoveryCaseError(409, '空个人库处理方式已经变化，请刷新后重试');
          }
        } else if (managedCase && firstApproval) {
          if (!managedBody?.relays || managedBody.transfer || managedBody.replaceEmptyPersonal) {
            throw new RecoveryCaseError(409, '请刷新后重新确认这次恢复协助');
          }
          await storeFirstApprovalRelays(
            tx,
            recoveryCase,
            recoveryKey[0],
            req.user.id,
            managedBody.actorDeviceId,
            managedBody.signature,
            managedBody.relays,
          );
        } else if (managedCase) {
          if (!managedBody?.transfer || managedBody.relays || managedBody.replaceEmptyPersonal) {
            throw new RecoveryCaseError(409, '请刷新后重新确认这次恢复协助');
          }
          const relay = (await tx.select().from(enterpriseRecoveryCaseShareRelays).where(and(
            eq(enterpriseRecoveryCaseShareRelays.caseId, recoveryCase.id),
            eq(enterpriseRecoveryCaseShareRelays.fromUserId, existingApprovals[0]!.approverUserId),
            eq(enterpriseRecoveryCaseShareRelays.toUserId, req.user.id),
          )).for('update').limit(1))[0];
          if (!relay || relay.expiresAt <= new Date() || relay.consumedAt) {
            throw new RecoveryCaseError(409, '第一位管理员的确认已经失效，请重新发起');
          }
        }
        let approvalSignature: Buffer | null = null;
        if (managedCase) {
          try { approvalSignature = decodeBase64Url(managedBody!.signature, { exact: 64 }); }
          catch { throw new RecoveryCaseError(400, '管理员安全确认格式不正确'); }
        }
        await tx.insert(enterpriseRecoveryCaseApprovals).values({
          caseId: recoveryCase.id,
          approverUserId: req.user.id,
          caseDigest,
          actorDeviceId: managedCase ? managedBody!.actorDeviceId : null,
          approvalSignature,
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
              if (recoveryCase.resolutionKind === 'replace_empty_personal') {
                await abandonEmptyPersonalVault(tx, recoveryCase);
              }
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
            if (recoveryCase.resolutionKind === 'replace_empty_personal') {
              await tx.insert(vaults).values({
                id: recoveryCase.replacementVaultId!,
                kind: 'personal',
                name: '个人库',
                ownerUserId: recoveryCase.targetUserId,
              });
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
        if (managedCase && !firstApproval && recoveryCase.resolutionKind === 'recover_access') {
          await storeManagedRecoveryTransfer(
            tx,
            recoveryCase,
            recoveryKey[0],
            req.user.id,
            managedBody!.transfer!,
            caseDigest,
          );
          await tx.update(enterpriseRecoveryCaseShareRelays).set({ consumedAt: new Date() }).where(and(
            eq(enterpriseRecoveryCaseShareRelays.caseId, recoveryCase.id),
            eq(enterpriseRecoveryCaseShareRelays.toUserId, req.user.id),
          ));
          await tx.update(enterpriseRecoveryCases).set({
            status: 'processing',
            processingAt: new Date(),
          }).where(and(
            eq(enterpriseRecoveryCases.id, recoveryCase.id),
            eq(enterpriseRecoveryCases.status, 'approved'),
          ));
        } else if (managedCase && !firstApproval && recoveryCase.resolutionKind === 'replace_empty_personal') {
          await tx.update(enterpriseRecoveryCases).set({
            status: 'completed',
            completedAt: new Date(),
          }).where(and(
            eq(enterpriseRecoveryCases.id, recoveryCase.id),
            eq(enterpriseRecoveryCases.status, 'approved'),
          ));
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
    if (recoveryKey[0].custodyMode === 'administrator_accounts') {
      return conflict(reply, '当前恢复由两位管理员在浏览器中自动完成，不需要下载案件文件');
    }

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
        if (recoveryKey.custodyMode === 'administrator_accounts') {
          throw new RecoveryCaseError(409, '当前恢复由两位管理员在浏览器中自动完成，不接受文件上传');
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

async function buildRecoveryCasePackage(
  db: DbOrTx,
  recoveryCase: typeof enterpriseRecoveryCases.$inferSelect,
  recoveryKey: typeof enterpriseRecoveryKeys.$inferSelect,
  statuses: Array<'pending' | 'approved'>,
) {
  if (!recoveryCase.caseDigest || recoveryCase.resolutionKind !== 'recover_access') {
    throw new RecoveryCaseError(409, '这次恢复协助不需要处理密码库密钥');
  }
  const [activeTargetProfile, accountReset, items] = await Promise.all([
    recoveryCase.accountResetRequestId
      ? Promise.resolve(null)
      : getCryptoProfile(db, recoveryCase.targetUserId),
    recoveryCase.accountResetRequestId
      ? db.select().from(accountCryptoResetRequests).where(eq(
          accountCryptoResetRequests.id,
          recoveryCase.accountResetRequestId,
        )).limit(1)
      : Promise.resolve([]),
    db.select().from(enterpriseRecoveryRequests).where(and(
      eq(enterpriseRecoveryRequests.caseId, recoveryCase.id),
      inArray(enterpriseRecoveryRequests.status, statuses),
    )).orderBy(asc(enterpriseRecoveryRequests.vaultId)),
  ]);
  const pendingReset = accountReset[0] ?? null;
  const targetProfile = pendingReset ? {
    userId: pendingReset.targetUserId,
    keyVersion: pendingReset.newCryptoGeneration,
    encryptionPublicKey: pendingReset.publicEncryptionKey,
    signingPublicKey: pendingReset.publicSigningKey,
  } : activeTargetProfile ? {
    userId: activeTargetProfile.userId,
    keyVersion: activeTargetProfile.cryptoGeneration,
    encryptionPublicKey: activeTargetProfile.publicEncryptionKey,
    signingPublicKey: activeTargetProfile.publicSigningKey,
  } : null;
  if (!targetProfile
    || targetProfile.userId !== recoveryCase.targetUserId
    || targetProfile.keyVersion !== recoveryCase.targetKeyVersion
    || !recoveryCase.targetEncryptionPublicKey
    || !Buffer.from(targetProfile.encryptionPublicKey).equals(recoveryCase.targetEncryptionPublicKey)
    || (pendingReset && (
      pendingReset.expiresAt <= new Date()
      || !['pending', 'approved'].includes(pendingReset.status)
      || pendingReset.caseId !== recoveryCase.id
    ))
  ) throw new RecoveryCaseError(409, '用户的新主密码准备信息已经变化，请重新发起');
  if (items.length === 0) throw new RecoveryCaseError(409, '当前没有可恢复的既有密码库权限');
  const packageItems = [];
  for (const item of items) {
    const currentCapability = await resolveAuthorizedVaultCapability(db, item.vaultId, item.targetUserId);
    if (!currentCapability || (item.targetCapability === 'full' && currentCapability !== 'full')) {
      throw new RecoveryCaseError(409, '用户的密码库权限已经变化，请刷新后重新发起');
    }
    const state = (await db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, item.vaultId)).limit(1))[0];
    if (!state?.activeEpoch || state.activeEpoch !== item.keyEpoch) {
      throw new RecoveryCaseError(409, '密码库安全状态已经更新，请刷新后重新发起');
    }
    const envelope = (await db.select().from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, item.vaultId),
      eq(vaultKeyEnvelopes.keyEpoch, item.keyEpoch),
      eq(vaultKeyEnvelopes.recipientRecoveryKeyId, recoveryKey.id),
      eq(vaultKeyEnvelopes.status, 'active'),
      isNotNull(vaultKeyEnvelopes.signerUserId),
    )).limit(1))[0];
    if (!envelope?.signerUserId || !envelope.signerKeyVersion || !envelope.signerPublicKey) {
      throw new RecoveryCaseError(409, '这个密码库尚未完成恢复保护，请先在“准备恢复”更新设置');
    }
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
        keyVersion: targetProfile.keyVersion,
        encryptionPublicKey: encodeBase64Url(targetProfile.encryptionPublicKey),
        signingPublicKey: encodeBase64Url(targetProfile.signingPublicKey),
      },
    });
  }
  return {
    protocol: 'mima-e2ee-v2' as const,
    kind: 'enterprise-recovery-case-package' as const,
    caseId: recoveryCase.id,
    caseDigest: encodeBase64Url(recoveryCase.caseDigest),
    recoveryKey: await recoveryKeyDto(db, recoveryKey),
    items: packageItems,
  };
}

async function storeFirstApprovalRelays(
  tx: DbOrTx,
  recoveryCase: typeof enterpriseRecoveryCases.$inferSelect,
  recoveryKey: typeof enterpriseRecoveryKeys.$inferSelect,
  actorUserId: string,
  actorDeviceId: string,
  signature: string,
  relays: NonNullable<ManagedRecoveryCaseApprovalRequest['relays']>,
) {
  const custody = await tx.select().from(enterpriseRecoveryCustodyShares)
    .where(eq(enterpriseRecoveryCustodyShares.recoveryKeyId, recoveryKey.id))
    .orderBy(asc(enterpriseRecoveryCustodyShares.shareIndex));
  const expected = custody.filter((entry) => entry.administratorUserId !== actorUserId);
  const submitted = new Map(relays.map((entry) => [entry.recipientUserId, entry]));
  if (submitted.size !== relays.length
    || submitted.size !== expected.length
    || expected.some((entry) => !submitted.has(entry.administratorUserId))
  ) throw new RecoveryCaseError(409, '管理员名单已经变化，请刷新后重试');
  let relaySignature: Buffer;
  try { relaySignature = decodeBase64Url(signature, { exact: 64 }); }
  catch { throw new RecoveryCaseError(400, '管理员安全确认格式不正确'); }
  for (const recipient of expected) {
    const relay = submitted.get(recipient.administratorUserId)!;
    if (relay.recipientKeyVersion !== recipient.administratorKeyVersion) {
      throw new RecoveryCaseError(409, '管理员账号安全信息已经变化，请刷新后重试');
    }
    let sealedShareCiphertext: Buffer;
    let sealedShareDigest: Buffer;
    try {
      sealedShareCiphertext = decodeBase64Url(relay.sealedShare, { min: 49, max: 20_000 });
      sealedShareDigest = decodeBase64Url(relay.sealedShareDigest, { exact: 32 });
    } catch {
      throw new RecoveryCaseError(400, '管理员账号中的恢复权限格式不正确');
    }
    if (!sha256(sealedShareCiphertext).equals(sealedShareDigest)) {
      throw new RecoveryCaseError(400, '管理员账号中的恢复权限校验失败');
    }
    await tx.insert(enterpriseRecoveryCaseShareRelays).values({
      caseId: recoveryCase.id,
      fromUserId: actorUserId,
      toUserId: recipient.administratorUserId,
      toKeyVersion: recipient.administratorKeyVersion,
      sealedShareCiphertext,
      sealedShareDigest,
      caseDigest: recoveryCase.caseDigest!,
      actorDeviceId,
      relaySignature,
      expiresAt: recoveryCase.expiresAt,
    });
  }
}

async function storeManagedRecoveryTransfer(
  tx: DbOrTx,
  recoveryCase: typeof enterpriseRecoveryCases.$inferSelect,
  recoveryKey: typeof enterpriseRecoveryKeys.$inferSelect,
  actorUserId: string,
  transfer: z.infer<typeof EnterpriseRecoveryCaseTransferSchema>,
  caseDigest: Buffer,
) {
  if (transfer.caseId !== recoveryCase.id
    || transfer.caseDigest !== encodeBase64Url(caseDigest)
    || recoveryKey.status !== 'active'
    || recoveryKey.custodyMode !== 'administrator_accounts'
  ) throw new RecoveryCaseError(409, '恢复结果与当前协助不匹配');
  const items = await tx.select().from(enterpriseRecoveryRequests)
    .where(eq(enterpriseRecoveryRequests.caseId, recoveryCase.id));
  const byId = new Map(items.map((item) => [item.id, item]));
  const approvedItems = items.filter((item) => item.status === 'approved');
  const seen = new Set<string>();
  for (const result of transfer.results) {
    const item = byId.get(result.requestId);
    if (!item || seen.has(item.id) || item.status !== 'approved'
      || result.requestDigest !== encodeBase64Url(item.requestDigest)
      || result.vaultId !== item.vaultId
      || result.epoch !== item.keyEpoch
      || result.recoveryKeyId !== item.recoveryKeyId
      || result.ceremonyId !== recoveryKey.ceremonyId
      || result.recoveryCeremonyDigest !== encodeBase64Url(recoveryKey.ceremonyEvidenceDigest)
      || result.targetUserId !== item.targetUserId
      || result.targetCapability !== item.targetCapability
      || result.recoveredEnvelope.vaultId !== item.vaultId
      || result.recoveredEnvelope.epoch !== item.keyEpoch
      || result.recoveredEnvelope.recipientKind !== 'user'
      || result.recoveredEnvelope.recipientId !== item.targetUserId
      || result.recoveredEnvelope.recipientKeyVersion !== item.targetKeyVersion
      || result.recoveredEnvelope.capability !== item.targetCapability
      || result.recoveredEnvelope.signerUserId !== item.targetUserId
      || result.recoveredEnvelope.signerKeyVersion !== item.targetKeyVersion
    ) throw new RecoveryCaseError(409, '恢复结果包含过期、重复或不属于本次协助的内容');
    const expectedEvidence = await enterpriseRecoveryTransferEvidenceDigest({
      requestId: result.requestId,
      requestDigest: result.requestDigest,
      vaultId: result.vaultId,
      epoch: result.epoch,
      recoveryKeyId: result.recoveryKeyId,
      ceremonyId: result.ceremonyId,
      recoveryCeremonyDigest: result.recoveryCeremonyDigest,
      targetUserId: result.targetUserId,
      targetCapability: result.targetCapability,
      recoveredEnvelope: result.recoveredEnvelope,
    });
    if (expectedEvidence !== result.toolEvidenceDigest) {
      throw new RecoveryCaseError(400, '恢复结果校验失败，请刷新后重试');
    }
    seen.add(item.id);
  }
  if (seen.size !== approvedItems.length) {
    throw new RecoveryCaseError(409, '恢复结果不完整，请刷新后重试');
  }
  const transferDigest = sha256(canonicalJson(transfer as never));
  await tx.insert(enterpriseRecoveryCaseTransfers).values({
    caseId: recoveryCase.id,
    caseDigest,
    transferDigest,
    transferPayload: transfer,
    uploadedByUserId: actorUserId,
  });
}

async function managedRecoveryCustodyIsCurrent(db: DbOrTx, recoveryKeyId: string): Promise<boolean> {
  const assignments = await db.select({
    userId: systemRoleAssignments.userId,
    active: users.active,
    source: users.source,
  }).from(systemRoleAssignments)
    .innerJoin(users, eq(users.id, systemRoleAssignments.userId))
    .where(eq(systemRoleAssignments.role, 'platform-admin'))
    .orderBy(asc(systemRoleAssignments.userId));
  if (assignments.length < 2 || assignments.length > 6
    || assignments.some((entry) => !entry.active || entry.source !== 'oidc')) return false;
  const userIds = assignments.map((entry) => entry.userId);
  const [custody, profiles, devices] = await Promise.all([
    db.select().from(enterpriseRecoveryCustodyShares)
      .where(eq(enterpriseRecoveryCustodyShares.recoveryKeyId, recoveryKeyId)),
    db.select().from(userCryptoProfiles).where(inArray(userCryptoProfiles.userId, userIds)),
    db.select().from(userDevices).where(and(
      inArray(userDevices.userId, userIds),
      eq(userDevices.status, 'active'),
    )),
  ]);
  if (custody.length !== assignments.length) return false;
  const profileByUser = new Map(profiles.map((entry) => [entry.userId, entry]));
  const custodyByUser = new Map(custody.map((entry) => [entry.administratorUserId, entry]));
  return assignments.every((assignment) => {
    const profile = profileByUser.get(assignment.userId);
    const share = custodyByUser.get(assignment.userId);
    return Boolean(profile && share
      && profile.cryptoGeneration === share.administratorKeyVersion
      && Buffer.from(profile.publicEncryptionKey).equals(share.administratorEncryptionPublicKey)
      && devices.some((device) => (
        device.userId === assignment.userId
        && device.deviceGeneration === profile.cryptoGeneration
      )));
  });
}

async function emptyPersonalVaultWitness(
  db: DbOrTx,
  vaultId: string,
  targetUserId: string,
  lock: boolean,
): Promise<Buffer | null> {
  const vault = (await db.select().from(vaults).where(and(
    eq(vaults.id, vaultId),
    eq(vaults.kind, 'personal'),
    eq(vaults.ownerUserId, targetUserId),
  )).for(lock ? 'update' : 'share').limit(1))[0];
  const state = (await db.select().from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.vaultId, vaultId)).for(lock ? 'update' : 'share').limit(1))[0];
  if (!vault || vault.parentVaultId || state?.activeEpoch !== 1 || state.activeHeaderVersion !== 1
    || state.storageMode !== 'e2ee' || state.writeState !== 'open') return null;
  const result = await db.execute(sql`
    SELECT
      (SELECT count(*) FROM items WHERE vault_id = ${vaultId})::text AS item_count,
      (SELECT count(*) FROM encrypted_vault_headers WHERE vault_id = ${vaultId})::text AS header_count,
      (SELECT count(*) FROM vault_key_epochs WHERE vault_id = ${vaultId})::text AS key_epoch_count,
      (SELECT count(*) FROM vaults WHERE parent_vault_id = ${vaultId})::text AS child_count,
      (SELECT count(*) FROM vault_memberships WHERE vault_id = ${vaultId})::text AS membership_count,
      (SELECT count(*) FROM vault_custom_group_roles WHERE vault_id = ${vaultId})::text AS group_role_count,
      (SELECT count(*) FROM legacy_migration_jobs WHERE vault_id = ${vaultId})::text AS migration_count,
      (SELECT count(*) FROM vault_rekey_jobs WHERE vault_id = ${vaultId})::text AS rekey_count,
      (SELECT count(*) FROM account_crypto_reset_vaults WHERE vault_id = ${vaultId})::text AS reset_count,
      (SELECT count(*) FROM enterprise_recovery_requests WHERE vault_id = ${vaultId})::text AS recovery_count,
      (SELECT count(*) FROM vault_envelope_tasks WHERE vault_id = ${vaultId})::text AS envelope_task_count,
      (SELECT count(*) FROM vault_ownership_transfer_requests WHERE vault_id = ${vaultId})::text AS transfer_count,
      (SELECT count(*) FROM encrypted_client_commands WHERE vault_id = ${vaultId})::text AS command_count
  `);
  const counts = result.rows[0] as Record<string, string> | undefined;
  if (!counts || counts.header_count !== '1' || counts.key_epoch_count !== '1') return null;
  const blockingCounts = Object.entries(counts).filter(([name]) => (
    name !== 'header_count' && name !== 'key_epoch_count'
  ));
  if (blockingCounts.some(([, value]) => value !== '0')) return null;
  return sha256(canonicalJson({
    kind: 'empty-personal-vault-witness',
    protocol: 'mima-e2ee-v2',
    targetUserId,
    vaultId,
    state: {
      activeEpoch: state.activeEpoch,
      activeHeaderVersion: state.activeHeaderVersion,
      accessGeneration: state.accessGeneration,
      rowVersion: state.rowVersion,
    },
    counts,
  } as never));
}

async function abandonEmptyPersonalVault(
  tx: DbOrTx,
  recoveryCase: typeof enterpriseRecoveryCases.$inferSelect,
): Promise<void> {
  if (!recoveryCase.abandonedVaultId || !recoveryCase.emptyVaultWitnessDigest) {
    throw new RecoveryCaseError(409, '空个人库处理信息不完整，请重新发起');
  }
  const witness = await emptyPersonalVaultWitness(
    tx,
    recoveryCase.abandonedVaultId,
    recoveryCase.targetUserId,
    true,
  );
  if (!witness || !Buffer.from(recoveryCase.emptyVaultWitnessDigest).equals(witness)) {
    throw new RecoveryCaseError(409, '个人库已经发生变化，系统已停止删除并保留原数据');
  }
  const removed = await tx.delete(vaults).where(and(
    eq(vaults.id, recoveryCase.abandonedVaultId),
    eq(vaults.kind, 'personal'),
    eq(vaults.ownerUserId, recoveryCase.targetUserId),
  )).returning({ id: vaults.id });
  if (!removed[0]) throw new RecoveryCaseError(409, '个人库已经发生变化，系统已停止删除');
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
    resolutionKind: row.resolutionKind,
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

function isManagedRecoveryCaseApprovalRequest(
  request: RecoveryCaseApprovalRequest,
): request is ManagedRecoveryCaseApprovalRequest {
  return 'actorDeviceId' in request;
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
