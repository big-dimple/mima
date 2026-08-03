import { and, asc, desc, eq, inArray } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  AcceptVaultOwnershipTransferRequestSchema,
  CancelVaultOwnershipTransferRequestSchema,
  CompleteVaultEnvelopeTaskRequestSchema,
  CreateVaultOwnershipTransferRequestSchema,
  VaultEnvelopeTaskSchema,
  VaultOwnershipTransferSchema,
} from '@mima/contracts';
import {
  ownershipTransferAcceptanceDigest,
  verifyVaultKeyPossession,
} from '@mima/e2ee';
import {
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultEnvelopeTasks,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaultOwnershipTransferRequests,
  vaults,
} from '../db/schema.ts';
import { getVaultAccess } from '../services/access.ts';
import { appendAudit, type DbOrTx } from '../services/audit.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import {
  decodeBase64Url,
  encodeBase64Url,
  getActiveDevice,
  getCryptoProfile,
  publicKeyFingerprint,
  sha256,
  verifyCommandSignature,
  verifyVaultEnvelope,
} from '../services/e2ee.ts';
import {
  ensureEnvelopeTasks,
  ensureMembershipRekeyTask,
  isEnvelopeTaskAuthorizationActive,
} from '../services/vault-envelope-tasks.ts';
import { lockRecipientSets } from '../services/recipient-set-lock.ts';

const VaultParams = z.object({ vaultId: z.string().uuid() });
const TaskParams = VaultParams.extend({ taskId: z.string().uuid() });
const TaskListQuery = z.object({
  status: z.enum(['pending', 'completed', 'cancelled', 'all']).default('pending'),
});

export function registerE2eeEnvelopeTaskRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();

  r.get('/api/v2/vaults/:vaultId/envelope-tasks', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      querystring: TaskListQuery,
      response: { 200: z.array(VaultEnvelopeTaskSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (access?.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以查看团队访问交付状态');
    const status = req.query.status;
    const rows = await db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, req.params.vaultId),
      ...(status === 'all' ? [] : [eq(vaultEnvelopeTasks.status, status)]),
    )).orderBy(asc(vaultEnvelopeTasks.createdAt), asc(vaultEnvelopeTasks.id));
    reply.header('cache-control', 'no-store');
    return taskDtos(db, rows);
  });

  r.get('/api/v2/envelope-tasks/mine', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee'],
      querystring: TaskListQuery,
      response: { 200: z.array(VaultEnvelopeTaskSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const status = req.query.status;
    const rows = await db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.recipientUserId, req.user.id),
      ...(status === 'all' ? [] : [eq(vaultEnvelopeTasks.status, status)]),
    )).orderBy(asc(vaultEnvelopeTasks.createdAt), asc(vaultEnvelopeTasks.id));
    reply.header('cache-control', 'no-store');
    return taskDtos(db, rows);
  });

  r.get('/api/v2/vaults/:vaultId/ownership-transfer', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      response: { 200: VaultOwnershipTransferSchema.nullable(), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const transfer = (await db.select().from(vaultOwnershipTransferRequests).where(and(
      eq(vaultOwnershipTransferRequests.vaultId, req.params.vaultId),
      eq(vaultOwnershipTransferRequests.status, 'pending'),
    )).limit(1))[0] ?? null;
    if (!transfer) return null;
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (access?.role !== 'owner' && transfer.toOwnerUserId !== req.user.id) {
      return forbidden(reply, '没有查看所有权转移状态的权限');
    }
    reply.header('cache-control', 'no-store');
    return transferDto(db, transfer, null);
  });

  r.post('/api/v2/vaults/:vaultId/ownership-transfer', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: CreateVaultOwnershipTransferRequestSchema,
      response: { 200: VaultOwnershipTransferSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (access?.vault.kind !== 'team' || access.role !== 'owner') {
      return forbidden(reply, '只有团队密码库的拥有者可以转移所有权');
    }
    if (req.body.newOwnerUserId === req.user.id) return badRequest(reply, '新拥有者不能是当前用户');
    const [actor, target] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.actorDeviceId),
      db.select({ id: users.id }).from(users).where(and(
        eq(users.id, req.body.newOwnerUserId),
        eq(users.active, true),
      )).limit(1),
    ]);
    if (!actor || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== actor.id) {
      return locked(reply);
    }
    if (!target[0]) return badRequest(reply, '新拥有者不存在或已经停用');
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'vault.ownership-transfer.create',
      { userId: req.user.id, vaultId: req.params.vaultId, request: unsigned },
    )) return unauthorized(reply, '当前设备无法确认这次所有权转移，请刷新页面后重试');

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockRecipientSets(tx, [req.body.newOwnerUserId]);
        const lockedActor = (await tx.select().from(userDevices).where(and(
          eq(userDevices.id, actor.id),
          eq(userDevices.userId, req.user.id),
          eq(userDevices.status, 'active'),
        )).for('share').limit(1))[0];
        if (!lockedActor || !await verifyCommandSignature(
          req.body.signature,
          encodeBase64Url(lockedActor.publicSigningKey),
          'vault.ownership-transfer.create',
          { userId: req.user.id, vaultId: req.params.vaultId, request: unsigned },
        )) throw new TaskConflictError('当前设备已失效，或转移信息已经变化，请刷新页面后重试');
        const lockedTargetProfile = (await tx.select({
          userId: userCryptoProfiles.userId,
          cryptoGeneration: userCryptoProfiles.cryptoGeneration,
          publicEncryptionKey: userCryptoProfiles.publicEncryptionKey,
        })
          .from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.body.newOwnerUserId))
          .for('share')
          .limit(1))[0];
        const lockedTarget = (await tx.select({ id: users.id }).from(users).where(and(
          eq(users.id, req.body.newOwnerUserId),
          eq(users.active, true),
        )).for('share').limit(1))[0];
        if (!lockedTargetProfile || !lockedTarget) {
          throw new TaskConflictError('新拥有者已经停用或尚未设置主密码');
        }
        const state = (await tx.select().from(vaultCryptoStates).where(
          eq(vaultCryptoStates.vaultId, req.params.vaultId),
        ).for('update').limit(1))[0];
        if (!state?.activeEpoch || state.storageMode !== 'e2ee' ||
          state.accessGeneration !== req.body.expectedAccessGeneration
        ) throw new TaskConflictError('成员权限已经变化，请刷新成员列表后重试');
        if (state.writeState !== 'open') {
          throw new TaskConflictError('密码库正在安全更新，请完成后再转移所有权');
        }
        const activeEpoch = (await tx.select({
          keyPossessionPublicKey: vaultKeyEpochs.keyPossessionPublicKey,
        }).from(vaultKeyEpochs).where(and(
          eq(vaultKeyEpochs.vaultId, state.vaultId),
          eq(vaultKeyEpochs.epoch, state.activeEpoch),
          eq(vaultKeyEpochs.status, 'active'),
        )).for('share').limit(1))[0];
        if (!activeEpoch?.keyPossessionPublicKey) {
          throw new TaskConflictError('当前密码库需要先完成一次安全更新，再转移所有权');
        }
        const currentOwner = (await tx.select().from(vaultMemberships).where(and(
          eq(vaultMemberships.vaultId, state.vaultId),
          eq(vaultMemberships.subjectKind, 'user'),
          eq(vaultMemberships.subjectId, req.user.id),
          eq(vaultMemberships.role, 'owner'),
        )).for('update').limit(1))[0];
        if (!currentOwner) throw new TaskConflictError('你已不再是此密码库的直接拥有者，请刷新成员列表');
        const pendingTransfer = (await tx.select({ id: vaultOwnershipTransferRequests.id })
          .from(vaultOwnershipTransferRequests).where(and(
            eq(vaultOwnershipTransferRequests.vaultId, state.vaultId),
            eq(vaultOwnershipTransferRequests.status, 'pending'),
          )).for('update').limit(1))[0];
        if (pendingTransfer) throw new TaskConflictError('已有待完成的所有权转移');
        const targetMembership = (await tx.select({ role: vaultMemberships.role }).from(vaultMemberships).where(and(
          eq(vaultMemberships.vaultId, state.vaultId),
          eq(vaultMemberships.subjectKind, 'user'),
          eq(vaultMemberships.subjectId, req.body.newOwnerUserId),
        )).limit(1))[0];
        if (targetMembership?.role !== 'viewer' && targetMembership?.role !== 'editor') {
          throw new TaskConflictError('请先把对方作为可查看或可编辑成员加入密码库');
        }
        await ensureEnvelopeTasks(tx, {
          vaultId: state.vaultId,
          keyEpoch: state.activeEpoch,
          authorizationKind: 'direct',
          authorizationRef: req.body.newOwnerUserId,
          recipientUserIds: [req.body.newOwnerUserId],
          capability: 'full',
        });
        const envelopeTask = (await tx.select().from(vaultEnvelopeTasks).where(and(
          eq(vaultEnvelopeTasks.vaultId, state.vaultId),
          eq(vaultEnvelopeTasks.keyEpoch, state.activeEpoch),
          eq(vaultEnvelopeTasks.authorizationKind, 'direct'),
          eq(vaultEnvelopeTasks.authorizationRef, req.body.newOwnerUserId),
          eq(vaultEnvelopeTasks.recipientUserId, req.body.newOwnerUserId),
          eq(vaultEnvelopeTasks.capability, 'full'),
          eq(vaultEnvelopeTasks.expectedProfileGeneration, lockedTargetProfile.cryptoGeneration),
          eq(vaultEnvelopeTasks.status, 'completed'),
        )).orderBy(desc(vaultEnvelopeTasks.createdAt)).limit(1))[0];
        if (!envelopeTask?.completedEnvelopeId) {
          throw new TaskConflictError('系统正在自动准备新拥有者的密码库访问，请稍后重试');
        }
        const targetFingerprint = publicKeyFingerprint(
          encodeBase64Url(lockedTargetProfile.publicEncryptionKey),
        );
        const completedEnvelope = (await tx.select({ id: vaultKeyEnvelopes.id })
          .from(vaultKeyEnvelopes).where(and(
            eq(vaultKeyEnvelopes.id, envelopeTask.completedEnvelopeId),
            eq(vaultKeyEnvelopes.vaultId, state.vaultId),
            eq(vaultKeyEnvelopes.keyEpoch, state.activeEpoch),
            eq(vaultKeyEnvelopes.recipientKind, 'user'),
            eq(vaultKeyEnvelopes.recipientUserId, req.body.newOwnerUserId),
            eq(vaultKeyEnvelopes.recipientKeyFingerprint, targetFingerprint),
            eq(vaultKeyEnvelopes.envelopeVersion, lockedTargetProfile.cryptoGeneration),
            eq(vaultKeyEnvelopes.accessScope, 'full'),
            eq(vaultKeyEnvelopes.authorizationKind, 'direct'),
            eq(vaultKeyEnvelopes.authorizationRef, req.body.newOwnerUserId),
            eq(vaultKeyEnvelopes.status, 'active'),
          )).for('share').limit(1))[0];
        if (!completedEnvelope) {
          throw new TaskConflictError('系统正在自动准备新拥有者的密码库访问，请稍后重试');
        }

        const transfer = (await tx.insert(vaultOwnershipTransferRequests).values({
          vaultId: state.vaultId,
          fromOwnerUserId: req.user.id,
          toOwnerUserId: req.body.newOwnerUserId,
          envelopeTaskId: envelopeTask.id,
          expectedAccessGeneration: state.accessGeneration,
          requestedByDeviceId: lockedActor.id,
          status: 'pending',
        }).returning())[0]!;
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed',
          vaultId: state.vaultId,
          itemId: null,
          payload: { ownershipTransferPending: true },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'vault.ownership_transfer.request',
          vaultId: state.vaultId,
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            transferId: transfer.id,
            rekeyTask: null,
          },
        };
      });
      const transfer = (await db.select().from(vaultOwnershipTransferRequests).where(
        eq(vaultOwnershipTransferRequests.id, result.response.transferId),
      ).limit(1))[0]!;
      return reply.code(200).send(await transferDto(
        db,
        transfer,
        result.response.rekeyTask,
      ));
    } catch (error) {
      if (error instanceof TaskConflictError || isUniqueViolation(error)) {
        return conflict(reply, error instanceof Error ? error.message : '所有权转移状态已经变化');
      }
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/ownership-transfer/accept', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: AcceptVaultOwnershipTransferRequestSchema,
      response: { 200: VaultOwnershipTransferSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const transferSnapshot = (await db.select().from(vaultOwnershipTransferRequests).where(and(
      eq(vaultOwnershipTransferRequests.id, req.body.transferId),
      eq(vaultOwnershipTransferRequests.vaultId, req.params.vaultId),
    )).limit(1))[0];
    if (!transferSnapshot) return conflict(reply, '所有权转移不存在');
    if (transferSnapshot.toOwnerUserId !== req.user.id) {
      return forbidden(reply, '只有目标用户可以确认接收所有权');
    }
    const actor = await getActiveDevice(db, req.user.id, req.body.actorDeviceId);
    if (!actor || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== actor.id) {
      return locked(reply);
    }
    if (
      req.body.envelopeTaskId !== transferSnapshot.envelopeTaskId ||
      req.body.expectedAccessGeneration !== transferSnapshot.expectedAccessGeneration
    ) return conflict(reply, '所有权转移状态已经变化，请刷新后重新确认');
    let acceptanceDigest: Buffer;
    let acceptanceSignature: Buffer;
    let keyPossessionSignature: Buffer;
    try {
      acceptanceDigest = decodeBase64Url(req.body.acceptanceDigest, { exact: 32 });
      acceptanceSignature = decodeBase64Url(req.body.signature, { exact: 64 });
      keyPossessionSignature = decodeBase64Url(req.body.keyPossessionSignature, { exact: 64 });
    } catch {
      return badRequest(reply, '接收信息校验失败，请刷新页面后重新确认');
    }
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'vault.ownership-transfer.accept',
      { userId: req.user.id, vaultId: req.params.vaultId, request: unsigned },
    )) return unauthorized(reply, '当前设备无法确认接收操作，请刷新页面后重试');

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const lockedActor = (await tx.select().from(userDevices).where(and(
          eq(userDevices.id, actor.id),
          eq(userDevices.userId, req.user.id),
          eq(userDevices.status, 'active'),
        )).for('share').limit(1))[0];
        if (!lockedActor) throw new TaskConflictError('当前设备已失效，请重新登录');
        const state = (await tx.select().from(vaultCryptoStates).where(
          eq(vaultCryptoStates.vaultId, req.params.vaultId),
        ).for('update').limit(1))[0];
        const task = (await tx.select().from(vaultEnvelopeTasks).where(and(
          eq(vaultEnvelopeTasks.id, req.body.envelopeTaskId),
          eq(vaultEnvelopeTasks.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        const transfer = (await tx.select().from(vaultOwnershipTransferRequests).where(and(
          eq(vaultOwnershipTransferRequests.id, req.body.transferId),
          eq(vaultOwnershipTransferRequests.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        if (!state?.activeEpoch || state.storageMode !== 'e2ee' || !task || !transfer) {
          throw new TaskConflictError('所有权转移状态已经变化，请刷新后重新确认');
        }
        if (
          transfer.status !== 'pending' ||
          !transfer.acceptanceRequired ||
          transfer.toOwnerUserId !== req.user.id ||
          transfer.envelopeTaskId !== task.id ||
          transfer.expectedAccessGeneration !== req.body.expectedAccessGeneration ||
          state.accessGeneration !== req.body.expectedAccessGeneration ||
          state.writeState !== 'open' ||
          task.keyEpoch !== state.activeEpoch ||
          task.status !== 'completed' ||
          !task.completedEnvelopeId ||
          task.capability !== 'full' ||
          task.recipientUserId !== transfer.toOwnerUserId ||
          task.authorizationKind !== 'direct' ||
          task.authorizationRef !== transfer.toOwnerUserId
        ) throw new TaskConflictError('所有权转移状态已经变化，请刷新后重新确认');
        const epoch = (await tx.select({
          keyPossessionPublicKey: vaultKeyEpochs.keyPossessionPublicKey,
        }).from(vaultKeyEpochs).where(and(
          eq(vaultKeyEpochs.vaultId, transfer.vaultId),
          eq(vaultKeyEpochs.epoch, state.activeEpoch),
          eq(vaultKeyEpochs.status, 'active'),
        )).for('share').limit(1))[0];
        if (!epoch?.keyPossessionPublicKey) {
          throw new TaskConflictError('当前密码库需要先完成一次安全更新，再确认接收所有权');
        }
        const completedEnvelope = (await tx.select({
          id: vaultKeyEnvelopes.id,
          ciphertextDigest: vaultKeyEnvelopes.ciphertextDigest,
        }).from(vaultKeyEnvelopes).where(and(
          eq(vaultKeyEnvelopes.id, task.completedEnvelopeId),
          eq(vaultKeyEnvelopes.vaultId, transfer.vaultId),
          eq(vaultKeyEnvelopes.keyEpoch, state.activeEpoch),
          eq(vaultKeyEnvelopes.recipientKind, 'user'),
          eq(vaultKeyEnvelopes.recipientUserId, transfer.toOwnerUserId),
          eq(vaultKeyEnvelopes.accessScope, 'full'),
          eq(vaultKeyEnvelopes.authorizationKind, 'direct'),
          eq(vaultKeyEnvelopes.authorizationRef, transfer.toOwnerUserId),
          eq(vaultKeyEnvelopes.status, 'active'),
        )).for('share').limit(1))[0];
        if (!completedEnvelope) throw new TaskConflictError('系统正在自动准备当前密码库访问，请稍后重试');
        const evidence = acceptanceEvidence(
          transfer,
          actor.id,
          req.body.idempotencyKey,
          {
            keyEpoch: state.activeEpoch,
            completedEnvelopeId: completedEnvelope.id,
            envelopeCiphertextDigest: encodeBase64Url(completedEnvelope.ciphertextDigest),
          },
        );
        const lockedDigest = await ownershipTransferAcceptanceDigest(evidence);
        if (lockedDigest !== req.body.acceptanceDigest) {
          throw new TaskConflictError('接收信息与当前状态不一致，请刷新后重新确认');
        }
        if (!await verifyVaultKeyPossession(
          req.body.keyPossessionSignature,
          encodeBase64Url(epoch.keyPossessionPublicKey),
          evidence,
        )) throw new TaskConflictError('无法确认你已能打开当前密码库，请同步后重试');
        if (!await verifyCommandSignature(
          req.body.signature,
          encodeBase64Url(lockedActor.publicSigningKey),
          'vault.ownership-transfer.accept',
          { userId: req.user.id, vaultId: req.params.vaultId, request: unsigned },
        )) throw new TaskConflictError('接收信息已经变化，请刷新后重新确认');
        const now = new Date();
        const accepted = (await tx.update(vaultOwnershipTransferRequests).set({
          acceptanceIdempotencyKey: req.body.idempotencyKey,
          acceptedByDeviceId: actor.id,
          acceptanceDigest,
          acceptanceSignature,
          keyPossessionSignature,
          acceptedKeyEpoch: state.activeEpoch,
          acceptedAt: now,
          updatedAt: now,
        }).where(and(
          eq(vaultOwnershipTransferRequests.id, transfer.id),
          eq(vaultOwnershipTransferRequests.status, 'pending'),
        )).returning())[0];
        if (!accepted) throw new TaskConflictError('所有权转移已经由其他设备处理');

        const { transfer: completedTransfer, rekeyTask } = await finalizeOwnershipTransfer(
          tx,
          accepted,
          state,
          req.user.id,
          actor.id,
        );
        collect(await recordSyncEvent(tx, {
          type: 'vault.rekey_required',
          vaultId: transfer.vaultId,
          itemId: null,
          payload: { pendingEpoch: rekeyTask.toEpoch, taskId: rekeyTask.id },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'vault.ownership_transfer.accept',
          vaultId: transfer.vaultId,
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            transferId: completedTransfer.id,
            rekeyTask: {
              id: rekeyTask.id,
              fromEpoch: rekeyTask.fromEpoch,
              toEpoch: rekeyTask.toEpoch,
            },
          },
        };
      });
      const transfer = (await db.select().from(vaultOwnershipTransferRequests).where(
        eq(vaultOwnershipTransferRequests.id, result.response.transferId),
      ).limit(1))[0]!;
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(await transferDto(
        db,
        transfer,
        result.response.rekeyTask,
      ));
    } catch (error) {
      if (error instanceof TaskConflictError || isUniqueViolation(error)) {
        return conflict(reply, error instanceof Error ? error.message : '所有权转移状态已经变化');
      }
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/ownership-transfer/cancel', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: CancelVaultOwnershipTransferRequestSchema,
      response: { 200: VaultOwnershipTransferSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const transferSnapshot = (await db.select().from(vaultOwnershipTransferRequests).where(and(
      eq(vaultOwnershipTransferRequests.id, req.body.transferId),
      eq(vaultOwnershipTransferRequests.vaultId, req.params.vaultId),
    )).limit(1))[0];
    if (!transferSnapshot) return conflict(reply, '所有权转移不存在');
    if (
      (req.body.decision === 'cancel' && transferSnapshot.fromOwnerUserId !== req.user.id) ||
      (req.body.decision === 'decline' && transferSnapshot.toOwnerUserId !== req.user.id)
    ) return forbidden(reply, req.body.decision === 'cancel'
      ? '只有发起用户可以取消所有权转移'
      : '只有目标用户可以拒绝接收所有权');
    if (
      req.body.envelopeTaskId !== transferSnapshot.envelopeTaskId ||
      req.body.expectedAccessGeneration !== transferSnapshot.expectedAccessGeneration
    ) return conflict(reply, '所有权转移状态已经变化，请刷新后重试');
    const actor = await getActiveDevice(db, req.user.id, req.body.actorDeviceId);
    if (!actor || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== actor.id) {
      return locked(reply);
    }
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'vault.ownership-transfer.cancel',
      { userId: req.user.id, vaultId: req.params.vaultId, request: unsigned },
    )) return unauthorized(reply, '当前设备无法确认这次操作，请刷新页面后重试');

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const lockedActor = (await tx.select().from(userDevices).where(and(
          eq(userDevices.id, actor.id),
          eq(userDevices.userId, req.user.id),
          eq(userDevices.status, 'active'),
        )).for('share').limit(1))[0];
        if (!lockedActor) throw new TaskConflictError('当前设备已失效，请重新登录');
        const state = (await tx.select().from(vaultCryptoStates).where(
          eq(vaultCryptoStates.vaultId, req.params.vaultId),
        ).for('update').limit(1))[0];
        const task = (await tx.select().from(vaultEnvelopeTasks).where(and(
          eq(vaultEnvelopeTasks.id, req.body.envelopeTaskId),
          eq(vaultEnvelopeTasks.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        const transfer = (await tx.select().from(vaultOwnershipTransferRequests).where(and(
          eq(vaultOwnershipTransferRequests.id, req.body.transferId),
          eq(vaultOwnershipTransferRequests.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        if (
          !state?.activeEpoch ||
          !task ||
          !transfer ||
          transfer.status !== 'pending' ||
          transfer.envelopeTaskId !== task.id ||
          transfer.expectedAccessGeneration !== req.body.expectedAccessGeneration ||
          state.accessGeneration !== req.body.expectedAccessGeneration ||
          (req.body.decision === 'cancel' && transfer.fromOwnerUserId !== req.user.id) ||
          (req.body.decision === 'decline' && transfer.toOwnerUserId !== req.user.id)
        ) throw new TaskConflictError('所有权转移状态已经变化，请刷新后重试');
        if (!await verifyCommandSignature(
          req.body.signature,
          encodeBase64Url(lockedActor.publicSigningKey),
          'vault.ownership-transfer.cancel',
          { userId: req.user.id, vaultId: req.params.vaultId, request: unsigned },
        )) throw new TaskConflictError('所有权转移信息已经变化，请刷新后重试');
        const now = new Date();
        const cancelled = (await tx.update(vaultOwnershipTransferRequests).set({
          status: 'cancelled',
          cancelledAt: now,
          updatedAt: now,
        }).where(and(
          eq(vaultOwnershipTransferRequests.id, transfer.id),
          eq(vaultOwnershipTransferRequests.status, 'pending'),
        )).returning())[0];
        if (!cancelled) throw new TaskConflictError('所有权转移已经由其他设备处理');
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed',
          vaultId: transfer.vaultId,
          itemId: null,
          payload: { ownershipTransferCancelled: req.body.decision },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: req.body.decision === 'cancel'
            ? 'vault.ownership_transfer.cancel'
            : 'vault.ownership_transfer.decline',
          vaultId: transfer.vaultId,
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            transferId: cancelled.id,
            rekeyTask: null,
          },
        };
      });
      const transfer = (await db.select().from(vaultOwnershipTransferRequests).where(
        eq(vaultOwnershipTransferRequests.id, result.response.transferId),
      ).limit(1))[0]!;
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(await transferDto(
        db,
        transfer,
        result.response.rekeyTask,
      ));
    } catch (error) {
      if (error instanceof TaskConflictError || isUniqueViolation(error)) {
        return conflict(reply, error instanceof Error ? error.message : '所有权转移状态已经变化');
      }
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/envelope-tasks/:taskId/complete', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['e2ee'],
      params: TaskParams,
      body: CompleteVaultEnvelopeTaskRequestSchema,
      response: { 200: VaultEnvelopeTaskSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (access?.role !== 'owner') return forbidden(reply, '只有已解锁的密码库拥有者可以完成自动访问交付');
    const [actor, signerProfile, taskSnapshots] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.actorDeviceId),
      getCryptoProfile(db, req.user.id),
      db.select({ recipientUserId: vaultEnvelopeTasks.recipientUserId }).from(vaultEnvelopeTasks).where(and(
        eq(vaultEnvelopeTasks.id, req.params.taskId),
        eq(vaultEnvelopeTasks.vaultId, req.params.vaultId),
      )).limit(1),
    ]);
    if (!actor || !signerProfile || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== actor.id) {
      return locked(reply);
    }
    const taskSnapshot = taskSnapshots[0];
    if (!taskSnapshot) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '这项自动访问交付任务已经不存在' } as never);
    }
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(actor.publicSigningKey),
      'vault.envelope-task.complete',
      { userId: req.user.id, vaultId: req.params.vaultId, request: { taskId: req.params.taskId, ...unsigned } },
    )) return unauthorized(reply, '当前设备无法确认这次开通，请刷新页面后重试');
    if (
      req.body.envelope.signerUserId !== req.user.id ||
      req.body.envelope.signerKeyVersion !== signerProfile.cryptoGeneration ||
      !await verifyVaultEnvelope(req.body.envelope, encodeBase64Url(signerProfile.publicSigningKey))
    ) return unauthorized(reply, '当前设备无法验证这次开通，请刷新页面后重试');

    let ciphertext: Buffer;
    let envelopeSignature: Buffer;
    try {
      ciphertext = decodeBase64Url(req.body.envelope.sealedKeyBundle, { min: 49, max: 10_000 });
      envelopeSignature = decodeBase64Url(req.body.envelope.signature, { exact: 64 });
    } catch {
      return badRequest(reply, '自动访问交付数据校验失败，请刷新页面后重试');
    }

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const profileUserIds = [...new Set([req.user.id, taskSnapshot.recipientUserId])].sort();
        const lockedProfiles = await tx.select().from(userCryptoProfiles)
          .where(inArray(userCryptoProfiles.userId, profileUserIds))
          .orderBy(asc(userCryptoProfiles.userId))
          .for('share');
        const lockedSignerProfile = lockedProfiles.find((profile) => profile.userId === req.user.id);
        const lockedRecipientProfile = lockedProfiles.find(
          (profile) => profile.userId === taskSnapshot.recipientUserId,
        );
        const lockedActor = (await tx.select().from(userDevices).where(and(
          eq(userDevices.id, actor.id),
          eq(userDevices.userId, req.user.id),
          eq(userDevices.status, 'active'),
        )).for('share').limit(1))[0];
        if (
          !lockedActor ||
          !lockedSignerProfile ||
          !lockedRecipientProfile ||
          req.body.envelope.signerUserId !== req.user.id ||
          req.body.envelope.signerKeyVersion !== lockedSignerProfile.cryptoGeneration ||
          !await verifyCommandSignature(
            req.body.signature,
            encodeBase64Url(lockedActor.publicSigningKey),
            'vault.envelope-task.complete',
            { userId: req.user.id, vaultId: req.params.vaultId, request: { taskId: req.params.taskId, ...unsigned } },
          ) ||
          !await verifyVaultEnvelope(
            req.body.envelope,
            encodeBase64Url(lockedSignerProfile.publicSigningKey),
          )
        ) throw new TaskConflictError('你的账号安全信息已更新，请刷新页面后重试');
        const state = (await tx.select().from(vaultCryptoStates).where(
          eq(vaultCryptoStates.vaultId, req.params.vaultId),
        ).for('update').limit(1))[0];
        if (!state?.activeEpoch || state.storageMode !== 'e2ee' || state.writeState !== 'open') {
          throw new TaskConflictError('密码库状态已经变化，请刷新成员列表后重试');
        }
        const lockedActorUser = (await tx.select({ active: users.active }).from(users).where(
          eq(users.id, req.user.id),
        ).for('share').limit(1))[0];
        const lockedVault = (await tx.select({
          kind: vaults.kind,
          ownerUserId: vaults.ownerUserId,
        }).from(vaults).where(eq(vaults.id, req.params.vaultId)).for('share').limit(1))[0];
        const lockedOwnerMembership = (await tx.select({ id: vaultMemberships.id })
          .from(vaultMemberships).where(and(
            eq(vaultMemberships.vaultId, req.params.vaultId),
            eq(vaultMemberships.subjectKind, 'user'),
            eq(vaultMemberships.subjectId, req.user.id),
            eq(vaultMemberships.role, 'owner'),
          )).for('share').limit(1))[0];
        const actorStillOwnsVault = lockedVault?.kind === 'personal'
          ? lockedVault.ownerUserId === req.user.id
          : Boolean(lockedOwnerMembership);
        if (!lockedActorUser?.active || !actorStillOwnsVault) {
          throw new TaskConflictError('当前用户已经不是密码库拥有者');
        }
        const task = (await tx.select().from(vaultEnvelopeTasks).where(and(
          eq(vaultEnvelopeTasks.id, req.params.taskId),
          eq(vaultEnvelopeTasks.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        if (!task) throw new TaskNotFoundError();
        if (task.status !== 'pending') throw new TaskConflictError('任务已经处理，请刷新成员列表');
        if (task.recipientUserId !== taskSnapshot.recipientUserId) {
          throw new TaskConflictError('接收人已经变化，请刷新成员列表');
        }
        if (!await isEnvelopeTaskAuthorizationActive(tx, task)) {
          await tx.update(vaultEnvelopeTasks).set({
            status: 'cancelled', cancelledAt: new Date(), updatedAt: new Date(),
          }).where(eq(vaultEnvelopeTasks.id, task.id));
          return { statusCode: 409, response: { taskId: task.id } };
        }
        const recipientProfile = lockedRecipientProfile;
        if (
          task.expectedProfileGeneration !== recipientProfile.cryptoGeneration ||
          req.body.envelope.vaultId !== task.vaultId ||
          req.body.envelope.epoch !== task.keyEpoch ||
          req.body.envelope.recipientKind !== 'user' ||
          req.body.envelope.recipientId !== task.recipientUserId ||
          req.body.envelope.recipientKeyVersion !== recipientProfile.cryptoGeneration ||
          req.body.envelope.capability !== task.capability
        ) throw new TaskConflictError('对方的账号安全信息或权限已更新，请刷新成员列表后重试');

        const fingerprint = publicKeyFingerprint(encodeBase64Url(recipientProfile.publicEncryptionKey));
        let envelope = (await tx.select().from(vaultKeyEnvelopes).where(and(
          eq(vaultKeyEnvelopes.vaultId, task.vaultId),
          eq(vaultKeyEnvelopes.keyEpoch, task.keyEpoch),
          eq(vaultKeyEnvelopes.recipientKind, 'user'),
          eq(vaultKeyEnvelopes.recipientUserId, task.recipientUserId),
          eq(vaultKeyEnvelopes.recipientKeyFingerprint, fingerprint),
          eq(vaultKeyEnvelopes.accessScope, task.capability),
          eq(vaultKeyEnvelopes.authorizationKind, task.authorizationKind),
          eq(vaultKeyEnvelopes.authorizationRef, task.authorizationRef),
        )).for('update').limit(1))[0];
        if (envelope) {
          if (
            envelope.status !== 'active' ||
            !Buffer.from(envelope.ciphertext).equals(ciphertext) ||
            !Buffer.from(envelope.signature).equals(envelopeSignature)
          ) throw new TaskConflictError('对方的账号安全信息已更新，请刷新成员列表后重试');
        } else {
          envelope = (await tx.insert(vaultKeyEnvelopes).values({
            vaultId: task.vaultId,
            keyEpoch: task.keyEpoch,
            recipientKind: 'user',
            accessScope: task.capability,
            recipientUserId: task.recipientUserId,
            recipientKeyFingerprint: fingerprint,
            authorizationKind: task.authorizationKind,
            authorizationRef: task.authorizationRef,
            envelopeVersion: recipientProfile.cryptoGeneration,
            ciphertext,
            ciphertextDigest: sha256(ciphertext),
            senderDeviceId: lockedActor.id,
            signerUserId: req.user.id,
            signerKeyVersion: lockedSignerProfile.cryptoGeneration,
            signerPublicKey: lockedSignerProfile.publicSigningKey,
            signature: envelopeSignature,
            status: 'active',
            activatedAt: new Date(),
          }).returning())[0]!;
        }
        const now = new Date();
        const completed = (await tx.update(vaultEnvelopeTasks).set({
          status: 'completed',
          expectedProfileGeneration: recipientProfile.cryptoGeneration,
          completedEnvelopeId: envelope.id,
          completedAt: now,
          updatedAt: now,
        }).where(and(
          eq(vaultEnvelopeTasks.id, task.id),
          eq(vaultEnvelopeTasks.status, 'pending'),
        )).returning())[0];
        if (!completed) throw new TaskConflictError('这项自动访问交付已由其他拥有者处理');
        const ownershipTransfer = (await tx.select().from(vaultOwnershipTransferRequests).where(and(
          eq(vaultOwnershipTransferRequests.envelopeTaskId, task.id),
          eq(vaultOwnershipTransferRequests.status, 'pending'),
        )).for('update').limit(1))[0];
        if (ownershipTransfer) {
          if (ownershipTransfer.fromOwnerUserId !== req.user.id) {
            throw new TaskConflictError('只能由发起所有权转移的拥有者完成该任务');
          }
          if (state.accessGeneration !== ownershipTransfer.expectedAccessGeneration) {
            throw new TaskConflictError('密码库成员状态已经变化，请重新发起所有权转移');
          }
          collect(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed',
            vaultId: task.vaultId,
            itemId: null,
            payload: { ownershipTransferWaitingAcceptance: true },
          }));
        } else {
          collect(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed',
            vaultId: task.vaultId,
            itemId: null,
            payload: { accessChanged: true },
          }));
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'vault.envelope_task.complete',
          vaultId: task.vaultId,
          success: true,
          details: {},
        });
        return { statusCode: 200, response: { taskId: completed.id } };
      });
      if (result.statusCode === 409) {
        return conflict(reply, '成员权限已经变化，这项自动交付已取消');
      }
      const row = (await db.select().from(vaultEnvelopeTasks).where(
        eq(vaultEnvelopeTasks.id, result.response.taskId),
      ).limit(1))[0]!;
      const [dto] = await taskDtos(db, [row]);
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(dto!);
    } catch (error) {
      if (error instanceof TaskNotFoundError) {
        return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '这项自动访问交付任务已经不存在' } as never);
      }
      if (error instanceof TaskConflictError || isUniqueViolation(error)) {
        return conflict(reply, error instanceof Error ? error.message : '这项自动访问交付已经变化');
      }
      throw error;
    }
  });
}

async function taskDtos(
  db: FastifyInstance['ctx']['db'],
  rows: Array<typeof vaultEnvelopeTasks.$inferSelect>,
) {
  const userIds = [...new Set(rows.map((row) => row.recipientUserId))];
  const profiles = userIds.length
    ? await db.select().from(userCryptoProfiles).where(inArray(userCryptoProfiles.userId, userIds))
    : [];
  const byUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  return rows.map((row) => {
    const profile = byUser.get(row.recipientUserId);
    return {
      id: row.id,
      vaultId: row.vaultId,
      keyEpoch: row.keyEpoch,
      authorizationKind: row.authorizationKind,
      authorizationRef: row.authorizationRef,
      recipientUserId: row.recipientUserId,
      capability: row.capability,
      expectedProfileGeneration: row.expectedProfileGeneration,
      status: row.status,
      completedEnvelopeId: row.completedEnvelopeId,
      recipientProfile: profile ? {
        keyVersion: profile.cryptoGeneration,
        encryptionPublicKey: encodeBase64Url(profile.publicEncryptionKey),
        signingPublicKey: encodeBase64Url(profile.publicSigningKey),
      } : null,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
      completedAt: row.completedAt?.toISOString() ?? null,
      cancelledAt: row.cancelledAt?.toISOString() ?? null,
    };
  });
}

async function finalizeOwnershipTransfer(
  db: DbOrTx,
  transfer: typeof vaultOwnershipTransferRequests.$inferSelect,
  state: typeof vaultCryptoStates.$inferSelect,
  actorUserId: string,
  actorDeviceId: string,
) {
  const now = new Date();
  if (
    transfer.status !== 'pending' ||
    transfer.expectedAccessGeneration !== state.accessGeneration ||
    !await hasValidOwnershipAcceptance(db, transfer)
  ) throw new TaskConflictError('新拥有者尚未完成有效的接收确认');
  const task = (await db.select().from(vaultEnvelopeTasks).where(
    eq(vaultEnvelopeTasks.id, transfer.envelopeTaskId),
  ).limit(1))[0];
  if (
    task?.status !== 'completed' ||
    !task.completedEnvelopeId ||
    task.recipientUserId !== transfer.toOwnerUserId ||
    task.vaultId !== transfer.vaultId ||
    task.keyEpoch !== state.activeEpoch ||
    task.capability !== 'full' ||
    task.authorizationKind !== 'direct' ||
    task.authorizationRef !== transfer.toOwnerUserId
  ) throw new TaskConflictError('系统仍在准备新拥有者的当前密码库访问');
  const completedEnvelope = await db.select({ id: vaultKeyEnvelopes.id }).from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.id, task.completedEnvelopeId),
      eq(vaultKeyEnvelopes.vaultId, transfer.vaultId),
      eq(vaultKeyEnvelopes.keyEpoch, task.keyEpoch),
      eq(vaultKeyEnvelopes.recipientKind, 'user'),
      eq(vaultKeyEnvelopes.recipientUserId, transfer.toOwnerUserId),
      eq(vaultKeyEnvelopes.accessScope, 'full'),
      eq(vaultKeyEnvelopes.authorizationKind, 'direct'),
      eq(vaultKeyEnvelopes.authorizationRef, transfer.toOwnerUserId),
      eq(vaultKeyEnvelopes.status, 'active'),
    )).for('share').limit(1);
  const activeTarget = await db.select({ id: users.id }).from(users).where(and(
      eq(users.id, transfer.toOwnerUserId),
      eq(users.active, true),
    )).for('share').limit(1);
  const currentOwner = await db.select({ id: vaultMemberships.id }).from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, transfer.vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, transfer.fromOwnerUserId),
      eq(vaultMemberships.role, 'owner'),
    )).for('update').limit(1);
  if (!completedEnvelope[0]) throw new TaskConflictError('新拥有者的密码库访问已经失效，请重新发起自动准备');
  if (!activeTarget[0]) throw new TaskConflictError('新拥有者已经停用');
  if (!currentOwner[0]) throw new TaskConflictError('发起用户已经不是密码库拥有者');
  await db.insert(vaultMemberships).values({
    vaultId: transfer.vaultId,
    subjectKind: 'user',
    subjectId: transfer.toOwnerUserId,
    role: 'owner',
  }).onConflictDoUpdate({
    target: [vaultMemberships.vaultId, vaultMemberships.subjectKind, vaultMemberships.subjectId],
    set: { role: 'owner' },
  });
  await db.update(vaultMemberships).set({ role: 'editor' }).where(and(
    eq(vaultMemberships.vaultId, transfer.vaultId),
    eq(vaultMemberships.subjectKind, 'user'),
    eq(vaultMemberships.subjectId, transfer.fromOwnerUserId),
    eq(vaultMemberships.role, 'owner'),
  ));
  const newOwner = (await db.select({ id: vaultMemberships.id }).from(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, transfer.vaultId),
    eq(vaultMemberships.subjectKind, 'user'),
    eq(vaultMemberships.subjectId, transfer.toOwnerUserId),
    eq(vaultMemberships.role, 'owner'),
  )).limit(1))[0];
  if (!newOwner) throw new TaskConflictError('所有权转移未能建立新的直接拥有者');
  const rekeyTask = await ensureMembershipRekeyTask(
    db,
    state.vaultId,
    actorUserId,
    actorDeviceId,
    now,
    'ownership_transfer',
  );
  const completed = (await db.update(vaultOwnershipTransferRequests).set({
    status: 'completed',
    completedAt: now,
    updatedAt: now,
  }).where(and(
    eq(vaultOwnershipTransferRequests.id, transfer.id),
    eq(vaultOwnershipTransferRequests.status, 'pending'),
  )).returning())[0];
  if (!completed) throw new TaskConflictError('所有权转移已经由其他设备处理');
  return { transfer: completed, rekeyTask };
}

async function hasValidOwnershipAcceptance(
  db: DbOrTx,
  transfer: typeof vaultOwnershipTransferRequests.$inferSelect,
): Promise<boolean> {
  if (
    !transfer.acceptanceRequired ||
    !transfer.acceptanceIdempotencyKey ||
    !transfer.acceptedByDeviceId ||
    !transfer.acceptanceDigest ||
    !transfer.acceptanceSignature ||
    !transfer.keyPossessionSignature ||
    !transfer.acceptedKeyEpoch ||
    !transfer.acceptedAt
  ) return false;
  const device = (await db.select().from(userDevices).where(and(
    eq(userDevices.id, transfer.acceptedByDeviceId),
    eq(userDevices.userId, transfer.toOwnerUserId),
    eq(userDevices.status, 'active'),
  )).for('share').limit(1))[0];
  if (!device) return false;
  const task = (await db.select().from(vaultEnvelopeTasks).where(and(
    eq(vaultEnvelopeTasks.id, transfer.envelopeTaskId),
    eq(vaultEnvelopeTasks.vaultId, transfer.vaultId),
  )).for('share').limit(1))[0];
  if (
    task?.status !== 'completed' ||
    !task.completedEnvelopeId ||
    task.keyEpoch !== transfer.acceptedKeyEpoch ||
    task.capability !== 'full' ||
    task.recipientUserId !== transfer.toOwnerUserId ||
    task.authorizationKind !== 'direct' ||
    task.authorizationRef !== transfer.toOwnerUserId
  ) return false;
  const envelope = (await db.select({
    id: vaultKeyEnvelopes.id,
    ciphertextDigest: vaultKeyEnvelopes.ciphertextDigest,
  }).from(vaultKeyEnvelopes).where(and(
    eq(vaultKeyEnvelopes.id, task.completedEnvelopeId),
    eq(vaultKeyEnvelopes.vaultId, transfer.vaultId),
    eq(vaultKeyEnvelopes.keyEpoch, transfer.acceptedKeyEpoch),
    eq(vaultKeyEnvelopes.recipientKind, 'user'),
    eq(vaultKeyEnvelopes.recipientUserId, transfer.toOwnerUserId),
    eq(vaultKeyEnvelopes.accessScope, 'full'),
    eq(vaultKeyEnvelopes.authorizationKind, 'direct'),
    eq(vaultKeyEnvelopes.authorizationRef, transfer.toOwnerUserId),
    eq(vaultKeyEnvelopes.status, 'active'),
  )).for('share').limit(1))[0];
  if (!envelope) return false;
  const epoch = (await db.select({
    keyPossessionPublicKey: vaultKeyEpochs.keyPossessionPublicKey,
  }).from(vaultKeyEpochs).where(and(
    eq(vaultKeyEpochs.vaultId, transfer.vaultId),
    eq(vaultKeyEpochs.epoch, transfer.acceptedKeyEpoch),
  )).for('share').limit(1))[0];
  if (!epoch?.keyPossessionPublicKey) return false;
  const evidence = acceptanceEvidence(
    transfer,
    transfer.acceptedByDeviceId,
    transfer.acceptanceIdempotencyKey,
    {
      keyEpoch: transfer.acceptedKeyEpoch,
      completedEnvelopeId: envelope.id,
      envelopeCiphertextDigest: encodeBase64Url(envelope.ciphertextDigest),
    },
  );
  const acceptanceDigest = encodeBase64Url(transfer.acceptanceDigest);
  if (acceptanceDigest !== await ownershipTransferAcceptanceDigest(evidence)) return false;
  const keyPossessionSignature = encodeBase64Url(transfer.keyPossessionSignature);
  if (!await verifyVaultKeyPossession(
    keyPossessionSignature,
    encodeBase64Url(epoch.keyPossessionPublicKey),
    evidence,
  )) return false;
  return verifyCommandSignature(
    encodeBase64Url(transfer.acceptanceSignature),
    encodeBase64Url(device.publicSigningKey),
    'vault.ownership-transfer.accept',
    {
      userId: transfer.toOwnerUserId,
      vaultId: transfer.vaultId,
      request: {
        idempotencyKey: transfer.acceptanceIdempotencyKey,
        transferId: transfer.id,
        envelopeTaskId: transfer.envelopeTaskId,
        expectedAccessGeneration: transfer.expectedAccessGeneration,
        acceptanceDigest,
        keyPossessionSignature,
        actorDeviceId: transfer.acceptedByDeviceId,
      },
    },
  );
}

function acceptanceEvidence(
  transfer: Pick<typeof vaultOwnershipTransferRequests.$inferSelect,
    'id' | 'vaultId' | 'envelopeTaskId' | 'fromOwnerUserId' | 'toOwnerUserId' | 'expectedAccessGeneration'>,
  actorDeviceId: string,
  idempotencyKey: string,
  proof: {
    keyEpoch: number;
    completedEnvelopeId: string;
    envelopeCiphertextDigest: string;
  },
) {
  return {
    transferId: transfer.id,
    vaultId: transfer.vaultId,
    keyEpoch: proof.keyEpoch,
    envelopeTaskId: transfer.envelopeTaskId,
    fromOwnerUserId: transfer.fromOwnerUserId,
    toOwnerUserId: transfer.toOwnerUserId,
    expectedAccessGeneration: transfer.expectedAccessGeneration,
    actorDeviceId,
    idempotencyKey,
    completedEnvelopeId: proof.completedEnvelopeId,
    envelopeCiphertextDigest: proof.envelopeCiphertextDigest,
  };
}

async function transferDto(
  db: DbOrTx,
  transfer: typeof vaultOwnershipTransferRequests.$inferSelect,
  rekeyTask: { id: string; fromEpoch: number; toEpoch: number } | null,
) {
  const task = (await db.select().from(vaultEnvelopeTasks).where(
    eq(vaultEnvelopeTasks.id, transfer.envelopeTaskId),
  ).limit(1))[0];
  if (!task) throw new TaskConflictError('所有权转移所需的自动访问交付记录不存在，请重新发起');
  const epoch = (await db.select({
    keyPossessionPublicKey: vaultKeyEpochs.keyPossessionPublicKey,
  }).from(vaultKeyEpochs).where(and(
    eq(vaultKeyEpochs.vaultId, transfer.vaultId),
    eq(vaultKeyEpochs.epoch, task.keyEpoch),
  )).limit(1))[0];
  const envelope = task.completedEnvelopeId
    ? (await db.select().from(vaultKeyEnvelopes).where(
      eq(vaultKeyEnvelopes.id, task.completedEnvelopeId),
    ).limit(1))[0]
    : null;
  const envelopeReady = Boolean(
    task.status === 'completed' &&
    envelope &&
    envelope.vaultId === transfer.vaultId &&
    envelope.keyEpoch === task.keyEpoch &&
    envelope.recipientKind === 'user' &&
    envelope.recipientUserId === transfer.toOwnerUserId &&
    envelope.accessScope === 'full' &&
    envelope.authorizationKind === 'direct' &&
    envelope.authorizationRef === transfer.toOwnerUserId &&
    envelope.status === 'active'
  );
  return {
    id: transfer.id,
    vaultId: transfer.vaultId,
    fromOwnerUserId: transfer.fromOwnerUserId,
    toOwnerUserId: transfer.toOwnerUserId,
    envelopeTaskId: transfer.envelopeTaskId,
    keyEpoch: task.keyEpoch,
    envelopeReady,
    completedEnvelopeId: task.completedEnvelopeId,
    envelopeCiphertextDigest: envelope ? encodeBase64Url(envelope.ciphertextDigest) : null,
    keyPossessionProofAvailable: Boolean(epoch?.keyPossessionPublicKey),
    expectedAccessGeneration: transfer.expectedAccessGeneration,
    status: transfer.status,
    acceptanceRequired: transfer.acceptanceRequired,
    acceptanceStatus: transfer.status === 'cancelled'
      ? 'cancelled' as const
      : transfer.acceptedAt
      ? 'accepted' as const
      : transfer.acceptanceRequired
        ? 'waiting' as const
        : 'legacy_completed' as const,
    acceptedByDeviceId: transfer.acceptedByDeviceId,
    acceptanceDigest: transfer.acceptanceDigest ? encodeBase64Url(transfer.acceptanceDigest) : null,
    acceptanceSignature: transfer.acceptanceSignature ? encodeBase64Url(transfer.acceptanceSignature) : null,
    acceptedAt: transfer.acceptedAt?.toISOString() ?? null,
    rekeyTask,
    createdAt: transfer.createdAt.toISOString(),
    updatedAt: transfer.updatedAt.toISOString(),
    completedAt: transfer.completedAt?.toISOString() ?? null,
    cancelledAt: transfer.cancelledAt?.toISOString() ?? null,
  };
}

class TaskNotFoundError extends Error {}
class TaskConflictError extends Error {}

function without<T extends Record<string, unknown>, K extends keyof T>(input: T, key: K): Omit<T, K> {
  const clone = { ...input };
  delete clone[key];
  return clone;
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === '23505');
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

function locked(reply: FastifyReply) {
  return reply.code(423).send({ statusCode: 423, error: 'Locked', message: '请先解锁工作台' } as never);
}

function conflict(reply: FastifyReply, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', message } as never);
}
