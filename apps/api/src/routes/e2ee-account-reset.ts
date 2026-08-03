import { randomUUID } from 'node:crypto';
import { and, desc, eq, inArray, lte, ne, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  AccountCryptoResetRequestSchema,
  ActivateAccountCryptoResetRequestSchema,
  ActivateAccountCryptoResetResponseSchema,
  ZeroKnowledgeApiErrorSchema,
  ApproveAccountCryptoResetRequestSchema,
  CancelAccountCryptoResetRequestSchema,
  CreateAccountCryptoResetRequestSchema,
  ListAccountCryptoResetRequestsQuerySchema,
} from '@mima/contracts';
import { canonicalJson } from '@mima/e2ee';
import {
  accountCryptoResetApprovals,
  accountCryptoResetRequests,
  accountCryptoResetVaults,
  deviceEnrollmentRequests,
  extensionPairingCodes,
  extensionSessions,
  sessionUnlockChallenges,
  sessions,
  userCryptoProfiles,
  userDevices,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultRekeyJobs,
} from '../db/schema.ts';
import { appendAudit, type DbOrTx } from '../services/audit.ts';
import { listAccessibleVaults } from '../services/access.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import { reconcilePendingEnvelopeTasksForProfile } from '../services/vault-envelope-tasks.ts';
import {
  decodeBase64Url,
  decodeCipherBlob,
  encodeBase64Url,
  parseDeviceCertificate,
  publicKeyFingerprint,
  sha256,
  toCryptoDeviceDto,
  toCryptoProfileDto,
  verifyCommandSignature,
} from '../services/e2ee.ts';
import { lockRecipientSets } from '../services/recipient-set-lock.ts';

const ResetParams = z.object({ requestId: z.string().uuid() });

class AccountResetConflictError extends Error {}

export function registerE2eeAccountResetRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const readGuard = [app.requireSession];
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.get('/api/v2/account-crypto-resets', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-account-reset'],
      querystring: ListAccountCryptoResetRequestsQuerySchema,
      response: { 200: z.array(AccountCryptoResetRequestSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await expireAccountCryptoResetRequests(db);
    const filters = [];
    if (!req.user.isLocalPlatformAdmin) filters.push(eq(accountCryptoResetRequests.targetUserId, req.user.id));
    else if (req.query.targetUserId) filters.push(eq(accountCryptoResetRequests.targetUserId, req.query.targetUserId));
    if (req.query.status) filters.push(eq(accountCryptoResetRequests.status, req.query.status));
    const rows = filters.length
      ? await db.select().from(accountCryptoResetRequests)
          .where(and(...filters)).orderBy(desc(accountCryptoResetRequests.createdAt))
      : await db.select().from(accountCryptoResetRequests).orderBy(desc(accountCryptoResetRequests.createdAt));
    reply.header('cache-control', 'no-store');
    return Promise.all(rows.map((row) => accountResetDto(db, row)));
  });

  r.get('/api/v2/account-crypto-resets/:requestId', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee-account-reset'],
      params: ResetParams,
      response: { 200: AccountCryptoResetRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await expireAccountCryptoResetRequests(db);
    const row = (await db.select().from(accountCryptoResetRequests)
      .where(eq(accountCryptoResetRequests.id, req.params.requestId)).limit(1))[0];
    if (!row) return reply.code(404).send(notFoundBody('账户加密身份重置请求不存在') as never);
    if (!req.user.isLocalPlatformAdmin && row.targetUserId !== req.user.id) {
      return forbidden(reply, '没有查看该账户加密身份重置请求的权限');
    }
    reply.header('cache-control', 'no-store');
    return accountResetDto(db, row);
  });

  r.post('/api/v2/account-crypto-resets', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-account-reset'],
      body: CreateAccountCryptoResetRequestSchema,
      response: { 201: AccountCryptoResetRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const profile = (await db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, req.user.id)).limit(1))[0];
    if (!profile) return conflict(reply, '当前账号尚未设置主密码，不需要重置加密身份');
    if (
      profile.profileVersion !== req.body.expectedProfileVersion
      || profile.cryptoGeneration !== req.body.expectedKeyVersion
      || req.body.newKeyVersion !== req.body.expectedKeyVersion + 1
    ) return conflict(reply, '账户加密身份已经变化，请刷新后重新开始');
    if (
      encodeBase64Url(profile.publicEncryptionKey) === req.body.encryptionPublicKey
      || encodeBase64Url(profile.publicSigningKey) === req.body.signingPublicKey
    ) return badRequest(reply, '重置必须生成全新的用户加密密钥和签名密钥');

    const candidatePayload = withoutKeys(req.body, ['candidateUserProof']);
    if (!await verifyCommandSignature(
      req.body.candidateUserProof,
      req.body.signingPublicKey,
      'crypto.account_reset.create.user',
      { userId: req.user.id, request: candidatePayload },
    )) return unauthorized(reply, '候选用户签名密钥的自签证明无效');

    let accountBundle;
    let accountEncryptionKey;
    let accountSigningKey;
    let kdfSalt;
    let deviceEncryptionKey;
    let deviceSigningKey;
    let deviceCertificate;
    let deviceCertificateSignature;
    let encryptedLabel: ReturnType<typeof decodeCipherBlob> | null;
    let candidateUserProof;
    try {
      accountBundle = decodeCipherBlob(req.body.encryptedAccountBundle, 48);
      accountEncryptionKey = decodeBase64Url(req.body.encryptionPublicKey, { exact: 32 });
      accountSigningKey = decodeBase64Url(req.body.signingPublicKey, { exact: 32 });
      kdfSalt = decodeBase64Url(req.body.kdf.salt, { exact: 16 });
      deviceEncryptionKey = decodeBase64Url(req.body.candidateDevice.encryptionPublicKey, { exact: 32 });
      deviceSigningKey = decodeBase64Url(req.body.candidateDevice.signingPublicKey, { exact: 32 });
      deviceCertificateSignature = decodeBase64Url(
        req.body.candidateDevice.certificateSignature,
        { exact: 64 },
      );
      candidateUserProof = decodeBase64Url(req.body.candidateUserProof, { exact: 64 });
      encryptedLabel = req.body.candidateDevice.encryptedLabel
        ? decodeCipherBlob(req.body.candidateDevice.encryptedLabel)
        : null;
      ({ bytes: deviceCertificate } = await parseDeviceCertificate(
        req.body.candidateDevice.certificate,
        req.body.candidateDevice.certificateSignature,
        req.body.signingPublicKey,
        {
          accountId: req.user.id,
          deviceId: req.body.candidateDevice.id,
          deviceType: req.body.candidateDevice.deviceType,
          encryptionPublicKey: req.body.candidateDevice.encryptionPublicKey,
          signingPublicKey: req.body.candidateDevice.signingPublicKey,
          keyVersion: req.body.newKeyVersion,
        },
      ));
    } catch {
      return badRequest(reply, '候选账户密钥、主密码加密包或设备证书格式无效');
    }

    const id = randomUUID();
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + 24 * 60 * 60_000);
    const requestDigest = sha256(canonicalJson({
      id,
      kind: 'account-crypto-reset',
      protocol: 'lm-e2ee-v1',
      targetUserId: req.user.id,
      expectedProfileVersion: req.body.expectedProfileVersion,
      expectedKeyVersion: req.body.expectedKeyVersion,
      newKeyVersion: req.body.newKeyVersion,
      kdf: req.body.kdf,
      encryptedAccountBundle: req.body.encryptedAccountBundle,
      encryptionPublicKey: req.body.encryptionPublicKey,
      signingPublicKey: req.body.signingPublicKey,
      candidateDevice: req.body.candidateDevice,
      candidateUserProof: req.body.candidateUserProof,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    } as never));

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await expireAccountCryptoResetRequests(tx);
        const current = (await tx.select().from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.user.id)).for('update').limit(1))[0];
        if (!current
          || current.profileVersion !== req.body.expectedProfileVersion
          || current.cryptoGeneration !== req.body.expectedKeyVersion
        ) throw new AccountResetConflictError('账户加密身份已经变化，请重新开始');
        const row = (await tx.insert(accountCryptoResetRequests).values({
          id,
          targetUserId: req.user.id,
          expectedProfileVersion: req.body.expectedProfileVersion,
          expectedCryptoGeneration: req.body.expectedKeyVersion,
          newCryptoGeneration: req.body.newKeyVersion,
          kdfMemoryKib: req.body.kdf.memoryKiB,
          kdfIterations: req.body.kdf.iterations,
          kdfParallelism: req.body.kdf.parallelism,
          kdfSalt,
          wrappedAccountKeyCiphertext: accountBundle.ciphertext,
          wrappedAccountKeyNonce: accountBundle.nonce,
          publicEncryptionKey: accountEncryptionKey,
          publicSigningKey: accountSigningKey,
          signingKeyFingerprint: publicKeyFingerprint(req.body.signingPublicKey),
          candidateDeviceId: req.body.candidateDevice.id,
          candidateDeviceType: req.body.candidateDevice.deviceType,
          candidateDeviceEncryptionPublicKey: deviceEncryptionKey,
          candidateDeviceSigningPublicKey: deviceSigningKey,
          candidateDeviceKeyFingerprint: publicKeyFingerprint(req.body.candidateDevice.signingPublicKey),
          candidateDeviceEncryptedLabel: encryptedLabel?.ciphertext ?? null,
          candidateDeviceLabelNonce: encryptedLabel?.nonce ?? null,
          candidateDeviceCertificatePayload: deviceCertificate,
          candidateDeviceCertificateSignature: deviceCertificateSignature,
          candidateUserProof,
          requestDigest,
          createdByUserId: req.user.id,
          createdAt,
          expiresAt,
        }).returning())[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'crypto.account_reset.create',
          success: true,
          details: {},
        });
        return { statusCode: 201, response: await accountResetDto(tx, row) };
      }, commandIdentity('crypto.account_reset.create', req.body));
      reply.header('cache-control', 'no-store');
      return reply.code(201).send(result.response);
    } catch (error) {
      if (error instanceof AccountResetConflictError) return conflict(reply, error.message);
      if (isUniqueViolation(error)) return conflict(reply, '该账号已有进行中的加密身份重置请求');
      throw error;
    }
  });

  r.post('/api/v2/account-crypto-resets/:requestId/approve', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-account-reset'],
      params: ResetParams,
      body: ApproveAccountCryptoResetRequestSchema,
      response: { 200: AccountCryptoResetRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (!req.user.isLocalPlatformAdmin) return forbidden(reply, '只有本地授权的系统管理员可以审批账户加密身份重置');
    await expireAccountCryptoResetRequests(db);
    const row = (await db.select().from(accountCryptoResetRequests)
      .where(eq(accountCryptoResetRequests.id, req.params.requestId)).limit(1))[0];
    if (!row) return reply.code(404).send(notFoundBody('账户加密身份重置请求不存在') as never);
    if (row.targetUserId === req.user.id) return forbidden(reply, '不能审批自己的账户加密身份重置');
    if (!['pending', 'approved'].includes(row.status) || row.expiresAt <= new Date()) {
      return conflict(reply, '该账户加密身份重置请求不再接受审批');
    }
    let requestDigest;
    try { requestDigest = decodeBase64Url(req.body.requestDigest, { exact: 32 }); }
    catch { return badRequest(reply, '账户加密身份重置摘要格式无效'); }
    if (!Buffer.from(row.requestDigest).equals(requestDigest)) return conflict(reply, '账户加密身份重置摘要不匹配');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await expireAccountCryptoResetRequests(tx);
        const locked = (await tx.select().from(accountCryptoResetRequests)
          .where(eq(accountCryptoResetRequests.id, row.id)).for('update').limit(1))[0];
        if (!locked || !['pending', 'approved'].includes(locked.status)) {
          throw new AccountResetConflictError(locked?.status === 'expired'
            ? '这次主密码重置申请已过期，请让申请人重新发起'
            : '这次主密码重置申请已经结束，请刷新查看最新状态');
        }
        const approvals = await tx.select({ userId: accountCryptoResetApprovals.approverUserId })
          .from(accountCryptoResetApprovals)
          .where(eq(accountCryptoResetApprovals.requestId, locked.id));
        if (approvals.some((approval) => approval.userId === req.user.id)) {
          throw new AccountResetConflictError('你已经确认过这次主密码重置，无需重复操作');
        }
        if (approvals.length >= 2) {
          throw new AccountResetConflictError('这次主密码重置已完成两人确认，请刷新后进入下一步');
        }
        await tx.insert(accountCryptoResetApprovals).values({
          requestId: locked.id,
          approverUserId: req.user.id,
          requestDigest,
        });
        const updated = (await tx.select().from(accountCryptoResetRequests)
          .where(eq(accountCryptoResetRequests.id, locked.id)).limit(1))[0]!;
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'crypto.account_reset.approve',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await accountResetDto(tx, updated) };
      }, commandIdentity('crypto.account_reset.approve', { requestId: req.params.requestId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof AccountResetConflictError) return conflict(reply, error.message);
      if (isUniqueViolation(error)) return conflict(reply, '你已经审批过该账户加密身份重置请求');
      return conflict(reply, '该账户加密身份重置请求已变化或不再接受审批');
    }
  });

  r.post('/api/v2/account-crypto-resets/:requestId/cancel', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-account-reset'],
      params: ResetParams,
      body: CancelAccountCryptoResetRequestSchema,
      response: { 200: AccountCryptoResetRequestSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await expireAccountCryptoResetRequests(db);
    const row = (await db.select().from(accountCryptoResetRequests)
      .where(eq(accountCryptoResetRequests.id, req.params.requestId)).limit(1))[0];
    if (!row) return reply.code(404).send(notFoundBody('账户加密身份重置请求不存在') as never);
    if (row.targetUserId !== req.user.id) return forbidden(reply, '只有目标用户可以取消账户加密身份重置');
    let requestDigest;
    try { requestDigest = decodeBase64Url(req.body.requestDigest, { exact: 32 }); }
    catch { return badRequest(reply, '账户加密身份重置摘要格式无效'); }
    if (!Buffer.from(row.requestDigest).equals(requestDigest)) return conflict(reply, '账户加密身份重置摘要不匹配');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const now = new Date();
        const cancelled = (await tx.update(accountCryptoResetRequests).set({
          status: 'cancelled',
          cancelledAt: now,
        }).where(and(
          eq(accountCryptoResetRequests.id, row.id),
          inArray(accountCryptoResetRequests.status, ['pending', 'approved']),
        )).returning())[0];
        if (!cancelled) throw new AccountResetConflictError('该账户加密身份重置请求已经结束');
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'crypto.account_reset.cancel',
          success: true,
          details: {},
        });
        return { statusCode: 200, response: await accountResetDto(tx, cancelled) };
      }, commandIdentity('crypto.account_reset.cancel', { requestId: req.params.requestId, ...req.body }));
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof AccountResetConflictError) return conflict(reply, error.message);
      throw error;
    }
  });

  r.post('/api/v2/account-crypto-resets/:requestId/activate', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-account-reset'],
      params: ResetParams,
      body: ActivateAccountCryptoResetRequestSchema,
      response: { 200: ActivateAccountCryptoResetResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    await expireAccountCryptoResetRequests(db);
    const row = (await db.select().from(accountCryptoResetRequests)
      .where(eq(accountCryptoResetRequests.id, req.params.requestId)).limit(1))[0];
    if (!row) return reply.code(404).send(notFoundBody('账户加密身份重置请求不存在') as never);
    if (row.targetUserId !== req.user.id) return forbidden(reply, '只有目标用户可以激活候选加密身份');
    if (row.status !== 'approved' || row.expiresAt <= new Date()) {
      return conflict(reply, '账户加密身份重置尚未获得两名管理员审批或已经过期');
    }
    let requestDigest;
    try { requestDigest = decodeBase64Url(req.body.requestDigest, { exact: 32 }); }
    catch { return badRequest(reply, '账户加密身份重置摘要格式无效'); }
    if (!Buffer.from(row.requestDigest).equals(requestDigest)) return conflict(reply, '账户加密身份重置摘要不匹配');
    const activationPayload = {
      idempotencyKey: req.body.idempotencyKey,
      requestId: row.id,
      requestDigest: req.body.requestDigest,
    };
    if (!await verifyCommandSignature(
      req.body.candidateDevicePossessionSignature,
      encodeBase64Url(row.candidateDeviceSigningPublicKey),
      'crypto.account_reset.activate.device',
      { userId: req.user.id, request: activationPayload },
    )) return unauthorized(reply, '候选设备持有证明无效');
    if (!await verifyCommandSignature(
      req.body.candidateUserSignature,
      encodeBase64Url(row.publicSigningKey),
      'crypto.account_reset.activate.user',
      { userId: req.user.id, request: activationPayload },
    )) return unauthorized(reply, '候选用户签名证明无效');

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockRecipientSets(tx, [req.user.id]);
        await expireAccountCryptoResetRequests(tx);
        const reset = (await tx.select().from(accountCryptoResetRequests)
          .where(eq(accountCryptoResetRequests.id, row.id)).for('update').limit(1))[0];
        const profile = (await tx.select().from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.user.id)).for('update').limit(1))[0];
        if (!reset || reset.status !== 'approved' || reset.expiresAt <= new Date()
          || !profile
          || profile.profileVersion !== reset.expectedProfileVersion
          || profile.cryptoGeneration !== reset.expectedCryptoGeneration
        ) throw new AccountResetConflictError('账户加密身份或重置请求已经变化');

        const oldDevices = await tx.select().from(userDevices)
          .where(eq(userDevices.userId, req.user.id)).for('update');
        const oldDeviceIds = oldDevices.map((device) => device.id);
        const userEnvelopeRows = await tx.select({ vaultId: vaultKeyEnvelopes.vaultId })
          .from(vaultKeyEnvelopes).where(and(
            eq(vaultKeyEnvelopes.recipientUserId, req.user.id),
            inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
          ));
        const deviceEnvelopeRows = oldDeviceIds.length
          ? await tx.select({ vaultId: vaultKeyEnvelopes.vaultId }).from(vaultKeyEnvelopes).where(and(
              inArray(vaultKeyEnvelopes.recipientDeviceId, oldDeviceIds),
              inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
            ))
          : [];
        const authorizedVaults = await listAccessibleVaults(tx, req.user);
        const affectedVaultIds = mergeAccountResetAffectedVaultIds(
          userEnvelopeRows,
          deviceEnvelopeRows,
          authorizedVaults.map((entry) => ({ vaultId: entry.vault.id })),
        );
        const now = new Date();

        const updatedProfile = (await tx.update(userCryptoProfiles).set({
          profileVersion: reset.expectedProfileVersion + 1,
          cryptoGeneration: reset.newCryptoGeneration,
          kdfAlgorithm: 'argon2id13',
          kdfMemoryKib: reset.kdfMemoryKib,
          kdfIterations: reset.kdfIterations,
          kdfParallelism: reset.kdfParallelism,
          kdfSalt: reset.kdfSalt,
          wrappedAccountKeyCiphertext: reset.wrappedAccountKeyCiphertext,
          wrappedAccountKeyNonce: reset.wrappedAccountKeyNonce,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          publicEncryptionKey: reset.publicEncryptionKey,
          publicSigningKey: reset.publicSigningKey,
          signingKeyFingerprint: reset.signingKeyFingerprint,
          updatedAt: now,
        }).where(and(
          eq(userCryptoProfiles.userId, req.user.id),
          eq(userCryptoProfiles.profileVersion, reset.expectedProfileVersion),
          eq(userCryptoProfiles.cryptoGeneration, reset.expectedCryptoGeneration),
        )).returning())[0];
        if (!updatedProfile) throw new AccountResetConflictError('账户加密身份已经变化');

        const revokedDevices = (await tx.update(userDevices).set({
          status: 'revoked',
          deviceGeneration: sql`${userDevices.deviceGeneration} + 1`,
          revokedAt: now,
          revokedByUserId: req.user.id,
          revocationReason: 'account_crypto_reset',
        }).where(and(eq(userDevices.userId, req.user.id), ne(userDevices.status, 'revoked')))
          .returning({ id: userDevices.id }));
        const candidateDevice = (await tx.insert(userDevices).values({
          id: reset.candidateDeviceId,
          userId: req.user.id,
          deviceType: reset.candidateDeviceType,
          status: 'active',
          trustMethod: 'recovery',
          deviceGeneration: reset.newCryptoGeneration,
          keyFingerprint: reset.candidateDeviceKeyFingerprint,
          publicEncryptionKey: reset.candidateDeviceEncryptionPublicKey,
          publicSigningKey: reset.candidateDeviceSigningPublicKey,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          encryptedLabel: reset.candidateDeviceEncryptedLabel,
          labelNonce: reset.candidateDeviceLabelNonce,
          certificatePayload: reset.candidateDeviceCertificatePayload,
          certificateSignature: reset.candidateDeviceCertificateSignature,
          activatedAt: now,
          lastSeenAt: now,
        }).returning())[0]!;

        await tx.update(vaultKeyEnvelopes).set({
          status: 'revoked', revokedAt: now, revocationReason: 'account_crypto_reset',
        }).where(and(
          eq(vaultKeyEnvelopes.recipientUserId, req.user.id),
          inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
        ));
        if (oldDeviceIds.length) {
          await tx.update(vaultKeyEnvelopes).set({
            status: 'revoked', revokedAt: now, revocationReason: 'account_crypto_reset',
          }).where(and(
            inArray(vaultKeyEnvelopes.recipientDeviceId, oldDeviceIds),
            inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
          ));
        }
        const envelopeTaskReconciliation = await reconcilePendingEnvelopeTasksForProfile(
          tx,
          req.user.id,
          reset.newCryptoGeneration,
          now,
        );

        await tx.delete(extensionSessions).where(eq(extensionSessions.userId, req.user.id));
        await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, req.user.id));
        await tx.update(deviceEnrollmentRequests).set({ status: 'rejected' }).where(and(
          eq(deviceEnrollmentRequests.userId, req.user.id),
          inArray(deviceEnrollmentRequests.status, ['pending', 'approved']),
        ));
        await tx.delete(sessionUnlockChallenges).where(eq(sessionUnlockChallenges.userId, req.user.id));
        await tx.delete(sessions).where(and(
          eq(sessions.userId, req.user.id),
          ne(sessions.id, req.sessionRow.id),
        ));
        const activatedSession = (await tx.update(sessions).set({
          locked: false,
          unlockedDeviceId: candidateDevice.id,
          unlockedAt: now,
          unlockGeneration: sql`${sessions.unlockGeneration} + 1`,
        }).where(and(
          eq(sessions.id, req.sessionRow.id),
          eq(sessions.userId, req.user.id),
        )).returning({ id: sessions.id }))[0];
        if (!activatedSession) throw new AccountResetConflictError('当前登录已经失效');

        const rekeyTasks: Array<{ vaultId: string; taskId: string; fromEpoch: number; toEpoch: number }> = [];
        if (affectedVaultIds.length) {
          const states = await tx.select().from(vaultCryptoStates).where(and(
            inArray(vaultCryptoStates.vaultId, affectedVaultIds),
            eq(vaultCryptoStates.storageMode, 'e2ee'),
          )).for('update');
          for (const state of states) {
            if (!state.activeEpoch) continue;
            const toEpoch = state.activeEpoch + 1;
            let task = (await tx.select().from(vaultRekeyJobs).where(and(
              eq(vaultRekeyJobs.vaultId, state.vaultId),
              inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
            )).for('update').limit(1))[0];
            if (task) {
              task = (await tx.update(vaultRekeyJobs).set({
                reason: 'device_compromise',
                initiatedByUserId: req.user.id,
                initiatedByDeviceId: candidateDevice.id,
                updatedAt: now,
              }).where(eq(vaultRekeyJobs.id, task.id)).returning())[0]!;
              await tx.update(vaultKeyEpochs).set({ reason: 'device_compromise' }).where(and(
                eq(vaultKeyEpochs.vaultId, task.vaultId),
                eq(vaultKeyEpochs.epoch, task.toEpoch),
              ));
            } else {
              const pendingDigest = (label: string) => sha256(canonicalJson({
                kind: 'pending-rekey-commitment',
                label,
                protocol: 'lm-e2ee-v1',
                vaultId: state.vaultId,
                epoch: toEpoch,
              } as never));
              await tx.insert(vaultKeyEpochs).values({
                vaultId: state.vaultId,
                epoch: toEpoch,
                previousEpoch: state.activeEpoch,
                status: 'preparing',
                reason: 'device_compromise',
                metadataKeyCommitment: pendingDigest('metadata'),
                contentKeyCommitment: pendingDigest('content'),
                recipientSetDigest: pendingDigest('recipients'),
                createdByUserId: req.user.id,
                createdByDeviceId: candidateDevice.id,
              }).onConflictDoNothing();
              const priorTask = (await tx.select().from(vaultRekeyJobs).where(and(
                eq(vaultRekeyJobs.vaultId, state.vaultId),
                eq(vaultRekeyJobs.toEpoch, toEpoch),
              )).for('update').limit(1))[0];
              task = priorTask
                ? (await tx.update(vaultRekeyJobs).set({
                    status: 'pending',
                    reason: 'device_compromise',
                    freezeGeneration: state.accessGeneration + 1,
                    initiatedByUserId: req.user.id,
                    initiatedByDeviceId: candidateDevice.id,
                    lastErrorCode: null,
                    updatedAt: now,
                  }).where(eq(vaultRekeyJobs.id, priorTask.id)).returning())[0]!
                : (await tx.insert(vaultRekeyJobs).values({
                    vaultId: state.vaultId,
                    fromEpoch: state.activeEpoch,
                    toEpoch,
                    reason: 'device_compromise',
                    status: 'pending',
                    freezeGeneration: state.accessGeneration + 1,
                    initiatedByUserId: req.user.id,
                    initiatedByDeviceId: candidateDevice.id,
                    startedAt: now,
                  }).returning())[0]!;
            }
            await tx.update(vaultCryptoStates).set({
              writeState: 'rekeying',
              accessGeneration: state.accessGeneration + 1,
              rowVersion: state.rowVersion + 1,
              updatedAt: now,
            }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
            await tx.insert(accountCryptoResetVaults).values({
              requestId: reset.id,
              vaultId: state.vaultId,
              rekeyJobId: task.id,
            });
            rekeyTasks.push({
              vaultId: state.vaultId,
              taskId: task.id,
              fromEpoch: task.fromEpoch,
              toEpoch: task.toEpoch,
            });
            collect(await recordSyncEvent(tx, {
              type: 'vault.rekey_required',
              vaultId: state.vaultId,
              itemId: null,
              payload: { pendingEpoch: task.toEpoch, taskId: task.id },
            }));
          }
        }
        for (const vaultId of envelopeTaskReconciliation.vaultIds) {
          if (rekeyTasks.some((task) => task.vaultId === vaultId)) continue;
          collect(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed',
            vaultId,
            itemId: null,
            payload: { recipientProfileChanged: true },
          }));
        }

        const activatedReset = (await tx.update(accountCryptoResetRequests).set({
          status: 'activated',
          activatedAt: now,
        }).where(and(
          eq(accountCryptoResetRequests.id, reset.id),
          eq(accountCryptoResetRequests.status, 'approved'),
        )).returning())[0];
        if (!activatedReset) throw new AccountResetConflictError('账户加密身份重置请求已经变化');

        for (const revoked of revokedDevices) {
          collect(await recordSyncEvent(tx, {
            type: 'device.revoked',
            vaultId: '00000000-0000-0000-0000-000000000000',
            itemId: null,
            payload: { deviceId: revoked.id, userId: req.user.id },
          }));
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'crypto.account_reset.activate',
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            request: await accountResetDto(tx, activatedReset),
            profile: toCryptoProfileDto(updatedProfile),
            device: toCryptoDeviceDto(candidateDevice),
            revokedDeviceCount: revokedDevices.length,
            affectedVaultIds: rekeyTasks.map((task) => task.vaultId),
            rekeyTasks,
          },
        };
      }, commandIdentity('crypto.account_reset.activate', { requestId: req.params.requestId, ...req.body }));
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof AccountResetConflictError || isUniqueViolation(error)) {
        return conflict(reply, error instanceof Error ? error.message : '账户加密身份重置发生冲突');
      }
      throw error;
    }
  });
}

export function mergeAccountResetAffectedVaultIds(
  userEnvelopeRows: Array<{ vaultId: string }>,
  deviceEnvelopeRows: Array<{ vaultId: string }>,
  authorizedVaults: Array<{ vaultId: string }>,
): string[] {
  return [...new Set([
    ...userEnvelopeRows.map((entry) => entry.vaultId),
    ...deviceEnvelopeRows.map((entry) => entry.vaultId),
    ...authorizedVaults.map((entry) => entry.vaultId),
  ])];
}

function commandIdentity(commandName: string, request: unknown) {
  return { commandName, requestDigest: sha256(canonicalJson(request as never)) };
}

async function expireAccountCryptoResetRequests(db: DbOrTx): Promise<void> {
  await db.update(accountCryptoResetRequests).set({
    status: 'expired',
    expiredAt: new Date(),
    lastErrorCode: 'request_expired',
  }).where(and(
    inArray(accountCryptoResetRequests.status, ['pending', 'approved']),
    lte(accountCryptoResetRequests.expiresAt, new Date()),
  ));
}

async function accountResetDto(
  db: DbOrTx,
  row: typeof accountCryptoResetRequests.$inferSelect,
) {
  const approvals = await db.select({ userId: accountCryptoResetApprovals.approverUserId })
    .from(accountCryptoResetApprovals)
    .where(eq(accountCryptoResetApprovals.requestId, row.id));
  const affectedVaults = await db.select({ vaultId: accountCryptoResetVaults.vaultId })
    .from(accountCryptoResetVaults)
    .where(eq(accountCryptoResetVaults.requestId, row.id));
  return {
    id: row.id,
    targetUserId: row.targetUserId,
    expectedProfileVersion: row.expectedProfileVersion,
    expectedKeyVersion: row.expectedCryptoGeneration,
    newKeyVersion: row.newCryptoGeneration,
    suite: 'lm-e2ee-v1' as const,
    kdf: {
      algorithm: 'argon2id13' as const,
      memoryKiB: 65_536 as const,
      iterations: 3 as const,
      parallelism: 1 as const,
      salt: encodeBase64Url(row.kdfSalt),
      outputBytes: 32 as const,
    },
    encryptedAccountBundle: {
      suite: 'lm-e2ee-v1' as const,
      aadVersion: 1 as const,
      nonce: encodeBase64Url(row.wrappedAccountKeyNonce),
      ciphertext: encodeBase64Url(row.wrappedAccountKeyCiphertext),
    },
    encryptionPublicKey: encodeBase64Url(row.publicEncryptionKey),
    signingPublicKey: encodeBase64Url(row.publicSigningKey),
    candidateDevice: {
      id: row.candidateDeviceId,
      deviceType: row.candidateDeviceType,
      encryptedLabel: row.candidateDeviceEncryptedLabel && row.candidateDeviceLabelNonce
        ? {
            suite: 'lm-e2ee-v1' as const,
            aadVersion: 1 as const,
            nonce: encodeBase64Url(row.candidateDeviceLabelNonce),
            ciphertext: encodeBase64Url(row.candidateDeviceEncryptedLabel),
          }
        : null,
      encryptionPublicKey: encodeBase64Url(row.candidateDeviceEncryptionPublicKey),
      signingPublicKey: encodeBase64Url(row.candidateDeviceSigningPublicKey),
      certificate: encodeBase64Url(row.candidateDeviceCertificatePayload),
      certificateSignature: encodeBase64Url(row.candidateDeviceCertificateSignature),
    },
    requestDigest: encodeBase64Url(row.requestDigest),
    status: row.status,
    approvalUserIds: approvals.map((approval) => approval.userId),
    affectedVaultIds: affectedVaults.map((entry) => entry.vaultId),
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    approvedAt: row.approvedAt?.toISOString() ?? null,
    activatedAt: row.activatedAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
    expiredAt: row.expiredAt?.toISOString() ?? null,
    lastErrorCode: row.lastErrorCode,
  };
}

function withoutKeys<T extends Record<string, unknown>, K extends keyof T>(
  input: T,
  keys: readonly K[],
): Omit<T, K> {
  const copy = { ...input };
  for (const key of keys) delete copy[key];
  return copy;
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

function conflict(reply: FastifyReply, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', message } as never);
}

function notFoundBody(message: string) {
  return { statusCode: 404, error: 'Not Found', message };
}
