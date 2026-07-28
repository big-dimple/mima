import { createHash, randomBytes, randomInt, randomUUID } from 'node:crypto';
import { and, desc, eq, inArray, isNull, max } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  CompleteCryptoUnlockRequestSchema,
  EncryptedContentRequestSchema,
  ExtensionSessionResponseSchema,
  PairingCodeResponseSchema,
  VaultKeyEnvelopeInputSchema,
  EXTENSION_SESSION_TTL_MS,
  ITEM_METADATA_FORMAT_HEADER,
  ITEM_METADATA_FORMAT_VERSION,
  PAIRING_CODE_TTL_MS,
} from '@mima/contracts';
import { canReveal } from '@mima/domain';
import {
  canonicalJson,
  createUnlockChallenge,
  assertExtensionTrustedUnlockRequest,
  EXTENSION_TRUSTED_UNLOCK_PROTOCOL,
  sealBytes,
  utf8,
  verifyUnlockChallenge,
  type UnlockChallenge as E2eeUnlockChallenge,
} from '@mima/e2ee';
import {
  deviceEnrollmentRequests,
  encryptedItemKeyWraps,
  encryptedItemMetadataVersions,
  encryptedItemSecretVersions,
  encryptedVaultHeaders,
  enterpriseRecoveryKeys,
  extensionPairingCodes,
  extensionSessions,
  items,
  sessionUnlockChallenges,
  sessions,
  syncEvents,
  userCryptoProfiles,
  userDevices,
  vaultCryptoStates,
  vaultKeyEnvelopes,
} from '../db/schema.ts';
import { CredentialAttemptLimiter } from '../auth/attempt-limiter.ts';
import { getVaultAccess, listAccessibleVaults, listVaultMemberships } from '../services/access.ts';
import { auditStandalone } from '../services/audit.ts';
import { retainExtensionSessionHandoff } from '../services/extension-sessions.ts';
import {
  decodeBase64Url,
  encodeBase64Url,
  encodeCipherBlob,
  envelopeSignerProfiles,
  equalDigest,
  getActiveDevice,
  getCryptoProfile,
  parseDeviceCertificate,
  publicKeyFingerprint,
  sha256,
  toCryptoDeviceDto,
  toCryptoProfileDto,
  toEnvelopeDto,
  verifyCommandSignature,
  verifyDetachedBytes,
  verifyVaultEnvelope,
} from '../services/e2ee.ts';
import { capabilityForRole } from '../services/vault-envelope-tasks.ts';
import { lockRecipientSets } from '../services/recipient-set-lock.ts';
import { hashToken, newToken } from '../plugins/auth.ts';

class ExtensionRecipientSnapshotChangedError extends Error {}
import { toMembershipDto } from '../services/mappers.ts';

const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const EnrollmentParams = z.object({ enrollmentId: z.string().uuid() });
const ItemParams = z.object({ itemId: z.string().uuid() });
const PairingClaimSchema = z.object({
  code: z.string().min(6).max(12),
  device: z.object({
    id: z.string().uuid(),
    deviceType: z.literal('extension'),
    encryptionPublicKey: z.string().min(1),
    signingPublicKey: z.string().min(1),
    joinChannelPublicKey: z.string().min(1),
    fingerprint: z.string().min(8).max(120),
  }),
  existingDeviceProof: z.string().min(1).optional(),
});
const EnrollmentApprovalSchema = z.object({
  approverDeviceId: z.string().uuid(),
  certificate: z.string().min(1),
  certificateSignature: z.string().min(1),
  envelopes: z.array(VaultKeyEnvelopeInputSchema).max(1000),
  approvalSignature: z.string().min(1),
});
const TrustedUnlockRequestSchema = z.object({
  protocol: z.literal(EXTENSION_TRUSTED_UNLOCK_PROTOCOL),
  requestId: z.string().uuid(),
  issuedAt: z.string().min(1),
  expiresAt: z.string().min(1),
  accountId: z.string().min(1),
  accountKeyVersion: z.number().int().positive(),
  deviceId: z.string().uuid(),
  deviceEncryptionPublicKey: z.string().min(1),
  deviceSigningPublicKey: z.string().min(1),
  fingerprint: z.string().min(8).max(120),
  recordDigest: z.string().min(1),
  ephemeralEncryptionPublicKey: z.string().min(1),
});
const ResumeExtensionSessionSchema = z.object({
  approverDeviceId: z.string().uuid(),
  trustedRequest: TrustedUnlockRequestSchema,
  signature: z.string().min(1),
});

export function registerE2eeExtensionRoutes(app: FastifyInstance): void {
  const { db, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const pairingAttempts = new CredentialAttemptLimiter(db);

  r.post('/api/v2/extension/pairing', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: { tags: ['e2ee-extension'], response: { 200: PairingCodeResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    if (req.sessionRow.locked || !req.sessionRow.unlockedDeviceId) return locked(reply);
    const code = generatePairingCode();
    const expiresAt = new Date(Date.now() + PAIRING_CODE_TTL_MS);
    await db.insert(extensionPairingCodes).values({
      code,
      userId: req.user.id,
      sessionId: req.sessionRow.id,
      expiresAt,
    });
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'extension.e2ee.pairing.create',
      success: true,
      details: {},
    });
    return { code, expiresAt: expiresAt.toISOString() };
  });

  r.post('/api/v2/extension/pairing/claim', {
    schema: { tags: ['e2ee-extension'], body: PairingClaimSchema, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const attemptKey = `extension-v2-claim:${req.ip}`;
    const retryAfter = await pairingAttempts.retryAfterSeconds(attemptKey);
    if (retryAfter > 0) {
      reply.header('retry-after', String(retryAfter));
      return reply.code(429).send({ statusCode: 429, error: 'Too Many Requests', message: '配对尝试过于频繁，请稍后再试' } as never);
    }
    let encryptionPublicKey; let signingPublicKey; let joinChannelPublicKey;
    try {
      encryptionPublicKey = decodeBase64Url(req.body.device.encryptionPublicKey, { exact: 32 });
      signingPublicKey = decodeBase64Url(req.body.device.signingPublicKey, { exact: 32 });
      joinChannelPublicKey = decodeBase64Url(req.body.device.joinChannelPublicKey, { exact: 32 });
    } catch {
      await pairingAttempts.recordFailure(attemptKey);
      return unauthorized(reply, '扩展设备信息校验失败，请重新生成配对码');
    }
    if (extensionFingerprint(req.body.device) !== req.body.device.fingerprint) {
      await pairingAttempts.recordFailure(attemptKey);
      return unauthorized(reply, '设备指纹不匹配');
    }
    if (req.body.existingDeviceProof) {
      const proofBytes = extensionClaimBytes(req.body.code, req.body.device);
      const valid = await verifyDetachedBytes(req.body.existingDeviceProof, req.body.device.signingPublicKey, proofBytes);
      proofBytes.fill(0);
      if (!valid) {
        await pairingAttempts.recordFailure(attemptKey);
        return unauthorized(reply, '扩展设备授权校验失败，请重新生成配对码');
      }
    }
    try {
      const claimed = await db.transaction(async (tx) => {
        const code = (await tx.select().from(extensionPairingCodes).where(and(
          eq(extensionPairingCodes.code, req.body.code.toUpperCase()),
          isNull(extensionPairingCodes.usedAt),
        )).for('update').limit(1))[0];
        const now = new Date();
        if (!code || code.expiresAt <= now || !code.sessionId) return null;
        const sourceSession = (await tx.select().from(sessions).where(eq(sessions.id, code.sessionId)).limit(1))[0];
        if (!sourceSession || sourceSession.locked || sourceSession.expiresAt <= now) return null;
        const pollToken = randomBytes(32);
        const enrollment = (await tx.insert(deviceEnrollmentRequests).values({
          userId: code.userId,
          requestedBySessionId: code.sessionId,
          requestedDeviceId: req.body.device.id,
          deviceType: 'extension',
          requestingKeyFingerprint: req.body.device.fingerprint,
          requestingEncryptionPublicKey: encryptionPublicKey,
          requestingSigningPublicKey: signingPublicKey,
          joinChannelPublicKey,
          encryptedLabel: null,
          labelNonce: null,
          challengeHash: sha256(pollToken),
          expiresAt: new Date(now.getTime() + 5 * 60_000),
        }).returning())[0]!;
        await tx.update(extensionPairingCodes).set({
          usedAt: now,
          enrollmentRequestId: enrollment.id,
        }).where(eq(extensionPairingCodes.code, code.code));
        return { enrollment, pollToken: encodeBase64Url(pollToken) };
      });
      if (!claimed) {
        await pairingAttempts.recordFailure(attemptKey);
        return unauthorized(reply, '配对码无效、已使用或来源会话已锁定');
      }
      await pairingAttempts.clear(attemptKey);
      return {
        enrollmentId: claimed.enrollment.id,
        expiresAt: claimed.enrollment.expiresAt.toISOString(),
        fingerprint: claimed.enrollment.requestingKeyFingerprint,
        status: 'pending',
        pollToken: claimed.pollToken,
      };
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '该设备已有进行中的配对请求');
      throw error;
    }
  });

  r.get('/api/v2/extension/pairing/:enrollmentId', {
    schema: { tags: ['e2ee-extension'], params: EnrollmentParams, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const pollToken = req.headers['x-pairing-token'];
    if (typeof pollToken !== 'string') return unauthorized(reply, '缺少配对轮询凭证');
    let pollHash;
    try { pollHash = sha256(decodeBase64Url(pollToken, { exact: 32 })); }
    catch { return unauthorized(reply, '配对轮询凭证无效'); }
    const enrollment = (await db.select().from(deviceEnrollmentRequests)
      .where(eq(deviceEnrollmentRequests.id, req.params.enrollmentId)).limit(1))[0];
    if (!enrollment || !equalDigest(enrollment.challengeHash, pollHash)) return unauthorized(reply, '配对请求不存在或轮询凭证无效');
    if (enrollment.expiresAt <= new Date() && enrollment.status === 'pending') {
      await db.update(deviceEnrollmentRequests).set({ status: 'expired' }).where(eq(deviceEnrollmentRequests.id, enrollment.id));
      return pairingStatus(enrollment, 'expired');
    }
    if ((enrollment.status === 'approved' || enrollment.status === 'claimed') && enrollment.approvalCiphertext) {
      if (enrollment.status === 'approved') {
        await db.update(deviceEnrollmentRequests).set({ status: 'claimed', claimedAt: new Date() })
          .where(and(eq(deviceEnrollmentRequests.id, enrollment.id), eq(deviceEnrollmentRequests.status, 'approved')));
      }
      return { ...pairingStatus(enrollment, 'approved'), sealedApproval: encodeBase64Url(enrollment.approvalCiphertext) };
    }
    return pairingStatus(enrollment, enrollment.status === 'rejected' ? 'rejected' : enrollment.status === 'expired' ? 'expired' : 'pending');
  });

  r.get('/api/v2/extension/enrollments', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-extension'], response: { 200: z.array(z.unknown()), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req) => {
    const rows = await db.select().from(deviceEnrollmentRequests)
      .where(eq(deviceEnrollmentRequests.userId, req.user.id)).orderBy(desc(deviceEnrollmentRequests.createdAt));
    return rows.map(enrollmentDto);
  });

  r.get('/api/v2/extension/enrollments/:enrollmentId', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee-extension'], params: EnrollmentParams, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const row = (await db.select().from(deviceEnrollmentRequests).where(and(
      eq(deviceEnrollmentRequests.id, req.params.enrollmentId),
      eq(deviceEnrollmentRequests.userId, req.user.id),
    )).limit(1))[0];
    if (!row) return reply.code(404).send(notFoundBody('配对请求不存在') as never);
    return enrollmentDto(row);
  });

  r.post('/api/v2/extension/enrollments/:enrollmentId/approve', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: { tags: ['e2ee-extension'], params: EnrollmentParams, body: EnrollmentApprovalSchema, response: { 200: z.object({ ok: z.literal(true) }), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    if (req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== req.body.approverDeviceId) return locked(reply);
    const enrollment = (await db.select().from(deviceEnrollmentRequests).where(and(
      eq(deviceEnrollmentRequests.id, req.params.enrollmentId),
      eq(deviceEnrollmentRequests.userId, req.user.id),
    )).limit(1))[0];
    if (!enrollment || enrollment.status !== 'pending' || enrollment.expiresAt <= new Date()) return conflict(reply, '配对请求已失效或已经处理');
    const [approver, profile, sourceSession] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.approverDeviceId),
      getCryptoProfile(db, req.user.id),
      db.select().from(sessions).where(eq(sessions.id, enrollment.requestedBySessionId)).limit(1),
    ]);
    if (!approver || !profile || !sourceSession[0] || sourceSession[0].locked || sourceSession[0].expiresAt <= new Date()) {
      return conflict(reply, '配对来源会话或批准设备已失效');
    }
    const profileSigningPublicKey = encodeBase64Url(profile.publicSigningKey);
    let certificateBytes;
    let certificate: import('@mima/e2ee').DeviceCertificate;
    try {
      ({ bytes: certificateBytes, certificate } = await parseDeviceCertificate(
        req.body.certificate,
        req.body.certificateSignature,
        profileSigningPublicKey,
        {
          accountId: req.user.id,
          deviceId: enrollment.requestedDeviceId,
          deviceType: 'extension',
          encryptionPublicKey: encodeBase64Url(enrollment.requestingEncryptionPublicKey),
          signingPublicKey: encodeBase64Url(enrollment.requestingSigningPublicKey),
          keyVersion: profile.cryptoGeneration,
        },
      ));
    } catch {
      return badRequest(reply, '设备证书无效');
    }
    if (certificate.deviceId !== enrollment.requestedDeviceId || extensionFingerprint({
      id: certificate.deviceId,
      encryptionPublicKey: certificate.encryptionPublicKey,
      signingPublicKey: certificate.signingPublicKey,
    }) !== enrollment.requestingKeyFingerprint) return badRequest(reply, '设备证书与配对指纹不匹配');
    const unsigned = { enrollmentId: enrollment.id, ...without(req.body, 'approvalSignature') };
    if (!await verifyCommandSignature(req.body.approvalSignature, encodeBase64Url(approver.publicSigningKey), 'crypto.extension.approve', {
      userId: req.user.id,
      request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认这次配对，请重新生成配对码');
    const activeAccesses = (await listAccessibleVaults(db, req.user)).filter((access) => canReveal(access.role));
    const states = activeAccesses.length ? await db.select().from(vaultCryptoStates).where(and(
      inArray(vaultCryptoStates.vaultId, activeAccesses.map((access) => access.vault.id)),
      eq(vaultCryptoStates.storageMode, 'e2ee'),
    )) : [];
    const requiredVaultIds = new Set(states.map((state) => state.vaultId));
    const envelopeVaultIds = new Set(req.body.envelopes.map((envelope) => envelope.vaultId));
    if (!sameSet(requiredVaultIds, envelopeVaultIds)) return badRequest(reply, '扩展未能取得全部可用密码库的访问，请重新生成配对码');
    for (const envelope of req.body.envelopes) {
      const state = states.find((candidate) => candidate.vaultId === envelope.vaultId);
      if (!state?.activeEpoch || envelope.epoch !== state.activeEpoch || envelope.recipientKind !== 'device' ||
        envelope.recipientId !== certificate.deviceId ||
        envelope.recipientKeyVersion !== certificate.keyVersion || envelope.capability !== 'full' ||
        envelope.signerUserId !== req.user.id || envelope.signerKeyVersion !== profile.cryptoGeneration ||
        !await verifyVaultEnvelope(envelope, profileSigningPublicKey)
      ) return badRequest(reply, '扩展访问校验失败，请重新生成配对码');
    }
    const token = newToken();
    const expiresAt = new Date(Date.now() + EXTENSION_SESSION_TTL_MS);
    const device = {
      id: certificate.deviceId,
      userId: req.user.id,
      deviceType: 'extension' as const,
      encryptedLabel: null,
      encryptionPublicKey: encodeBase64Url(enrollment.requestingEncryptionPublicKey),
      signingPublicKey: encodeBase64Url(enrollment.requestingSigningPublicKey),
      certificate: req.body.certificate,
      certificateSignature: req.body.certificateSignature,
      keyVersion: certificate.keyVersion,
      trustedAt: new Date().toISOString(),
      lastSeenAt: null,
      revokedAt: null,
    };
    const approvalPlaintext = Buffer.from(JSON.stringify({
      session: { token, expiresAt: expiresAt.toISOString(), user: req.user },
      device,
      profileSigningPublicKey,
    }));
    const sealedApproval = await sealBytes(approvalPlaintext, encodeBase64Url(enrollment.joinChannelPublicKey));
    approvalPlaintext.fill(0);
    const sealedBytes = decodeBase64Url(sealedApproval, { min: 49, max: 500_000 });
    try {
      await db.transaction(async (tx) => {
        await lockRecipientSets(tx, [req.user.id]);
        const currentEnrollment = await tx.select().from(deviceEnrollmentRequests).where(and(
          eq(deviceEnrollmentRequests.id, enrollment.id),
          eq(deviceEnrollmentRequests.userId, req.user.id),
        )).for('update').limit(1);
        const currentApprover = await getActiveDevice(tx, req.user.id, approver.id);
        const currentProfile = await getCryptoProfile(tx, req.user.id);
        const currentSourceSession = await tx.select().from(sessions)
          .where(eq(sessions.id, enrollment.requestedBySessionId)).for('share').limit(1);
        if (
          !currentEnrollment[0] || currentEnrollment[0].status !== 'pending' ||
          currentEnrollment[0].expiresAt <= new Date() || !currentApprover || !currentProfile ||
          !currentSourceSession[0] || currentSourceSession[0].locked || currentSourceSession[0].expiresAt <= new Date() ||
          currentProfile.cryptoGeneration !== profile.cryptoGeneration ||
          !Buffer.from(currentProfile.publicSigningKey).equals(profile.publicSigningKey)
        ) throw new ExtensionRecipientSnapshotChangedError();
        const currentAccesses = (await listAccessibleVaults(tx, req.user))
          .filter((access) => canReveal(access.role));
        const currentStates = currentAccesses.length ? await tx.select().from(vaultCryptoStates).where(and(
          inArray(vaultCryptoStates.vaultId, currentAccesses.map((access) => access.vault.id)),
          eq(vaultCryptoStates.storageMode, 'e2ee'),
        )) : [];
        const currentRequiredVaultIds = new Set(currentStates.map((state) => state.vaultId));
        if (!sameSet(currentRequiredVaultIds, envelopeVaultIds)) {
          throw new ExtensionRecipientSnapshotChangedError();
        }
        for (const envelope of req.body.envelopes) {
          const state = currentStates.find((candidate) => candidate.vaultId === envelope.vaultId);
          if (!state?.activeEpoch || envelope.epoch !== state.activeEpoch) {
            throw new ExtensionRecipientSnapshotChangedError();
          }
        }
        const now = new Date();
        await tx.insert(userDevices).values({
          id: certificate.deviceId,
          userId: req.user.id,
          deviceType: 'extension',
          status: 'active',
          trustMethod: 'device_approval',
          deviceGeneration: certificate.keyVersion,
          keyFingerprint: publicKeyFingerprint(encodeBase64Url(enrollment.requestingSigningPublicKey)),
          publicEncryptionKey: enrollment.requestingEncryptionPublicKey,
          publicSigningKey: enrollment.requestingSigningPublicKey,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          encryptedLabel: null,
          labelNonce: null,
          certificatePayload: certificateBytes,
          certificateSignature: decodeBase64Url(req.body.certificateSignature, { exact: 64 }),
          approvedByDeviceId: approver.id,
          activatedAt: now,
        });
        for (const envelope of req.body.envelopes) {
          const ciphertext = decodeBase64Url(envelope.sealedKeyBundle, { min: 49, max: 10_000 });
          await tx.insert(vaultKeyEnvelopes).values({
            vaultId: envelope.vaultId,
            keyEpoch: envelope.epoch,
            recipientKind: 'device',
            accessScope: 'full',
            recipientDeviceId: certificate.deviceId,
            recipientKeyFingerprint: publicKeyFingerprint(encodeBase64Url(enrollment.requestingEncryptionPublicKey)),
            authorizationKind: 'direct',
            envelopeVersion: certificate.keyVersion,
            ciphertext,
            ciphertextDigest: sha256(ciphertext),
            senderDeviceId: approver.id,
            signerUserId: req.user.id,
            signerKeyVersion: currentProfile.cryptoGeneration,
            signerPublicKey: currentProfile.publicSigningKey,
            signature: decodeBase64Url(envelope.signature, { exact: 64 }),
            status: 'active',
            activatedAt: now,
          });
        }
        await tx.insert(extensionSessions).values({
          tokenHash: hashToken(token),
          userId: req.user.id,
          deviceId: certificate.deviceId,
          securityGeneration: certificate.keyVersion,
          expiresAt,
        });
        const updated = await tx.update(deviceEnrollmentRequests).set({
          status: 'approved',
          approvedByDeviceId: approver.id,
          approvalCiphertext: sealedBytes,
          approvalNonce: null,
          approvalAlgorithm: 'x25519-sealed-box',
          approvalSignature: decodeBase64Url(req.body.approvalSignature, { exact: 64 }),
          approvedAt: now,
        }).where(and(
          eq(deviceEnrollmentRequests.id, enrollment.id),
          eq(deviceEnrollmentRequests.status, 'pending'),
        )).returning({ id: deviceEnrollmentRequests.id });
        if (updated.length !== 1) throw new Error('enrollment changed');
      });
      await auditStandalone(db, audit, {
        actorUserId: req.user.id,
        action: 'extension.e2ee.enrollment.approve',
        success: true,
        details: {},
      });
      return { ok: true as const };
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '该扩展设备已经注册');
      if (error instanceof ExtensionRecipientSnapshotChangedError) {
        return conflict(reply, '可访问密码库、主密码身份或设备状态刚发生变化，请刷新后重新批准配对');
      }
      throw error;
    }
  });

  r.post('/api/v2/extension/session/resume', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['e2ee-extension'],
      body: ResumeExtensionSessionSchema,
      response: { 200: ExtensionSessionResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (
      req.sessionRow.locked
      || req.sessionRow.unlockedDeviceId !== req.body.approverDeviceId
    ) return locked(reply);
    try {
      assertExtensionTrustedUnlockRequest(req.body.trustedRequest);
      decodeBase64Url(req.body.trustedRequest.ephemeralEncryptionPublicKey, { exact: 32 });
      decodeBase64Url(req.body.trustedRequest.recordDigest, { exact: 32 });
    } catch {
      return badRequest(reply, '扩展续期请求无效或已经过期');
    }
    const [approver, target, profile] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.approverDeviceId),
      getActiveDevice(db, req.user.id, req.body.trustedRequest.deviceId),
      getCryptoProfile(db, req.user.id),
    ]);
    if (!approver || !target || !profile) return forbidden(reply, '扩展设备未获得当前账号授权');
    const trustedRequest = req.body.trustedRequest;
    const targetEncryptionKey = encodeBase64Url(target.publicEncryptionKey);
    const targetSigningKey = encodeBase64Url(target.publicSigningKey);
    if (
      target.deviceType !== 'extension'
      || trustedRequest.accountId !== req.user.id
      || trustedRequest.accountKeyVersion !== profile.cryptoGeneration
      || target.deviceGeneration !== profile.cryptoGeneration
      || trustedRequest.deviceEncryptionPublicKey !== targetEncryptionKey
      || trustedRequest.deviceSigningPublicKey !== targetSigningKey
      || trustedRequest.fingerprint !== extensionFingerprint({
        id: target.id,
        encryptionPublicKey: targetEncryptionKey,
        signingPublicKey: targetSigningKey,
      })
    ) return forbidden(reply, '扩展设备未获得当前账号授权');
    const unsigned = {
      approverDeviceId: req.body.approverDeviceId,
      trustedRequest,
    };
    if (!await verifyCommandSignature(
      req.body.signature,
      encodeBase64Url(approver.publicSigningKey),
      'crypto.extension.session.resume',
      { userId: req.user.id, request: unsigned },
    )) return unauthorized(reply, '扩展连接验证失败，请重新打开扩展');

    const token = newToken();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + EXTENSION_SESSION_TTL_MS);
    try {
      await db.transaction(async (tx) => {
        const lockedTarget = (await tx.select({
          id: userDevices.id,
          deviceGeneration: userDevices.deviceGeneration,
        }).from(userDevices).where(and(
          eq(userDevices.id, target.id),
          eq(userDevices.userId, req.user.id),
          eq(userDevices.status, 'active'),
        )).for('update').limit(1))[0];
        if (!lockedTarget || lockedTarget.deviceGeneration !== target.deviceGeneration) {
          throw new ExtensionResumeTargetChangedError();
        }
        await tx.insert(extensionSessions).values({
          id: trustedRequest.requestId,
          tokenHash: hashToken(token),
          userId: req.user.id,
          deviceId: target.id,
          securityGeneration: target.deviceGeneration,
          expiresAt,
        });
        await retainExtensionSessionHandoff(tx, target.id, trustedRequest.requestId);
        await tx.update(userDevices).set({ lastSeenAt: now }).where(eq(userDevices.id, target.id));
      });
    } catch (error) {
      if (error instanceof ExtensionResumeTargetChangedError) {
        return forbidden(reply, '扩展设备的授权状态已经变化，请刷新工作台后重试');
      }
      if (isUniqueViolation(error)) return conflict(reply, '扩展续期请求已经处理，请重试');
      throw error;
    }
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'extension.e2ee.session.resume',
      success: true,
      details: {},
    });
    reply.header('cache-control', 'no-store');
    return { token, expiresAt: expiresAt.toISOString(), user: req.user };
  });

  registerExtensionCryptoRoutes(app, pairingAttempts);
}

function registerExtensionCryptoRoutes(
  app: FastifyInstance,
  attempts: CredentialAttemptLimiter,
): void {
  const { db, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();

  r.post('/api/v2/extension/unlock-challenges', {
    preHandler: [app.requireExtensionSession],
    schema: {
      tags: ['e2ee-extension'],
      body: z.object({ deviceId: z.string().uuid() }),
      response: { 200: z.object({ id: z.string().uuid(), challenge: z.string(), expiresAt: z.string() }), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (req.extensionSessionRow.deviceId !== req.body.deviceId) return forbidden(reply, '扩展会话与设备不匹配');
    const [device, profile] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.deviceId),
      getCryptoProfile(db, req.user.id),
    ]);
    if (!device || !profile) return unauthorized(reply, '扩展设备未授权');
    const id = randomUUID();
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + 60_000);
    const challenge = await createUnlockChallenge({
      challengeId: id,
      accountId: req.user.id,
      deviceId: device.id,
      sessionId: req.extensionSessionRow.id,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    });
    const encoded = Buffer.from(canonicalJson(challenge as never));
    await db.transaction(async (tx) => {
      await tx.delete(sessionUnlockChallenges).where(and(
        eq(sessionUnlockChallenges.extensionSessionId, req.extensionSessionRow.id),
        isNull(sessionUnlockChallenges.consumedAt),
      ));
      await tx.insert(sessionUnlockChallenges).values({
        id,
        extensionSessionId: req.extensionSessionRow.id,
        userId: req.user.id,
        deviceId: device.id,
        purpose: 'unlock',
        challengeHash: sha256(encoded),
        challengeNonce: decodeBase64Url(challenge.nonce, { exact: 32 }),
        sessionGeneration: req.extensionSessionRow.securityGeneration,
        profileVersion: profile.profileVersion,
        deviceGeneration: device.deviceGeneration,
        createdAt: issuedAt,
        expiresAt,
      });
    });
    reply.header('cache-control', 'no-store');
    return { id, challenge: encodeBase64Url(encoded), expiresAt: expiresAt.toISOString() };
  });

  r.post('/api/v2/extension/crypto-unlock', {
    preHandler: [app.requireExtensionSession],
    schema: {
      tags: ['e2ee-extension'],
      body: CompleteCryptoUnlockRequestSchema,
      response: { 200: z.object({ unlocked: z.literal(true) }), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (req.extensionSessionRow.deviceId !== req.body.deviceId) return forbidden(reply, '扩展会话与设备不匹配');
    const attemptKey = `extension-unlock:${req.ip}:${req.user.id}:${req.extensionSessionRow.id}`;
    const retryAfter = await attempts.retryAfterSeconds(attemptKey);
    if (retryAfter > 0) {
      reply.header('retry-after', String(retryAfter));
      return reply.code(429).send({ statusCode: 429, error: 'Too Many Requests', message: '解锁尝试过于频繁，请稍后再试' } as never);
    }
    const result = await db.transaction(async (tx) => {
      const challenge = (await tx.select().from(sessionUnlockChallenges).where(and(
        eq(sessionUnlockChallenges.id, req.body.challengeId),
        eq(sessionUnlockChallenges.userId, req.user.id),
        eq(sessionUnlockChallenges.deviceId, req.body.deviceId),
        eq(sessionUnlockChallenges.extensionSessionId, req.extensionSessionRow.id),
        isNull(sessionUnlockChallenges.consumedAt),
      )).for('update').limit(1))[0];
      const device = await getActiveDevice(tx, req.user.id, req.body.deviceId);
      const profile = await getCryptoProfile(tx, req.user.id);
      if (!challenge || !challenge.extensionSessionId || !device || !profile || challenge.expiresAt <= new Date() ||
        challenge.sessionGeneration !== req.extensionSessionRow.securityGeneration ||
        challenge.profileVersion !== profile.profileVersion ||
        challenge.deviceGeneration !== device.deviceGeneration
      ) return false;
      const signed: E2eeUnlockChallenge = {
        protocol: 'lm-e2ee-v1',
        kind: 'unlock-challenge',
        challengeId: challenge.id,
        accountId: challenge.userId,
        deviceId: challenge.deviceId,
        sessionId: challenge.extensionSessionId,
        nonce: encodeBase64Url(challenge.challengeNonce),
        issuedAt: challenge.createdAt.toISOString(),
        expiresAt: challenge.expiresAt.toISOString(),
      };
      const encoded = Buffer.from(canonicalJson(signed as never));
      const valid = Buffer.from(challenge.challengeHash).equals(sha256(encoded)) &&
        await verifyUnlockChallenge(
          { ...signed, signature: req.body.signature },
          encodeBase64Url(device.publicSigningKey),
        );
      encoded.fill(0);
      if (!valid) {
        await tx.update(sessionUnlockChallenges).set({
          failedAttempts: challenge.failedAttempts + 1,
          ...(challenge.failedAttempts >= 4 ? { consumedAt: new Date() } : {}),
        }).where(eq(sessionUnlockChallenges.id, challenge.id));
        return false;
      }
      const now = new Date();
      await tx.update(sessionUnlockChallenges).set({ verifiedAt: now, consumedAt: now })
        .where(eq(sessionUnlockChallenges.id, challenge.id));
      await tx.update(userDevices).set({ lastSeenAt: now }).where(eq(userDevices.id, device.id));
      return true;
    });
    if (!result) {
      await attempts.recordFailure(attemptKey);
      return unauthorized(reply, '扩展解锁确认已过期或无效，请重试');
    }
    await attempts.clear(attemptKey);
    return { unlocked: true as const };
  });

  r.get('/api/v2/extension/bootstrap', {
    preHandler: [app.requireExtensionSession],
    schema: { tags: ['e2ee-extension'], response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    if (!supportsCurrentItemMetadata(req.headers[ITEM_METADATA_FORMAT_HEADER])) return extensionUpgradeRequired(reply);
    if (!req.extensionSessionRow.deviceId) return unauthorized(reply, '扩展设备未绑定');
    return buildExtensionBootstrap(app, req.user, req.extensionSessionRow.deviceId);
  });

  r.post('/api/v2/extension/items/:itemId/content', {
    preHandler: [app.requireExtensionSession],
    schema: { tags: ['e2ee-extension'], params: ItemParams, body: EncryptedContentRequestSchema, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    if (!supportsCurrentItemMetadata(req.headers[ITEM_METADATA_FORMAT_HEADER])) return extensionUpgradeRequired(reply);
    if (!req.extensionSessionRow.deviceId || req.extensionSessionRow.deviceId !== req.body.deviceId) {
      return forbidden(reply, '扩展会话与设备不匹配');
    }
    const item = (await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1))[0];
    if (!item || item.deleted) return reply.code(404).send(notFoundBody('条目不存在') as never);
    const access = await getVaultAccess(db, req.user, item.vaultId);
    if (!access || !canReveal(access.role)) return forbidden(reply, '没有查看密码或敏感内容的权限');
    const device = await getActiveDevice(db, req.user.id, req.body.deviceId);
    if (!device) return unauthorized(reply, '扩展设备已撤销');
    const secretVersion = req.body.secretVersion ?? item.secretVersion;
    const intent = utf8(canonicalJson({
      deviceId: device.id,
      itemId: item.id,
      kind: 'encrypted-content-intent',
      protocol: 'lm-e2ee-v1',
      purpose: req.body.purpose,
      secretVersion,
    }));
    const validIntent = await verifyDetachedBytes(req.body.intentSignature, encodeBase64Url(device.publicSigningKey), intent);
    intent.fill(0);
    if (!validIntent) return unauthorized(reply, '扩展无法确认本次查看，请重新打开扩展后重试');
    const response = await encryptedContentResponse(db, item, secretVersion);
    if (!response) return conflict(reply, '条目内容暂时不完整，请刷新后重试');
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'item.e2ee.ciphertext_delivered',
      vaultId: item.vaultId,
      itemId: item.id,
      success: true,
      details: {},
    });
    return response;
  });

  r.delete('/api/v2/extension/session', {
    preHandler: [app.requireExtensionSession],
    schema: { tags: ['e2ee-extension'], response: { 200: z.object({ ok: z.literal(true) }), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req) => {
    if (req.extensionSessionRow.deviceId) {
      await db.delete(extensionSessions).where(and(
        eq(extensionSessions.deviceId, req.extensionSessionRow.deviceId),
        eq(extensionSessions.userId, req.extensionSessionRow.userId),
      ));
    } else {
      await db.delete(extensionSessions).where(eq(extensionSessions.id, req.extensionSessionRow.id));
    }
    return { ok: true as const };
  });
}

class ExtensionResumeTargetChangedError extends Error {}

async function buildExtensionBootstrap(
  app: FastifyInstance,
  user: import('@mima/contracts').SessionUser,
  deviceId: string,
) {
  const { db } = app.ctx;
  const profile = await getCryptoProfile(db, user.id);
  const devices = await db.select().from(userDevices).where(eq(userDevices.userId, user.id));
  const allAccesses = await listAccessibleVaults(db, user);
  const allStates = allAccesses.length ? await db.select().from(vaultCryptoStates).where(and(
    inArray(vaultCryptoStates.vaultId, allAccesses.map((access) => access.vault.id)),
    eq(vaultCryptoStates.storageMode, 'e2ee'),
  )) : [];
  const stateByVault = new Map(allStates.map((state) => [state.vaultId, state]));
  const accesses = allAccesses.filter((access) => stateByVault.has(access.vault.id));
  const vaultIds = accesses.map((access) => access.vault.id);
  const [memberships, headers, currentItems, recoveryRows, cursorRows] = await Promise.all([
    Promise.all(vaultIds.map((vaultId) => listVaultMemberships(db, vaultId))).then((rows) => rows.flat()),
    vaultIds.length ? db.select().from(encryptedVaultHeaders).where(inArray(encryptedVaultHeaders.vaultId, vaultIds)) : [],
    vaultIds.length ? db.select({ item: items, metadata: encryptedItemMetadataVersions })
      .from(items)
      .innerJoin(encryptedItemMetadataVersions, and(
        eq(encryptedItemMetadataVersions.itemId, items.id),
        eq(encryptedItemMetadataVersions.recordVersion, items.version),
      ))
      .innerJoin(vaultCryptoStates, and(
        eq(vaultCryptoStates.vaultId, items.vaultId),
        eq(vaultCryptoStates.activeEpoch, encryptedItemMetadataVersions.keyEpoch),
      ))
      .where(inArray(items.vaultId, vaultIds)) : [],
    db.select().from(enterpriseRecoveryKeys).where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1),
    db.select({ cursor: max(syncEvents.id) }).from(syncEvents),
  ]);
  const envelopeRows = vaultIds.length ? await db.select({
    envelope: vaultKeyEnvelopes,
    sender: userDevices,
    signer: userCryptoProfiles,
  }).from(vaultKeyEnvelopes)
    .innerJoin(userDevices, eq(userDevices.id, vaultKeyEnvelopes.senderDeviceId))
    .innerJoin(userCryptoProfiles, eq(userCryptoProfiles.userId, userDevices.userId))
    .where(and(
      inArray(vaultKeyEnvelopes.vaultId, vaultIds),
      eq(vaultKeyEnvelopes.status, 'active'),
    )) : [];
  const capabilityByVault = new Map(accesses.map(({ vault, role }) => [
    vault.id,
    capabilityForRole(role!),
  ]));
  const ownEnvelopes = envelopeRows.filter(({ envelope }) => {
    const state = stateByVault.get(envelope.vaultId);
    return state?.activeEpoch === envelope.keyEpoch &&
      capabilityByVault.get(envelope.vaultId) === envelope.accessScope &&
      (envelope.recipientUserId === user.id || envelope.recipientDeviceId === deviceId);
  });
  const activeHeaders = headers.filter((header) => {
    const state = stateByVault.get(header.vaultId);
    return state?.activeEpoch === header.keyEpoch && state.activeHeaderVersion === header.headerVersion;
  });
  const signerProfiles = envelopeSignerProfiles(ownEnvelopes);
  const revealVaultIds = new Set(accesses.filter((access) => canReveal(access.role)).map((access) => access.vault.id));
  const contents = [];
  for (const { item } of currentItems) {
    if (item.deleted || !revealVaultIds.has(item.vaultId)) continue;
    const content = await encryptedContentResponse(db, item, item.secretVersion);
    if (content) contents.push(content);
  }
  return {
    user,
    profile: profile ? toCryptoProfileDto(profile) : null,
    recoveryKey: recoveryRows[0] ? {
      id: recoveryRows[0].id,
      ceremonyId: recoveryRows[0].ceremonyId,
      keyFingerprint: recoveryRows[0].keyFingerprint,
      publicEncryptionKey: encodeBase64Url(recoveryRows[0].publicEncryptionKey),
      threshold: 2,
      shareCount: 3,
      status: recoveryRows[0].status,
      ceremonyEvidenceDigest: encodeBase64Url(recoveryRows[0].ceremonyEvidenceDigest),
      createdAt: recoveryRows[0].createdAt.toISOString(),
      retiredAt: recoveryRows[0].retiredAt?.toISOString() ?? null,
      cancelledAt: recoveryRows[0].cancelledAt?.toISOString() ?? null,
    } : null,
    devices: devices.map(toCryptoDeviceDto),
    vaults: accesses.map(({ vault }) => {
      const state = stateByVault.get(vault.id)!;
      const header = activeHeaders.find((candidate) =>
        candidate.vaultId === vault.id && candidate.keyEpoch === state.activeEpoch && candidate.headerVersion === state.activeHeaderVersion
      );
      return {
        id: vault.id,
        kind: vault.kind,
        ownerUserId: vault.ownerUserId,
        createdAt: vault.createdAt.toISOString(),
        updatedAt: vault.updatedAt.toISOString(),
        crypto: {
          vaultId: vault.id,
          status: state.writeState === 'rekeying' ? 'rekey_required' : 'e2ee',
          activeEpoch: state.activeEpoch ?? 0,
          pendingEpoch: null,
          encryptedHeader: header ? encodeCipherBlob(header.nonce, header.ciphertext) : null,
          migrationJobId: null,
          updatedAt: state.updatedAt.toISOString(),
        },
      };
    }),
    memberships: memberships.map(toMembershipDto),
    envelopes: ownEnvelopes.map(({ envelope, sender, signer }) => toEnvelopeDto(envelope, {
      userId: sender.userId,
      keyVersion: signer.cryptoGeneration,
    })),
    signerProfiles,
    headers: activeHeaders.map((header) => ({
      vaultId: header.vaultId,
      version: header.headerVersion,
      keyEpoch: header.keyEpoch,
      blob: encodeCipherBlob(header.nonce, header.ciphertext),
      updatedAt: header.createdAt.toISOString(),
      updatedBy: header.createdByDeviceId,
    })),
    items: currentItems.map(({ item, metadata }) => ({
      itemId: item.id,
      vaultId: item.vaultId,
      version: item.version,
      secretVersion: item.secretVersion,
      keyEpoch: metadata.keyEpoch,
      deleted: item.deleted,
      blob: encodeCipherBlob(metadata.nonce, metadata.ciphertext),
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
      updatedBy: item.updatedBy,
    })),
    contents,
    cursor: cursorRows[0]?.cursor ?? 0,
  };
}

async function encryptedContentResponse(
  db: import('../services/audit.ts').DbOrTx,
  item: typeof items.$inferSelect,
  secretVersion: number,
) {
  const state = (await db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, item.vaultId)).limit(1))[0];
  if (!state?.activeEpoch || state.storageMode !== 'e2ee') return null;
  const metadata = await db.select().from(encryptedItemMetadataVersions).where(and(
    eq(encryptedItemMetadataVersions.itemId, item.id),
    eq(encryptedItemMetadataVersions.recordVersion, item.version),
    eq(encryptedItemMetadataVersions.keyEpoch, state.activeEpoch),
  )).limit(1);
  const secret = await db.select().from(encryptedItemSecretVersions).where(and(
    eq(encryptedItemSecretVersions.itemId, item.id),
    eq(encryptedItemSecretVersions.secretVersion, secretVersion),
  )).limit(1);
  const wrap = await db.select().from(encryptedItemKeyWraps).where(and(
    eq(encryptedItemKeyWraps.itemId, item.id),
    eq(encryptedItemKeyWraps.secretVersion, secretVersion),
    eq(encryptedItemKeyWraps.keyEpoch, state.activeEpoch),
  )).limit(1);
  if (!metadata[0] || !secret[0] || !wrap[0]) return null;
  return {
    metadata: {
      itemId: item.id,
      vaultId: item.vaultId,
      version: item.version,
      secretVersion: item.secretVersion,
      keyEpoch: state.activeEpoch,
      deleted: item.deleted,
      blob: encodeCipherBlob(metadata[0].nonce, metadata[0].ciphertext),
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
      updatedBy: item.updatedBy,
    },
    secret: {
      itemId: item.id,
      vaultId: item.vaultId,
      recordVersion: secret[0].recordVersion,
      secretVersion,
      encryptedValue: encodeCipherBlob(secret[0].nonce, secret[0].ciphertext),
      createdAt: secret[0].createdAt.toISOString(),
      createdBy: secret[0].createdByDeviceId,
    },
    keyWrap: {
      itemId: item.id,
      vaultId: item.vaultId,
      secretVersion,
      keyEpoch: state.activeEpoch,
      wrappedDek: encodeCipherBlob(wrap[0].wrappedDekNonce, wrap[0].wrappedDekCiphertext),
      createdAt: wrap[0].createdAt.toISOString(),
      createdBy: wrap[0].createdByDeviceId,
    },
  };
}

function generatePairingCode() {
  let code = '';
  for (let index = 0; index < 8; index += 1) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return code;
}

function extensionFingerprint(device: {
  id: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
}) {
  const encoded = Buffer.from(canonicalJson({
    deviceId: device.id,
    encryptionPublicKey: device.encryptionPublicKey,
    kind: 'extension-device-fingerprint',
    protocol: 'lm-e2ee-v1',
    signingPublicKey: device.signingPublicKey,
  } as never));
  const digest = createHash('sha256').update(encoded).digest().subarray(0, 16);
  return digest.toString('hex').toUpperCase().match(/.{1,4}/g)!.join(' ');
}

function extensionClaimBytes(code: string, device: {
  id: string;
  deviceType: 'extension';
  encryptionPublicKey: string;
  signingPublicKey: string;
  joinChannelPublicKey: string;
  fingerprint: string;
}) {
  return utf8(canonicalJson({
    code,
    deviceId: device.id,
    deviceType: device.deviceType,
    encryptionPublicKey: device.encryptionPublicKey,
    fingerprint: device.fingerprint,
    kind: 'extension-pairing-claim',
    protocol: 'lm-e2ee-v1',
    signingPublicKey: device.signingPublicKey,
    joinChannelPublicKey: device.joinChannelPublicKey,
  }));
}

function enrollmentDto(row: typeof deviceEnrollmentRequests.$inferSelect) {
  return {
    enrollmentId: row.id,
    deviceId: row.requestedDeviceId,
    deviceType: row.deviceType,
    fingerprint: row.requestingKeyFingerprint,
    encryptionPublicKey: encodeBase64Url(row.requestingEncryptionPublicKey),
    signingPublicKey: encodeBase64Url(row.requestingSigningPublicKey),
    joinChannelPublicKey: encodeBase64Url(row.joinChannelPublicKey),
    status: row.status,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
  };
}

function pairingStatus(
  row: typeof deviceEnrollmentRequests.$inferSelect,
  status: 'pending' | 'approved' | 'expired' | 'rejected',
) {
  return {
    enrollmentId: row.id,
    deviceId: row.requestedDeviceId,
    expiresAt: row.expiresAt.toISOString(),
    fingerprint: row.requestingKeyFingerprint,
    status,
  };
}

function sameSet(left: Set<string>, right: Set<string>) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function without<T extends Record<string, unknown>, K extends keyof T>(input: T, key: K): Omit<T, K> {
  const copy = { ...input };
  delete copy[key];
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

function extensionUpgradeRequired(reply: FastifyReply) {
  return reply.code(426).send({
    statusCode: 426,
    error: 'Upgrade Required',
    code: 'extension_update_required',
    message: '扩展版本较旧，请更新扩展后继续使用；当前设备授权仍然保留，无需重新配对',
  } as never);
}

function supportsCurrentItemMetadata(value: string | string[] | undefined): boolean {
  if (Array.isArray(value)) return false;
  const version = Number(value);
  return Number.isInteger(version) && version >= 4 && version <= ITEM_METADATA_FORMAT_VERSION;
}

function locked(reply: FastifyReply) {
  return reply.code(423).send({ statusCode: 423, error: 'Locked', message: '工作台已锁定，请先使用主密码解锁' } as never);
}

function notFoundBody(message: string) {
  return { statusCode: 404, error: 'Not Found', message };
}
