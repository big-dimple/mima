import { randomUUID } from 'node:crypto';
import { and, eq, inArray, isNull, ne, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  CompleteCryptoUnlockRequestSchema,
  CreateCryptoProfileRequestSchema,
  CreateUnlockChallengeRequestSchema,
  CryptoDeviceSchema,
  RegisterCryptoDeviceRequestSchema,
  RevokeCryptoDeviceRequestSchema,
  RotateCryptoProfileRequestSchema,
  RotateCryptoProfileResponseSchema,
  RewrapCryptoProfileRequestSchema,
  UnlockChallengeSchema,
  UserCryptoProfileSchema,
} from '@mima/contracts';
import {
  canonicalJson,
  createUnlockChallenge,
  utf8,
  verifyUnlockChallenge,
  type UnlockChallenge as E2eeUnlockChallenge,
} from '@mima/e2ee';
import {
  extensionSessions,
  extensionPairingCodes,
  deviceEnrollmentRequests,
  sessionUnlockChallenges,
  sessions,
  userCryptoProfiles,
  userDevices,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultRekeyJobs,
} from '../db/schema.ts';
import { appendAudit, recordAnchor } from '../services/audit.ts';
import { listAccessibleVaults } from '../services/access.ts';
import { CredentialAttemptLimiter } from '../auth/attempt-limiter.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import {
  decodeBase64Url,
  decodeCipherBlob,
  encodeBase64Url,
  getActiveDevice,
  getCryptoProfile,
  listPublicCryptoProfiles,
  parseDeviceCertificate,
  publicKeyFingerprint,
  sha256,
  toCryptoDeviceDto,
  toCryptoProfileDto,
  verifyCommandSignature,
} from '../services/e2ee.ts';
import {
  ensureMembershipRekeyTask,
  reconcilePendingEnvelopeTasksForProfile,
} from '../services/vault-envelope-tasks.ts';
import { lockRecipientSets } from '../services/recipient-set-lock.ts';

const DeviceParams = z.object({ deviceId: z.string().uuid() });
const PublicProfilesRequestSchema = z.object({ userIds: z.array(z.string().min(1)).min(1).max(1000) });
const PublicProfileSchema = z.object({
  userId: z.string(),
  keyVersion: z.number().int().positive(),
  encryptionPublicKey: z.string(),
  signingPublicKey: z.string(),
});

class CryptoProfileConflictError extends Error {}
class CryptoDeviceConflictError extends Error {}

export function registerE2eeCryptoRoutes(app: FastifyInstance): void {
  const { db, audit, bus } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const unlockAttempts = new CredentialAttemptLimiter(db);
  const readGuard = [app.requireSession];
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.get('/api/v2/crypto/profile', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee'],
      response: { 200: UserCryptoProfileSchema.nullable(), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    const profile = await getCryptoProfile(db, req.user.id);
    return profile ? toCryptoProfileDto(profile) : null;
  });

  r.post('/api/v2/crypto/profile', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: CreateCryptoProfileRequestSchema,
      response: { 201: UserCryptoProfileSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (await getCryptoProfile(db, req.user.id)) {
      return conflict(reply, '加密资料已经初始化');
    }
    try {
      const accountBundle = decodeCipherBlob(req.body.encryptedAccountBundle, 48);
      const kdfSalt = decodeBase64Url(req.body.kdf.salt, { exact: 16 });
      const accountEncryptionKey = decodeBase64Url(req.body.encryptionPublicKey, { exact: 32 });
      const accountSigningKey = decodeBase64Url(req.body.signingPublicKey, { exact: 32 });
      const deviceEncryptionKey = decodeBase64Url(req.body.device.encryptionPublicKey, { exact: 32 });
      const deviceSigningKey = decodeBase64Url(req.body.device.signingPublicKey, { exact: 32 });
      const certificateSignature = decodeBase64Url(req.body.device.certificateSignature, { exact: 64 });
      const { bytes: certificateBytes } = await parseDeviceCertificate(
        req.body.device.certificate,
        req.body.device.certificateSignature,
        req.body.signingPublicKey,
        {
        accountId: req.user.id,
        deviceId: req.body.device.id,
        deviceType: req.body.device.deviceType,
        encryptionPublicKey: req.body.device.encryptionPublicKey,
        signingPublicKey: req.body.device.signingPublicKey,
      });
      const encryptedLabel = req.body.device.encryptedLabel
        ? decodeCipherBlob(req.body.device.encryptedLabel)
        : null;
      const now = new Date();
      const committed = await db.transaction(async (tx) => {
        await lockRecipientSets(tx, [req.user.id]);
        const profile = (
          await tx.insert(userCryptoProfiles).values({
            userId: req.user.id,
            profileVersion: 1,
            cryptoGeneration: 1,
            kdfSalt,
            wrappedAccountKeyCiphertext: accountBundle.ciphertext,
            wrappedAccountKeyNonce: accountBundle.nonce,
            encryptedPrivateKeyBundle: null,
            privateKeyBundleNonce: null,
            publicEncryptionKey: accountEncryptionKey,
            publicSigningKey: accountSigningKey,
            signingKeyFingerprint: publicKeyFingerprint(req.body.signingPublicKey),
          }).returning()
        )[0]!;
        await tx.insert(userDevices).values({
          id: req.body.device.id,
          userId: req.user.id,
          deviceType: req.body.device.deviceType,
          status: 'active',
          trustMethod: 'master_password',
          keyFingerprint: publicKeyFingerprint(req.body.device.signingPublicKey),
          publicEncryptionKey: deviceEncryptionKey,
          publicSigningKey: deviceSigningKey,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          encryptedLabel: encryptedLabel?.ciphertext ?? null,
          labelNonce: encryptedLabel?.nonce ?? null,
          certificatePayload: certificateBytes,
          certificateSignature,
          activatedAt: now,
          lastSeenAt: now,
        });
        const reconciliation = await reconcilePendingEnvelopeTasksForProfile(tx, req.user.id, 1, now);
        const events: Awaited<ReturnType<typeof recordSyncEvent>>[] = [];
        for (const vaultId of reconciliation.vaultIds) {
          events.push(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed',
            vaultId,
            itemId: null,
            payload: { recipientProfileChanged: true },
          }));
        }
        await tx.update(sessions).set({
          locked: false,
          unlockedDeviceId: req.body.device.id,
          unlockedAt: now,
          unlockGeneration: sql`${sessions.unlockGeneration} + 1`,
        }).where(eq(sessions.id, req.sessionRow.id));
        const auditHead = await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'crypto.profile.create',
          success: true,
          details: {},
        });
        return { profile, events, auditHead };
      });
      bus.publish(committed.events);
      recordAnchor(audit, committed.auditHead);
      reply.header('cache-control', 'no-store');
      return reply.code(201).send(toCryptoProfileDto(committed.profile));
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '加密资料已经初始化');
      if (error instanceof SyntaxError || error instanceof z.ZodError) {
        return badRequest(reply, '加密资料格式或设备证书无效');
      }
      throw error;
    }
  });

  r.put('/api/v2/crypto/profile', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: RewrapCryptoProfileRequestSchema,
      response: { 200: UserCryptoProfileSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== req.body.deviceId) {
      return locked(reply);
    }
    const [profile, device] = await Promise.all([
      getCryptoProfile(db, req.user.id),
      getActiveDevice(db, req.user.id, req.body.deviceId),
    ]);
    if (!profile || !device) return unauthorized(reply, '当前设备未授权');
    const unsigned = { ...req.body, signature: undefined };
    delete unsigned.signature;
    if (!(await verifyCommandSignature(req.body.signature, encodeBase64Url(device.publicSigningKey), 'crypto.profile.rewrap', {
      userId: req.user.id,
      request: unsigned,
    }))) return unauthorized(reply, '签名校验失败');
    let bundle;
    let salt;
    try {
      bundle = decodeCipherBlob(req.body.encryptedAccountBundle, 48);
      salt = decodeBase64Url(req.body.kdf.salt, { exact: 16 });
    } catch {
      return badRequest(reply, '加密资料格式无效');
    }
    const committed = await db.transaction(async (tx) => {
      const updated = (
        await tx.update(userCryptoProfiles).set({
          profileVersion: profile.profileVersion + 1,
          kdfSalt: salt,
          wrappedAccountKeyCiphertext: bundle.ciphertext,
          wrappedAccountKeyNonce: bundle.nonce,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          updatedAt: new Date(),
        }).where(and(
          eq(userCryptoProfiles.userId, req.user.id),
          eq(userCryptoProfiles.profileVersion, req.body.expectedProfileVersion),
        )).returning()
      )[0];
      if (!updated) return null;
      const event = await recordSyncEvent(tx, {
        type: 'crypto.profile_rewrapped',
        vaultId: '00000000-0000-0000-0000-000000000000',
        itemId: null,
        payload: {
          userId: req.user.id,
          actorDeviceId: req.body.deviceId,
          profileVersion: updated.profileVersion,
        },
      });
      const auditHead = await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'crypto.profile.rewrap',
        success: true,
        details: {},
      });
      return { updated, event, auditHead };
    });
    if (!committed) return conflict(reply, '加密资料已经被其他设备更新');
    bus.publish([committed.event]);
    recordAnchor(audit, committed.auditHead);
    reply.header('cache-control', 'no-store');
    return toCryptoProfileDto(committed.updated);
  });

  r.post('/api/v2/crypto/profile/rotate', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: RotateCryptoProfileRequestSchema,
      response: { 200: RotateCryptoProfileResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== req.body.actorDeviceId) {
      return locked(reply);
    }
    const [profile, actor] = await Promise.all([
      getCryptoProfile(db, req.user.id),
      getActiveDevice(db, req.user.id, req.body.actorDeviceId),
    ]);
    if (!profile || !actor) return unauthorized(reply, '当前设备未授权');
    if (
      profile.profileVersion !== req.body.expectedProfileVersion ||
      profile.cryptoGeneration !== req.body.expectedKeyVersion ||
      req.body.newKeyVersion !== req.body.expectedKeyVersion + 1
    ) return conflict(reply, '身份密钥已经被其他设备更新');
    if (
      encodeBase64Url(profile.publicEncryptionKey) === req.body.encryptionPublicKey ||
      encodeBase64Url(profile.publicSigningKey) === req.body.signingPublicKey
    ) return badRequest(reply, '身份密钥轮换必须生成新的用户加密密钥和签名密钥');

    const newKeyPayload = withoutKeys(req.body, ['actorSignature', 'newSigningKeyProof']);
    if (!await verifyCommandSignature(
      req.body.newSigningKeyProof,
      req.body.signingPublicKey,
      'crypto.profile.rotate.new-key',
      { userId: req.user.id, request: newKeyPayload },
    )) return unauthorized(reply, '新签名密钥自签证明无效');
    const actorPayload = withoutKeys(req.body, ['actorSignature']);
    if (!await verifyCommandSignature(
      req.body.actorSignature,
      encodeBase64Url(actor.publicSigningKey),
      'crypto.profile.rotate',
      { userId: req.user.id, request: actorPayload },
    )) return unauthorized(reply, '当前设备签名无效');

    let accountBundle; let accountEncryptionKey; let accountSigningKey;
    let deviceEncryptionKey; let deviceSigningKey; let certificateSignature; let certificateBytes;
    try {
      accountBundle = decodeCipherBlob(req.body.encryptedAccountBundle, 48);
      accountEncryptionKey = decodeBase64Url(req.body.encryptionPublicKey, { exact: 32 });
      accountSigningKey = decodeBase64Url(req.body.signingPublicKey, { exact: 32 });
      deviceEncryptionKey = decodeBase64Url(req.body.actorDevice.encryptionPublicKey, { exact: 32 });
      deviceSigningKey = decodeBase64Url(req.body.actorDevice.signingPublicKey, { exact: 32 });
      certificateSignature = decodeBase64Url(req.body.actorDevice.certificateSignature, { exact: 64 });
      ({ bytes: certificateBytes } = await parseDeviceCertificate(
        req.body.actorDevice.certificate,
        req.body.actorDevice.certificateSignature,
        req.body.signingPublicKey,
        {
          accountId: req.user.id,
          deviceId: actor.id,
          deviceType: actor.deviceType,
          encryptionPublicKey: req.body.actorDevice.encryptionPublicKey,
          signingPublicKey: req.body.actorDevice.signingPublicKey,
          keyVersion: req.body.newKeyVersion,
        },
      ));
    } catch {
      return badRequest(reply, '新的身份密钥或设备证书格式无效');
    }

    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockRecipientSets(tx, [req.user.id]);
        const currentProfile = (await tx.select().from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.user.id)).for('update').limit(1))[0];
        const currentActor = (await tx.select().from(userDevices).where(and(
          eq(userDevices.id, actor.id), eq(userDevices.userId, req.user.id), eq(userDevices.status, 'active'),
        )).for('update').limit(1))[0];
        if (!currentProfile || !currentActor ||
          currentProfile.profileVersion !== req.body.expectedProfileVersion ||
          currentProfile.cryptoGeneration !== req.body.expectedKeyVersion ||
          currentActor.deviceGeneration !== actor.deviceGeneration
        ) throw new CryptoProfileConflictError();

        const allDevices = await tx.select().from(userDevices).where(eq(userDevices.userId, req.user.id));
        const deviceIds = allDevices.map((device) => device.id);
        const userEnvelopeRows = await tx.select({ vaultId: vaultKeyEnvelopes.vaultId })
          .from(vaultKeyEnvelopes).where(and(
            eq(vaultKeyEnvelopes.recipientUserId, req.user.id),
            inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
          ));
        const deviceEnvelopeRows = deviceIds.length
          ? await tx.select({ vaultId: vaultKeyEnvelopes.vaultId }).from(vaultKeyEnvelopes).where(and(
              inArray(vaultKeyEnvelopes.recipientDeviceId, deviceIds),
              inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
            ))
          : [];
        const accessibleVaults = await listAccessibleVaults(tx, req.user);
        const affectedVaultIds = mergeSecurityMutationVaultIds(
          userEnvelopeRows,
          deviceEnvelopeRows,
          accessibleVaults.map((entry) => ({ vaultId: entry.vault.id })),
        );
        const now = new Date();

        const updatedProfile = (await tx.update(userCryptoProfiles).set({
          profileVersion: currentProfile.profileVersion + 1,
          cryptoGeneration: req.body.newKeyVersion,
          wrappedAccountKeyCiphertext: accountBundle.ciphertext,
          wrappedAccountKeyNonce: accountBundle.nonce,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          publicEncryptionKey: accountEncryptionKey,
          publicSigningKey: accountSigningKey,
          signingKeyFingerprint: publicKeyFingerprint(req.body.signingPublicKey),
          updatedAt: now,
        }).where(and(
          eq(userCryptoProfiles.userId, req.user.id),
          eq(userCryptoProfiles.profileVersion, req.body.expectedProfileVersion),
          eq(userCryptoProfiles.cryptoGeneration, req.body.expectedKeyVersion),
        )).returning())[0];
        if (!updatedProfile) throw new CryptoProfileConflictError();

        const revokedDevices = (await tx.update(userDevices).set({
          status: 'revoked',
          deviceGeneration: sql`${userDevices.deviceGeneration} + 1`,
          revokedAt: now,
          revokedByUserId: req.user.id,
          revocationReason: 'account_key_rotated',
        }).where(and(eq(userDevices.userId, req.user.id), ne(userDevices.id, actor.id), ne(userDevices.status, 'revoked')))
          .returning({ id: userDevices.id }));
        const updatedActor = (await tx.update(userDevices).set({
          status: 'active',
          trustMethod: 'master_password',
          deviceGeneration: req.body.newKeyVersion,
          keyFingerprint: publicKeyFingerprint(req.body.actorDevice.signingPublicKey),
          publicEncryptionKey: deviceEncryptionKey,
          publicSigningKey: deviceSigningKey,
          encryptedPrivateKeyBundle: null,
          privateKeyBundleNonce: null,
          certificatePayload: certificateBytes,
          certificateSignature,
          approvedByDeviceId: null,
          revokedAt: null,
          revokedByUserId: null,
          revocationReason: null,
          lastSeenAt: now,
        }).where(and(eq(userDevices.id, actor.id), eq(userDevices.deviceGeneration, actor.deviceGeneration)))
          .returning())[0];
        if (!updatedActor) throw new CryptoProfileConflictError();

        await tx.update(vaultKeyEnvelopes).set({
          status: 'revoked', revokedAt: now, revocationReason: 'account_key_rotated',
        }).where(and(
          eq(vaultKeyEnvelopes.recipientUserId, req.user.id),
          inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
        ));
        if (deviceIds.length) {
          await tx.update(vaultKeyEnvelopes).set({
            status: 'revoked', revokedAt: now, revocationReason: 'account_key_rotated',
          }).where(and(
            inArray(vaultKeyEnvelopes.recipientDeviceId, deviceIds),
            inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
          ));
        }
        const envelopeTaskReconciliation = await reconcilePendingEnvelopeTasksForProfile(
          tx,
          req.user.id,
          req.body.newKeyVersion,
          now,
        );

        await tx.delete(extensionSessions).where(eq(extensionSessions.userId, req.user.id));
        await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, req.user.id));
        await tx.update(deviceEnrollmentRequests).set({ status: 'rejected' }).where(and(
          eq(deviceEnrollmentRequests.userId, req.user.id),
          inArray(deviceEnrollmentRequests.status, ['pending', 'approved']),
        ));
        await tx.delete(sessionUnlockChallenges).where(eq(sessionUnlockChallenges.userId, req.user.id));
        await tx.delete(sessions).where(and(eq(sessions.userId, req.user.id), ne(sessions.id, req.sessionRow.id)));
        await tx.update(sessions).set({
          locked: false,
          unlockedDeviceId: actor.id,
          unlockedAt: now,
          unlockGeneration: sql`${sessions.unlockGeneration} + 1`,
        }).where(eq(sessions.id, req.sessionRow.id));

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
                initiatedByDeviceId: actor.id,
                updatedAt: now,
              }).where(eq(vaultRekeyJobs.id, task.id)).returning())[0]!;
              await tx.update(vaultKeyEpochs).set({ reason: 'device_compromise' }).where(and(
                eq(vaultKeyEpochs.vaultId, task.vaultId), eq(vaultKeyEpochs.epoch, task.toEpoch),
              ));
            } else {
              const pendingDigest = (label: string) => sha256(canonicalJson({
                kind: 'pending-rekey-commitment', label, protocol: 'lm-e2ee-v1',
                vaultId: state.vaultId, epoch: toEpoch,
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
                createdByDeviceId: actor.id,
              }).onConflictDoNothing();
              const priorTask = (await tx.select().from(vaultRekeyJobs).where(and(
                eq(vaultRekeyJobs.vaultId, state.vaultId), eq(vaultRekeyJobs.toEpoch, toEpoch),
              )).for('update').limit(1))[0];
              task = priorTask
                ? (await tx.update(vaultRekeyJobs).set({
                    status: 'pending', reason: 'device_compromise', freezeGeneration: state.accessGeneration + 1,
                    initiatedByUserId: req.user.id, initiatedByDeviceId: actor.id,
                    lastErrorCode: null, updatedAt: now,
                  }).where(eq(vaultRekeyJobs.id, priorTask.id)).returning())[0]!
                : (await tx.insert(vaultRekeyJobs).values({
                    vaultId: state.vaultId,
                    fromEpoch: state.activeEpoch,
                    toEpoch,
                    reason: 'device_compromise',
                    status: 'pending',
                    freezeGeneration: state.accessGeneration + 1,
                    initiatedByUserId: req.user.id,
                    initiatedByDeviceId: actor.id,
                    startedAt: now,
                  }).returning())[0]!;
            }
            await tx.update(vaultCryptoStates).set({
              writeState: 'rekeying',
              accessGeneration: state.accessGeneration + 1,
              rowVersion: state.rowVersion + 1,
              updatedAt: now,
            }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
            rekeyTasks.push({ vaultId: state.vaultId, taskId: task.id, fromEpoch: task.fromEpoch, toEpoch: task.toEpoch });
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
          action: 'crypto.profile.rotate',
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            profile: toCryptoProfileDto(updatedProfile),
            device: toCryptoDeviceDto(updatedActor),
            revokedDeviceCount: revokedDevices.length,
            rekeyTasks,
          },
        };
      });
      reply.header('cache-control', 'no-store');
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof CryptoProfileConflictError || isUniqueViolation(error)) {
        return conflict(reply, '身份密钥已经被其他设备更新');
      }
      throw error;
    }
  });

  r.get('/api/v2/devices', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee'],
      response: { 200: z.array(CryptoDeviceSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    const rows = await db.select().from(userDevices).where(eq(userDevices.userId, req.user.id));
    return rows.map(toCryptoDeviceDto);
  });

  r.post('/api/v2/devices', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: RegisterCryptoDeviceRequestSchema,
      response: { 201: CryptoDeviceSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const profile = await getCryptoProfile(db, req.user.id);
    if (!profile) return conflict(reply, '请先设置主密码');
    try {
      const encryptionKey = decodeBase64Url(req.body.encryptionPublicKey, { exact: 32 });
      const signingKey = decodeBase64Url(req.body.signingPublicKey, { exact: 32 });
      const certificateSignature = decodeBase64Url(req.body.certificateSignature, { exact: 64 });
      const profileSigningKey = encodeBase64Url(profile.publicSigningKey);
      const { bytes: certificateBytes } = await parseDeviceCertificate(
        req.body.certificate,
        req.body.certificateSignature,
        profileSigningKey,
        {
        accountId: req.user.id,
        deviceId: req.body.id,
        deviceType: req.body.deviceType,
        encryptionPublicKey: req.body.encryptionPublicKey,
        signingPublicKey: req.body.signingPublicKey,
        keyVersion: profile.cryptoGeneration,
      });
      const unsigned = { ...req.body, approvalSignature: undefined };
      delete unsigned.approvalSignature;
      const approver = req.body.approvalDeviceId
        ? await getActiveDevice(db, req.user.id, req.body.approvalDeviceId)
        : null;
      if (req.body.approvalDeviceId && (
        !approver || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== approver.id
      )) return locked(reply);
      const approvalKey = approver ? encodeBase64Url(approver.publicSigningKey) : profileSigningKey;
      if (!(await verifyCommandSignature(req.body.approvalSignature, approvalKey, 'crypto.device.register', {
        userId: req.user.id,
        request: unsigned,
      }))) return unauthorized(reply, '设备授权签名无效');
      const encryptedLabel = req.body.encryptedLabel ? decodeCipherBlob(req.body.encryptedLabel) : null;
      const saved = await db.transaction(async (tx) => {
        await lockRecipientSets(tx, [req.user.id]);
        const currentProfile = await getCryptoProfile(tx, req.user.id);
        const currentApprover = req.body.approvalDeviceId
          ? await getActiveDevice(tx, req.user.id, req.body.approvalDeviceId)
          : null;
        if (
          !currentProfile || currentProfile.cryptoGeneration !== profile.cryptoGeneration ||
          !Buffer.from(currentProfile.publicSigningKey).equals(profile.publicSigningKey) ||
          (req.body.approvalDeviceId !== undefined && !currentApprover)
        ) throw new CryptoDeviceConflictError();
        const now = new Date();
        const row = (
          await tx.insert(userDevices).values({
            id: req.body.id,
            userId: req.user.id,
            deviceType: req.body.deviceType,
            status: 'active',
            trustMethod: currentApprover ? 'device_approval' : 'master_password',
            deviceGeneration: currentProfile.cryptoGeneration,
            keyFingerprint: publicKeyFingerprint(req.body.signingPublicKey),
            publicEncryptionKey: encryptionKey,
            publicSigningKey: signingKey,
            encryptedPrivateKeyBundle: null,
            privateKeyBundleNonce: null,
            encryptedLabel: encryptedLabel?.ciphertext ?? null,
            labelNonce: encryptedLabel?.nonce ?? null,
            certificatePayload: certificateBytes,
            certificateSignature,
            approvedByDeviceId: currentApprover?.id ?? null,
            activatedAt: now,
            lastSeenAt: now,
          }).returning()
        )[0]!;
        const auditHead = await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'crypto.device.register',
          success: true,
          details: {},
        });
        return { row, auditHead };
      });
      recordAnchor(audit, saved.auditHead);
      return reply.code(201).send(toCryptoDeviceDto(saved.row));
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '该设备已经注册');
      if (error instanceof CryptoDeviceConflictError) {
        return conflict(reply, '主密码身份或批准设备刚发生变化，请刷新后重新注册设备');
      }
      return badRequest(reply, '设备资料格式无效');
    }
  });

  r.post('/api/v2/devices/:deviceId/revoke', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      params: DeviceParams,
      body: RevokeCryptoDeviceRequestSchema,
      response: { 200: z.object({ ok: z.literal(true), rekeyVaultIds: z.array(z.string().uuid()) }), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (req.sessionRow.locked || !req.sessionRow.unlockedDeviceId) return locked(reply);
    const [actorDevice, targetDevice] = await Promise.all([
      getActiveDevice(db, req.user.id, req.sessionRow.unlockedDeviceId),
      getActiveDevice(db, req.user.id, req.params.deviceId),
    ]);
    if (!actorDevice || !targetDevice) return reply.code(404).send(notFoundBody('设备不存在或已经撤销') as never);
    if (targetDevice.deviceGeneration !== req.body.expectedKeyVersion) return conflict(reply, '设备状态已经变化');
    const unsigned = { ...req.body, signature: undefined };
    delete unsigned.signature;
    if (!(await verifyCommandSignature(req.body.signature, encodeBase64Url(actorDevice.publicSigningKey), 'crypto.device.revoke', {
      userId: req.user.id,
      request: { ...unsigned, deviceId: req.params.deviceId },
    }))) return unauthorized(reply, '签名校验失败');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      await lockRecipientSets(tx, [req.user.id]);
      const currentTarget = (await tx.select().from(userDevices).where(and(
        eq(userDevices.id, targetDevice.id),
        eq(userDevices.userId, req.user.id),
        eq(userDevices.status, 'active'),
      )).for('update').limit(1))[0];
      if (!currentTarget || currentTarget.deviceGeneration !== req.body.expectedKeyVersion) {
        throw new CryptoDeviceConflictError();
      }
      const rows = await tx
        .select({ vaultId: vaultKeyEnvelopes.vaultId })
        .from(vaultKeyEnvelopes)
        .where(and(
          eq(vaultKeyEnvelopes.recipientDeviceId, currentTarget.id),
          eq(vaultKeyEnvelopes.status, 'active'),
        ));
      const accessibleVaults = await listAccessibleVaults(tx, req.user);
      const vaultIds = mergeSecurityMutationVaultIds(
        rows,
        accessibleVaults.map((entry) => ({ vaultId: entry.vault.id })),
      );
      const now = new Date();
      await tx.update(userDevices).set({
        status: 'revoked',
        deviceGeneration: currentTarget.deviceGeneration + 1,
        revokedAt: now,
        revokedByUserId: req.user.id,
        revocationReason: 'user_requested',
      }).where(and(eq(userDevices.id, currentTarget.id), eq(userDevices.status, 'active')));
      await tx.update(vaultKeyEnvelopes).set({
        status: 'revoked',
        revokedAt: now,
        revocationReason: 'device_revoked',
      }).where(and(
        eq(vaultKeyEnvelopes.recipientDeviceId, currentTarget.id),
        eq(vaultKeyEnvelopes.status, 'active'),
      ));
      // 保留短期会话 tombstone，下一次扩展请求会同时校验设备状态、返回 403，
      // 随后由鉴权钩子删除会话。扩展据此区分“设备被撤销”和普通会话过期，
      // 并清除本机私钥包与密文缓存。
      await tx.delete(sessionUnlockChallenges).where(and(
        eq(sessionUnlockChallenges.deviceId, currentTarget.id),
        isNull(sessionUnlockChallenges.consumedAt),
      ));
      await tx.update(sessions).set({
        locked: true,
        unlockedDeviceId: null,
        unlockedAt: null,
        unlockGeneration: sql`${sessions.unlockGeneration} + 1`,
      }).where(eq(sessions.unlockedDeviceId, currentTarget.id));
      if (vaultIds.length > 0) {
        const states = await tx.select().from(vaultCryptoStates).where(and(
          inArray(vaultCryptoStates.vaultId, vaultIds),
          eq(vaultCryptoStates.storageMode, 'e2ee'),
        )).for('update');
        for (const state of states) {
          const task = await ensureMembershipRekeyTask(
            tx,
            state.vaultId,
            req.user.id,
            actorDevice.id,
            now,
            'device_compromise',
          );
          collect(await recordSyncEvent(tx, {
            type: 'vault.rekey_required',
            vaultId: state.vaultId,
            itemId: null,
            payload: { pendingEpoch: task.toEpoch, taskId: task.id },
          }));
        }
      }
      collect(await recordSyncEvent(tx, {
        type: 'device.revoked',
        vaultId: '00000000-0000-0000-0000-000000000000',
        itemId: null,
        payload: { deviceId: currentTarget.id, userId: req.user.id },
      }));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'crypto.device.revoke',
        success: true,
        details: {},
      });
      return { statusCode: 200, response: { ok: true as const, rekeyVaultIds: vaultIds } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof CryptoDeviceConflictError) {
        return conflict(reply, '设备状态刚被其他操作更新，请刷新设备列表后重试');
      }
      throw error;
    }
  });

  r.post('/api/v2/crypto/public-profiles', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee'],
      body: PublicProfilesRequestSchema,
      response: { 200: z.array(PublicProfileSchema), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req) => listPublicCryptoProfiles(db, req.body.userIds));

  r.post('/api/v2/session/unlock-challenge', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: CreateUnlockChallengeRequestSchema,
      response: { 200: UnlockChallengeSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const [device, profile] = await Promise.all([
      getActiveDevice(db, req.user.id, req.body.deviceId),
      getCryptoProfile(db, req.user.id),
    ]);
    if (!device || !profile) return unauthorized(reply, '当前设备未授权');
    const id = randomUUID();
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + 60_000);
    const challenge = await createUnlockChallenge({
      challengeId: id,
      accountId: req.user.id,
      deviceId: device.id,
      sessionId: req.sessionRow.id,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    });
    const encoded = encodeChallenge(challenge);
    await db.transaction(async (tx) => {
      await tx.delete(sessionUnlockChallenges).where(and(
        eq(sessionUnlockChallenges.sessionId, req.sessionRow.id),
        isNull(sessionUnlockChallenges.consumedAt),
      ));
      await tx.insert(sessionUnlockChallenges).values({
        id,
        sessionId: req.sessionRow.id,
        userId: req.user.id,
        deviceId: device.id,
        purpose: 'unlock',
        challengeHash: sha256(encoded),
        challengeNonce: decodeBase64Url(challenge.nonce, { exact: 32 }),
        sessionGeneration: req.sessionRow.unlockGeneration,
        profileVersion: profile.profileVersion,
        deviceGeneration: device.deviceGeneration,
        createdAt: issuedAt,
        expiresAt,
      });
    });
    reply.header('cache-control', 'no-store');
    return { id, challenge: encoded.toString('base64url'), expiresAt: expiresAt.toISOString() };
  });

  r.post('/api/v2/session/crypto-unlock', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: CompleteCryptoUnlockRequestSchema,
      response: { 200: z.object({ ok: z.literal(true), deviceId: z.string().uuid() }), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const attemptKey = `web-unlock:${req.ip}:${req.user.id}:${req.sessionRow.id}`;
    const retryAfter = await unlockAttempts.retryAfterSeconds(attemptKey);
    if (retryAfter > 0) {
      reply.header('retry-after', String(retryAfter));
      return reply.code(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: '解锁尝试过于频繁，请稍后再试',
      } as never);
    }
    const result = await db.transaction(async (tx) => {
      const challenge = (
        await tx
          .select()
          .from(sessionUnlockChallenges)
          .where(and(
            eq(sessionUnlockChallenges.id, req.body.challengeId),
            eq(sessionUnlockChallenges.sessionId, req.sessionRow.id),
            eq(sessionUnlockChallenges.userId, req.user.id),
          ))
          .for('update')
          .limit(1)
      )[0];
      if (!challenge || !challenge.sessionId || challenge.consumedAt || challenge.expiresAt.getTime() <= Date.now()) {
        return { ok: false as const, code: 'expired' as const };
      }
      if (challenge.deviceId !== req.body.deviceId) return { ok: false as const, code: 'invalid' as const };
      const device = await getActiveDevice(tx, req.user.id, req.body.deviceId);
      const profile = await getCryptoProfile(tx, req.user.id);
      const session = await tx.select().from(sessions)
        .where(eq(sessions.id, req.sessionRow.id)).for('update').limit(1);
      if (!device || !profile || !session[0] ||
        challenge.profileVersion !== profile.profileVersion ||
        challenge.deviceGeneration !== device.deviceGeneration ||
        challenge.sessionGeneration !== session[0].unlockGeneration
      ) return { ok: false as const, code: 'invalid' as const };
      const signed: E2eeUnlockChallenge = {
        protocol: 'lm-e2ee-v1',
        kind: 'unlock-challenge',
        challengeId: challenge.id,
        accountId: challenge.userId,
        deviceId: challenge.deviceId,
        sessionId: challenge.sessionId,
        nonce: encodeBase64Url(challenge.challengeNonce),
        issuedAt: challenge.createdAt.toISOString(),
        expiresAt: challenge.expiresAt.toISOString(),
      };
      const encoded = encodeChallenge(signed);
      if (!Buffer.from(challenge.challengeHash).equals(sha256(encoded)) || !await verifyUnlockChallenge(
        { ...signed, signature: req.body.signature },
        encodeBase64Url(device.publicSigningKey),
      )) {
        await tx.update(sessionUnlockChallenges).set({
          failedAttempts: challenge.failedAttempts + 1,
          ...(challenge.failedAttempts >= 4 ? { consumedAt: new Date() } : {}),
        }).where(eq(sessionUnlockChallenges.id, challenge.id));
        return { ok: false as const, code: 'signature' as const };
      }
      const now = new Date();
      await tx.update(sessionUnlockChallenges).set({ verifiedAt: now, consumedAt: now }).where(and(
        eq(sessionUnlockChallenges.id, challenge.id),
        isNull(sessionUnlockChallenges.consumedAt),
      ));
      const unlocked = await tx.update(sessions).set({
        locked: false,
        unlockedDeviceId: device.id,
        unlockedAt: now,
        unlockGeneration: session[0].unlockGeneration + 1,
      }).where(and(
        eq(sessions.id, session[0].id),
        eq(sessions.unlockGeneration, challenge.sessionGeneration),
      )).returning({ id: sessions.id });
      if (unlocked.length !== 1) return { ok: false as const, code: 'invalid' as const };
      await tx.update(userDevices).set({ lastSeenAt: now }).where(eq(userDevices.id, device.id));
      const auditHead = await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'session.crypto_unlock',
        success: true,
        details: {},
      });
      return { ok: true as const, deviceId: device.id, auditHead };
    });
    if (!result.ok) {
      await unlockAttempts.recordFailure(attemptKey);
      if (result.code === 'expired') return unauthorized(reply, '解锁请求已失效，请重新开始');
      return unauthorized(reply, '解锁签名无效');
    }
    recordAnchor(audit, result.auditHead);
    await unlockAttempts.clear(attemptKey);
    reply.header('cache-control', 'no-store');
    return { ok: true as const, deviceId: result.deviceId };
  });
}

export function mergeSecurityMutationVaultIds(
  ...sources: Array<Array<{ vaultId: string }>>
): string[] {
  return [...new Set(sources.flatMap((rows) => rows.map((row) => row.vaultId)))];
}

function encodeChallenge(challenge: E2eeUnlockChallenge): Buffer {
  return Buffer.from(utf8(canonicalJson(challenge as never)));
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

function badRequest(reply: import('fastify').FastifyReply, message: string) {
  return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message } as never);
}

function unauthorized(reply: import('fastify').FastifyReply, message: string) {
  return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message } as never);
}

function conflict(reply: import('fastify').FastifyReply, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', message } as never);
}

function locked(reply: import('fastify').FastifyReply) {
  return reply.code(423).send({ statusCode: 423, error: 'Locked', message: '工作台已锁定，请先使用主密码或已授权设备解锁' } as never);
}

function notFoundBody(message: string) {
  return { statusCode: 404, error: 'Not Found', message };
}
