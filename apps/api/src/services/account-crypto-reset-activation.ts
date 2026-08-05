import { and, eq, inArray, ne, sql } from 'drizzle-orm';
import type { SessionUser } from '@mima/contracts';
import { canonicalJson } from '@mima/e2ee';
import {
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
import { listAccessibleVaults } from './access.ts';
import type { DbOrTx } from './audit.ts';
import type { SyncEventRow } from './bus.ts';
import { recordSyncEvent } from './commands.ts';
import { sha256 } from './e2ee.ts';
import { lockRecipientSets } from './recipient-set-lock.ts';
import { reconcilePendingEnvelopeTasksForProfile } from './vault-envelope-tasks.ts';

export class AccountCryptoResetActivationConflictError extends Error {}

export interface AppliedAccountCryptoReset {
  reset: typeof accountCryptoResetRequests.$inferSelect;
  profile: typeof userCryptoProfiles.$inferSelect;
  device: typeof userDevices.$inferSelect;
  revokedDeviceCount: number;
  rekeyTasks: Array<{ vaultId: string; taskId: string; fromEpoch: number; toEpoch: number }>;
}

export async function applyApprovedAccountCryptoReset(
  tx: DbOrTx,
  collect: (event: SyncEventRow) => void,
  input: {
    requestId: string;
    targetUser: SessionUser;
    unlockedSessionId?: string | null;
  },
): Promise<AppliedAccountCryptoReset> {
  await lockRecipientSets(tx, [input.targetUser.id]);
  const reset = (await tx.select().from(accountCryptoResetRequests)
    .where(eq(accountCryptoResetRequests.id, input.requestId)).for('update').limit(1))[0];
  const profile = (await tx.select().from(userCryptoProfiles)
    .where(eq(userCryptoProfiles.userId, input.targetUser.id)).for('update').limit(1))[0];
  if (!reset || reset.status !== 'approved' || reset.expiresAt <= new Date()
    || reset.targetUserId !== input.targetUser.id
    || !profile
    || profile.profileVersion !== reset.expectedProfileVersion
    || profile.cryptoGeneration !== reset.expectedCryptoGeneration
  ) throw new AccountCryptoResetActivationConflictError('账户加密身份或重置请求已经变化');

  const oldDevices = await tx.select().from(userDevices)
    .where(eq(userDevices.userId, input.targetUser.id)).for('update');
  const oldDeviceIds = oldDevices.map((device) => device.id);
  const userEnvelopeRows = await tx.select({ vaultId: vaultKeyEnvelopes.vaultId })
    .from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.recipientUserId, input.targetUser.id),
      inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
    ));
  const deviceEnvelopeRows = oldDeviceIds.length
    ? await tx.select({ vaultId: vaultKeyEnvelopes.vaultId }).from(vaultKeyEnvelopes).where(and(
        inArray(vaultKeyEnvelopes.recipientDeviceId, oldDeviceIds),
        inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
      ))
    : [];
  const authorizedVaults = await listAccessibleVaults(tx, input.targetUser);
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
    eq(userCryptoProfiles.userId, input.targetUser.id),
    eq(userCryptoProfiles.profileVersion, reset.expectedProfileVersion),
    eq(userCryptoProfiles.cryptoGeneration, reset.expectedCryptoGeneration),
  )).returning())[0];
  if (!updatedProfile) throw new AccountCryptoResetActivationConflictError('账户加密身份已经变化');

  const revokedDevices = (await tx.update(userDevices).set({
    status: 'revoked',
    deviceGeneration: sql`${userDevices.deviceGeneration} + 1`,
    revokedAt: now,
    revokedByUserId: input.targetUser.id,
    revocationReason: 'account_crypto_reset',
  }).where(and(eq(userDevices.userId, input.targetUser.id), ne(userDevices.status, 'revoked')))
    .returning({ id: userDevices.id }));
  const candidateDevice = (await tx.insert(userDevices).values({
    id: reset.candidateDeviceId,
    userId: input.targetUser.id,
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
    eq(vaultKeyEnvelopes.recipientUserId, input.targetUser.id),
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
    input.targetUser.id,
    reset.newCryptoGeneration,
    now,
  );

  await tx.delete(extensionSessions).where(eq(extensionSessions.userId, input.targetUser.id));
  await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, input.targetUser.id));
  await tx.update(deviceEnrollmentRequests).set({ status: 'rejected' }).where(and(
    eq(deviceEnrollmentRequests.userId, input.targetUser.id),
    inArray(deviceEnrollmentRequests.status, ['pending', 'approved']),
  ));
  await tx.delete(sessionUnlockChallenges).where(eq(sessionUnlockChallenges.userId, input.targetUser.id));
  if (input.unlockedSessionId) {
    await tx.delete(sessions).where(and(
      eq(sessions.userId, input.targetUser.id),
      ne(sessions.id, input.unlockedSessionId),
    ));
    const activatedSession = (await tx.update(sessions).set({
      locked: false,
      unlockedDeviceId: candidateDevice.id,
      unlockedAt: now,
      unlockGeneration: sql`${sessions.unlockGeneration} + 1`,
    }).where(and(
      eq(sessions.id, input.unlockedSessionId),
      eq(sessions.userId, input.targetUser.id),
    )).returning({ id: sessions.id }))[0];
    if (!activatedSession) throw new AccountCryptoResetActivationConflictError('当前登录已经失效');
  } else {
    await tx.delete(sessions).where(eq(sessions.userId, input.targetUser.id));
  }

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
          initiatedByUserId: input.targetUser.id,
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
          createdByUserId: input.targetUser.id,
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
              initiatedByUserId: input.targetUser.id,
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
              initiatedByUserId: input.targetUser.id,
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
  if (!activatedReset) {
    throw new AccountCryptoResetActivationConflictError('账户加密身份重置请求已经变化');
  }

  for (const revoked of revokedDevices) {
    collect(await recordSyncEvent(tx, {
      type: 'device.revoked',
      vaultId: '00000000-0000-0000-0000-000000000000',
      itemId: null,
      payload: { deviceId: revoked.id, userId: input.targetUser.id },
    }));
  }
  return {
    reset: activatedReset,
    profile: updatedProfile,
    device: candidateDevice,
    revokedDeviceCount: revokedDevices.length,
    rekeyTasks,
  };
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
