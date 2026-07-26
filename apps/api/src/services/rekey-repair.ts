import { and, desc, eq, gte, inArray, sql } from 'drizzle-orm';
import { canonicalJson } from '@mima/e2ee';
import type { AuditContext, AuditHead, DbOrTx } from './audit.ts';
import type { Db } from '../db/client.ts';
import { appendAudit } from './audit.ts';
import { recordSyncEvent } from './commands.ts';
import {
  encryptedItemKeyWraps,
  encryptedItemMetadataVersions,
  encryptedVaultHeaders,
  enterpriseRecoveryKeys,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultRekeyJobs,
} from '../db/schema.ts';
import { publicKeyFingerprint, sha256 } from './e2ee.ts';
import {
  ensureEnvelopeTasks,
  resolveEffectiveEnvelopeAuthorization,
} from './vault-envelope-tasks.ts';

const ACTIVE_REKEY_STATUSES = ['pending', 'distributing', 'rewrapping', 'verifying', 'ready'] as const;
type ActiveRekeyStatus = (typeof ACTIVE_REKEY_STATUSES)[number];

export class NoopRekeyRepairError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'NoopRekeyRepairError';
  }
}

export interface NoopRekeyRepairProof {
  taskId: string;
  vaultId: string;
  fromEpoch: number;
  toEpoch: number;
  status: 'repairable';
  targetArtifactCount: 0;
  revokedHolderEnvelopeCount: 0;
  expectedRecipientDescriptorCount: number;
  activeRecipientDescriptorCount: number;
}

export interface ActiveMembershipRekeyInspection {
  taskId: string;
  vaultId: string;
  fromEpoch: number;
  toEpoch: number;
  taskStatus: ActiveRekeyStatus;
  diagnosis: 'repairable' | 'blocked';
  code?: string;
}

export async function listActiveMembershipRekeys(
  db: DbOrTx,
): Promise<ActiveMembershipRekeyInspection[]> {
  const tasks = await db.select().from(vaultRekeyJobs).where(and(
    eq(vaultRekeyJobs.reason, 'membership_change'),
    inArray(vaultRekeyJobs.status, ACTIVE_REKEY_STATUSES),
  )).orderBy(desc(vaultRekeyJobs.createdAt));
  const inspections: ActiveMembershipRekeyInspection[] = [];
  for (const task of tasks) {
    try {
      await proveNoopMembershipRekey(db, task.id, false);
      inspections.push({
        taskId: task.id,
        vaultId: task.vaultId,
        fromEpoch: task.fromEpoch,
        toEpoch: task.toEpoch,
        taskStatus: task.status as ActiveRekeyStatus,
        diagnosis: 'repairable',
      });
    } catch (error) {
      if (!(error instanceof NoopRekeyRepairError)) throw error;
      inspections.push({
        taskId: task.id,
        vaultId: task.vaultId,
        fromEpoch: task.fromEpoch,
        toEpoch: task.toEpoch,
        taskStatus: task.status as ActiveRekeyStatus,
        diagnosis: 'blocked',
        code: error.code,
      });
    }
  }
  return inspections;
}

export async function inspectNoopMembershipRekey(
  db: DbOrTx,
  taskId: string,
): Promise<NoopRekeyRepairProof> {
  return proveNoopMembershipRekey(db, taskId, false);
}

export async function cancelNoopMembershipRekey(
  db: Db,
  audit: AuditContext,
  taskId: string,
): Promise<{ proof: NoopRekeyRepairProof; auditHead: AuditHead }> {
  const now = new Date();
  return db.transaction(async (tx) => {
    const proof = await proveNoopMembershipRekey(tx, taskId, true);
    const cancelled = await tx.update(vaultRekeyJobs).set({
      status: 'cancelled',
      lastErrorCode: 'no_effective_key_reduction',
      lastErrorDetailCiphertext: null,
      lastErrorDetailNonce: null,
      updatedAt: now,
    }).where(and(
      eq(vaultRekeyJobs.id, proof.taskId),
      eq(vaultRekeyJobs.status, 'pending'),
    )).returning({ id: vaultRekeyJobs.id });
    if (cancelled.length !== 1) throw new NoopRekeyRepairError('rekey_task_changed');

    const retired = await tx.update(vaultKeyEpochs).set({
      status: 'retired',
      retiredAt: now,
    }).where(and(
      eq(vaultKeyEpochs.vaultId, proof.vaultId),
      eq(vaultKeyEpochs.epoch, proof.toEpoch),
      eq(vaultKeyEpochs.status, 'preparing'),
    )).returning({ epoch: vaultKeyEpochs.epoch });
    if (retired.length !== 1) throw new NoopRekeyRepairError('target_epoch_changed');

    const opened = await tx.update(vaultCryptoStates).set({
      writeState: 'open',
      rowVersion: sql`${vaultCryptoStates.rowVersion} + 1`,
      updatedAt: now,
    }).where(and(
      eq(vaultCryptoStates.vaultId, proof.vaultId),
      eq(vaultCryptoStates.activeEpoch, proof.fromEpoch),
      eq(vaultCryptoStates.writeState, 'rekeying'),
    )).returning({ vaultId: vaultCryptoStates.vaultId });
    if (opened.length !== 1) throw new NoopRekeyRepairError('vault_state_changed');

    const activeUsers = await tx.select({ id: users.id }).from(users).where(eq(users.active, true));
    for (const user of activeUsers) {
      const authorization = await resolveEffectiveEnvelopeAuthorization(tx, proof.vaultId, user.id);
      if (!authorization) continue;
      await ensureEnvelopeTasks(tx, {
        vaultId: proof.vaultId,
        keyEpoch: proof.fromEpoch,
        authorizationKind: authorization.authorizationKind,
        authorizationRef: authorization.authorizationRef,
        recipientUserIds: [user.id],
        capability: authorization.capability,
        now,
      });
    }

    await recordSyncEvent(tx, {
      type: 'vault.crypto_changed',
      vaultId: proof.vaultId,
      itemId: null,
      payload: { rekeyCancelled: true, reason: 'no_effective_key_reduction' },
    });
    const auditHead = await appendAudit(tx, audit, {
      actorUserId: null,
      action: 'vault.rekey.cancel_noop',
      vaultId: proof.vaultId,
      success: true,
      details: {},
    });
    return { proof, auditHead };
  });
}

async function proveNoopMembershipRekey(
  db: DbOrTx,
  taskId: string,
  lock: boolean,
): Promise<NoopRekeyRepairProof> {
  const taskSnapshot = (await db.select().from(vaultRekeyJobs)
    .where(eq(vaultRekeyJobs.id, taskId)).limit(1))[0];
  if (!taskSnapshot) throw new NoopRekeyRepairError('rekey_task_not_found');

  const stateQuery = db.select().from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.vaultId, taskSnapshot.vaultId));
  const state = (await (lock ? stateQuery.for('update') : stateQuery).limit(1))[0];
  const taskQuery = db.select().from(vaultRekeyJobs).where(eq(vaultRekeyJobs.id, taskId));
  const task = (await (lock ? taskQuery.for('update') : taskQuery).limit(1))[0];
  if (!task || task.vaultId !== taskSnapshot.vaultId) {
    throw new NoopRekeyRepairError('rekey_task_changed');
  }
  const epochQuery = db.select().from(vaultKeyEpochs).where(and(
    eq(vaultKeyEpochs.vaultId, task.vaultId),
    inArray(vaultKeyEpochs.epoch, [task.fromEpoch, task.toEpoch]),
  ));
  const epochs = await (lock ? epochQuery.for('update') : epochQuery);
  const fromEpoch = epochs.find((epoch) => epoch.epoch === task.fromEpoch);
  const targetEpoch = epochs.find((epoch) => epoch.epoch === task.toEpoch);

  if (
    task.reason !== 'membership_change' ||
    task.status !== 'pending' ||
    task.expectedRecipientCount !== 0 ||
    task.distributedRecipientCount !== 0 ||
    task.expectedSecretVersionCount !== 0 ||
    task.rewrappedSecretVersionCount !== 0 ||
    task.expectedMetadataVersionCount !== 0 ||
    task.reencryptedMetadataVersionCount !== 0 ||
    task.checkpointCursor !== null ||
    task.sourceDigest !== null ||
    task.resultDigest !== null ||
    task.verificationSignature !== null ||
    task.committedAt !== null
  ) throw new NoopRekeyRepairError('rekey_task_not_pristine');
  if (
    !state ||
    state.storageMode !== 'e2ee' ||
    state.writeState !== 'rekeying' ||
    state.activeEpoch !== task.fromEpoch ||
    state.accessGeneration !== task.freezeGeneration ||
    !fromEpoch ||
    fromEpoch.status !== 'active' ||
    !targetEpoch ||
    targetEpoch.previousEpoch !== task.fromEpoch ||
    targetEpoch.status !== 'preparing' ||
    targetEpoch.keyPossessionPublicKey !== null ||
    targetEpoch.activatedAt !== null ||
    targetEpoch.retiredAt !== null
  ) throw new NoopRekeyRepairError('rekey_state_not_pristine');

  for (const [label, actual] of [
    ['metadata', targetEpoch.metadataKeyCommitment],
    ['content', targetEpoch.contentKeyCommitment],
    ['recipients', targetEpoch.recipientSetDigest],
  ] as const) {
    const expected = sha256(canonicalJson({
      kind: 'pending-rekey-commitment',
      label,
      protocol: 'lm-e2ee-v1',
      vaultId: task.vaultId,
      epoch: task.toEpoch,
    } as never));
    if (!Buffer.from(actual).equals(expected)) {
      throw new NoopRekeyRepairError('target_epoch_commitment_changed');
    }
  }

  const targetHeaders = await db.select({ id: encryptedVaultHeaders.vaultId })
    .from(encryptedVaultHeaders).where(and(
      eq(encryptedVaultHeaders.vaultId, task.vaultId),
      eq(encryptedVaultHeaders.keyEpoch, task.toEpoch),
    ));
  const targetEnvelopes = await db.select({ id: vaultKeyEnvelopes.id })
    .from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, task.vaultId),
      eq(vaultKeyEnvelopes.keyEpoch, task.toEpoch),
    ));
  const targetMetadata = await db.select({ id: encryptedItemMetadataVersions.id })
    .from(encryptedItemMetadataVersions).where(and(
      eq(encryptedItemMetadataVersions.vaultId, task.vaultId),
      eq(encryptedItemMetadataVersions.keyEpoch, task.toEpoch),
    ));
  const targetWraps = await db.select({ id: encryptedItemKeyWraps.id })
    .from(encryptedItemKeyWraps).where(and(
      eq(encryptedItemKeyWraps.vaultId, task.vaultId),
      eq(encryptedItemKeyWraps.keyEpoch, task.toEpoch),
    ));
  const revokedHolders = await db.select({ id: vaultKeyEnvelopes.id })
    .from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, task.vaultId),
      eq(vaultKeyEnvelopes.keyEpoch, task.fromEpoch),
      inArray(vaultKeyEnvelopes.recipientKind, ['user', 'device']),
      inArray(vaultKeyEnvelopes.status, ['revoked', 'superseded']),
      gte(vaultKeyEnvelopes.revokedAt, task.startedAt ?? task.createdAt),
    ));
  const targetArtifactCount = targetHeaders.length + targetEnvelopes.length + targetMetadata.length + targetWraps.length;
  if (targetArtifactCount !== 0) throw new NoopRekeyRepairError('target_epoch_has_artifacts');
  if (revokedHolders.length !== 0) throw new NoopRekeyRepairError('current_holder_was_revoked');

  const descriptors = await recipientDescriptors(db, task.vaultId, task.fromEpoch);
  if (!isSubset(descriptors.active, descriptors.expected)) {
    throw new NoopRekeyRepairError('recipient_descriptors_changed');
  }
  return {
    taskId: task.id,
    vaultId: task.vaultId,
    fromEpoch: task.fromEpoch,
    toEpoch: task.toEpoch,
    status: 'repairable',
    targetArtifactCount: 0,
    revokedHolderEnvelopeCount: 0,
    expectedRecipientDescriptorCount: descriptors.expected.size,
    activeRecipientDescriptorCount: descriptors.active.size,
  };
}

async function recipientDescriptors(
  db: DbOrTx,
  vaultId: string,
  keyEpoch: number,
): Promise<{ expected: Set<string>; active: Set<string> }> {
  const activeUsers = await db.select({ id: users.id }).from(users).where(eq(users.active, true));
  const profiles = await db.select().from(userCryptoProfiles);
  const devices = await db.select().from(userDevices).where(and(
    eq(userDevices.status, 'active'),
    eq(userDevices.deviceType, 'extension'),
  ));
  const recoveryRows = await db.select().from(enterpriseRecoveryKeys)
    .where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1);
  const envelopes = await db.select().from(vaultKeyEnvelopes).where(and(
    eq(vaultKeyEnvelopes.vaultId, vaultId),
    eq(vaultKeyEnvelopes.keyEpoch, keyEpoch),
    eq(vaultKeyEnvelopes.status, 'active'),
  ));
  const profileByUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  const deviceById = new Map(devices.map((device) => [device.id, device]));
  const capabilityByUser = new Map<string, 'metadata' | 'full'>();
  const expected = new Set<string>();
  for (const user of activeUsers) {
    const authorization = await resolveEffectiveEnvelopeAuthorization(db, vaultId, user.id);
    const profile = profileByUser.get(user.id);
    if (!authorization || !profile) continue;
    capabilityByUser.set(user.id, authorization.capability);
    expected.add(descriptor(
      'user',
      user.id,
      authorization.capability,
      profile.cryptoGeneration,
      publicKeyFingerprint(Buffer.from(profile.publicEncryptionKey).toString('base64url')),
    ));
  }
  for (const device of devices) {
    const capability = capabilityByUser.get(device.userId);
    if (!capability) continue;
    expected.add(descriptor(
      'device',
      device.id,
      capability,
      device.deviceGeneration,
      publicKeyFingerprint(Buffer.from(device.publicEncryptionKey).toString('base64url')),
    ));
  }
  if (recoveryRows[0]) {
    expected.add(descriptor(
      'enterprise_recovery',
      recoveryRows[0].id,
      'recovery',
      1,
      recoveryRows[0].keyFingerprint,
    ));
  }

  const active = new Set<string>();
  for (const envelope of envelopes) {
    if (envelope.recipientKind === 'user' && envelope.recipientUserId) {
      const profile = profileByUser.get(envelope.recipientUserId);
      const capability = capabilityByUser.get(envelope.recipientUserId);
      if (!profile || !capability || envelope.accessScope !== capability) {
        throw new NoopRekeyRepairError('unexpected_active_user_envelope');
      }
      active.add(descriptor(
        'user',
        envelope.recipientUserId,
        envelope.accessScope,
        envelope.envelopeVersion,
        envelope.recipientKeyFingerprint,
      ));
    } else if (envelope.recipientKind === 'device' && envelope.recipientDeviceId) {
      const device = deviceById.get(envelope.recipientDeviceId);
      const capability = device ? capabilityByUser.get(device.userId) : null;
      if (!device || !capability || envelope.accessScope !== capability) {
        throw new NoopRekeyRepairError('unexpected_active_device_envelope');
      }
      active.add(descriptor(
        'device',
        envelope.recipientDeviceId,
        envelope.accessScope,
        envelope.envelopeVersion,
        envelope.recipientKeyFingerprint,
      ));
    } else if (envelope.recipientKind === 'enterprise_recovery' && envelope.recipientRecoveryKeyId) {
      const recovery = recoveryRows[0];
      if (
        !recovery ||
        recovery.id !== envelope.recipientRecoveryKeyId ||
        envelope.accessScope !== 'recovery'
      ) throw new NoopRekeyRepairError('unexpected_active_recovery_envelope');
      active.add(descriptor(
        'enterprise_recovery',
        envelope.recipientRecoveryKeyId,
        envelope.accessScope,
        envelope.envelopeVersion,
        envelope.recipientKeyFingerprint,
      ));
    } else {
      throw new NoopRekeyRepairError('unexpected_active_envelope');
    }
  }
  return { expected, active };
}

function descriptor(
  kind: 'user' | 'device' | 'enterprise_recovery',
  id: string,
  capability: 'metadata' | 'full' | 'recovery',
  version: number,
  fingerprint: string,
): string {
  return `${kind}:${id}:${capability}:${version}:${fingerprint}`;
}

function isSubset(subset: Set<string>, superset: Set<string>): boolean {
  return [...subset].every((value) => superset.has(value));
}
