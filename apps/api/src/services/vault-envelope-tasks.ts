import { and, eq, inArray, or, sql } from 'drizzle-orm';
import { canonicalJson } from '@mima/e2ee';
import type { MembershipRole } from '@mima/contracts';
import { resolveEffectiveRole } from '@mima/domain';
import {
  customGroupMembers,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultCustomGroupRoles,
  vaultEnvelopeTasks,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaultOwnershipTransferRequests,
  vaultRekeyJobs,
  vaults,
} from '../db/schema.ts';
import type { DbOrTx } from './audit.ts';
import { publicKeyFingerprint, sha256 } from './e2ee.ts';
import { recordSyncEvent } from './commands.ts';
import type { SyncEventRow } from './bus.ts';

export type EnvelopeAuthorizationKind = 'direct' | 'custom_group' | 'directory_group';
export type EnvelopeCapability = 'metadata' | 'full';

export interface EnsureEnvelopeTasksInput {
  vaultId: string;
  keyEpoch: number;
  authorizationKind: EnvelopeAuthorizationKind;
  authorizationRef: string;
  recipientUserIds: string[];
  capability: EnvelopeCapability;
  now?: Date;
}

export interface VaultAccessRevocationResult {
  rekeyTask: typeof vaultRekeyJobs.$inferSelect | null;
  rekeyUserIds: string[];
  retainedAccessUserIds: string[];
}

export async function ensureEnvelopeTasks(
  db: DbOrTx,
  input: EnsureEnvelopeTasksInput,
): Promise<{ pending: number; completed: number; withoutProfile: number }> {
  const requestedUserIds = [...new Set(input.recipientUserIds)];
  const recipientUserIds: string[] = [];
  const ineligibleUserIds: string[] = [];
  for (const recipientUserId of requestedUserIds) {
    if (await isEnvelopeTaskAuthorizationActive(db, {
      vaultId: input.vaultId,
      keyEpoch: input.keyEpoch,
      authorizationKind: input.authorizationKind,
      authorizationRef: input.authorizationRef,
      recipientUserId,
      capability: input.capability,
    })) {
      recipientUserIds.push(recipientUserId);
    } else {
      ineligibleUserIds.push(recipientUserId);
    }
  }
  if (ineligibleUserIds.length > 0) {
    await cancelEnvelopeTasks(db, {
      vaultId: input.vaultId,
      authorizationKind: input.authorizationKind,
      authorizationRef: input.authorizationRef,
      recipientUserIds: ineligibleUserIds,
      keyEpoch: input.keyEpoch,
      capability: input.capability,
      now: input.now,
    });
  }
  if (recipientUserIds.length === 0) return { pending: 0, completed: 0, withoutProfile: 0 };
  const now = input.now ?? new Date();
  const profiles = await db.select().from(userCryptoProfiles)
    .where(inArray(userCryptoProfiles.userId, recipientUserIds));
  const envelopes = await db.select().from(vaultKeyEnvelopes).where(and(
    eq(vaultKeyEnvelopes.vaultId, input.vaultId),
    eq(vaultKeyEnvelopes.keyEpoch, input.keyEpoch),
    eq(vaultKeyEnvelopes.recipientKind, 'user'),
    eq(vaultKeyEnvelopes.authorizationKind, input.authorizationKind),
    eq(vaultKeyEnvelopes.authorizationRef, input.authorizationRef),
    inArray(vaultKeyEnvelopes.recipientUserId, recipientUserIds),
    eq(vaultKeyEnvelopes.accessScope, input.capability),
    eq(vaultKeyEnvelopes.status, 'active'),
  ));
  const existingTasks = await db.select().from(vaultEnvelopeTasks).where(and(
    eq(vaultEnvelopeTasks.vaultId, input.vaultId),
    eq(vaultEnvelopeTasks.keyEpoch, input.keyEpoch),
    eq(vaultEnvelopeTasks.authorizationKind, input.authorizationKind),
    eq(vaultEnvelopeTasks.authorizationRef, input.authorizationRef),
    inArray(vaultEnvelopeTasks.recipientUserId, recipientUserIds),
    eq(vaultEnvelopeTasks.capability, input.capability),
  ));
  const profileByUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  let pending = 0;
  let completed = 0;
  let withoutProfile = 0;

  for (const recipientUserId of recipientUserIds) {
    const profile = profileByUser.get(recipientUserId);
    const exactEnvelope = profile
      ? envelopes.find((envelope) =>
          envelope.recipientUserId === recipientUserId &&
          envelope.envelopeVersion === profile.cryptoGeneration &&
          envelope.recipientKeyFingerprint === publicKeyFingerprint(
            Buffer.from(profile.publicEncryptionKey).toString('base64url'),
          ))
      : undefined;
    const matchingTasks = existingTasks.filter((task) => task.recipientUserId === recipientUserId);
    const currentPending = matchingTasks.find((task) => task.status === 'pending');

    if (exactEnvelope) {
      if (currentPending) {
        await db.update(vaultEnvelopeTasks).set({
          status: 'completed',
          expectedProfileGeneration: profile!.cryptoGeneration,
          completedEnvelopeId: exactEnvelope.id,
          completedAt: now,
          updatedAt: now,
        }).where(eq(vaultEnvelopeTasks.id, currentPending.id));
      } else if (!matchingTasks.some((task) =>
        task.status === 'completed' && task.completedEnvelopeId === exactEnvelope.id
      )) {
        await db.insert(vaultEnvelopeTasks).values({
          vaultId: input.vaultId,
          keyEpoch: input.keyEpoch,
          authorizationKind: input.authorizationKind,
          authorizationRef: input.authorizationRef,
          recipientUserId,
          capability: input.capability,
          expectedProfileGeneration: profile!.cryptoGeneration,
          status: 'completed',
          completedEnvelopeId: exactEnvelope.id,
          completedAt: now,
          updatedAt: now,
        });
      }
      completed += 1;
      continue;
    }

    const generation = profile?.cryptoGeneration ?? null;
    if (currentPending?.expectedProfileGeneration !== generation) {
      if (currentPending) {
        await db.update(vaultEnvelopeTasks).set({
          status: 'cancelled',
          cancelledAt: now,
          updatedAt: now,
        }).where(eq(vaultEnvelopeTasks.id, currentPending.id));
      }
      await db.insert(vaultEnvelopeTasks).values({
        vaultId: input.vaultId,
        keyEpoch: input.keyEpoch,
        authorizationKind: input.authorizationKind,
        authorizationRef: input.authorizationRef,
        recipientUserId,
        capability: input.capability,
        expectedProfileGeneration: generation,
        status: 'pending',
        updatedAt: now,
      }).onConflictDoNothing();
    }
    pending += 1;
    if (!profile) withoutProfile += 1;
  }
  return { pending, completed, withoutProfile };
}

export async function cancelEnvelopeTasks(
  db: DbOrTx,
  input: {
    vaultId: string;
    authorizationKind?: EnvelopeAuthorizationKind;
    authorizationRef?: string;
    recipientUserIds?: string[];
    keyEpoch?: number;
    capability?: EnvelopeCapability;
    now?: Date;
  },
): Promise<void> {
  const conditions = [
    eq(vaultEnvelopeTasks.vaultId, input.vaultId),
    eq(vaultEnvelopeTasks.status, 'pending'),
  ];
  if (input.authorizationKind) conditions.push(eq(vaultEnvelopeTasks.authorizationKind, input.authorizationKind));
  if (input.authorizationRef) conditions.push(eq(vaultEnvelopeTasks.authorizationRef, input.authorizationRef));
  if (input.keyEpoch !== undefined) conditions.push(eq(vaultEnvelopeTasks.keyEpoch, input.keyEpoch));
  if (input.capability) conditions.push(eq(vaultEnvelopeTasks.capability, input.capability));
  if (input.recipientUserIds?.length) {
    conditions.push(inArray(vaultEnvelopeTasks.recipientUserId, [...new Set(input.recipientUserIds)]));
  }
  const now = input.now ?? new Date();
  const pendingTasks = await db.select({ id: vaultEnvelopeTasks.id }).from(vaultEnvelopeTasks)
    .where(and(...conditions));
  await db.update(vaultEnvelopeTasks).set({
    status: 'cancelled',
    completedEnvelopeId: null,
    completedAt: null,
    cancelledAt: now,
    updatedAt: now,
  }).where(and(...conditions));
  if (pendingTasks.length) {
    await db.update(vaultOwnershipTransferRequests).set({
      status: 'cancelled',
      cancelledAt: now,
      updatedAt: now,
    }).where(and(
      inArray(vaultOwnershipTransferRequests.envelopeTaskId, pendingTasks.map((task) => task.id)),
      eq(vaultOwnershipTransferRequests.status, 'pending'),
    ));
  }
}

export async function reconcilePendingEnvelopeTasksForProfile(
  db: DbOrTx,
  userId: string,
  newGeneration: number,
  now = new Date(),
): Promise<{ rebuilt: number; vaultIds: string[] }> {
  const pending = await db.select().from(vaultEnvelopeTasks).where(and(
    eq(vaultEnvelopeTasks.recipientUserId, userId),
    eq(vaultEnvelopeTasks.status, 'pending'),
  ));
  let rebuilt = 0;
  const vaultIds = new Set<string>();
  for (const task of pending) {
    await cancelEnvelopeTasks(db, {
      vaultId: task.vaultId,
      authorizationKind: task.authorizationKind,
      authorizationRef: task.authorizationRef,
      recipientUserIds: [task.recipientUserId],
      keyEpoch: task.keyEpoch,
      capability: task.capability,
      now,
    });
    if (!await isEnvelopeTaskAuthorizationActive(db, task)) continue;
    await db.insert(vaultEnvelopeTasks).values({
      vaultId: task.vaultId,
      keyEpoch: task.keyEpoch,
      authorizationKind: task.authorizationKind,
      authorizationRef: task.authorizationRef,
      recipientUserId: task.recipientUserId,
      capability: task.capability,
      expectedProfileGeneration: newGeneration,
      status: 'pending',
      updatedAt: now,
    }).onConflictDoNothing();
    vaultIds.add(task.vaultId);
    rebuilt += 1;
  }
  return { rebuilt, vaultIds: [...vaultIds] };
}

export async function isEnvelopeTaskAuthorizationActive(
  db: DbOrTx,
  task: Pick<typeof vaultEnvelopeTasks.$inferSelect,
    'vaultId' | 'keyEpoch' | 'authorizationKind' | 'authorizationRef' | 'recipientUserId' | 'capability'>,
): Promise<boolean> {
  const state = (await db.select().from(vaultCryptoStates).where(and(
    eq(vaultCryptoStates.vaultId, task.vaultId),
    eq(vaultCryptoStates.storageMode, 'e2ee'),
  )).limit(1))[0];
  if (!state?.activeEpoch || state.activeEpoch !== task.keyEpoch) return false;

  const effectiveCapability = await resolveAuthorizedVaultCapability(
    db,
    task.vaultId,
    task.recipientUserId,
  );
  if (effectiveCapability !== task.capability) return false;

  if (task.authorizationKind !== 'direct') {
    const directMembership = (await db.select({ id: vaultMemberships.id }).from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, task.vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, task.recipientUserId),
    )).limit(1))[0];
    if (directMembership) return false;
  }

  let role: MembershipRole | null = null;
  if (task.authorizationKind === 'direct') {
    if (task.authorizationRef !== task.recipientUserId) return false;
    const membership = await db.select({ role: vaultMemberships.role }).from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, task.vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, task.authorizationRef),
    )).limit(1);
    const personal = await db.select({ id: vaults.id }).from(vaults).where(and(
      eq(vaults.id, task.vaultId),
      eq(vaults.kind, 'personal'),
      eq(vaults.ownerUserId, task.recipientUserId),
    )).limit(1);
    role = membership[0]?.role ?? (personal[0] ? 'owner' : null);
  } else if (task.authorizationKind === 'custom_group') {
    const authorization = await db.select({ role: vaultCustomGroupRoles.role }).from(vaultCustomGroupRoles).where(and(
      eq(vaultCustomGroupRoles.vaultId, task.vaultId),
      eq(vaultCustomGroupRoles.groupId, task.authorizationRef),
    )).limit(1);
    const membership = await db.select({ userId: customGroupMembers.userId }).from(customGroupMembers).where(and(
      eq(customGroupMembers.groupId, task.authorizationRef),
      eq(customGroupMembers.userId, task.recipientUserId),
    )).limit(1);
    role = membership[0] ? authorization[0]?.role ?? null : null;
  } else {
    const authorization = await db.select({ role: vaultMemberships.role }).from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, task.vaultId),
      eq(vaultMemberships.subjectKind, 'group'),
      eq(vaultMemberships.subjectId, task.authorizationRef),
    )).limit(1);
    const recipient = await db.select({ groups: users.groups, active: users.active }).from(users)
      .where(eq(users.id, task.recipientUserId)).limit(1);
    role = recipient[0]?.active && recipient[0].groups.includes(task.authorizationRef)
      ? authorization[0]?.role ?? null
      : null;
  }
  return role !== null && capabilityForRole(role) === task.capability;
}

export function capabilityForRole(role: MembershipRole): EnvelopeCapability {
  return role === 'auditor' ? 'metadata' : 'full';
}

export async function resolveAuthorizedVaultCapability(
  db: DbOrTx,
  vaultId: string,
  userId: string,
): Promise<EnvelopeCapability | null> {
  const vault = (await db.select({ kind: vaults.kind, ownerUserId: vaults.ownerUserId }).from(vaults)
    .where(eq(vaults.id, vaultId)).limit(1))[0];
  if (!vault) return null;
  const recipient = await db.select({ groups: users.groups, active: users.active })
    .from(users).where(eq(users.id, userId)).limit(1);
  if (!recipient[0]?.active) return null;
  if (vault.kind === 'personal') return vault.ownerUserId === userId ? 'full' : null;
  const memberships = await db.select().from(vaultMemberships)
    .where(eq(vaultMemberships.vaultId, vaultId));
  const customMemberships = await db.select({
    role: vaultCustomGroupRoles.role,
    groupId: vaultCustomGroupRoles.groupId,
  })
    .from(customGroupMembers)
    .innerJoin(vaultCustomGroupRoles, and(
      eq(vaultCustomGroupRoles.groupId, customGroupMembers.groupId),
      eq(vaultCustomGroupRoles.vaultId, vaultId),
    ))
    .where(eq(customGroupMembers.userId, userId));
  const customGroupIds = customMemberships.map((row) => row.groupId);
  const role = resolveEffectiveRole([
    ...memberships,
    ...customMemberships.map((row) => ({
      subjectKind: 'group' as const,
      subjectId: row.groupId,
      role: row.role,
    })),
  ], {
    userId,
    groups: [...recipient[0].groups, ...customGroupIds],
  });
  return role ? capabilityForRole(role) : null;
}

export async function resolveEffectiveEnvelopeAuthorization(
  db: DbOrTx,
  vaultId: string,
  userId: string,
): Promise<{
  authorizationKind: EnvelopeAuthorizationKind;
  authorizationRef: string;
  capability: EnvelopeCapability;
} | null> {
  const vault = (await db.select({ kind: vaults.kind, ownerUserId: vaults.ownerUserId }).from(vaults)
    .where(eq(vaults.id, vaultId)).limit(1))[0];
  const recipient = (await db.select({ groups: users.groups, active: users.active }).from(users)
    .where(eq(users.id, userId)).limit(1))[0];
  if (!vault || !recipient?.active) return null;
  if (vault.kind === 'personal') {
    return vault.ownerUserId === userId
      ? { authorizationKind: 'direct', authorizationRef: userId, capability: 'full' }
      : null;
  }

  const direct = (await db.select({ role: vaultMemberships.role }).from(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, vaultId),
    eq(vaultMemberships.subjectKind, 'user'),
    eq(vaultMemberships.subjectId, userId),
  )).limit(1))[0];
  if (direct) {
    return {
      authorizationKind: 'direct',
      authorizationRef: userId,
      capability: capabilityForRole(direct.role),
    };
  }

  const directoryRoles = await db
    .select({ role: vaultMemberships.role, authorizationRef: vaultMemberships.subjectId })
    .from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, vaultId),
      eq(vaultMemberships.subjectKind, 'group'),
    ));
  const customRoles = await db
    .select({ role: vaultCustomGroupRoles.role, authorizationRef: vaultCustomGroupRoles.groupId })
    .from(customGroupMembers)
    .innerJoin(vaultCustomGroupRoles, and(
      eq(vaultCustomGroupRoles.groupId, customGroupMembers.groupId),
      eq(vaultCustomGroupRoles.vaultId, vaultId),
    ))
    .where(eq(customGroupMembers.userId, userId));
  const candidates = [
    ...directoryRoles
      .filter((row) => recipient.groups.includes(row.authorizationRef))
      .map((row) => ({
        authorizationKind: 'directory_group' as const,
        authorizationRef: row.authorizationRef,
        capability: capabilityForRole(row.role),
      })),
    ...customRoles.map((row) => ({
      authorizationKind: 'custom_group' as const,
      authorizationRef: row.authorizationRef,
      capability: capabilityForRole(row.role),
    })),
  ].sort((left, right) =>
    capabilityRank(right.capability) - capabilityRank(left.capability) ||
    left.authorizationKind.localeCompare(right.authorizationKind) ||
    left.authorizationRef.localeCompare(right.authorizationRef));
  return candidates[0] ?? null;
}

export async function revokeUsersAndRequireRekey(
  db: DbOrTx,
  state: typeof vaultCryptoStates.$inferSelect,
  userIds: string[],
  input: {
    initiatedByUserId: string | null;
    initiatedByDeviceId: string | null;
    reason: 'member_removed' | 'role_reduced' | 'directory_membership_removed';
    now?: Date;
  },
): Promise<VaultAccessRevocationResult> {
  const recipients = [...new Set(userIds)];
  const now = input.now ?? new Date();
  if (recipients.length === 0) {
    return { rekeyTask: null, rekeyUserIds: [], retainedAccessUserIds: [] };
  }

  const authorizations = new Map<
    string,
    Awaited<ReturnType<typeof resolveEffectiveEnvelopeAuthorization>>
  >();
  for (const userId of recipients) {
    authorizations.set(userId, await resolveEffectiveEnvelopeAuthorization(db, state.vaultId, userId));
  }
  const retainedAccessUserIds = recipients.filter((userId) => authorizations.get(userId) !== null);
  const devices = await db.select({ id: userDevices.id, userId: userDevices.userId }).from(userDevices)
    .where(inArray(userDevices.userId, recipients));
  const deviceOwner = new Map(devices.map((device) => [device.id, device.userId]));
  const recipientCondition = devices.length > 0
    ? or(
        inArray(vaultKeyEnvelopes.recipientUserId, recipients),
        inArray(vaultKeyEnvelopes.recipientDeviceId, devices.map((device) => device.id)),
      )
    : inArray(vaultKeyEnvelopes.recipientUserId, recipients);
  const activeEnvelopes = await db.select({
    recipientUserId: vaultKeyEnvelopes.recipientUserId,
    recipientDeviceId: vaultKeyEnvelopes.recipientDeviceId,
    accessScope: vaultKeyEnvelopes.accessScope,
  }).from(vaultKeyEnvelopes).where(and(
    eq(vaultKeyEnvelopes.vaultId, state.vaultId),
    eq(vaultKeyEnvelopes.keyEpoch, state.activeEpoch!),
    eq(vaultKeyEnvelopes.status, 'active'),
    inArray(vaultKeyEnvelopes.accessScope, ['metadata', 'full']),
    recipientCondition,
  ));
  const activeCapabilities = new Map<string, EnvelopeCapability[]>();
  for (const envelope of activeEnvelopes) {
    const userId = envelope.recipientUserId ?? (
      envelope.recipientDeviceId ? deviceOwner.get(envelope.recipientDeviceId) : undefined
    );
    if (!userId || envelope.accessScope === 'recovery') continue;
    const capabilities = activeCapabilities.get(userId) ?? [];
    capabilities.push(envelope.accessScope);
    activeCapabilities.set(userId, capabilities);
  }
  const rekeyUserIds = recipients.filter((userId) => {
    const currentCapability = authorizations.get(userId)?.capability ?? null;
    return (activeCapabilities.get(userId) ?? []).some((capability) =>
      capabilityRank(capability) > capabilityRank(currentCapability));
  });

  await cancelEnvelopeTasks(db, { vaultId: state.vaultId, recipientUserIds: recipients, now });
  for (const userId of retainedAccessUserIds) {
    const authorization = authorizations.get(userId)!;
    await ensureEnvelopeTasks(db, {
      vaultId: state.vaultId,
      keyEpoch: state.activeEpoch!,
      authorizationKind: authorization.authorizationKind,
      authorizationRef: authorization.authorizationRef,
      recipientUserIds: [userId],
      capability: authorization.capability,
      now,
    });
  }

  if (rekeyUserIds.length > 0) {
    await db.update(vaultKeyEnvelopes).set({
      status: 'revoked', revokedAt: now, revocationReason: input.reason,
    }).where(and(
      eq(vaultKeyEnvelopes.vaultId, state.vaultId),
      inArray(vaultKeyEnvelopes.recipientUserId, rekeyUserIds),
      inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
    ));
    const rekeyDeviceIds = devices
      .filter((device) => rekeyUserIds.includes(device.userId))
      .map((device) => device.id);
    if (rekeyDeviceIds.length > 0) {
      await db.update(vaultKeyEnvelopes).set({
        status: 'revoked', revokedAt: now, revocationReason: input.reason,
      }).where(and(
        eq(vaultKeyEnvelopes.vaultId, state.vaultId),
        inArray(vaultKeyEnvelopes.recipientDeviceId, rekeyDeviceIds),
        inArray(vaultKeyEnvelopes.status, ['active', 'pending']),
      ));
    }
  }
  const rekeyTask = rekeyUserIds.length > 0
    ? await ensureMembershipRekeyTask(
        db,
        state.vaultId,
        input.initiatedByUserId,
        input.initiatedByDeviceId,
        now,
      )
    : null;
  return { rekeyTask, rekeyUserIds, retainedAccessUserIds };
}

export async function ensureMembershipRekeyTask(
  db: DbOrTx,
  vaultId: string,
  userId: string | null,
  deviceId: string | null,
  now = new Date(),
  reason: 'membership_change' | 'device_compromise' | 'ownership_transfer' = 'membership_change',
) {
  const state = (await db.select().from(vaultCryptoStates).where(and(
    eq(vaultCryptoStates.vaultId, vaultId),
    eq(vaultCryptoStates.storageMode, 'e2ee'),
  )).for('update').limit(1))[0];
  if (!state?.activeEpoch) throw new Error('active E2EE epoch required');
  const fromEpoch = state.activeEpoch;
  const toEpoch = fromEpoch + 1;
  let task = (await db.select().from(vaultRekeyJobs).where(and(
    eq(vaultRekeyJobs.vaultId, vaultId),
    eq(vaultRekeyJobs.fromEpoch, fromEpoch),
    inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
  )).for('update').limit(1))[0];
  if (!task) {
    const pendingDigest = (label: string) => sha256(canonicalJson({
      kind: 'pending-rekey-commitment', label, protocol: 'lm-e2ee-v1',
      vaultId, epoch: toEpoch,
    } as never));
    await db.insert(vaultKeyEpochs).values({
      vaultId,
      epoch: toEpoch,
      previousEpoch: fromEpoch,
      status: 'preparing',
      reason,
      metadataKeyCommitment: pendingDigest('metadata'),
      contentKeyCommitment: pendingDigest('content'),
      recipientSetDigest: pendingDigest('recipients'),
      createdByUserId: userId,
      createdByDeviceId: deviceId,
    }).onConflictDoNothing();
    const priorTask = (await db.select().from(vaultRekeyJobs).where(and(
      eq(vaultRekeyJobs.vaultId, vaultId),
      eq(vaultRekeyJobs.toEpoch, toEpoch),
    )).for('update').limit(1))[0];
    if (priorTask) {
      throw new Error(`rekey epoch ${toEpoch} already belongs to inactive job ${priorTask.id}`);
    }
    task = (await db.insert(vaultRekeyJobs).values({
      vaultId,
      fromEpoch,
      toEpoch,
      reason,
      status: 'pending',
      freezeGeneration: state.accessGeneration + 1,
      initiatedByUserId: userId,
      initiatedByDeviceId: deviceId,
      startedAt: now,
    }).returning())[0]!;
  } else {
    if (task.toEpoch !== toEpoch) {
      throw new Error(`active rekey job ${task.id} does not advance the locked epoch`);
    }
    const mergedReason = reason === 'device_compromise' || task.reason === 'device_compromise'
      ? 'device_compromise'
      : reason === 'ownership_transfer' || task.reason === 'ownership_transfer'
        ? 'ownership_transfer'
        : task.reason;
    task = (await db.update(vaultRekeyJobs).set({
      reason: mergedReason,
      freezeGeneration: state.accessGeneration + 1,
      updatedAt: now,
    }).where(eq(vaultRekeyJobs.id, task.id)).returning())[0]!;
    await db.update(vaultKeyEpochs).set({ reason: mergedReason }).where(and(
      eq(vaultKeyEpochs.vaultId, task.vaultId),
      eq(vaultKeyEpochs.epoch, task.toEpoch),
    ));
  }
  const targetEpoch = (await db.select({
    previousEpoch: vaultKeyEpochs.previousEpoch,
    status: vaultKeyEpochs.status,
  }).from(vaultKeyEpochs).where(and(
    eq(vaultKeyEpochs.vaultId, vaultId),
    eq(vaultKeyEpochs.epoch, task.toEpoch),
  )).for('update').limit(1))[0];
  if (targetEpoch?.previousEpoch !== fromEpoch || targetEpoch.status !== 'preparing') {
    throw new Error(`active rekey job ${task.id} has an inconsistent target epoch`);
  }
  const updatedState = await db.update(vaultCryptoStates).set({
    writeState: 'rekeying',
    accessGeneration: state.accessGeneration + 1,
    rowVersion: state.rowVersion + 1,
    updatedAt: now,
  }).where(and(
    eq(vaultCryptoStates.vaultId, vaultId),
    eq(vaultCryptoStates.activeEpoch, fromEpoch),
    eq(vaultCryptoStates.rowVersion, state.rowVersion),
  )).returning({ vaultId: vaultCryptoStates.vaultId });
  if (!updatedState[0]) throw new Error('locked E2EE vault state changed unexpectedly');
  return task;
}

export async function settleEnvelopeTasksAfterRekey(
  db: DbOrTx,
  vaultId: string,
  newEpoch: number,
  envelopes: Array<typeof vaultKeyEnvelopes.$inferSelect>,
  now = new Date(),
): Promise<void> {
  const pending = await db.select().from(vaultEnvelopeTasks).where(and(
    eq(vaultEnvelopeTasks.vaultId, vaultId),
    eq(vaultEnvelopeTasks.status, 'pending'),
  ));
  for (const task of pending) {
    const envelope = envelopes.find((candidate) =>
      candidate.keyEpoch === newEpoch &&
      candidate.recipientKind === 'user' &&
      candidate.recipientUserId === task.recipientUserId &&
      candidate.accessScope === task.capability &&
      candidate.authorizationKind === task.authorizationKind &&
      candidate.authorizationRef === task.authorizationRef &&
      candidate.status === 'active'
    );
    await db.update(vaultEnvelopeTasks).set({
      status: 'cancelled', cancelledAt: now, updatedAt: now,
    }).where(eq(vaultEnvelopeTasks.id, task.id));
    if (!await isAuthorizationActiveIgnoringEpoch(db, task)) continue;
    if (envelope) {
      await db.insert(vaultEnvelopeTasks).values({
        vaultId,
        keyEpoch: newEpoch,
        authorizationKind: task.authorizationKind,
        authorizationRef: task.authorizationRef,
        recipientUserId: task.recipientUserId,
        capability: task.capability,
        expectedProfileGeneration: envelope.envelopeVersion,
        status: 'completed',
        completedEnvelopeId: envelope.id,
        completedAt: now,
        updatedAt: now,
      });
    } else {
      const profile = (await db.select({ generation: userCryptoProfiles.cryptoGeneration })
        .from(userCryptoProfiles).where(eq(userCryptoProfiles.userId, task.recipientUserId)).limit(1))[0];
      await db.insert(vaultEnvelopeTasks).values({
        vaultId,
        keyEpoch: newEpoch,
        authorizationKind: task.authorizationKind,
        authorizationRef: task.authorizationRef,
        recipientUserId: task.recipientUserId,
        capability: task.capability,
        expectedProfileGeneration: profile?.generation ?? null,
        status: 'pending',
        updatedAt: now,
      }).onConflictDoNothing();
    }
  }
}

export async function reconcileDirectoryMembershipChange(
  db: DbOrTx,
  userId: string,
  previousGroups: string[],
  nextGroups: string[],
  now = new Date(),
  nextActive = true,
  previousActive = true,
): Promise<{ addedVaultIds: string[]; rekeyVaultIds: string[]; events: SyncEventRow[] }> {
  const previous = new Set(previousActive ? previousGroups : []);
  const next = new Set(nextActive ? nextGroups : []);
  const addedGroups = [...next].filter((groupId) => !previous.has(groupId));
  const removedGroups = [...previous].filter((groupId) => !next.has(groupId));
  if (addedGroups.length === 0 && removedGroups.length === 0 && nextActive === previousActive) {
    return { addedVaultIds: [], rekeyVaultIds: [], events: [] };
  }
  const changedGroups = [...new Set([...addedGroups, ...removedGroups])];
  const links = changedGroups.length ? await db.select({ membership: vaultMemberships, state: vaultCryptoStates })
    .from(vaultMemberships)
    .innerJoin(vaultCryptoStates, and(
      eq(vaultCryptoStates.vaultId, vaultMemberships.vaultId),
      eq(vaultCryptoStates.storageMode, 'e2ee'),
    ))
    .where(and(
      eq(vaultMemberships.subjectKind, 'group'),
      inArray(vaultMemberships.subjectId, changedGroups),
    )) : [];
  const removedLinks = links.filter((row) => removedGroups.includes(row.membership.subjectId));
  const addedLinks = links.filter((row) => addedGroups.includes(row.membership.subjectId));
  const rekeyVaultIds = new Set<string>();
  const events: SyncEventRow[] = [];

  const directAndPreviousGroupLinks = !nextActive || !previousActive
    ? await db.select({ membership: vaultMemberships, state: vaultCryptoStates })
      .from(vaultMemberships)
      .innerJoin(vaultCryptoStates, and(
        eq(vaultCryptoStates.vaultId, vaultMemberships.vaultId),
        eq(vaultCryptoStates.storageMode, 'e2ee'),
      ))
      .where(or(
        and(eq(vaultMemberships.subjectKind, 'user'), eq(vaultMemberships.subjectId, userId)),
        ...(previousGroups.length ? [and(
          eq(vaultMemberships.subjectKind, 'group'),
          inArray(vaultMemberships.subjectId, previousGroups),
        )] : []),
      ))
    : [];
  const customLinks = !nextActive || !previousActive
    ? await db.select({ role: vaultCustomGroupRoles.role, groupId: vaultCustomGroupRoles.groupId, state: vaultCryptoStates })
      .from(customGroupMembers)
      .innerJoin(vaultCustomGroupRoles, eq(vaultCustomGroupRoles.groupId, customGroupMembers.groupId))
      .innerJoin(vaultCryptoStates, and(
        eq(vaultCryptoStates.vaultId, vaultCustomGroupRoles.vaultId),
        eq(vaultCryptoStates.storageMode, 'e2ee'),
      ))
      .where(eq(customGroupMembers.userId, userId))
    : [];
  const personalStates = !nextActive || !previousActive
    ? await db.select({ state: vaultCryptoStates }).from(vaults)
        .innerJoin(vaultCryptoStates, and(
          eq(vaultCryptoStates.vaultId, vaults.id),
          eq(vaultCryptoStates.storageMode, 'e2ee'),
        ))
        .where(and(eq(vaults.kind, 'personal'), eq(vaults.ownerUserId, userId)))
    : [];

  const stateByVaultId = new Map<string, typeof vaultCryptoStates.$inferSelect>();
  for (const state of [
    ...links.map((row) => row.state),
    ...directAndPreviousGroupLinks.map((row) => row.state),
    ...customLinks.map((row) => row.state),
    ...personalStates.map((row) => row.state),
  ]) {
    stateByVaultId.set(state.vaultId, state);
  }

  const cryptoChangedVaultIds = new Set<string>();
  const addedVaultIds = new Set<string>();
  for (const row of addedLinks) {
    if (!row.state.activeEpoch) continue;
    await ensureEnvelopeTasks(db, {
      vaultId: row.state.vaultId,
      keyEpoch: row.state.activeEpoch,
      authorizationKind: 'directory_group',
      authorizationRef: row.membership.subjectId,
      recipientUserIds: [userId],
      capability: capabilityForRole(row.membership.role),
      now,
    });
    addedVaultIds.add(row.state.vaultId);
  }
  if (nextActive && !previousActive) {
    for (const row of directAndPreviousGroupLinks) {
      if (!row.state.activeEpoch || row.membership.subjectKind !== 'user') continue;
      await ensureEnvelopeTasks(db, {
        vaultId: row.state.vaultId,
        keyEpoch: row.state.activeEpoch,
        authorizationKind: 'direct',
        authorizationRef: userId,
        recipientUserIds: [userId],
        capability: capabilityForRole(row.membership.role),
        now,
      });
      addedVaultIds.add(row.state.vaultId);
    }
    for (const row of customLinks) {
      if (!row.state.activeEpoch) continue;
      await ensureEnvelopeTasks(db, {
        vaultId: row.state.vaultId,
        keyEpoch: row.state.activeEpoch,
        authorizationKind: 'custom_group',
        authorizationRef: row.groupId,
        recipientUserIds: [userId],
        capability: capabilityForRole(row.role),
        now,
      });
      addedVaultIds.add(row.state.vaultId);
    }
    for (const row of personalStates) {
      if (!row.state.activeEpoch || row.state.writeState === 'rekeying') continue;
      await ensureEnvelopeTasks(db, {
        vaultId: row.state.vaultId,
        keyEpoch: row.state.activeEpoch,
        authorizationKind: 'direct',
        authorizationRef: userId,
        recipientUserIds: [userId],
        capability: 'full',
        now,
      });
      addedVaultIds.add(row.state.vaultId);
    }
  }

  for (const row of removedLinks) {
    await cancelEnvelopeTasks(db, {
      vaultId: row.state.vaultId,
      authorizationKind: 'directory_group',
      authorizationRef: row.membership.subjectId,
      recipientUserIds: [userId],
      now,
    });
  }
  const removedStateRows = nextActive
    ? removedLinks.map((row) => row.state)
    : [
        ...removedLinks.map((row) => row.state),
        ...directAndPreviousGroupLinks.map((row) => row.state),
        ...customLinks.map((row) => row.state),
        ...personalStates.map((row) => row.state),
      ];
  for (const vaultId of [...new Set(removedStateRows.map((state) => state.vaultId))]) {
    const state = stateByVaultId.get(vaultId)!;
    if (!state.activeEpoch) continue;
    const revocation = await revokeUsersAndRequireRekey(db, state, [userId], {
      initiatedByUserId: null,
      initiatedByDeviceId: null,
      reason: 'directory_membership_removed',
      now,
    });
    if (revocation.rekeyTask) {
      rekeyVaultIds.add(vaultId);
      events.push(await recordSyncEvent(db, {
        type: 'vault.rekey_required',
        vaultId,
        itemId: null,
        payload: {
          pendingEpoch: revocation.rekeyTask.toEpoch,
          taskId: revocation.rekeyTask.id,
        },
      }));
    } else {
      cryptoChangedVaultIds.add(vaultId);
    }
  }
  for (const vaultId of addedVaultIds) {
    if (rekeyVaultIds.has(vaultId)) continue;
    cryptoChangedVaultIds.add(vaultId);
  }
  for (const vaultId of cryptoChangedVaultIds) {
    if (rekeyVaultIds.has(vaultId)) continue;
    const state = stateByVaultId.get(vaultId);
    if (!state?.activeEpoch) continue;
    await db.update(vaultCryptoStates).set({
      accessGeneration: sql`${vaultCryptoStates.accessGeneration} + 1`,
      rowVersion: sql`${vaultCryptoStates.rowVersion} + 1`,
      updatedAt: now,
    }).where(eq(vaultCryptoStates.vaultId, vaultId));
    events.push(await recordSyncEvent(db, {
      type: 'vault.crypto_changed',
      vaultId,
      itemId: null,
      payload: { accessChanged: true },
    }));
  }
  return { addedVaultIds: [...addedVaultIds], rekeyVaultIds: [...rekeyVaultIds], events };
}

function capabilityRank(capability: EnvelopeCapability | null): number {
  if (capability === 'full') return 2;
  if (capability === 'metadata') return 1;
  return 0;
}

async function isAuthorizationActiveIgnoringEpoch(
  db: DbOrTx,
  task: Pick<typeof vaultEnvelopeTasks.$inferSelect,
    'vaultId' | 'authorizationKind' | 'authorizationRef' | 'recipientUserId' | 'capability'>,
): Promise<boolean> {
  const state = (await db.select({ activeEpoch: vaultCryptoStates.activeEpoch }).from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.vaultId, task.vaultId)).limit(1))[0];
  return Boolean(state?.activeEpoch && await isEnvelopeTaskAuthorizationActive(db, {
    ...task,
    keyEpoch: state.activeEpoch,
  }));
}
