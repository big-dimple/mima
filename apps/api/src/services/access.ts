import { eq, inArray, and } from 'drizzle-orm';
import type { MembershipRole, SessionUser } from '@mima/contracts';
import { resolveEffectiveRole } from '@mima/domain';
import {
  customGroupMembers,
  items,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCustomGroupRoles,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultMemberships,
  vaults,
} from '../db/schema.ts';
import type { DbOrTx } from './audit.ts';
import { encodeBase64Url, publicKeyFingerprint } from './e2ee.ts';

export interface VaultAccess {
  vault: typeof vaults.$inferSelect;
  role: MembershipRole | null;
}

export interface PersonalVaultRecoveryCandidate {
  vault: typeof vaults.$inferSelect;
  state: typeof vaultCryptoStates.$inferSelect;
  user: typeof users.$inferSelect;
  profile: typeof userCryptoProfiles.$inferSelect;
  targetDevice: typeof userDevices.$inferSelect;
}

/** 解析用户对单个库的实时授权，不以当前密钥信封是否已经生成作为前提。 */
export async function getVaultAuthorization(
  db: DbOrTx,
  user: SessionUser,
  vaultId: string,
): Promise<VaultAccess | null> {
  const vaultRows = await db.select().from(vaults).where(eq(vaults.id, vaultId)).limit(1);
  const vault = vaultRows[0];
  if (!vault) return null;
  if (vault.kind === 'personal') {
    return { vault, role: vault.ownerUserId === user.id ? 'owner' : null };
  }
  const memberships = await db
    .select()
    .from(vaultMemberships)
    .where(eq(vaultMemberships.vaultId, vaultId));
  const customGroupIds = await listUserCustomGroupIds(db, user.id);
  const customRoles = customGroupIds.length
    ? await db
        .select()
        .from(vaultCustomGroupRoles)
        .where(and(
          eq(vaultCustomGroupRoles.vaultId, vaultId),
          inArray(vaultCustomGroupRoles.groupId, customGroupIds),
        ))
    : [];
  const role = resolveEffectiveRole(
    [
      ...memberships,
      ...customRoles.map((row) => ({
        subjectKind: 'group' as const,
        subjectId: row.groupId,
        role: row.role,
      })),
    ],
    { userId: user.id, groups: [...user.groups, ...customGroupIds] },
  );
  return { vault, role };
}

/** 列出用户实时获权的全部库；调用方不得据此开放密文内容读取。 */
export async function listAuthorizedVaults(db: DbOrTx, user: SessionUser): Promise<VaultAccess[]> {
  const allVaults = await db.select().from(vaults);
  const teamIds = allVaults.filter((v) => v.kind === 'team').map((v) => v.id);
  const allMemberships = teamIds.length
    ? await db.select().from(vaultMemberships).where(inArray(vaultMemberships.vaultId, teamIds))
    : [];
  const customGroupIds = await listUserCustomGroupIds(db, user.id);
  const allCustomRoles = teamIds.length && customGroupIds.length
    ? await db
        .select()
        .from(vaultCustomGroupRoles)
        .where(and(
          inArray(vaultCustomGroupRoles.vaultId, teamIds),
          inArray(vaultCustomGroupRoles.groupId, customGroupIds),
        ))
    : [];
  const byVault = new Map<string, (typeof allMemberships)[number][]>();
  for (const m of allMemberships) {
    const list = byVault.get(m.vaultId) ?? [];
    list.push(m);
    byVault.set(m.vaultId, list);
  }
  const result: VaultAccess[] = [];
  for (const vault of allVaults) {
    if (vault.kind === 'personal') {
      if (vault.ownerUserId === user.id) result.push({ vault, role: 'owner' });
      continue;
    }
    const customRoles = allCustomRoles
      .filter((row) => row.vaultId === vault.id)
      .map((row) => ({ subjectKind: 'group' as const, subjectId: row.groupId, role: row.role }));
    const role = resolveEffectiveRole(
      [...(byVault.get(vault.id) ?? []), ...customRoles],
      { userId: user.id, groups: [...user.groups, ...customGroupIds] },
    );
    if (role) result.push({ vault, role });
  }
  return result;
}

/** 解析用户对单个库的可用访问；E2EE 库必须同时存在当前代、当前能力信封。 */
export async function getVaultAccess(
  db: DbOrTx,
  user: SessionUser,
  vaultId: string,
): Promise<VaultAccess | null> {
  const authorization = await getVaultAuthorization(db, user, vaultId);
  if (!authorization) return null;
  return {
    vault: authorization.vault,
    role: await requireCurrentEnvelope(
      db,
      authorization.vault.id,
      user.id,
      authorization.role,
    ),
  };
}

/** 列出已有当前信封、可以实际读取相应密文内容的全部库。 */
export async function listAccessibleVaults(db: DbOrTx, user: SessionUser): Promise<VaultAccess[]> {
  const authorized = await listAuthorizedVaults(db, user);
  const result: VaultAccess[] = [];
  for (const authorization of authorized) {
    const role = await requireCurrentEnvelope(
      db,
      authorization.vault.id,
      user.id,
      authorization.role,
    );
    if (role) result.push({ vault: authorization.vault, role });
  }
  return result;
}

/**
 * 个人库归属仍然有效，但当前用户 profile 没有活动 epoch 的当前代 full 用户信封时，
 * 只把它列为企业恢复候选。调用方不得据此放宽条目、内容或轮换材料权限。
 */
export async function listPersonalVaultRecoveryCandidates(
  db: DbOrTx,
  userId?: string,
): Promise<PersonalVaultRecoveryCandidate[]> {
  const personalVaults = await db.select().from(vaults).where(and(
    eq(vaults.kind, 'personal'),
    ...(userId ? [eq(vaults.ownerUserId, userId)] : []),
  ));
  if (personalVaults.length === 0) return [];
  const vaultIds = personalVaults.map((vault) => vault.id);
  const ownerIds = [...new Set(personalVaults
    .map((vault) => vault.ownerUserId)
    .filter((ownerId): ownerId is string => ownerId !== null))];
  if (ownerIds.length === 0) return [];

  const [states, activeUsers, profiles, activeDevices, activeEnvelopes] = await Promise.all([
    db.select().from(vaultCryptoStates).where(and(
      inArray(vaultCryptoStates.vaultId, vaultIds),
      eq(vaultCryptoStates.storageMode, 'e2ee'),
    )),
    db.select().from(users).where(and(
      inArray(users.id, ownerIds),
      eq(users.active, true),
    )),
    db.select().from(userCryptoProfiles).where(inArray(userCryptoProfiles.userId, ownerIds)),
    db.select().from(userDevices).where(and(
      inArray(userDevices.userId, ownerIds),
      eq(userDevices.deviceType, 'web'),
      eq(userDevices.status, 'active'),
    )),
    db.select().from(vaultKeyEnvelopes).where(and(
      inArray(vaultKeyEnvelopes.vaultId, vaultIds),
      eq(vaultKeyEnvelopes.status, 'active'),
      eq(vaultKeyEnvelopes.accessScope, 'full'),
    )),
  ]);
  const stateByVault = new Map(states.map((state) => [state.vaultId, state]));
  const userById = new Map(activeUsers.map((user) => [user.id, user]));
  const profileByUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  const devicesByUser = new Map<string, (typeof activeDevices)[number][]>();
  for (const device of activeDevices) {
    const devices = devicesByUser.get(device.userId) ?? [];
    devices.push(device);
    devicesByUser.set(device.userId, devices);
  }

  const result: PersonalVaultRecoveryCandidate[] = [];
  for (const vault of personalVaults) {
    const ownerUserId = vault.ownerUserId;
    const state = stateByVault.get(vault.id);
    const user = ownerUserId ? userById.get(ownerUserId) : undefined;
    const profile = ownerUserId ? profileByUser.get(ownerUserId) : undefined;
    const devices = ownerUserId ? (devicesByUser.get(ownerUserId) ?? []).filter((device) =>
      device.deviceGeneration === profile?.cryptoGeneration) : [];
    const targetDevice = [...devices].sort((left, right) =>
      deviceActivityTime(right) - deviceActivityTime(left) || right.id.localeCompare(left.id))[0];
    if (!ownerUserId || !state?.activeEpoch || !user || !profile || !targetDevice) continue;
    const activeDeviceIds = new Set(devices.map((device) => device.id));
    const hasCurrentFullEnvelope = activeEnvelopes.some((envelope) =>
      envelope.vaultId === vault.id &&
      envelope.keyEpoch === state.activeEpoch &&
      (envelope.recipientUserId === ownerUserId ||
        (envelope.recipientDeviceId !== null && activeDeviceIds.has(envelope.recipientDeviceId))));
    if (!hasCurrentFullEnvelope) result.push({ vault, state, user, profile, targetDevice });
  }
  return result;
}

export async function listVaultItems(db: DbOrTx, vaultId: string) {
  return db
    .select()
    .from(items)
    .where(and(eq(items.vaultId, vaultId), eq(items.deleted, false)));
}

export async function listVaultMemberships(db: DbOrTx, vaultId: string) {
  const legacy = await db.select().from(vaultMemberships).where(eq(vaultMemberships.vaultId, vaultId));
  const custom = await db.select().from(vaultCustomGroupRoles).where(eq(vaultCustomGroupRoles.vaultId, vaultId));
  return [
    ...legacy,
    ...custom.map((row) => ({
      id: row.id,
      vaultId: row.vaultId,
      subjectKind: 'custom_group' as const,
      subjectId: row.groupId,
      role: row.role,
      createdAt: row.createdAt,
    })),
  ];
}

async function listUserCustomGroupIds(db: DbOrTx, userId: string): Promise<string[]> {
  const rows = await db
    .select({ groupId: customGroupMembers.groupId })
    .from(customGroupMembers)
    .where(eq(customGroupMembers.userId, userId));
  return rows.map((row) => row.groupId);
}

async function requireCurrentEnvelope(
  db: DbOrTx,
  vaultId: string,
  userId: string,
  role: MembershipRole | null,
): Promise<MembershipRole | null> {
  if (!role) return null;
  const state = (
    await db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, vaultId)).limit(1)
  )[0];
  if (!state || state.storageMode !== 'e2ee') return role;
  if (!state.activeEpoch) return null;
  const profile = (await db.select().from(userCryptoProfiles)
    .where(eq(userCryptoProfiles.userId, userId)).limit(1))[0];
  if (!profile) return null;
  const scopes = role === 'auditor' ? ['metadata'] as const : ['full'] as const;
  const fingerprint = publicKeyFingerprint(encodeBase64Url(profile.publicEncryptionKey));
  const envelope = (
    await db.select({ id: vaultKeyEnvelopes.id }).from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, vaultId),
      eq(vaultKeyEnvelopes.keyEpoch, state.activeEpoch),
      eq(vaultKeyEnvelopes.status, 'active'),
      inArray(vaultKeyEnvelopes.accessScope, [...scopes]),
      eq(vaultKeyEnvelopes.recipientKind, 'user'),
      eq(vaultKeyEnvelopes.recipientUserId, userId),
      eq(vaultKeyEnvelopes.envelopeVersion, profile.cryptoGeneration),
      eq(vaultKeyEnvelopes.recipientKeyFingerprint, fingerprint),
    )).limit(1)
  )[0];
  return envelope ? role : null;
}

function deviceActivityTime(device: typeof userDevices.$inferSelect): number {
  return device.lastSeenAt?.getTime()
    ?? device.activatedAt?.getTime()
    ?? device.createdAt.getTime();
}
