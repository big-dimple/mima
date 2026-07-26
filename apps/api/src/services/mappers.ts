import type { ItemMeta, Membership, Vault } from '@mima/contracts';
import type { items, vaults, vaultMemberships } from '../db/schema.ts';

type ItemRow = typeof items.$inferSelect;
type VaultRow = typeof vaults.$inferSelect;
type MembershipRow = Omit<typeof vaultMemberships.$inferSelect, 'subjectKind'> & {
  subjectKind: Membership['subjectKind'];
};

export function toItemMeta(row: ItemRow): ItemMeta {
  return {
    id: row.id,
    vaultId: row.vaultId,
    kind: row.kind,
    title: row.title,
    username: row.username,
    origin: row.origin,
    tags: row.tags,
    favorite: row.favorite,
    sensitivity: row.sensitivity,
    version: row.version,
    secretVersion: row.secretVersion,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    updatedBy: row.updatedBy,
  };
}

export function toVaultDto(row: VaultRow): Vault {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    ownerUserId: row.ownerUserId,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toMembershipDto(row: MembershipRow): Membership {
  return {
    id: row.id,
    vaultId: row.vaultId,
    subjectKind: row.subjectKind,
    subjectId: row.subjectId,
    role: row.role,
    createdAt: row.createdAt.toISOString(),
  };
}
