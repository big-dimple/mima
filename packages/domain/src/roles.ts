import type { Membership, MembershipRole, SessionUser } from '@mima/contracts';

/**
 * 角色权重：仅用于"取组角色中的最高权限"。
 * auditor 排最低，它有审计读取特权，但没有任何敏感内容读取/写入能力，
 * 因此当用户同时通过多个组获得 auditor 和 viewer 时，viewer 视为更高权限。
 */
const ROLE_RANK: Record<MembershipRole, number> = {
  auditor: 0,
  viewer: 1,
  editor: 2,
  owner: 3,
};

export interface SubjectRef {
  userId: string;
  groups: string[];
}

/**
 * 解析用户在某个库上的生效角色。
 * 规则：直接用户角色存在时无条件覆盖组角色；否则取所有组角色中的最高权限。
 * platform-admin 不参与此解析——它必须同时是成员才能获得库内角色。
 */
export function resolveEffectiveRole(
  memberships: Pick<Membership, 'subjectKind' | 'subjectId' | 'role'>[],
  subject: SubjectRef,
): MembershipRole | null {
  const direct = memberships.find(
    (m) => m.subjectKind === 'user' && m.subjectId === subject.userId,
  );
  if (direct) return direct.role;

  const groupRoles = memberships
    .filter((m) => m.subjectKind === 'group' && subject.groups.includes(m.subjectId))
    .map((m) => m.role);
  if (groupRoles.length === 0) return null;
  return groupRoles.reduce((best, r) => (ROLE_RANK[r] > ROLE_RANK[best] ? r : best));
}

export function canReadMetadata(role: MembershipRole | null): boolean {
  return role !== null;
}

/** auditor 永远不能读取敏感内容正文。 */
export function canReveal(role: MembershipRole | null): boolean {
  return role === 'viewer' || role === 'editor' || role === 'owner';
}

export function canEditItems(role: MembershipRole | null): boolean {
  return role === 'editor' || role === 'owner';
}

/**
 * 成员增删改只能由该库的生效 owner 执行。
 * platform-admin 不再拥有成员管理权（防止管理面自提权读取敏感内容）。
 */
export function canManageMembers(role: MembershipRole | null): boolean {
  return role === 'owner';
}

/** 库本身的管理（改名/删除）：owner 或 platform-admin（系统管理面，不含敏感内容读取）。 */
export function canManageVault(role: MembershipRole | null, platformAdmin: boolean): boolean {
  return role === 'owner' || platformAdmin;
}

export function canReadAudit(role: MembershipRole | null, platformAdmin: boolean): boolean {
  return role === 'auditor' || role === 'owner' || platformAdmin;
}

export function isUserSubject(user: SessionUser, subjectKind: string, subjectId: string): boolean {
  if (subjectKind === 'user') return subjectId === user.id;
  return user.groups.includes(subjectId);
}
