import { createHash } from 'node:crypto';
import { and, asc, eq, inArray, or, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  CreateCustomGroupRequestSchema,
  CustomGroupDetailSchema,
  CustomGroupSchema,
  DeleteCustomGroupRequestSchema,
  RenameCustomGroupRequestSchema,
  SetCustomGroupMembersRequestSchema,
  TransferCustomGroupRequestSchema,
  UpdateCustomGroupRequestSchema,
  UserSearchResponseSchema,
} from '@mima/contracts';
import {
  customGroupMembers,
  customGroups,
  users,
  vaultCustomGroupRoles,
  vaultCryptoStates,
  vaultEnvelopeTasks,
} from '../db/schema.ts';
import { appendAudit, type AuditContext, type DbOrTx } from '../services/audit.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import type { SyncEventRow } from '../services/bus.ts';
import { DirectoryUnavailableError } from '../auth/directory.ts';
import {
  cancelEnvelopeTasks,
  capabilityForRole,
  ensureEnvelopeTasks,
  revokeUsersAndRequireRekey,
} from '../services/vault-envelope-tasks.ts';
import { lockRecipientSets } from '../services/recipient-set-lock.ts';

const GroupParams = z.object({ groupId: z.string().uuid() });
const GroupQuery = z.object({
  scope: z.enum(['owned', 'joined']).default('owned'),
  q: z.string().max(100).default(''),
  limit: z.coerce.number().int().min(1).max(50).default(50),
});
const UserSearchQuery = z.object({
  q: z.string().max(100).default(''),
  includeIds: z.string().max(4000).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(50),
});
class GroupStateConflictError extends Error {}
class GroupOwnerAccessError extends Error {}
class GroupTargetUnavailableError extends Error {}
class GroupLegacyLinkError extends Error {}

export function registerGroupRoutes(app: FastifyInstance): void {
  const { db, bus, audit, auth } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.get('/api/users/search', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['directory'],
      querystring: UserSearchQuery,
      response: { 200: UserSearchResponseSchema, 503: ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    try {
      const snapshot = await auth.directory.listDirectory();
      const includeIds = new Set(
        (req.query.includeIds ?? '').split(',').map((value) => value.trim()).filter(Boolean).slice(0, 50),
      );
      const query = req.query.q.trim().toLocaleLowerCase();
      const matches = snapshot.users.filter((user) =>
        includeIds.has(user.id) ||
        !query ||
        user.username.toLocaleLowerCase().includes(query) ||
        user.displayName.toLocaleLowerCase().includes(query),
      );
      const selected = matches
        .sort((left, right) => Number(includeIds.has(right.id)) - Number(includeIds.has(left.id)) ||
          left.displayName.localeCompare(right.displayName, 'zh-Hans-CN'))
        .slice(0, req.query.limit);
      return { users: selected, syncedAt: snapshot.syncedAt?.toISOString() ?? null };
    } catch (error) {
      if (!(error instanceof DirectoryUnavailableError)) throw error;
      return reply.code(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: error.message,
      } as never);
    }
  });

  r.get('/api/groups', {
    preHandler: [app.requireSession],
    schema: { tags: ['groups'], querystring: GroupQuery, response: { 200: z.array(CustomGroupSchema) } },
  }, async (req) => {
    const rows = req.query.scope === 'owned'
      ? await db
          .select({ group: customGroups, ownerDisplayName: users.displayName })
          .from(customGroups)
          .innerJoin(users, eq(users.id, customGroups.ownerUserId))
          .where(and(
            eq(customGroups.ownerUserId, req.user.id),
            groupNameMatches(req.query.q),
          ))
          .orderBy(asc(customGroups.name))
          .limit(req.query.limit)
      : await db
          .select({ group: customGroups, ownerDisplayName: users.displayName })
          .from(customGroupMembers)
          .innerJoin(customGroups, eq(customGroups.id, customGroupMembers.groupId))
          .innerJoin(users, eq(users.id, customGroups.ownerUserId))
          .where(and(
            eq(customGroupMembers.userId, req.user.id),
            groupNameMatches(req.query.q),
          ))
          .orderBy(asc(customGroups.name))
          .limit(req.query.limit);
    return groupDtos(db, rows, req.user.id);
  });

  r.get('/api/groups/:groupId', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['groups'],
      params: GroupParams,
      response: { 200: CustomGroupDetailSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const group = await visibleGroup(app, req.params.groupId, req.user.id, req.user.isPlatformAdmin);
    if (!group) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '用户组不存在' } as never);
    }
    return groupDetail(db, group.group.id, req.user.id);
  });

  r.post('/api/groups', {
    preHandler: writeGuard,
    schema: {
      tags: ['groups'],
      body: CreateCustomGroupRequestSchema,
      response: { 201: CustomGroupDetailSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const memberIds = uniqueIds(req.body.memberUserIds);
    if (!(await allActiveUsersExist(db, memberIds))) {
      return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: '包含不存在或已停用的用户' } as never);
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const group = (
          await tx
            .insert(customGroups)
            .values({ ownerUserId: req.user.id, name: req.body.name.trim() })
            .returning()
        )[0]!;
        if (memberIds.length > 0) {
          await tx.insert(customGroupMembers).values(
            memberIds.map((userId) => ({ groupId: group.id, userId, addedBy: req.user.id })),
          );
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'group.create',
          success: true,
          details: { groupId: group.id, name: group.name, memberCount: memberIds.length },
        });
        return { statusCode: 201, response: { groupId: group.id } };
      });
      const detail = await groupDetail(db, result.response.groupId, req.user.id);
      return reply.code(201).send(detail as never);
    } catch (error) {
      if (isDuplicateGroupName(error)) return duplicateGroupName(reply);
      throw error;
    }
  });

  r.put('/api/groups/:groupId', {
    preHandler: writeGuard,
    schema: {
      tags: ['groups'],
      params: GroupParams,
      body: UpdateCustomGroupRequestSchema,
      response: { 200: CustomGroupDetailSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const memberIds = uniqueIds(req.body.memberUserIds);
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const { group, members } = await lockGroupState(tx, req.params.groupId);
        if (!group) throw new GroupOwnerAccessError();
        assertGroupRevision(group, members, req.body.expectedRevision);
        if (group.ownerUserId !== req.user.id || group.frozen) throw new GroupOwnerAccessError();
        const nextName = req.body.name.trim();
        const membersChanged = !sameIds(members.map((member) => member.userId), memberIds);
        if (membersChanged) {
          await applyGroupMembershipChange(tx, {
            groupId: group.id,
            previousMembers: members,
            memberIds,
            actorUserId: req.user.id,
            actorDeviceId: req.sessionRow.unlockedDeviceId,
            audit,
            collect,
          });
        }
        const nameChanged = nextName !== group.name;
        if (nameChanged || membersChanged) {
          await tx.update(customGroups).set({ name: nextName, updatedAt: new Date() })
            .where(eq(customGroups.id, group.id));
        }
        if (nameChanged) {
          await appendAudit(tx, audit, {
            actorUserId: req.user.id,
            action: 'group.rename',
            success: true,
            details: { groupId: group.id, name: nextName },
          });
        }
        return { statusCode: 200, response: await groupDetail(tx, group.id, req.user.id) };
      });
      return reply.code(200).send(result.response as never);
    } catch (error) {
      if (isDuplicateGroupName(error)) return duplicateGroupName(reply);
      if (error instanceof GroupStateConflictError) return groupStateConflict(reply);
      if (error instanceof GroupOwnerAccessError) return groupOwnerError(reply);
      throw error;
    }
  });

  r.patch('/api/groups/:groupId', {
    preHandler: writeGuard,
    schema: { tags: ['groups'], params: GroupParams, body: RenameCustomGroupRequestSchema },
  }, async (req, reply) => {
    if (!req.body.expectedRevision) return groupClientUpgradeRequired(reply);
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const locked = await lockGroupState(tx, req.params.groupId);
        if (!locked.group) throw new GroupOwnerAccessError();
        assertGroupRevision(locked.group, locked.members, req.body.expectedRevision!);
        if (locked.group.ownerUserId !== req.user.id || locked.group.frozen) throw new GroupOwnerAccessError();
        await tx
          .update(customGroups)
          .set({ name: req.body.name.trim(), updatedAt: new Date() })
          .where(eq(customGroups.id, locked.group.id));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'group.rename',
          success: true,
          details: { groupId: locked.group.id, name: req.body.name.trim() },
        });
        return { statusCode: 200, response: { ok: true } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (isDuplicateGroupName(error)) return duplicateGroupName(reply);
      if (error instanceof GroupStateConflictError) return groupStateConflict(reply);
      if (error instanceof GroupOwnerAccessError) return groupOwnerError(reply);
      throw error;
    }
  });

  r.put('/api/groups/:groupId/members', {
    preHandler: writeGuard,
    schema: { tags: ['groups'], params: GroupParams, body: SetCustomGroupMembersRequestSchema },
  }, async (req, reply) => {
    if (!req.body.expectedRevision) return groupClientUpgradeRequired(reply);
    const memberIds = uniqueIds(req.body.memberUserIds);
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const locked = await lockGroupState(tx, req.params.groupId);
        if (!locked.group) throw new GroupOwnerAccessError();
        assertGroupRevision(locked.group, locked.members, req.body.expectedRevision!);
        if (locked.group.ownerUserId !== req.user.id || locked.group.frozen) throw new GroupOwnerAccessError();
        const changed = !sameIds(locked.members.map((member) => member.userId), memberIds);
        const membership = changed
          ? await applyGroupMembershipChange(tx, {
              groupId: locked.group.id,
              previousMembers: locked.members,
              memberIds,
              actorUserId: req.user.id,
              actorDeviceId: req.sessionRow.unlockedDeviceId,
              audit,
              collect,
            })
          : { pendingEnvelopeCount: 0 };
        if (changed) await tx.update(customGroups).set({ updatedAt: new Date() }).where(eq(customGroups.id, locked.group.id));
        return { statusCode: 200, response: { ok: true, ...membership } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof GroupStateConflictError) return groupStateConflict(reply);
      if (error instanceof GroupOwnerAccessError) return groupOwnerError(reply);
      throw error;
    }
  });

  r.post('/api/groups/:groupId/transfer', {
    preHandler: writeGuard,
    schema: { tags: ['groups'], params: GroupParams, body: TransferCustomGroupRequestSchema },
  }, async (req, reply) => {
    if (!req.body.expectedRevision) return groupClientUpgradeRequired(reply);
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const locked = await lockGroupState(tx, req.params.groupId);
        if (!locked.group) throw new GroupOwnerAccessError();
        assertGroupRevision(locked.group, locked.members, req.body.expectedRevision!);
        const stillAllowed = (
          (!locked.group.frozen && locked.group.ownerUserId === req.user.id) ||
          (locked.group.frozen && req.user.isPlatformAdmin)
        );
        if (!stillAllowed) throw new GroupOwnerAccessError();
        if (!(await allActiveUsersExist(tx, [req.body.newOwnerUserId]))) throw new GroupTargetUnavailableError();
        await tx
          .update(customGroups)
          .set({ ownerUserId: req.body.newOwnerUserId, frozen: false, updatedAt: new Date() })
          .where(eq(customGroups.id, locked.group.id));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'group.transfer',
          success: true,
          details: { groupId: locked.group.id, newOwnerUserId: req.body.newOwnerUserId },
        });
        return { statusCode: 200, response: { ok: true } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof GroupStateConflictError) return groupStateConflict(reply);
      if (error instanceof GroupOwnerAccessError) return groupOwnerError(reply);
      if (error instanceof GroupTargetUnavailableError) {
        return reply.code(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: '新拥有者不存在或已停用，请重新选择',
        } as never);
      }
      throw error;
    }
  });

  r.delete('/api/groups/:groupId', {
    preHandler: writeGuard,
    schema: { tags: ['groups'], params: GroupParams, body: DeleteCustomGroupRequestSchema },
  }, async (req, reply) => {
    if (!req.body.expectedRevision) return groupClientUpgradeRequired(reply);
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      const locked = await lockGroupState(tx, req.params.groupId);
      if (!locked.group) throw new GroupOwnerAccessError();
      assertGroupRevision(locked.group, locked.members, req.body.expectedRevision!);
      if (locked.group.ownerUserId !== req.user.id || locked.group.frozen) throw new GroupOwnerAccessError();
      const legacyLink = (await tx.select({ id: vaultCustomGroupRoles.id }).from(vaultCustomGroupRoles)
        .leftJoin(vaultCryptoStates, eq(vaultCryptoStates.vaultId, vaultCustomGroupRoles.vaultId))
        .where(and(
          eq(vaultCustomGroupRoles.groupId, locked.group.id),
          sql`${vaultCryptoStates.storageMode} IS DISTINCT FROM 'e2ee'`,
        )).limit(1))[0];
      if (legacyLink) {
        throw new GroupLegacyLinkError();
      }
      const members = locked.members;
      await lockRecipientSets(tx, members.map((member) => member.userId));
      const linked = await tx.select({ state: vaultCryptoStates }).from(vaultCustomGroupRoles)
        .innerJoin(vaultCryptoStates, and(
          eq(vaultCryptoStates.vaultId, vaultCustomGroupRoles.vaultId),
          eq(vaultCryptoStates.storageMode, 'e2ee'),
        ))
        .where(eq(vaultCustomGroupRoles.groupId, locked.group.id));
      const memberIds = members.map((member) => member.userId);
      await tx.delete(vaultCustomGroupRoles).where(eq(vaultCustomGroupRoles.groupId, locked.group.id));
      let rekeyVaultCount = 0;
      for (const row of linked) {
        if (!row.state.activeEpoch) continue;
        const now = new Date();
        await cancelEnvelopeTasks(tx, {
          vaultId: row.state.vaultId,
          authorizationKind: 'custom_group',
          authorizationRef: locked.group.id,
          now,
        });
        const revocation = await revokeUsersAndRequireRekey(tx, row.state, memberIds, {
          initiatedByUserId: req.user.id,
          initiatedByDeviceId: req.sessionRow.unlockedDeviceId,
          reason: 'member_removed',
          now,
        });
        if (revocation.rekeyTask) {
          rekeyVaultCount += 1;
          collect(await recordSyncEvent(tx, {
            type: 'vault.rekey_required',
            vaultId: row.state.vaultId,
            itemId: null,
            payload: {
              pendingEpoch: revocation.rekeyTask.toEpoch,
              taskId: revocation.rekeyTask.id,
            },
          }));
        } else {
          await tx.update(vaultCryptoStates).set({
            accessGeneration: sql`${vaultCryptoStates.accessGeneration} + 1`,
            rowVersion: sql`${vaultCryptoStates.rowVersion} + 1`,
            updatedAt: now,
          }).where(eq(vaultCryptoStates.vaultId, row.state.vaultId));
          collect(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed',
            vaultId: row.state.vaultId,
            itemId: null,
            payload: { accessChanged: true },
          }));
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'group.authorization_removed',
          vaultId: row.state.vaultId,
          success: true,
          details: {},
        });
      }
      await tx.delete(customGroups).where(eq(customGroups.id, locked.group.id));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'group.delete',
        success: true,
        details: {},
      });
      return { statusCode: 200, response: { ok: true, rekeyVaultCount } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof GroupStateConflictError) return groupStateConflict(reply);
      if (error instanceof GroupOwnerAccessError) return groupOwnerError(reply);
      if (error instanceof GroupLegacyLinkError) {
        return reply.code(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: '该用户组仍被旧格式密码库使用，请先移除相关授权',
        } as never);
      }
      throw error;
    }
  });
}

async function lockGroupState(tx: DbOrTx, groupId: string) {
  const group = (await tx.select().from(customGroups)
    .where(eq(customGroups.id, groupId)).for('update').limit(1))[0] ?? null;
  const members = group
    ? await tx.select({ userId: customGroupMembers.userId }).from(customGroupMembers)
        .where(eq(customGroupMembers.groupId, groupId)).for('update')
    : [];
  return { group, members };
}

function groupRevision(group: typeof customGroups.$inferSelect, memberIds: string[]): string {
  const canonical = JSON.stringify([
    group.id,
    group.ownerUserId,
    group.name,
    group.frozen,
    [...memberIds].sort(),
  ]);
  return createHash('sha256').update(canonical).digest('base64url');
}

function assertGroupRevision(
  group: typeof customGroups.$inferSelect,
  members: Array<{ userId: string }>,
  expectedRevision: string,
): void {
  if (groupRevision(group, members.map((member) => member.userId)) !== expectedRevision) {
    throw new GroupStateConflictError();
  }
}

function sameIds(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((value, index) => value === sortedRight[index]);
}

async function applyGroupMembershipChange(
  tx: DbOrTx,
  options: {
    groupId: string;
    previousMembers: Array<{ userId: string }>;
    memberIds: string[];
    actorUserId: string;
    actorDeviceId: string | null;
    audit: AuditContext;
    collect: (event: SyncEventRow) => void;
  },
): Promise<{ pendingEnvelopeCount: number }> {
  await lockRecipientSets(tx, [
    ...options.previousMembers.map((member) => member.userId),
    ...options.memberIds,
  ]);
  if (!(await allActiveUsersExist(tx, options.memberIds))) throw new GroupStateConflictError();
  const previousIds = new Set(options.previousMembers.map((member) => member.userId));
  const nextIds = new Set(options.memberIds);
  const added = options.memberIds.filter((userId) => !previousIds.has(userId));
  const removed = [...previousIds].filter((userId) => !nextIds.has(userId));
  await tx.delete(customGroupMembers).where(eq(customGroupMembers.groupId, options.groupId));
  if (options.memberIds.length > 0) {
    await tx.insert(customGroupMembers).values(
      options.memberIds.map((userId) => ({
        groupId: options.groupId,
        userId,
        addedBy: options.actorUserId,
      })),
    );
  }
  const linked = await tx
    .select({ role: vaultCustomGroupRoles.role, state: vaultCryptoStates })
    .from(vaultCustomGroupRoles)
    .innerJoin(vaultCryptoStates, and(
      eq(vaultCryptoStates.vaultId, vaultCustomGroupRoles.vaultId),
      eq(vaultCryptoStates.storageMode, 'e2ee'),
    ))
    .where(eq(vaultCustomGroupRoles.groupId, options.groupId));
  let pendingEnvelopeCount = 0;
  for (const row of linked) {
    if (!row.state.activeEpoch) continue;
    const now = new Date();
    if (added.length > 0) {
      const distribution = await ensureEnvelopeTasks(tx, {
        vaultId: row.state.vaultId,
        keyEpoch: row.state.activeEpoch,
        authorizationKind: 'custom_group',
        authorizationRef: options.groupId,
        recipientUserIds: added,
        capability: capabilityForRole(row.role),
        now,
      });
      pendingEnvelopeCount += distribution.pending;
    }
    let rekeyRequired = false;
    if (removed.length > 0) {
      await cancelEnvelopeTasks(tx, {
        vaultId: row.state.vaultId,
        authorizationKind: 'custom_group',
        authorizationRef: options.groupId,
        recipientUserIds: removed,
        now,
      });
      const revocation = await revokeUsersAndRequireRekey(tx, row.state, removed, {
        initiatedByUserId: options.actorUserId,
        initiatedByDeviceId: options.actorDeviceId,
        reason: 'member_removed',
        now,
      });
      if (revocation.rekeyTask) {
        rekeyRequired = true;
        options.collect(await recordSyncEvent(tx, {
          type: 'vault.rekey_required',
          vaultId: row.state.vaultId,
          itemId: null,
          payload: {
            pendingEpoch: revocation.rekeyTask.toEpoch,
            taskId: revocation.rekeyTask.id,
          },
        }));
      }
    }
    if (!rekeyRequired) {
      await tx.update(vaultCryptoStates).set({
        accessGeneration: sql`${vaultCryptoStates.accessGeneration} + 1`,
        rowVersion: sql`${vaultCryptoStates.rowVersion} + 1`,
        updatedAt: now,
      }).where(eq(vaultCryptoStates.vaultId, row.state.vaultId));
      options.collect(await recordSyncEvent(tx, {
        type: 'vault.crypto_changed',
        vaultId: row.state.vaultId,
        itemId: null,
        payload: { accessChanged: true },
      }));
    }
    await appendAudit(tx, options.audit, {
      actorUserId: options.actorUserId,
      action: 'group.members_changed',
      vaultId: row.state.vaultId,
      success: true,
      details: {},
    });
  }
  await appendAudit(tx, options.audit, {
    actorUserId: options.actorUserId,
    action: 'group.members_changed',
    success: true,
    details: {},
  });
  return { pendingEnvelopeCount };
}

function groupStateConflict(reply: import('fastify').FastifyReply) {
  return reply.code(409).send({
    statusCode: 409,
    error: 'Conflict',
    code: 'group_version_conflict',
    message: '另一位同事刚更新了这个用户组。你的修改尚未丢失，请加载最新内容后重新确认',
  });
}

function groupClientUpgradeRequired(reply: import('fastify').FastifyReply) {
  return reply.code(409).send({
    statusCode: 409,
    error: 'Conflict',
    code: 'client_upgrade_required',
    message: '页面版本过旧，系统已阻止覆盖最新用户组内容。请刷新页面后重试',
  });
}

function groupNameMatches(query: string) {
  const value = `%${escapeLike(query.trim().toLocaleLowerCase())}%`;
  return sql`lower(${customGroups.name}) LIKE ${value} ESCAPE '\\'`;
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (character) => `\\${character}`);
}

function uniqueIds(ids: string[]): string[] {
  return [...new Set(ids)];
}

async function allActiveUsersExist(db: DbOrTx, ids: string[]): Promise<boolean> {
  if (ids.length === 0) return true;
  const rows = await db
    .select({ id: users.id })
    .from(users)
    .where(and(inArray(users.id, ids), eq(users.active, true)));
  return rows.length === ids.length;
}

async function visibleGroup(
  app: FastifyInstance,
  groupId: string,
  userId: string,
  isPlatformAdmin: boolean,
) {
  const visible = or(
    eq(customGroups.ownerUserId, userId),
    eq(customGroupMembers.userId, userId),
    ...(isPlatformAdmin ? [eq(customGroups.frozen, true)] : []),
  );
  return (
    await app.ctx.db
      .select({ group: customGroups, ownerDisplayName: users.displayName })
      .from(customGroups)
      .innerJoin(users, eq(users.id, customGroups.ownerUserId))
      .leftJoin(customGroupMembers, and(
        eq(customGroupMembers.groupId, customGroups.id),
        eq(customGroupMembers.userId, userId),
      ))
      .where(and(
        eq(customGroups.id, groupId),
        visible,
      ))
      .limit(1)
  )[0] ?? null;
}

async function groupDtos(
  db: DbOrTx,
  rows: Array<{ group: typeof customGroups.$inferSelect; ownerDisplayName: string }>,
  userId: string,
) {
  const ids = rows.map((row) => row.group.id);
  const [memberships, pendingTasks] = ids.length
    ? await Promise.all([
        db.select().from(customGroupMembers).where(inArray(customGroupMembers.groupId, ids)),
        db.select({ authorizationRef: vaultEnvelopeTasks.authorizationRef }).from(vaultEnvelopeTasks).where(and(
          eq(vaultEnvelopeTasks.authorizationKind, 'custom_group'),
          inArray(vaultEnvelopeTasks.authorizationRef, ids),
          eq(vaultEnvelopeTasks.status, 'pending'),
        )),
      ])
    : [[], []];
  return rows.map(({ group, ownerDisplayName }) => ({
    id: group.id,
    name: group.name,
    ownerUserId: group.ownerUserId,
    ownerDisplayName,
    memberCount: memberships.filter((row) => row.groupId === group.id).length,
    pendingEnvelopeCount: pendingTasks.filter((row) => row.authorizationRef === group.id).length,
    isOwner: group.ownerUserId === userId,
    isMember: memberships.some((row) => row.groupId === group.id && row.userId === userId),
    frozen: group.frozen,
    createdAt: group.createdAt.toISOString(),
    updatedAt: group.updatedAt.toISOString(),
  }));
}

async function groupDetail(db: DbOrTx, groupId: string, userId: string) {
  const row = (
    await db
      .select({ group: customGroups, ownerDisplayName: users.displayName })
      .from(customGroups)
      .innerJoin(users, eq(users.id, customGroups.ownerUserId))
      .where(eq(customGroups.id, groupId))
      .limit(1)
  )[0]!;
  const [dto] = await groupDtos(db, [row], userId);
  const members = await db
    .select({ id: users.id, username: users.username, displayName: users.displayName })
    .from(customGroupMembers)
    .innerJoin(users, eq(users.id, customGroupMembers.userId))
    .where(eq(customGroupMembers.groupId, groupId))
    .orderBy(asc(users.displayName));
  return {
    ...dto!,
    members,
    revision: groupRevision(row.group, members.map((member) => member.id)),
  };
}

function groupOwnerError(reply: import('fastify').FastifyReply) {
  return reply.code(403).send({
    statusCode: 403,
    error: 'Forbidden',
    message: '只有该用户组的拥有者可以执行此操作',
  });
}

function isDuplicateGroupName(error: unknown): boolean {
  let candidate = error;
  for (let depth = 0; depth < 4 && candidate && typeof candidate === 'object'; depth += 1) {
    const databaseError = candidate as { code?: string; constraint?: string; cause?: unknown };
    if (
      databaseError.code === '23505' &&
      (!databaseError.constraint || databaseError.constraint === 'custom_groups_owner_name_uq')
    ) {
      return true;
    }
    candidate = databaseError.cause;
  }
  return false;
}

function duplicateGroupName(reply: import('fastify').FastifyReply) {
  return reply.code(409).send({
    statusCode: 409,
    error: 'Conflict',
    message: '你已经有一个同名用户组，请换一个名称',
  });
}
