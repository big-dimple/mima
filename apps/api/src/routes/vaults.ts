import { and, desc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  CreateVaultRequestSchema,
  RenameVaultRequestSchema,
  SetMembershipRequestSchema,
  RemoveMembershipRequestSchema,
  TransferOwnershipRequestSchema,
  VaultSchema,
  MembershipSchema,
  AuditEventSchema,
  ApiErrorSchema,
} from '@mima/contracts';
import { canManageMembers, canManageVault, canReadAudit } from '@mima/domain';
import {
  auditEvents,
  customGroups,
  vaultCustomGroupRoles,
  vaultCryptoStates,
  vaultMemberships,
  vaults,
} from '../db/schema.ts';
import { getVaultAccess, listVaultMemberships } from '../services/access.ts';
import { appendAudit, type DbOrTx } from '../services/audit.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import { toMembershipDto, toVaultDto } from '../services/mappers.ts';
import { DirectoryUnavailableError } from '../auth/directory.ts';

const VaultParams = z.object({ vaultId: z.string().uuid() });

/** 团队库 owner 不变量被破坏时抛出：路由层转换为 400 并写审计。 */
class OwnerInvariantError extends Error {
  constructor() {
    super('团队库必须至少保留一名直接用户拥有者；请先转移所有权');
  }
}

/** 事务内校验：该团队库仍有至少一名直接用户 owner（组 owner 不算——组成员可变，会悬空）。 */
async function assertUserOwnerRemains(tx: DbOrTx, vaultId: string): Promise<void> {
  const owners = await tx
    .select({ id: vaultMemberships.id })
    .from(vaultMemberships)
    .where(and(
      eq(vaultMemberships.vaultId, vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.role, 'owner'),
    ));
  if (owners.length === 0) throw new OwnerInvariantError();
}

export function registerVaultRoutes(app: FastifyInstance): void {
  const { db, bus, audit, auth } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.post('/api/vaults', {
    preHandler: writeGuard,
    schema: { tags: ['vaults'], body: CreateVaultRequestSchema, response: { 201: VaultSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    if (app.ctx.e2eeRequired) return e2eeRouteRequired(reply);
    if (req.body.initialOwnerUserId !== undefined && req.body.initialOwnerUserId !== req.user.id) {
      return reply.code(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: '初始拥有者必须是当前用户；如需更换拥有者，请创建后转移所有权',
      } as never);
    }
    const initialOwner = req.user.id;
    const initialOwnerRecord = await activeDirectoryUser(auth.directory, initialOwner, reply);
    if (initialOwnerRecord === 'unavailable') return;
    if (!initialOwnerRecord) {
      return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: '初始拥有者不存在或已停用' } as never);
    }
    const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      const inserted = await tx
        .insert(vaults)
        .values({ kind: 'team', name: req.body.name, ownerUserId: null })
        .returning();
      const vault = inserted[0]!;
      await tx.insert(vaultMemberships).values({
        vaultId: vault.id,
        subjectKind: 'user',
        subjectId: initialOwner,
        role: 'owner',
      });
      collect(await recordSyncEvent(tx, {
        type: 'vault.upserted',
        vaultId: vault.id,
        itemId: null,
        payload: { accessChanged: true },
      }));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'vault.create',
        vaultId: vault.id,
        success: true,
        details: { name: vault.name, initialOwner },
      });
      return { statusCode: 201, response: toVaultDto(vault) };
    });
    return reply.code(result.statusCode as 200).send(result.response as never);
  });

  r.patch('/api/vaults/:vaultId', {
    preHandler: writeGuard,
    schema: { tags: ['vaults'], params: VaultParams, body: RenameVaultRequestSchema, response: { 200: VaultSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    if (await isE2eeVault(db, req.params.vaultId)) return e2eeRouteRequired(reply);
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind === 'personal' || !canManageVault(access.role, req.user.isPlatformAdmin)) {
      return await denyVault(app, req.user.id, 'vault.rename', req.params.vaultId, reply);
    }
    const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      const updated = await tx
        .update(vaults)
        .set({ name: req.body.name, updatedAt: new Date() })
        .where(eq(vaults.id, req.params.vaultId))
        .returning();
      collect(await recordSyncEvent(tx, {
        type: 'vault.upserted',
        vaultId: req.params.vaultId,
        itemId: null,
        payload: {},
      }));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'vault.rename',
        vaultId: req.params.vaultId,
        success: true,
        details: { name: req.body.name },
      });
      return { statusCode: 200, response: toVaultDto(updated[0]!) };
    });
    return reply.code(result.statusCode as 200).send(result.response as never);
  });

  r.delete('/api/vaults/:vaultId', {
    preHandler: writeGuard,
    schema: {
      tags: ['vaults'],
      params: VaultParams,
      body: z.object({ idempotencyKey: z.string().min(8).max(80) }),
    },
  }, async (req, reply) => {
    if (await isE2eeVault(db, req.params.vaultId)) return e2eeRouteRequired(reply);
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind === 'personal' || !canManageVault(access.role, req.user.isPlatformAdmin)) {
      return await denyVault(app, req.user.id, 'vault.delete', req.params.vaultId, reply);
    }
    const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      collect(await recordSyncEvent(tx, {
        type: 'vault.deleted',
        vaultId: req.params.vaultId,
        itemId: null,
        payload: {},
      }));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'vault.delete',
        vaultId: req.params.vaultId,
        success: true,
        details: { name: access.vault.name },
      });
      await tx.delete(vaults).where(eq(vaults.id, req.params.vaultId));
      return { statusCode: 200, response: { ok: true } };
    });
    return reply.code(result.statusCode as 200).send(result.response as never);
  });

  r.get('/api/vaults/:vaultId/members', {
    preHandler: [app.requireSession],
    schema: { tags: ['vaults'], params: VaultParams, response: { 200: z.array(MembershipSchema), '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    const visible = access && (access.role !== null || req.user.isPlatformAdmin);
    if (!visible || access.vault.kind === 'personal') {
      return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message: '无权查看成员' } as never);
    }
    return (await listVaultMemberships(db, req.params.vaultId)).map(toMembershipDto);
  });

  r.put('/api/vaults/:vaultId/members', {
    preHandler: writeGuard,
    schema: { tags: ['vaults'], params: VaultParams, body: SetMembershipRequestSchema },
  }, async (req, reply) => {
    if (await isE2eeVault(db, req.params.vaultId)) return e2eeRouteRequired(reply);
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    // 成员增删改只能由该库 owner 操作；platform-admin 无库内 owner 角色时一律拒绝
    if (!access || access.vault.kind === 'personal' || !canManageMembers(access.role)) {
      return await denyVault(app, req.user.id, 'membership.set', req.params.vaultId, reply);
    }
    const { subjectKind, subjectId, role } = req.body;
    const customGroupRole = role === 'owner' ? null : role;
    if (subjectKind === 'custom_group') {
      if (role === 'owner') {
        return reply.code(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: '用户组不能成为密码库拥有者',
        } as never);
      }
      const group = (
        await db
          .select()
          .from(customGroups)
          .where(and(eq(customGroups.id, subjectId), eq(customGroups.ownerUserId, req.user.id)))
          .limit(1)
      )[0];
      if (!group || group.frozen) {
        return reply.code(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: '只能授权自己管理的可用用户组',
        } as never);
      }
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        if (subjectKind === 'custom_group') {
          await tx
            .insert(vaultCustomGroupRoles)
            .values({ vaultId: req.params.vaultId, groupId: subjectId, role: customGroupRole! })
            .onConflictDoUpdate({
              target: [vaultCustomGroupRoles.vaultId, vaultCustomGroupRoles.groupId],
              set: { role: customGroupRole! },
            });
        } else {
          await tx
            .insert(vaultMemberships)
            .values({ vaultId: req.params.vaultId, subjectKind, subjectId, role })
            .onConflictDoUpdate({
              target: [vaultMemberships.vaultId, vaultMemberships.subjectKind, vaultMemberships.subjectId],
              set: { role },
            });
        }
        // 不变量：任何成员变更后团队库必须仍有直接用户 owner（防"降级最后一个 owner"）
        await assertUserOwnerRemains(tx, req.params.vaultId);
        collect(await recordSyncEvent(tx, {
          type: 'vault.upserted',
          vaultId: req.params.vaultId,
          itemId: null,
          payload: { accessChanged: true },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'membership.set',
          vaultId: req.params.vaultId,
          success: true,
          details: { subjectKind, subjectId, role },
        });
        return { statusCode: 200, response: { ok: true } };
      });
      return reply.code(result.statusCode as 200).send(result.response as never);
    } catch (err) {
      if (err instanceof OwnerInvariantError) {
        return await ownerInvariantRejected(app, req.user.id, 'membership.set', req.params.vaultId, reply, err);
      }
      throw err;
    }
  });

  r.delete('/api/vaults/:vaultId/members', {
    preHandler: writeGuard,
    schema: { tags: ['vaults'], params: VaultParams, body: RemoveMembershipRequestSchema },
  }, async (req, reply) => {
    if (await isE2eeVault(db, req.params.vaultId)) return e2eeRouteRequired(reply);
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind === 'personal' || !canManageMembers(access.role)) {
      return await denyVault(app, req.user.id, 'membership.remove', req.params.vaultId, reply);
    }
    const { subjectKind, subjectId } = req.body;
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        if (subjectKind === 'custom_group') {
          await tx
            .delete(vaultCustomGroupRoles)
            .where(and(
              eq(vaultCustomGroupRoles.vaultId, req.params.vaultId),
              eq(vaultCustomGroupRoles.groupId, subjectId),
            ));
        } else {
          await tx
            .delete(vaultMemberships)
            .where(and(
              eq(vaultMemberships.vaultId, req.params.vaultId),
              eq(vaultMemberships.subjectKind, subjectKind),
              eq(vaultMemberships.subjectId, subjectId),
            ));
        }
        // 不变量：不得移除最后一个直接用户 owner
        await assertUserOwnerRemains(tx, req.params.vaultId);
        collect(await recordSyncEvent(tx, {
          type: 'vault.upserted',
          vaultId: req.params.vaultId,
          itemId: null,
          payload: { accessChanged: true },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'membership.remove',
          vaultId: req.params.vaultId,
          success: true,
          details: { subjectKind, subjectId },
        });
        return { statusCode: 200, response: { ok: true } };
      });
      return reply.code(result.statusCode as 200).send(result.response as never);
    } catch (err) {
      if (err instanceof OwnerInvariantError) {
        return await ownerInvariantRejected(app, req.user.id, 'membership.remove', req.params.vaultId, reply, err);
      }
      throw err;
    }
  });

  /** 原子转移所有权：仅现任 owner 可调用。新 owner 设为直接用户 owner，
   * 调用者自己的直接用户成员条目（若存在）降为 editor——同一事务完成，
   * 不存在"两个 owner"或"没有 owner"的可观察中间态被提交。 */
  r.post('/api/vaults/:vaultId/transfer', {
    preHandler: writeGuard,
    schema: { tags: ['vaults'], params: VaultParams, body: TransferOwnershipRequestSchema, response: { 200: z.object({ ok: z.boolean() }), '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    if (await isE2eeVault(db, req.params.vaultId)) return e2eeRouteRequired(reply);
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind === 'personal' || !canManageMembers(access.role)) {
      return await denyVault(app, req.user.id, 'vault.transfer_ownership', req.params.vaultId, reply);
    }
    const newOwner = req.body.newOwnerUserId;
    if (newOwner === req.user.id) {
      return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: '不能把所有权转移给自己' } as never);
    }
    const newOwnerRecord = await activeDirectoryUser(auth.directory, newOwner, reply);
    if (newOwnerRecord === 'unavailable') return;
    if (!newOwnerRecord) {
      return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: '目标用户不存在' } as never);
    }
    const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      await tx
        .insert(vaultMemberships)
        .values({ vaultId: req.params.vaultId, subjectKind: 'user', subjectId: newOwner, role: 'owner' })
        .onConflictDoUpdate({
          target: [vaultMemberships.vaultId, vaultMemberships.subjectKind, vaultMemberships.subjectId],
          set: { role: 'owner' },
        });
      // 原 owner 的直接用户条目降为 editor（若其 owner 身份来自组授权则无行可降）
      await tx
        .update(vaultMemberships)
        .set({ role: 'editor' })
        .where(and(
          eq(vaultMemberships.vaultId, req.params.vaultId),
          eq(vaultMemberships.subjectKind, 'user'),
          eq(vaultMemberships.subjectId, req.user.id),
          eq(vaultMemberships.role, 'owner'),
        ));
      await assertUserOwnerRemains(tx, req.params.vaultId);
      collect(await recordSyncEvent(tx, {
        type: 'vault.upserted',
        vaultId: req.params.vaultId,
        itemId: null,
        payload: { accessChanged: true },
      }));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'vault.transfer_ownership',
        vaultId: req.params.vaultId,
        success: true,
        details: { newOwnerUserId: newOwner },
      });
      return { statusCode: 200, response: { ok: true } };
    });
    return reply.code(result.statusCode as 200).send(result.response as never);
  });

  r.get('/api/vaults/:vaultId/audit', {
    preHandler: [app.requireSession],
    schema: { tags: ['audit'], params: VaultParams, response: { 200: z.array(AuditEventSchema), '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    const role = access?.role ?? null;
    if (!access || !canReadAudit(role, req.user.isPlatformAdmin)) {
      return await denyVault(app, req.user.id, 'audit.read', req.params.vaultId, reply);
    }
    reply.header('cache-control', 'no-store');
    const rows = await db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.vaultId, req.params.vaultId))
      .orderBy(desc(auditEvents.id))
      .limit(200);
    return rows.map((row) => ({ ...row, ts: row.ts.toISOString() }));
  });
}

async function activeDirectoryUser(
  directory: import('../auth/contracts.ts').DirectoryService,
  userId: string,
  reply: import('fastify').FastifyReply,
) {
  try {
    return await directory.findActiveUser(userId);
  } catch (error) {
    if (!(error instanceof DirectoryUnavailableError)) throw error;
    reply.code(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: error.message,
    });
    return 'unavailable' as const;
  }
}

async function ownerInvariantRejected(
  app: FastifyInstance,
  userId: string,
  action: string,
  vaultId: string,
  reply: import('fastify').FastifyReply,
  err: Error,
) {
  const { auditStandalone } = await import('../services/audit.ts');
  await auditStandalone(app.ctx.db, app.ctx.audit, {
    actorUserId: userId,
    action,
    vaultId,
    success: false,
    details: { reason: 'owner_invariant' },
  });
  return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: err.message });
}

async function denyVault(
  app: FastifyInstance,
  userId: string,
  action: string,
  vaultId: string,
  reply: import('fastify').FastifyReply,
  reason = 'access_denied',
) {
  const { auditStandalone } = await import('../services/audit.ts');
  await auditStandalone(app.ctx.db, app.ctx.audit, {
    actorUserId: userId,
    action,
    vaultId,
    success: false,
    details: { reason },
  });
  return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message: '没有执行该操作的权限' });
}

async function isE2eeVault(db: import('../context.ts').AppContext['db'], vaultId: string) {
  const state = (
    await db.select({ storageMode: vaultCryptoStates.storageMode })
      .from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, vaultId))
      .limit(1)
  )[0];
  return state?.storageMode === 'e2ee';
}

function e2eeRouteRequired(reply: import('fastify').FastifyReply) {
  return reply.code(410).send({
    statusCode: 410,
    error: 'Gone',
    message: '该密码库已启用客户端加密，请使用安全共享流程',
  });
}
