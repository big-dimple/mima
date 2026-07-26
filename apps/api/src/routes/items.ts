import { randomUUID } from 'node:crypto';
import { and, asc, eq } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  CreateItemRequestSchema,
  UpdateItemMetaRequestSchema,
  RotateSecretRequestSchema,
  DeleteItemRequestSchema,
  RevealRequestSchema,
  RevealResponseSchema,
  ItemMetaSchema,
  ApiErrorSchema,
  SecretVersionInfoSchema,
} from '@mima/contracts';
import { canEditItems, canReveal, normalizeOrigin } from '@mima/domain';
import { decryptSecret, encryptSecret } from '@mima/crypto';
import { items, itemSecretVersions, vaultCryptoStates } from '../db/schema.ts';
import { getVaultAccess } from '../services/access.ts';
import { appendAudit, auditStandalone } from '../services/audit.ts';
import { recordSyncEvent, runCommand, VersionConflictError } from '../services/commands.ts';
import { toItemMeta } from '../services/mappers.ts';

const ItemParams = z.object({ itemId: z.string().uuid() });
const VaultParams = z.object({ vaultId: z.string().uuid() });

export function registerItemRoutes(app: FastifyInstance): void {
  const { db, bus, legacyContentKeys: keys, audit } = app.ctx;
  if (!keys) return;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  async function deny(req: FastifyRequest, reply: FastifyReply, action: string, vaultId: string | null, itemId: string | null, message = '没有执行该操作的权限') {
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action,
      vaultId,
      itemId,
      success: false,
      details: { reason: 'access_denied' },
    });
    return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message });
  }

  function conflict(reply: FastifyReply, err: VersionConflictError) {
    return reply.code(409).send({
      statusCode: 409,
      error: 'Conflict',
      message: '其他人已经修改了这个条目。已显示最新内容，密码或敏感内容不会自动合并。',
      currentVersion: err.currentVersion,
      ...(err.currentItem ? { currentItem: err.currentItem } : {}),
    });
  }

  r.post('/api/vaults/:vaultId/items', {
    preHandler: writeGuard,
    schema: { tags: ['items'], params: VaultParams, body: CreateItemRequestSchema, response: { 201: ItemMetaSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || !canEditItems(access.role)) {
      return deny(req, reply, 'item.create', req.params.vaultId, null);
    }
    if (!await requireLegacyVault(req.params.vaultId, reply, true)) return;
    if (req.body.origin !== null && normalizeOrigin(req.body.origin) === null) {
      return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: '网站地址格式不正确' } as never);
    }
    const itemId = randomUUID();
    const enc = encryptSecret(keys, {
      vaultId: req.params.vaultId,
      itemId,
      secretVersion: 1,
      itemKind: req.body.kind,
    }, req.body.secretValue);

    const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
      const inserted = await tx.insert(items).values({
        id: itemId,
        vaultId: req.params.vaultId,
        kind: req.body.kind,
        title: req.body.title,
        username: req.body.username,
        origin: req.body.origin === null ? null : normalizeOrigin(req.body.origin),
        tags: req.body.tags,
        favorite: req.body.favorite,
        sensitivity: req.body.sensitivity,
        version: 1,
        secretVersion: 1,
        updatedBy: req.user.id,
      }).returning();
      await tx.insert(itemSecretVersions).values({
        itemId,
        vaultId: req.params.vaultId,
        itemKind: req.body.kind,
        secretVersion: 1,
        ciphertext: enc.ciphertext,
        iv: enc.iv,
        authTag: enc.authTag,
        wrappedDek: enc.wrappedDek,
        keyVersion: enc.keyVersion,
        createdBy: req.user.id,
      });
      const meta = toItemMeta(inserted[0]!);
      collect(await recordSyncEvent(tx, {
        type: 'item.upserted',
        vaultId: req.params.vaultId,
        itemId,
        payload: { item: meta },
      }));
      await appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'item.create',
        vaultId: req.params.vaultId,
        itemId,
        success: true,
        details: { kind: req.body.kind, title: req.body.title },
      });
      return { statusCode: 201, response: meta };
    });
    return reply.code(result.statusCode as 200).send(result.response as never);
  });

  r.patch('/api/items/:itemId', {
    preHandler: writeGuard,
    schema: { tags: ['items'], params: ItemParams, body: UpdateItemMetaRequestSchema, response: { 200: ItemMetaSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const found = await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1);
    const existing = found[0];
    if (!existing || existing.deleted) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '条目不存在' } as never);
    }
    if (!await requireLegacyVault(existing.vaultId, reply, true)) return;
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canEditItems(access.role)) {
      return deny(req, reply, 'item.update_meta', existing.vaultId, existing.id);
    }
    if (req.body.patch.origin != null && normalizeOrigin(req.body.patch.origin) === null) {
      return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message: '网站地址格式不正确' } as never);
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const locked = await tx.select().from(items).where(eq(items.id, req.params.itemId)).for('update');
        const row = locked[0]!;
        if (row.version !== req.body.expectedVersion) {
          throw new VersionConflictError(row.version, toItemMeta(row));
        }
        const p = req.body.patch;
        const updated = await tx.update(items).set({
          ...(p.title !== undefined ? { title: p.title } : {}),
          ...(p.username !== undefined ? { username: p.username } : {}),
          ...(p.origin !== undefined ? { origin: p.origin === null ? null : normalizeOrigin(p.origin) } : {}),
          ...(p.tags !== undefined ? { tags: p.tags } : {}),
          ...(p.favorite !== undefined ? { favorite: p.favorite } : {}),
          ...(p.sensitivity !== undefined ? { sensitivity: p.sensitivity } : {}),
          version: row.version + 1,
          updatedAt: new Date(),
          updatedBy: req.user.id,
        }).where(eq(items.id, row.id)).returning();
        const meta = toItemMeta(updated[0]!);
        collect(await recordSyncEvent(tx, {
          type: 'item.upserted',
          vaultId: row.vaultId,
          itemId: row.id,
          payload: { item: meta },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'item.update_meta',
          vaultId: row.vaultId,
          itemId: row.id,
          success: true,
          details: { fields: Object.keys(p) },
        });
        return { statusCode: 200, response: meta };
      });
      return reply.code(result.statusCode as 200).send(result.response as never);
    } catch (err) {
      if (err instanceof VersionConflictError) return conflict(reply, err);
      throw err;
    }
  });

  r.put('/api/items/:itemId/secret', {
    preHandler: writeGuard,
    schema: { tags: ['items'], params: ItemParams, body: RotateSecretRequestSchema, response: { 200: ItemMetaSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const found = await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1);
    const existing = found[0];
    if (!existing || existing.deleted) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '条目不存在' } as never);
    }
    if (!await requireLegacyVault(existing.vaultId, reply, true)) return;
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canEditItems(access.role)) {
      return deny(req, reply, 'item.rotate_secret', existing.vaultId, existing.id);
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const locked = await tx.select().from(items).where(eq(items.id, req.params.itemId)).for('update');
        const row = locked[0]!;
        if (row.version !== req.body.expectedVersion) {
          throw new VersionConflictError(row.version, toItemMeta(row));
        }
        const newVersion = row.version + 1;
        const enc = encryptSecret(keys, {
          vaultId: row.vaultId,
          itemId: row.id,
          secretVersion: newVersion,
          itemKind: row.kind,
        }, req.body.secretValue);
        await tx.insert(itemSecretVersions).values({
          itemId: row.id,
          vaultId: row.vaultId,
          itemKind: row.kind,
          secretVersion: newVersion,
          ciphertext: enc.ciphertext,
          iv: enc.iv,
          authTag: enc.authTag,
          wrappedDek: enc.wrappedDek,
          keyVersion: enc.keyVersion,
          createdBy: req.user.id,
        });
        const updated = await tx.update(items).set({
          version: newVersion,
          secretVersion: newVersion,
          updatedAt: new Date(),
          updatedBy: req.user.id,
        }).where(eq(items.id, row.id)).returning();
        const meta = toItemMeta(updated[0]!);
        collect(await recordSyncEvent(tx, {
          type: 'item.upserted',
          vaultId: row.vaultId,
          itemId: row.id,
          payload: { item: meta },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'item.rotate_secret',
          vaultId: row.vaultId,
          itemId: row.id,
          success: true,
          details: { secretVersion: newVersion },
        });
        return { statusCode: 200, response: meta };
      });
      return reply.code(result.statusCode as 200).send(result.response as never);
    } catch (err) {
      if (err instanceof VersionConflictError) return conflict(reply, err);
      throw err;
    }
  });

  r.delete('/api/items/:itemId', {
    preHandler: writeGuard,
    schema: { tags: ['items'], params: ItemParams, body: DeleteItemRequestSchema, response: { '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const found = await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1);
    const existing = found[0];
    if (!existing || existing.deleted) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '条目不存在' } as never);
    }
    if (!await requireLegacyVault(existing.vaultId, reply, true)) return;
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canEditItems(access.role)) {
      return deny(req, reply, 'item.delete', existing.vaultId, existing.id);
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const locked = await tx.select().from(items).where(eq(items.id, req.params.itemId)).for('update');
        const row = locked[0]!;
        if (row.version !== req.body.expectedVersion) {
          throw new VersionConflictError(row.version, toItemMeta(row));
        }
        await tx.update(items).set({
          deleted: true,
          version: row.version + 1,
          updatedAt: new Date(),
          updatedBy: req.user.id,
        }).where(eq(items.id, row.id));
        collect(await recordSyncEvent(tx, {
          type: 'item.deleted',
          vaultId: row.vaultId,
          itemId: row.id,
          payload: {},
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'item.delete',
          vaultId: row.vaultId,
          itemId: row.id,
          success: true,
          details: { title: row.title },
        });
        return { statusCode: 200, response: { ok: true } };
      });
      return reply.code(result.statusCode as 200).send(result.response as never);
    } catch (err) {
      if (err instanceof VersionConflictError) return conflict(reply, err);
      throw err;
    }
  });

  r.get('/api/items/:itemId/versions', {
    preHandler: [app.requireSession],
    schema: { tags: ['items'], params: ItemParams, response: { 200: z.array(SecretVersionInfoSchema), '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    const found = await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1);
    const existing = found[0];
    if (!existing) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '条目不存在' } as never);
    }
    if (!await requireLegacyVault(existing.vaultId, reply, false)) return;
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || access.role === null) {
      return deny(req, reply, 'item.versions', existing.vaultId, existing.id);
    }
    const rows = await db
      .select({
        itemId: itemSecretVersions.itemId,
        secretVersion: itemSecretVersions.secretVersion,
        keyVersion: itemSecretVersions.keyVersion,
        createdAt: itemSecretVersions.createdAt,
        createdBy: itemSecretVersions.createdBy,
      })
      .from(itemSecretVersions)
      .where(eq(itemSecretVersions.itemId, existing.id))
      .orderBy(asc(itemSecretVersions.secretVersion));
    return rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() }));
  });

  /** 敏感内容读取：工作台锁定时拒绝；auditor 永远拒绝；成功与失败都写审计。 */
  r.post('/api/items/:itemId/reveal', {
    preHandler: writeGuard,
    schema: { tags: ['items'], params: ItemParams, body: RevealRequestSchema, response: { 200: RevealResponseSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    if (req.sessionRow.locked) {
      return reply.code(423).send({ statusCode: 423, error: 'Locked', message: '工作台已锁定，请先解锁' } as never);
    }
    const found = await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1);
    const existing = found[0];
    if (!existing || existing.deleted) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '条目不存在' } as never);
    }
    if (!await requireLegacyVault(existing.vaultId, reply, false)) return;
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canReveal(access.role)) {
      await auditStandalone(db, audit, {
        actorUserId: req.user.id,
        action: 'item.reveal',
        vaultId: existing.vaultId,
        itemId: existing.id,
        success: false,
        details: { reason: 'access_denied', purpose: req.body.purpose, role: access?.role ?? 'none' },
      });
      return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message: '没有查看密码或敏感内容的权限' } as never);
    }
    const secretVersion = req.body.secretVersion ?? existing.secretVersion;
    const rows = await db
      .select()
      .from(itemSecretVersions)
      .where(and(
        eq(itemSecretVersions.itemId, existing.id),
        eq(itemSecretVersions.secretVersion, secretVersion),
      ))
      .limit(1);
    const secretRow = rows[0];
    if (!secretRow) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '该内容版本不存在' } as never);
    }
    // AAD 由已鉴权的当前条目上下文构造；密文行冗余上下文若与条目不一致，
    // 说明存储层被移花接木，直接拒绝（数据库组合外键在写入侧同样拒绝这种行）。
    if (secretRow.vaultId !== existing.vaultId || secretRow.itemKind !== existing.kind) {
      await auditStandalone(db, audit, {
        actorUserId: req.user.id,
        action: 'item.reveal',
        vaultId: existing.vaultId,
        itemId: existing.id,
        success: false,
        details: { reason: 'ciphertext_context_mismatch', secretVersion },
      });
      return reply.code(409).send({ statusCode: 409, error: 'Conflict', message: '内容完整性校验失败，已拒绝读取' } as never);
    }
    const value = decryptSecret(keys, {
      vaultId: existing.vaultId,
      itemId: existing.id,
      secretVersion,
      itemKind: existing.kind,
    }, {
      ciphertext: secretRow.ciphertext,
      iv: secretRow.iv,
      authTag: secretRow.authTag,
      wrappedDek: secretRow.wrappedDek,
      keyVersion: secretRow.keyVersion,
    });
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'item.reveal',
      vaultId: existing.vaultId,
      itemId: existing.id,
      success: true,
      details: { purpose: req.body.purpose, secretVersion, channel: 'web' },
    });
    return { itemId: existing.id, secretVersion, value };
  });

  async function requireLegacyVault(vaultId: string, reply: FastifyReply, write: boolean) {
    const state = (await db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, vaultId)).limit(1))[0];
    if (!state || state.storageMode !== 'legacy') {
      reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '该密码库已完成零知识迁移，请刷新页面',
      } as never);
      return false;
    }
    if (state.writeState !== 'open') {
      reply.code(423).send({
        statusCode: 423,
        error: 'Locked',
        message: write ? '密码库正在迁移，暂时不能修改' : '密码库正在迁移，旧数据已经冻结',
      } as never);
      return false;
    }
    return true;
  }

}
