import { randomInt } from 'node:crypto';
import { and, eq, isNull } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ExtensionSessionRequestSchema,
  ExtensionSessionResponseSchema,
  ExtensionRevealRequestSchema,
  PairingCodeResponseSchema,
  RevealResponseSchema,
  BootstrapResponseSchema,
  ApiErrorSchema,
  PAIRING_CODE_TTL_MS,
  EXTENSION_SESSION_TTL_MS,
} from '@mima/contracts';
import { canReveal, normalizeOrigin } from '@mima/domain';
import { decryptSecret } from '@mima/crypto';
import { extensionPairingCodes, extensionSessions, items, itemSecretVersions, sessions, users } from '../db/schema.ts';
import { getVaultAccess, listAccessibleVaults, listVaultItems, listVaultMemberships } from '../services/access.ts';
import { auditStandalone } from '../services/audit.ts';
import { hashToken, newToken, userFromRow } from '../plugins/auth.ts';
import { toItemMeta, toMembershipDto, toVaultDto } from '../services/mappers.ts';
import { CredentialAttemptLimiter } from '../auth/attempt-limiter.ts';

/** 无易混淆字符的配对码字母表。 */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

function generatePairingCode(): string {
  let code = '';
  for (let i = 0; i < 8; i++) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return code;
}

export function registerExtensionRoutes(app: FastifyInstance): void {
  const { db, legacyContentKeys: keys, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const pairingAttempts = new CredentialAttemptLimiter(db);

  /** Web 端生成 120 秒一次性配对码（需要已登录会话 + CSRF）。
   * 配对码绑定来源 Web 会话；锁定中的会话不得生成配对码。 */
  r.post('/api/extension/pairing', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: { tags: ['extension'], response: { 200: PairingCodeResponseSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    if (!keys) {
      return reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '旧版扩展配对已停用，请升级浏览器扩展',
      } as never);
    }
    if (req.sessionRow.locked) {
      await auditStandalone(db, audit, {
        actorUserId: req.user.id,
        action: 'extension.pair.created',
        success: false,
        details: { reason: 'session_locked' },
      });
      return reply.code(423).send({ statusCode: 423, error: 'Locked', message: '工作台已锁定，请先解锁再配对' } as never);
    }
    const code = generatePairingCode();
    const expiresAt = new Date(Date.now() + PAIRING_CODE_TTL_MS);
    await db.insert(extensionPairingCodes).values({
      code,
      userId: req.user.id,
      sessionId: req.sessionRow.id,
      expiresAt,
    });
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'extension.pair.created',
      success: true,
    });
    return { code, expiresAt: expiresAt.toISOString() };
  });

  /** 扩展用一次性配对码换取长期设备授权的 opaque token（不发 refresh token）。
   * used_at 原子占用保证并发领取只有一个成功；领取时重校验来源 Web 会话
   * 仍然存在、未过期且未锁定——code→lock→claim 一律失败。 */
  r.post('/api/extension/sessions', {
    schema: { tags: ['extension'], body: ExtensionSessionRequestSchema, response: { 200: ExtensionSessionResponseSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    if (!keys) {
      return reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '旧版扩展配对已停用，请升级浏览器扩展',
      } as never);
    }
    const attemptKey = `extension-pair-claim:${req.ip}`;
    const retryAfter = await pairingAttempts.retryAfterSeconds(attemptKey);
    if (retryAfter > 0) {
      reply.header('retry-after', String(retryAfter));
      return reply.code(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: '配对尝试过于频繁，请稍后再试',
      } as never);
    }
    const now = new Date();
    const claimed = await db
      .update(extensionPairingCodes)
      .set({ usedAt: now })
      .where(and(
        eq(extensionPairingCodes.code, req.body.code.toUpperCase()),
        isNull(extensionPairingCodes.usedAt),
      ))
      .returning();
    const row = claimed[0];
    if (!row || row.expiresAt.getTime() < now.getTime()) {
      await pairingAttempts.recordFailure(attemptKey);
      await auditStandalone(db, audit, {
        actorUserId: row?.userId ?? null,
        action: 'extension.pair.claimed',
        success: false,
        details: { reason: row ? 'expired' : 'invalid_code' },
      });
      return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '配对码无效或已过期' } as never);
    }
    // 来源 Web 会话必须仍有效且未锁定（锁定/退出会删除未消费配对码，
    // 此处再兜底一次：并发窗口内 lock 先落库的场景同样拒绝）
    const sourceSession = row.sessionId
      ? (await db.select().from(sessions).where(eq(sessions.id, row.sessionId)).limit(1))[0]
      : undefined;
    if (!sourceSession || sourceSession.expiresAt.getTime() < now.getTime() || sourceSession.locked) {
      await pairingAttempts.recordFailure(attemptKey);
      await auditStandalone(db, audit, {
        actorUserId: row.userId,
        action: 'extension.pair.claimed',
        success: false,
        details: { reason: !sourceSession ? 'source_session_gone' : sourceSession.locked ? 'source_session_locked' : 'source_session_expired' },
      });
      return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '配对码来源会话已失效，请在 Web 端重新生成' } as never);
    }
    const userRows = await db.select().from(users).where(eq(users.id, row.userId)).limit(1);
    if (!userRows[0]) {
      await pairingAttempts.recordFailure(attemptKey);
      return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '用户不存在' } as never);
    }
    const token = newToken();
    const expiresAt = new Date(now.getTime() + EXTENSION_SESSION_TTL_MS);
    await db.insert(extensionSessions).values({
      tokenHash: hashToken(token),
      userId: row.userId,
      expiresAt,
    });
    await auditStandalone(db, audit, {
      actorUserId: row.userId,
      action: 'extension.pair.claimed',
      success: true,
    });
    await pairingAttempts.clear(attemptKey);
    return { token, expiresAt: expiresAt.toISOString(), user: userFromRow(userRows[0]) };
  });

  /** 扩展元数据快照（不含敏感内容明文），供本地网站地址匹配。 */
  r.get('/api/extension/bootstrap', {
    preHandler: [app.requireExtensionSession],
    schema: { tags: ['extension'], response: { 200: BootstrapResponseSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    if (!keys) {
      return reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '服务端明文读取接口已停用，请升级浏览器扩展',
      } as never);
    }
    const accesses = await listAccessibleVaults(db, req.user);
    const allItems = [];
    const memberships = [];
    for (const a of accesses) {
      allItems.push(...(await listVaultItems(db, a.vault.id)).map(toItemMeta));
      if (a.vault.kind === 'team') {
        memberships.push(...(await listVaultMemberships(db, a.vault.id)).map(toMembershipDto));
      }
    }
    return {
      user: req.user,
      vaults: accesses.map((a) => toVaultDto(a.vault)),
      memberships,
      items: allItems,
      cursor: 0,
    };
  });

  /** 扩展读取：仅用户在面板中显式选中条目后调用。
   * fill 必须携带当前标签页 Origin 与本地缓存的 item version，
   * 服务端用最新条目再次校验——Origin 改变或条目已被他人修改（version 过期）一律拒绝。 */
  r.post('/api/extension/items/:itemId/reveal', {
    preHandler: [app.requireExtensionSession],
    schema: {
      tags: ['extension'],
      params: z.object({ itemId: z.string().uuid() }),
      body: ExtensionRevealRequestSchema,
      response: { 200: RevealResponseSchema, '4xx': ApiErrorSchema },
    },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    if (!keys) {
      return reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '服务端明文读取接口已停用，请升级浏览器扩展',
      } as never);
    }
    const found = await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1);
    const existing = found[0];
    if (!existing || existing.deleted) {
      return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: '条目不存在' } as never);
    }
    const denyReveal = async (statusCode: 403 | 409, reason: string, message: string) => {
      await auditStandalone(db, audit, {
        actorUserId: req.user.id,
        action: 'item.reveal',
        vaultId: existing.vaultId,
        itemId: existing.id,
        success: false,
        details: { reason, purpose: req.body.purpose, channel: 'extension' },
      });
      return reply.code(statusCode).send({ statusCode, error: statusCode === 403 ? 'Forbidden' : 'Conflict', message } as never);
    };
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canReveal(access.role)) {
      return denyReveal(403, 'access_denied', '没有查看密码或敏感内容的权限');
    }
    if (req.body.purpose === 'fill') {
      if (req.body.origin === undefined || req.body.itemVersion === undefined) {
        return denyReveal(403, 'fill_context_missing', '无法确认当前网站和内容版本，已拒绝填充');
      }
      if (existing.kind !== 'login' || existing.origin === null) {
        return denyReveal(403, 'fill_not_login', '该条目不支持填充');
      }
      if (normalizeOrigin(req.body.origin) !== existing.origin) {
        return denyReveal(403, 'fill_origin_mismatch', '当前网站与这条登录信息不匹配，已拒绝填充');
      }
      if (req.body.itemVersion !== existing.version) {
        return denyReveal(409, 'fill_stale_version', '条目已被修改，请刷新后重试填充');
      }
    }
    const rows = await db
      .select()
      .from(itemSecretVersions)
      .where(and(
        eq(itemSecretVersions.itemId, existing.id),
        eq(itemSecretVersions.secretVersion, existing.secretVersion),
      ))
      .limit(1);
    const secretRow = rows[0]!;
    // AAD 由已鉴权的当前条目上下文构造；密文行冗余上下文不一致即拒绝
    if (secretRow.vaultId !== existing.vaultId || secretRow.itemKind !== existing.kind) {
      return denyReveal(409, 'ciphertext_context_mismatch', '条目信息校验失败，已拒绝显示');
    }
    const value = decryptSecret(keys, {
      vaultId: existing.vaultId,
      itemId: existing.id,
      secretVersion: existing.secretVersion,
      itemKind: existing.kind,
    }, secretRow);
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'item.reveal',
      vaultId: existing.vaultId,
      itemId: existing.id,
      success: true,
      details: { purpose: req.body.purpose, secretVersion: existing.secretVersion, channel: 'extension' },
    });
    return { itemId: existing.id, secretVersion: existing.secretVersion, value };
  });

  /** 解除配对：撤销服务端扩展会话 Token（客户端随后清空 storage.session）。 */
  r.delete('/api/extension/sessions', {
    preHandler: [app.requireExtensionSession],
    schema: { tags: ['extension'], response: { 200: z.object({ ok: z.boolean() }), '4xx': ApiErrorSchema } },
  }, async (req) => {
    const auth = req.headers.authorization!;
    const token = auth.slice(7);
    await db.delete(extensionSessions).where(eq(extensionSessions.tokenHash, hashToken(token)));
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'extension.unpair',
      success: true,
    });
    return { ok: true };
  });
}
