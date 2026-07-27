import { createHash, randomBytes } from 'node:crypto';
import { and, eq, lt } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { SessionUser } from '@mima/contracts';
import { CSRF_HEADER } from '@mima/contracts';
import { sessions, extensionSessions, userDevices, users } from '../db/schema.ts';
import type { AppContext } from '../context.ts';
import { toSessionUser, type AuthUserRecord } from '../auth/contracts.ts';
import { hasLocalPlatformAdminRole } from '../services/system-roles.ts';

declare module 'fastify' {
  interface FastifyRequest {
    user: SessionUser;
    sessionRow: typeof sessions.$inferSelect;
    extensionSessionRow: typeof extensionSessions.$inferSelect;
  }
  interface FastifyInstance {
    ctx: AppContext;
    requireSession: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireCsrf: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireExtensionSession: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

export const SESSION_COOKIE = 'mima_sid';

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export function userFromRow(
  row: AuthUserRecord,
  isLocalPlatformAdmin = false,
): SessionUser {
  return toSessionUser(row, isLocalPlatformAdmin);
}

export function registerAuthHooks(app: FastifyInstance): void {
  const { db } = app.ctx;

  app.decorate('requireSession', async (req: FastifyRequest, reply: FastifyReply) => {
    const token = req.cookies[SESSION_COOKIE];
    if (!token) return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '未登录' });
    const rows = await db
      .select()
      .from(sessions)
      .where(eq(sessions.tokenHash, hashToken(token)))
      .limit(1);
    const session = rows[0];
    if (!session || session.expiresAt.getTime() < Date.now()) {
      return reply
        .code(401)
        .clearCookie(SESSION_COOKIE, { path: '/' })
        .send({ statusCode: 401, error: 'Unauthorized', message: '登录已过期，请重新登录' });
    }
    const userRows = await db.select().from(users).where(eq(users.id, session.userId)).limit(1);
    if (!userRows[0] || !userRows[0].active) {
      await db.delete(sessions).where(eq(sessions.id, session.id));
      return reply
        .code(401)
        .clearCookie(SESSION_COOKIE, { path: '/' })
        .send({ statusCode: 401, error: 'Unauthorized', message: '用户不存在或已停用' });
    }
    req.sessionRow = session;
    req.user = userFromRow(userRows[0], await hasLocalPlatformAdminRole(db, userRows[0].id));
    if (session.locked && !isAllowedWhileLocked(req.method, req.routeOptions.url ?? '')) {
      return reply.code(423).send({
        statusCode: 423,
        error: 'Locked',
        message: '工作台已锁定，请先使用主密码或已授权设备解锁',
      });
    }
  });

  /** 写请求防护：校验 Origin（若存在）与 CSRF Token。 */
  app.decorate('requireCsrf', async (req: FastifyRequest, reply: FastifyReply) => {
    const origin = req.headers.origin;
    if (origin && !app.ctx.webOrigins.includes(origin)) {
      return reply
        .code(403)
        .send({ statusCode: 403, error: 'Forbidden', message: '请求来源不受信任' });
    }
    const csrf = req.headers[CSRF_HEADER];
    if (!csrf || csrf !== req.sessionRow.csrfToken) {
      return reply
        .code(403)
        .send({ statusCode: 403, error: 'Forbidden', message: '安全校验失败，请刷新页面后重试' });
    }
  });

  app.decorate('requireExtensionSession', async (req: FastifyRequest, reply: FastifyReply) => {
    const auth = req.headers.authorization;
    const token = auth?.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) {
      return reply
        .code(401)
        .send({ statusCode: 401, error: 'Unauthorized', message: '浏览器扩展尚未配对' });
    }
    const rows = await db
      .select()
      .from(extensionSessions)
      .where(eq(extensionSessions.tokenHash, hashToken(token)))
      .limit(1);
    const session = rows[0];
    if (!session || session.expiresAt.getTime() < Date.now()) {
      return reply
        .code(401)
        .send({ statusCode: 401, error: 'Unauthorized', message: '扩展配对无效或已过期，请重新配对' });
    }
    if (session.deviceId) {
      const device = (
        await db.select().from(userDevices).where(and(
          eq(userDevices.id, session.deviceId),
          eq(userDevices.userId, session.userId),
          eq(userDevices.status, 'active'),
        )).limit(1)
      )[0];
      if (!device || device.deviceGeneration !== session.securityGeneration) {
        await db.delete(extensionSessions).where(eq(extensionSessions.id, session.id));
        return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message: '扩展设备已被撤销，请重新配对' });
      }
    } else if (app.ctx.e2eeRequired) {
      await db.delete(extensionSessions).where(eq(extensionSessions.id, session.id));
      return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '旧版扩展会话已停用，请重新配对' });
    }
    const userRows = await db.select().from(users).where(eq(users.id, session.userId)).limit(1);
    if (!userRows[0] || !userRows[0].active) {
      await db.delete(extensionSessions).where(eq(extensionSessions.id, session.id));
      return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '用户不存在或已停用' });
    }
    req.user = userFromRow(userRows[0], await hasLocalPlatformAdminRole(db, userRows[0].id));
    req.extensionSessionRow = session;
  });
}

function isAllowedWhileLocked(method: string, route: string): boolean {
  if (route === '/api/session' && (method === 'GET' || method === 'DELETE')) return true;
  if (route === '/api/v2/crypto/profile' && (method === 'GET' || method === 'POST')) return true;
  if (route === '/api/v2/devices' && (method === 'GET' || method === 'POST')) return true;
  if (route === '/api/v2/session/unlock-challenge' && method === 'POST') return true;
  if (route === '/api/v2/session/crypto-unlock' && method === 'POST') return true;
  if (route === '/api/v2/account-crypto-resets' && (method === 'GET' || method === 'POST')) return true;
  if (route === '/api/v2/account-crypto-resets/:requestId' && method === 'GET') return true;
  if (route === '/api/v2/legacy-key-retirement' && method === 'GET') return true;
  if (
    [
      '/api/v2/account-crypto-resets/:requestId/approve',
      '/api/v2/account-crypto-resets/:requestId/activate',
      '/api/v2/account-crypto-resets/:requestId/cancel',
    ].includes(route) && method === 'POST'
  ) return true;
  if (route === '/api/v2/recovery/requests' && (method === 'GET' || method === 'POST')) return true;
  if (route === '/api/v2/recovery/requests/:requestId' && method === 'GET') return true;
  if (route === '/api/v2/recovery/requests/:requestId/package' && method === 'GET') return true;
  if (route === '/api/v2/recovery/requests/:requestId/approve' && method === 'POST') return true;
  return route === '/api/session/lock' || route === '/api/session/unlock' || route === '/api/session/reauth';
}

/** 惰性清理过期会话/配对码（每次登录时顺带执行）。 */
export async function pruneExpired(db: AppContext['db']): Promise<void> {
  const now = new Date();
  await db.delete(sessions).where(lt(sessions.expiresAt, now));
  await db.delete(extensionSessions).where(lt(extensionSessions.expiresAt, now));
}
