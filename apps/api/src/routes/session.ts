import { createHash } from 'node:crypto';
import { and, eq, isNull } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  AuthConfigSchema,
  DirectoryResponseSchema,
  LoginRequestSchema,
  SessionInfoSchema,
} from '@mima/contracts';
import { DirectoryUnavailableError } from '../auth/directory.ts';
import { SESSION_COOKIE, hashToken } from '../plugins/auth.ts';
import {
  extensionPairingCodes,
  extensionSessions,
  sessions,
  userCryptoProfiles,
} from '../db/schema.ts';
import { appendAudit, auditStandalone, recordAnchor } from '../services/audit.ts';
import { env } from '../env.ts';
import { CredentialAttemptLimiter } from '../auth/attempt-limiter.ts';

const OIDC_TRANSACTION_COOKIE = 'mima_oidc_tx';
const FEISHU_TRANSACTION_COOKIE = 'mima_feishu_tx';
const OidcFormPostCallbackSchema = z.object({
  code: z.string().min(1).max(8192).optional(),
  error: z.string().regex(/^[A-Za-z0-9._~-]+$/).max(128).optional(),
  error_description: z.string().max(2048).optional(),
  error_uri: z.string().url().max(2048).optional(),
  iss: z.string().url().max(2048).optional(),
  scope: z.string().max(2048).optional(),
  session_state: z.string().max(1024).optional(),
  state: z.string().min(1).max(512),
}).strict().refine((value) => Boolean(value.code) !== Boolean(value.error), {
  message: 'OIDC callback must contain exactly one of code or error',
});
const FeishuCallbackQuerySchema = z.object({
  code: z.string().min(1).max(8192).optional(),
  error: z.string().regex(/^[A-Za-z0-9._~-]+$/).max(128).optional(),
  state: z.string().min(1).max(512),
}).strict().refine((value) => Boolean(value.code) !== Boolean(value.error), {
  message: 'Feishu callback must contain exactly one of code or error',
});

export function registerSessionRoutes(app: FastifyInstance): void {
  const { db, auth, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const credentialAttempts = new CredentialAttemptLimiter(db);

  r.get('/api/auth/config', {
    schema: { tags: ['session'], response: { 200: AuthConfigSchema } },
  }, async (_req, reply) => {
    reply.header('cache-control', 'no-store');
    const reauthMethod: 'none' | 'password' | 'oidc' = auth.reauth?.method ?? 'none';
    return {
      mode: auth.loginProvider,
      loginProvider: auth.loginProvider,
      reauthProvider: auth.reauthProvider,
      directoryProvider: auth.directoryProvider,
      loginMethod: auth.login.method,
      reauthMethod,
      providerLabel: providerLabel(auth.loginProvider),
    };
  });

  r.get('/api/auth/dev-users', {
    schema: {
      tags: ['session'],
      response: {
        200: z.object({
          mode: z.literal('dev'),
          users: z.array(z.object({ username: z.string(), displayName: z.string() })),
        }),
        404: ZeroKnowledgeApiErrorSchema,
      },
    },
  }, async (_req, reply) => {
    if (auth.loginProvider !== 'dev') return notFound(reply);
    const directory = await auth.directory.listDirectory();
    return {
      mode: 'dev' as const,
      users: directory.users.map(({ username, displayName }) => ({ username, displayName })),
    };
  });

  r.get('/api/auth/oidc/start', {
    schema: { tags: ['session'], response: { 404: ZeroKnowledgeApiErrorSchema } },
  }, async (_req, reply) => {
    if (auth.login.method !== 'oidc') return notFound(reply);
    try {
      const start = await auth.login.beginLogin();
      setOidcTransactionCookie(reply, start.browserBindingToken);
      reply.header('cache-control', 'no-store');
      return reply.redirect(start.url.href, 303);
    } catch {
      return reply.redirect(authResultUrl('company_auth_unavailable'), 303);
    }
  });

  r.post('/api/auth/oidc/callback', {
    onRequest: [protectAuthCallbackResponse],
    schema: { tags: ['session'], body: OidcFormPostCallbackSchema },
  }, async (req, reply) => {
    if (auth.login.method !== 'oidc') return notFound(reply);
    reply.clearCookie(OIDC_TRANSACTION_COOKIE, {
      path: '/api/auth/oidc/callback',
      sameSite: 'none',
      secure: true,
    });
    try {
      const callbackUrl = configuredOidcFormPostCallbackUrl(req.body);
      const result = await auth.login.completeCallback(
        callbackUrl,
        req.cookies[OIDC_TRANSACTION_COOKIE],
      );
      const directoryUser = await auth.directory.findActiveOidcUser(
        result.identity.issuer,
        result.identity.subject,
      );
      if (!directoryUser) throw new Error('OIDC identity is not an active directory user');
      const user = directoryUser;

      if (result.purpose === 'login') {
        const created = await auth.sessions.create(user, {
          method: 'oidc',
          provider: 'oidc',
          authenticatedAt: result.identity.authTime,
          issuer: result.identity.issuer,
          subject: result.identity.subject,
          sid: result.identity.sid,
        });
        setSessionCookie(reply, created.token);
        await auditStandalone(db, audit, {
          actorUserId: user.id,
          action: 'session.login',
          success: true,
          details: { username: user.username, authMethod: 'oidc' },
        });
      } else {
        const current = await sessionFromCookie(app, req);
        if (
          !current ||
          !current.locked ||
          current.authMethod !== 'oidc' ||
          current.id !== result.sessionId ||
          current.userId !== result.userId ||
          current.userId !== user.id ||
          current.oidcIssuer !== result.identity.issuer ||
          current.oidcSubject !== result.identity.subject
        ) {
          throw new Error('OIDC reauthentication session binding failed');
        }
        const unlocked = await auth.sessions.completeReauthentication(
          current.id,
          current.userId,
          result.identity.authTime,
        );
        if (!unlocked) throw new Error('OIDC reauthentication session is no longer locked');
        await auditStandalone(db, audit, {
          actorUserId: user.id,
          action: 'session.unlock',
          success: true,
          details: { authMethod: 'oidc' },
        });
      }
      return reply.redirect(authResultUrl(), 303);
    } catch {
      await auditStandalone(db, audit, {
        actorUserId: null,
        action: 'session.oidc_callback',
        success: false,
        details: { reason: 'oidc_callback_failed' },
      });
      return reply.redirect(authResultUrl('company_auth_failed'), 303);
    }
  });

  r.get('/api/auth/feishu/start', {
    schema: { tags: ['session'], response: { 404: ZeroKnowledgeApiErrorSchema } },
  }, async (_req, reply) => {
    if (auth.login.method !== 'feishu') return notFound(reply);
    try {
      const start = await auth.login.beginLogin();
      setFeishuTransactionCookie(reply, start.browserBindingToken);
      reply.header('cache-control', 'no-store');
      return reply.redirect(start.url.href, 303);
    } catch {
      return reply.redirect(authResultUrl('feishu_auth_unavailable'), 303);
    }
  });

  r.get('/api/auth/feishu/callback', {
    onRequest: [protectAuthCallbackResponse],
    schema: { tags: ['session'], querystring: FeishuCallbackQuerySchema },
  }, async (req, reply) => {
    if (auth.login.method !== 'feishu') return notFound(reply);
    reply.clearCookie(FEISHU_TRANSACTION_COOKIE, {
      path: '/api/auth/feishu/callback',
      sameSite: 'lax',
      secure: true,
    });
    try {
      const result = await auth.login.completeCallback(
        configuredFeishuCallbackUrl(req.query),
        req.cookies[FEISHU_TRANSACTION_COOKIE],
      );
      const user = await auth.directory.resolveExternalIdentity(
        'feishu',
        result.identity.tenantKey,
        result.identity.userId,
      );
      if (!user) throw new Error('Feishu identity is not an active directory user');
      const created = await auth.sessions.create(user, {
        method: 'feishu',
        provider: 'feishu',
        authenticatedAt: new Date(),
        issuer: result.identity.tenantKey,
        subject: result.identity.userId,
      });
      setSessionCookie(reply, created.token);
      await auditStandalone(db, audit, {
        actorUserId: user.id,
        action: 'session.login',
        success: true,
        details: { username: user.username, authMethod: 'feishu' },
      });
      return reply.redirect(authResultUrl(), 303);
    } catch {
      await auditStandalone(db, audit, {
        actorUserId: null,
        action: 'session.feishu_callback',
        success: false,
        details: { reason: 'feishu_callback_failed' },
      });
      return reply.redirect(authResultUrl('feishu_auth_failed'), 303);
    }
  });

  r.post('/api/session', {
    schema: {
      tags: ['session'],
      body: LoginRequestSchema,
      response: { 200: SessionInfoSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (auth.login.method !== 'password') return notFound(reply);
    const origin = req.headers.origin;
    if (origin && !app.ctx.webOrigins.includes(origin)) {
      return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message: '请求来源不受信任' } as never);
    }
    const attemptKey = `login:${req.ip}:${req.body.username.trim().toLocaleLowerCase()}`;
    const retryAfter = await credentialAttempts.retryAfterSeconds(attemptKey);
    if (retryAfter > 0) {
      reply.header('retry-after', String(retryAfter));
      return reply.code(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: '登录尝试过于频繁，请稍后再试',
      } as never);
    }
    const record = await auth.login
      .authenticatePassword(req.body.username, req.body.password)
      .catch(() => null);
    if (!record) {
      await credentialAttempts.recordFailure(attemptKey);
      await auditStandalone(db, audit, {
        actorUserId: null,
        action: 'session.login',
        success: false,
        details: { username: req.body.username, reason: 'invalid_credentials' },
      });
      return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message: '用户名或登录密码错误' } as never);
    }
    await credentialAttempts.clear(attemptKey);
    const created = await auth.sessions.create(record, {
      method: 'password',
      provider: auth.loginProvider === 'ldap' ? 'ldap' : 'dev',
      authenticatedAt: new Date(),
    });
    await auditStandalone(db, audit, {
      actorUserId: record.id,
      action: 'session.login',
      success: true,
      details: { username: record.username, authMethod: 'password' },
    });
    setSessionCookie(reply, created.token);
    return created.info;
  });

  r.get('/api/session', {
    preHandler: [app.requireSession],
    schema: { tags: ['session'], response: { 200: SessionInfoSchema } },
  }, async (req) => {
    const profile = (
      await db
        .select({ userId: userCryptoProfiles.userId })
        .from(userCryptoProfiles)
        .where(eq(userCryptoProfiles.userId, req.user.id))
        .limit(1)
    )[0];
    return {
      user: req.user,
      csrfToken: req.sessionRow.csrfToken,
      locked: req.sessionRow.locked,
      cryptoProfileInitialized: Boolean(profile),
      cryptoDeviceId: req.sessionRow.unlockedDeviceId,
    };
  });

  r.delete('/api/session', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: { tags: ['session'] },
  }, async (req, reply) => {
    await db.delete(sessions).where(eq(sessions.id, req.sessionRow.id));
    await auditStandalone(db, audit, { actorUserId: req.user.id, action: 'session.logout', success: true });
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    return { ok: true };
  });

  r.post('/api/session/lock', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: { tags: ['session'] },
  }, async (req) => {
    const head = await db.transaction(async (tx) => {
      await tx.update(sessions).set({
        locked: true,
        unlockedDeviceId: null,
        unlockedAt: null,
        unlockGeneration: req.sessionRow.unlockGeneration + 1,
      }).where(eq(sessions.id, req.sessionRow.id));
      const revoked = await tx
        .delete(extensionSessions)
        .where(eq(extensionSessions.userId, req.user.id))
        .returning({ id: extensionSessions.id });
      const codesDeleted = await tx
        .delete(extensionPairingCodes)
        .where(and(eq(extensionPairingCodes.userId, req.user.id), isNull(extensionPairingCodes.usedAt)))
        .returning({ code: extensionPairingCodes.code });
      return appendAudit(tx, audit, {
        actorUserId: req.user.id,
        action: 'session.lock',
        success: true,
        details: {
          extensionSessionsRevoked: revoked.length,
          pairingCodesDeleted: codesDeleted.length,
        },
      });
    });
    recordAnchor(audit, head);
    return { ok: true };
  });

  r.post('/api/session/unlock', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: { tags: ['session'], body: z.object({ password: z.string().min(1) }) },
  }, async (req, reply) => {
    if (auth.reauth?.method !== 'password') return notFound(reply);
    const attemptKey = `unlock:${req.ip}:${req.user.id}:${req.sessionRow.id}`;
    const retryAfter = await credentialAttempts.retryAfterSeconds(attemptKey);
    if (retryAfter > 0) {
      reply.header('retry-after', String(retryAfter));
      return reply.code(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: '解锁尝试过于频繁，请稍后再试',
      } as never);
    }
    const valid = await auth.reauth
      .reauthenticatePassword(req.user.username, req.body.password)
      .catch(() => false);
    if (!valid) {
      await credentialAttempts.recordFailure(attemptKey);
      await auditStandalone(db, audit, {
        actorUserId: req.user.id,
        action: 'session.unlock',
        success: false,
        details: { reason: 'invalid_credentials' },
      });
      return reply.code(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: auth.reauthProvider === 'ldap' ? '域密码错误' : '登录密码错误',
      } as never);
    }
    await credentialAttempts.clear(attemptKey);
    await db.update(sessions).set({ locked: false, authenticatedAt: new Date() }).where(eq(sessions.id, req.sessionRow.id));
    await auditStandalone(db, audit, {
      actorUserId: req.user.id,
      action: 'session.unlock',
      success: true,
      details: { authMethod: auth.reauthProvider },
    });
    return { ok: true };
  });

  r.post('/api/session/reauth', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['session'],
      response: {
        200: z.object({ redirectUrl: z.string().url() }),
        '4xx': ZeroKnowledgeApiErrorSchema,
      },
    },
  }, async (req, reply) => {
    if (auth.reauth?.method !== 'oidc') return notFound(reply);
    if (!req.sessionRow.locked || req.sessionRow.authProvider !== 'oidc') {
      return reply.code(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: '当前会话不需要组织统一认证解锁',
      } as never);
    }
    const start = await auth.reauth.beginReauthentication({
      sessionId: req.sessionRow.id,
      userId: req.user.id,
      authenticatedAt: req.sessionRow.authenticatedAt,
    });
    setOidcTransactionCookie(reply, start.browserBindingToken);
    reply.header('cache-control', 'no-store');
    return { redirectUrl: start.url.href };
  });

  r.post('/api/auth/oidc/backchannel-logout', {
    schema: {
      tags: ['session'],
      body: z.object({ logout_token: z.string().min(1) }),
      response: { 200: z.object({ ok: z.literal(true) }), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    if (auth.login.method !== 'oidc') return notFound(reply);
    const identity = await auth.login
      .validateLogoutToken(req.body.logout_token)
      .catch(() => null);
    if (!identity) {
      return reply.code(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: '无效的退出通知',
      } as never);
    }
    const revoked = await auth.sessions.consumeOidcLogout(
      identity,
      createHash('sha256').update(identity.jti).digest('hex'),
    );
    if (revoked.replayed) return { ok: true as const };
    await auditStandalone(db, audit, {
      actorUserId: null,
      action: 'session.backchannel_logout',
      success: true,
      details: { sessionsRevoked: revoked.sessionsRevoked, usersAffected: revoked.userIds.length },
    });
    reply.header('cache-control', 'no-store');
    return { ok: true as const };
  });

  r.get('/api/directory', {
    preHandler: [app.requireSession],
    schema: { tags: ['session'], response: { 200: DirectoryResponseSchema, 503: ZeroKnowledgeApiErrorSchema } },
  }, async (_req, reply) => {
    try {
      const directory = await auth.directory.listDirectory();
      return {
        users: directory.users,
        groups: directory.groups,
        syncedAt: directory.syncedAt?.toISOString() ?? null,
      };
    } catch (error) {
      if (!(error instanceof DirectoryUnavailableError)) throw error;
      return reply.code(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: error.message,
      } as never);
    }
  });
}

function setSessionCookie(reply: import('fastify').FastifyReply, token: string): void {
  reply.setCookie(SESSION_COOKIE, token, {
    path: '/',
    httpOnly: true,
    sameSite: env.loginProvider === 'dev' ? 'strict' : 'lax',
    secure: env.sessionCookieSecure,
    maxAge: Math.floor(env.sessionTtlMs / 1000),
  });
}

function setOidcTransactionCookie(reply: import('fastify').FastifyReply, token: string): void {
  reply.setCookie(OIDC_TRANSACTION_COOKIE, token, {
    path: '/api/auth/oidc/callback',
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    maxAge: 5 * 60,
  });
}

function setFeishuTransactionCookie(reply: import('fastify').FastifyReply, token: string): void {
  reply.setCookie(FEISHU_TRANSACTION_COOKIE, token, {
    path: '/api/auth/feishu/callback',
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    maxAge: 5 * 60,
  });
}

function configuredOidcFormPostCallbackUrl(body: unknown): URL {
  const callback = new URL(env.oidc.redirectUri!);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return callback;
  const allowed = new Set([
    'code',
    'error',
    'error_description',
    'error_uri',
    'iss',
    'scope',
    'session_state',
    'state',
  ]);
  for (const [key, value] of Object.entries(body)) {
    if (allowed.has(key) && typeof value === 'string') callback.searchParams.set(key, value);
  }
  return callback;
}

function configuredFeishuCallbackUrl(query: unknown): URL {
  const callback = new URL(env.feishu.redirectUri!);
  if (!query || typeof query !== 'object' || Array.isArray(query)) return callback;
  for (const key of ['code', 'error', 'state'] as const) {
    const value = (query as Record<string, unknown>)[key];
    if (typeof value === 'string') callback.searchParams.set(key, value);
  }
  return callback;
}

async function protectAuthCallbackResponse(
  _request: FastifyRequest,
  reply: import('fastify').FastifyReply,
): Promise<void> {
  reply.header('cache-control', 'no-store');
  reply.header('referrer-policy', 'no-referrer');
}

function providerLabel(provider: typeof env.loginProvider): string {
  if (provider === 'feishu') return '飞书登录';
  if (provider === 'ldap') return '域账号登录';
  if (provider === 'oidc') return '组织统一认证';
  return '本地开发身份';
}

async function sessionFromCookie(app: FastifyInstance, req: FastifyRequest) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return null;
  const row = (
    await app.ctx.db
      .select()
      .from(sessions)
      .where(eq(sessions.tokenHash, hashToken(token)))
      .limit(1)
  )[0];
  if (!row || row.expiresAt.getTime() < Date.now()) return null;
  return row;
}

function authResultUrl(error?: string): string {
  const url = new URL('/', `${env.publicBaseUrl}/`);
  if (error) url.searchParams.set('auth_error', error);
  return url.href;
}

function notFound(reply: import('fastify').FastifyReply) {
  return reply.code(404).send({
    statusCode: 404,
    error: 'Not Found',
    message: '认证方式不可用',
  });
}
