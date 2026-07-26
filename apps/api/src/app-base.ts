import Fastify, { LogController, type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import {
  serializerCompiler,
  validatorCompiler,
  jsonSchemaTransform,
} from 'fastify-type-provider-zod';
import { AuditAnchorStore, FileMasterKeyProvider, loadAuditKey } from '@mima/crypto';
import { createDb, createPool } from './db/client.ts';
import { runMigrations } from './db/migrate.ts';
import { env } from './env.ts';
import { createAuthRuntime, type AuthRuntime } from './auth/runtime.ts';
import { SyncBus } from './services/bus.ts';
import type { AppContext } from './context.ts';
import { registerAuthHooks } from './plugins/auth.ts';
import { registerSessionRoutes } from './routes/session.ts';
import { registerGroupRoutes } from './routes/groups.ts';
import { registerMetaRoutes } from './routes/meta.ts';
import { verifyAuditChain, type AuditContext } from './services/audit.ts';

export interface BuildBaseAppOptions {
  databaseUrl?: string;
  runtimeKeyDir?: string;
  auditKeyDir?: string;
  e2eeRequired: boolean;
  logger?: boolean;
  migrate?: boolean;
  verifyAuditChainOnStartup?: boolean;
  authRuntime?: AuthRuntime;
}

export async function buildBaseApp(opts: BuildBaseAppOptions): Promise<FastifyInstance> {
  const databaseUrl = opts.databaseUrl ?? env.databaseUrl;
  if (opts.migrate !== false) await runMigrations(databaseUrl);

  const pool = createPool(databaseUrl);
  const runtimeKeyDir = opts.runtimeKeyDir ?? env.runtimeKeyDir;
  const auditKeyDir = opts.auditKeyDir ?? env.auditKeyDir;
  const dbName = new URL(databaseUrl).pathname.replace(/^\//, '') || 'default';
  const runtimeKeys = new FileMasterKeyProvider(runtimeKeyDir);
  const db = createDb(pool);
  const bus = new SyncBus();
  let audit: AuditContext;
  try {
    audit = {
      hmacKey: loadAuditKey(auditKeyDir),
      anchors: new AuditAnchorStore(auditKeyDir, dbName),
    };
    if (opts.verifyAuditChainOnStartup !== false) {
      await verifyAuditChain(db, audit);
    }
  } catch (error) {
    await pool.end();
    throw error;
  }
  const ctx: AppContext = {
    pool,
    db,
    runtimeKeys,
    audit,
    bus,
    auth: opts.authRuntime ?? createAuthRuntime(db, runtimeKeys, bus),
    webOrigins: env.webOrigins,
    extensionOrigins: env.extensionIds.map((id) => `chrome-extension://${id}`),
    e2eeRequired: opts.e2eeRequired,
  };
  const app = Fastify({
    logger: opts.logger === false ? false : { level: env.logLevel },
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: env.trustProxy,
  });
  app.setErrorHandler((error, request, reply) => {
    const safeError = typeof error === 'object' && error !== null
      ? error as { statusCode?: unknown; name?: unknown }
      : {};
    const statusCode = typeof safeError.statusCode === 'number'
      && safeError.statusCode >= 400
      && safeError.statusCode <= 599
      ? safeError.statusCode
      : 500;
    if (statusCode >= 500) {
      app.log.error({
        requestId: request.id,
        method: request.method,
        route: request.routeOptions.url,
        errorName: typeof safeError.name === 'string' ? safeError.name : 'Error',
      }, 'request failed');
    }
    return reply.code(statusCode).send({
      statusCode,
      error: safeHttpErrorName(statusCode),
      message: safeHttpErrorMessage(statusCode),
    });
  });
  app.setNotFoundHandler((_request, reply) => reply
    .header('cache-control', 'no-store')
    .header('referrer-policy', 'no-referrer')
    .code(404)
    .send({
      statusCode: 404,
      error: 'Not Found',
      message: '请求的资源不存在',
    }));
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.decorate('ctx', ctx);

  await app.register(cookie);
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string' },
    (_request, body, done) => {
      done(null, Object.fromEntries(new URLSearchParams(String(body))));
    },
  );
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin || env.webOrigins.includes(origin) || ctx.extensionOrigins.includes(origin)) {
        cb(null, true);
        return;
      }
      cb(null, false);
    },
    credentials: true,
    allowedHeaders: ['content-type', 'authorization', 'x-mima-csrf', 'x-pairing-token'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  });
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Mima管理 API',
        description: '零知识密码管理 API。服务端仅保存密文、公钥、签名和授权路由信息。',
        version: '0.2.0',
      },
      servers: [{ url: env.publicBaseUrl }],
    },
    transform: jsonSchemaTransform,
  });

  registerAuthHooks(app);
  registerSessionRoutes(app);
  registerGroupRoutes(app);
  registerMetaRoutes(app);

  app.addHook('onClose', async () => {
    ctx.auth.directory.stop();
    await pool.end();
  });
  ctx.auth.directory.start();
  return app;
}

function safeHttpErrorName(statusCode: number): string {
  if (statusCode === 400) return 'Bad Request';
  if (statusCode === 401) return 'Unauthorized';
  if (statusCode === 403) return 'Forbidden';
  if (statusCode === 404) return 'Not Found';
  if (statusCode === 409) return 'Conflict';
  if (statusCode === 413) return 'Payload Too Large';
  if (statusCode === 423) return 'Locked';
  if (statusCode === 429) return 'Too Many Requests';
  return statusCode >= 500 ? 'Internal Server Error' : 'Request Rejected';
}

function safeHttpErrorMessage(statusCode: number): string {
  if (statusCode === 400) return '请求格式不正确';
  if (statusCode === 401) return '登录状态无效或已经过期';
  if (statusCode === 403) return '没有执行该操作的权限';
  if (statusCode === 404) return '请求的资源不存在';
  if (statusCode === 409) return '请求与当前状态冲突';
  if (statusCode === 413) return '请求内容过大';
  if (statusCode === 423) return '当前资源暂时不可用';
  if (statusCode === 429) return '操作过于频繁，请稍后再试';
  return statusCode >= 500 ? '服务暂时无法处理请求' : '请求未通过安全检查';
}
