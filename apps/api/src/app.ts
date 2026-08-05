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
import { legacyEnv } from './legacy-env.ts';
import { createAuthRuntime, type AuthRuntime } from './auth/runtime.ts';
import { SyncBus } from './services/bus.ts';
import type { AppContext } from './context.ts';
import { registerAuthHooks } from './plugins/auth.ts';
import { registerSessionRoutes } from './routes/session.ts';
import { registerBootstrapRoutes } from './routes/bootstrap.ts';
import { registerEventRoutes } from './routes/events.ts';
import { registerEncryptedEventRoutes } from './routes/e2ee-events.ts';
import { registerVaultRoutes } from './routes/vaults.ts';
import { registerGroupRoutes } from './routes/groups.ts';
import { registerItemRoutes } from './routes/items.ts';
import { registerExtensionRoutes } from './routes/extension.ts';
import { registerMetaRoutes } from './routes/meta.ts';
import { registerE2eeCryptoRoutes } from './routes/e2ee-crypto.ts';
import { registerE2eeVaultRoutes } from './routes/e2ee-vaults.ts';
import { registerE2eeRecoveryRoutes } from './routes/e2ee-recovery.ts';
import { registerE2eeRecoveryCaseRoutes } from './routes/e2ee-recovery-cases.ts';
import { registerE2eeExtensionRoutes } from './routes/e2ee-extension.ts';
import { registerE2eeEnvelopeTaskRoutes } from './routes/e2ee-envelope-tasks.ts';
import { registerE2eeAccountResetRoutes } from './routes/e2ee-account-reset.ts';
import { registerE2eeLegacyKeyRetirementRoutes } from './routes/e2ee-legacy-key-retirement.ts';
import { buildOpenApiDocument } from './openapi-contract.ts';

export interface BuildAppOptions {
  databaseUrl?: string;
  masterKeyDir?: string;
  runtimeKeyDir?: string;
  auditKeyDir?: string;
  legacyContentKeyDir?: string | null;
  e2eeRequired?: boolean;
  logger?: boolean;
  migrate?: boolean;
  authRuntime?: AuthRuntime;
}

export async function buildApp(opts: BuildAppOptions = {}): Promise<FastifyInstance> {
  const databaseUrl = opts.databaseUrl ?? env.databaseUrl;
  if (opts.migrate !== false) await runMigrations(databaseUrl);

  const pool = createPool(databaseUrl);
  const compatibilityKeyDir = opts.masterKeyDir;
  const runtimeKeyDir = opts.runtimeKeyDir ?? compatibilityKeyDir ?? env.runtimeKeyDir;
  const auditKeyDir = opts.auditKeyDir ?? compatibilityKeyDir ?? env.auditKeyDir;
  const e2eeRequired = opts.e2eeRequired ?? env.e2eeRequired;
  const legacyContentKeyDir = e2eeRequired
    ? null
    : opts.legacyContentKeyDir !== undefined
      ? opts.legacyContentKeyDir
      : compatibilityKeyDir ?? legacyEnv.legacyContentKeyDir ?? legacyEnv.masterKeyDir;
  const dbName = new URL(databaseUrl).pathname.replace(/^\//, '') || 'default';
  const runtimeKeys = new FileMasterKeyProvider(runtimeKeyDir);
  const legacyContentKeys = legacyContentKeyDir ? new FileMasterKeyProvider(legacyContentKeyDir) : null;
  const db = createDb(pool);
  const bus = new SyncBus();
  const ctx: AppContext = {
    pool,
    db,
    runtimeKeys,
    legacyContentKeys,
    audit: {
      // 审计密钥只允许 keys:init 创建；缺失直接拒绝启动（不静默生成新钥）
      hmacKey: loadAuditKey(auditKeyDir),
      anchors: new AuditAnchorStore(auditKeyDir, dbName),
    },
    bus,
    auth: opts.authRuntime ?? createAuthRuntime(db, runtimeKeys, bus),
    webOrigins: env.webOrigins,
    extensionOrigins: env.extensionIds.map((id) => `chrome-extension://${id}`),
    e2eeRequired,
  };
  const app = Fastify({
    logger: opts.logger === false ? false : { level: env.logLevel },
    // 日志中绝不输出请求体/响应体，避免敏感内容明文泄漏
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: env.trustProxy,
  });
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
      // 无 Origin（同源/CLI）、白名单 Web Origin、白名单扩展 ID 允许；其余扩展默认拒绝
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
  registerBootstrapRoutes(app);
  registerEventRoutes(app);
  registerEncryptedEventRoutes(app);
  registerVaultRoutes(app);
  registerGroupRoutes(app);
  registerItemRoutes(app);
  registerExtensionRoutes(app);
  registerE2eeCryptoRoutes(app);
  registerE2eeAccountResetRoutes(app);
  registerE2eeLegacyKeyRetirementRoutes(app);
  registerE2eeVaultRoutes(app);
  registerE2eeRecoveryRoutes(app);
  registerE2eeRecoveryCaseRoutes(app);
  registerE2eeExtensionRoutes(app);
  registerE2eeEnvelopeTaskRoutes(app);
  registerMetaRoutes(app);

  app.get('/api/openapi.json', async () => buildOpenApiDocument(
    app.swagger(),
    env.publicBaseUrl,
    { pruneUndocumented: true },
  ));

  app.addHook('onClose', async () => {
    ctx.auth.directory.stop();
    await pool.end();
  });
  ctx.auth.directory.start();
  return app;
}
