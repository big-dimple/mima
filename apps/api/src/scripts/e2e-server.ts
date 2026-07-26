// E2E 专用 API 启动：强制校验数据库名为 mima_test_e2e，整库重建后只加载严格密文夹具。
// 绝不允许指向开发库/生产库（数据库名不符直接拒绝启动）。
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { eq } from 'drizzle-orm';
import {
  FileMasterKeyProvider,
  encryptSecret,
  resetAuditAnchor,
} from '@mima/crypto';
import { createEnterpriseRecoveryKit } from '@mima/e2ee';

const E2E_DB_NAME = 'mima_test_e2e';
const fixtureRoot = join(tmpdir(), 'mima-e2e-strict');
const runtimeKeyDir = join(fixtureRoot, 'runtime-keys');
const auditKeyDir = join(fixtureRoot, 'audit-keys');
const legacyContentKeyDir = join(fixtureRoot, 'legacy-content-keys');
const migrationDatabaseUrlFile = join(fixtureRoot, 'migration-database-url');

rmSync(fixtureRoot, { recursive: true, force: true });
for (const directory of [runtimeKeyDir, auditKeyDir, legacyContentKeyDir]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
}
writeFileSync(join(runtimeKeyDir, 'kek-v1.key'), `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
writeFileSync(join(auditKeyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
writeFileSync(join(legacyContentKeyDir, 'kek-v1.key'), `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });

process.env.MIMA_RUNTIME_KEY_DIR = runtimeKeyDir;
process.env.MIMA_AUDIT_KEY_DIR = auditKeyDir;
process.env.MIMA_E2EE_REQUIRED = 'true';
process.env.MIMA_REAUTH_PROVIDER = 'none';
delete process.env.MIMA_MASTER_KEY_DIR;
delete process.env.MIMA_LEGACY_CONTENT_KEY_DIR;

const [
  { buildStrictApp },
  { createDb, createPool },
  { runMigrations },
  schema,
  { DEV_USERS },
  { env },
] = await Promise.all([
  import('../strict-app.ts'),
  import('../db/client.ts'),
  import('../db/migrate.ts'),
  import('../db/schema.ts'),
  import('../auth/provider.ts'),
  import('../env.ts'),
]);

const url = new URL(env.databaseUrl);
const dbName = url.pathname.replace(/^\//, '');
if (dbName !== E2E_DB_NAME) {
  console.error(`[e2e-server] 拒绝启动：数据库必须是 ${E2E_DB_NAME}，当前为 ${dbName}`);
  process.exit(1);
}

// reset：整库重建，保证每轮 E2E 从相同身份、恢复公钥和隔离旧数据样本出发
const adminUrl = new URL(env.databaseUrl);
adminUrl.pathname = '/mima';
const admin = new pg.Client({ connectionString: adminUrl.toString() });
console.log('[e2e-server] resetting isolated database');
await admin.connect();
try {
  await admin.query(`DROP DATABASE IF EXISTS ${E2E_DB_NAME} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${E2E_DB_NAME}`);
} finally {
  await admin.end();
}
// 数据库整库重建 → 审计链从头开始，旧锚点必然高于新链头，必须一并清理
resetAuditAnchor(env.auditKeyDir, E2E_DB_NAME);
console.log('[e2e-server] applying migrations');
await runMigrations(env.databaseUrl);
writeFileSync(migrationDatabaseUrlFile, `${env.databaseUrl}\n`, { mode: 0o600 });

const fixturePool = createPool(env.databaseUrl);
const fixtureDb = createDb(fixturePool);
console.log('[e2e-server] loading strict fixtures');
try {
  await fixtureDb.insert(schema.users).values(DEV_USERS.map((user) => ({
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    groups: user.groups,
    source: user.source,
    active: user.active,
  })));
  await fixtureDb.insert(schema.systemRoleAssignments).values([
    { userId: 'u-alice', role: 'platform-admin', assignedBy: 'e2e-fixture' },
    { userId: 'u-dave', role: 'platform-admin', assignedBy: 'e2e-fixture' },
  ]);

  const recoveryKit = await createEnterpriseRecoveryKit('e2e-strict-recovery');
  const recoveryKey = (await fixtureDb.insert(schema.enterpriseRecoveryKeys).values({
    ceremonyId: recoveryKit.ceremonyId,
    keyFingerprint: recoveryKit.publicKeyFingerprint,
    publicEncryptionKey: Buffer.from(recoveryKit.publicKey, 'base64url'),
    threshold: recoveryKit.threshold,
    shareCount: recoveryKit.shareCount,
    ceremonyEvidenceDigest: Buffer.from(recoveryKit.ceremonyDigest, 'base64url'),
    createdByUserId: 'u-alice',
  }).returning())[0]!;
  await fixtureDb.insert(schema.enterpriseRecoveryKeyApprovals).values([
    {
      recoveryKeyId: recoveryKey.id,
      approverUserId: 'u-alice',
      ceremonyEvidenceDigest: Buffer.from(recoveryKit.ceremonyDigest, 'base64url'),
    },
    {
      recoveryKeyId: recoveryKey.id,
      approverUserId: 'u-dave',
      ceremonyEvidenceDigest: Buffer.from(recoveryKit.ceremonyDigest, 'base64url'),
    },
  ]);
  await fixtureDb.update(schema.enterpriseRecoveryKeys)
    .set({ status: 'active' })
    .where(eq(schema.enterpriseRecoveryKeys.id, recoveryKey.id));

  const legacyVault = (await fixtureDb.insert(schema.vaults).values({
    kind: 'team',
    name: 'E2E 旧格式密码库',
    ownerUserId: null,
  }).returning())[0]!;
  await fixtureDb.insert(schema.vaultMemberships).values({
    vaultId: legacyVault.id,
    subjectKind: 'user',
    subjectId: 'u-erin',
    role: 'owner',
  });
  const itemId = randomUUID();
  const legacyKeys = new FileMasterKeyProvider(legacyContentKeyDir);
  const encrypted = encryptSecret(legacyKeys, {
    vaultId: legacyVault.id,
    itemId,
    secretVersion: 1,
    itemKind: 'login',
  }, 'e2e-legacy-secret-canary-001');
  await fixtureDb.insert(schema.items).values({
    id: itemId,
    vaultId: legacyVault.id,
    kind: 'login',
    title: 'E2E 旧数据迁移样本',
    username: 'legacy-e2e-user',
    origin: 'https://legacy-e2e.example.test',
    tags: ['e2e', 'migration'],
    favorite: false,
    sensitivity: 'high',
    updatedBy: 'e2e-fixture',
  });
  await fixtureDb.insert(schema.itemSecretVersions).values({
    itemId,
    vaultId: legacyVault.id,
    itemKind: 'login',
    secretVersion: 1,
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    wrappedDek: encrypted.wrappedDek,
    keyVersion: encrypted.keyVersion,
    createdBy: 'e2e-fixture',
  });
} finally {
  await fixturePool.end();
}

console.log('[e2e-server] building strict application');
const app = await buildStrictApp({
  runtimeKeyDir,
  auditKeyDir,
});
let closing = false;
const shutdown = async () => {
  if (closing) return;
  closing = true;
  await app.close().catch(() => undefined);
  rmSync(fixtureRoot, { recursive: true, force: true });
};
process.once('SIGINT', () => void shutdown().finally(() => process.exit(0)));
process.once('SIGTERM', () => void shutdown().finally(() => process.exit(0)));
try {
  await app.listen({ port: env.port, host: env.host });
  console.log(`[e2e-server] mima E2E API listening on http://${env.host}:${env.port} (db=${E2E_DB_NAME})`);
} catch (err) {
  app.log.error(err);
  await shutdown();
  process.exit(1);
}
