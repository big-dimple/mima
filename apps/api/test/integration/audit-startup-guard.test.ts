import { randomBytes } from 'node:crypto';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import pg from 'pg';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildStrictApp } from '../../src/strict-app.ts';
import { auditStandalone, repairAuditAnchor } from '../../src/services/audit.ts';
import { testDbUrl } from './helpers.ts';

const databaseName = 'mima_test_audit_startup_guard';
const databaseUrl = testDbUrl(databaseName);
const adminUrl = testDbUrl('mima');
const anchorFileName = `audit-anchor-${databaseName}.json`;

interface KeyMaterial {
  root: string;
  runtime: string;
  audit: string;
}

let app: FastifyInstance | null = null;
let keyRoots: string[] = [];

beforeEach(async () => {
  await resetDatabase();
  await createDatabase();
});

afterEach(async () => {
  await app?.close();
  app = null;
  await resetDatabase();
  for (const root of keyRoots) rmSync(root, { recursive: true, force: true });
  keyRoots = [];
});

describe('strict API audit startup guard', () => {
  it('allows a new empty database without an anchor', async () => {
    const keys = createKeyMaterial();
    app = await startStrictApp(keys);

    const readiness = await app.inject({ method: 'GET', url: '/api/readyz' });
    expect(readiness.statusCode).toBe(200);
    expect(readiness.json()).toMatchObject({ ok: true, database: true, e2eeRequired: true });
  });

  it('starts with the original key and current anchor after a valid audit write', async () => {
    const keys = createKeyMaterial();
    app = await startStrictApp(keys);
    await appendTestAudit(app, 'audit.guard.correct-key');
    await app.close();
    app = null;

    app = await startStrictApp(keys);
    expect((await app.inject({ method: 'GET', url: '/api/readyz' })).statusCode).toBe(200);
  });

  it('rejects a different HMAC key before any request can append another event', async () => {
    const original = createKeyMaterial();
    app = await startStrictApp(original);
    await appendTestAudit(app, 'audit.guard.original-key');
    await app.close();
    app = null;
    const beforeCount = await auditEventCount();

    const wrong = createKeyMaterial();
    copyFileSync(join(original.audit, anchorFileName), join(wrong.audit, anchorFileName));

    await expect(startStrictApp(wrong)).rejects.toMatchObject({
      name: 'AuditChainVerificationError',
      code: 'hmac-mismatch',
    });
    expect(await auditEventCount()).toBe(beforeCount);
  });

  it('rejects an anchor whose hash does not match the database chain', async () => {
    const keys = createKeyMaterial();
    app = await startStrictApp(keys);
    await appendTestAudit(app, 'audit.guard.anchor-hash');
    await app.close();
    app = null;

    const anchorPath = join(keys.audit, anchorFileName);
    const anchor = JSON.parse(readFileSync(anchorPath, 'utf8')) as { id: number; ts: string };
    writeFileSync(anchorPath, JSON.stringify({ ...anchor, hash: '0'.repeat(64) }), { mode: 0o600 });

    await expect(startStrictApp(keys)).rejects.toMatchObject({
      name: 'AuditChainVerificationError',
      code: 'anchor-hash-mismatch',
    });
  });

  it('rejects a valid but lagging anchor instead of advancing it automatically', async () => {
    const keys = createKeyMaterial();
    app = await startStrictApp(keys);
    await appendTestAudit(app, 'audit.guard.first');
    const firstAnchor = readFileSync(join(keys.audit, anchorFileName), 'utf8');
    await appendTestAudit(app, 'audit.guard.second');
    await app.close();
    app = null;
    writeFileSync(join(keys.audit, anchorFileName), firstAnchor, { mode: 0o600 });

    await expect(startStrictApp(keys)).rejects.toMatchObject({
      name: 'AuditChainVerificationError',
      code: 'anchor-behind',
    });
  });

  it('advances a verified lagging anchor only through the explicit repair operation', async () => {
    const keys = createKeyMaterial();
    app = await startStrictApp(keys);
    await appendTestAudit(app, 'audit.guard.repair-first');
    const firstAnchor = readFileSync(join(keys.audit, anchorFileName), 'utf8');
    await appendTestAudit(app, 'audit.guard.repair-second');
    await app.close();
    app = null;
    writeFileSync(join(keys.audit, anchorFileName), firstAnchor, { mode: 0o600 });

    const repairApp = await buildStrictApp({
      databaseUrl,
      runtimeKeyDir: keys.runtime,
      auditKeyDir: keys.audit,
      logger: false,
      verifyAuditChainOnStartup: false,
    });
    const repaired = await repairAuditAnchor(repairApp.ctx.db, repairApp.ctx.audit);
    expect(repaired).toMatchObject({ status: 'advanced', recordCount: 2, anchorId: 1, headId: 2 });
    await repairApp.close();

    app = await startStrictApp(keys);
    expect((await app.inject({ method: 'GET', url: '/api/readyz' })).statusCode).toBe(200);
  });

  it('rejects a non-empty chain when its external anchor is missing', async () => {
    const keys = createKeyMaterial();
    app = await startStrictApp(keys);
    await appendTestAudit(app, 'audit.guard.missing-anchor');
    await app.close();
    app = null;
    rmSync(join(keys.audit, anchorFileName));

    await expect(startStrictApp(keys)).rejects.toMatchObject({
      name: 'AuditChainVerificationError',
      code: 'anchor-missing',
    });
  });
});

function createKeyMaterial(): KeyMaterial {
  const root = mkdtempSync(join(tmpdir(), 'mima-audit-startup-'));
  keyRoots.push(root);
  const runtime = join(root, 'runtime');
  const audit = join(root, 'audit');
  mkdirSync(runtime);
  mkdirSync(audit);
  writeFileSync(join(runtime, 'kek-v1.key'), `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
  writeFileSync(join(audit, 'audit-hmac.key'), `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
  return { root, runtime, audit };
}

function startStrictApp(keys: KeyMaterial): Promise<FastifyInstance> {
  return buildStrictApp({
    databaseUrl,
    runtimeKeyDir: keys.runtime,
    auditKeyDir: keys.audit,
    logger: false,
  });
}

async function appendTestAudit(target: FastifyInstance, action: string): Promise<void> {
  await auditStandalone(target.ctx.db, target.ctx.audit, {
    actorUserId: null,
    action,
    success: true,
    details: {},
  });
}

async function auditEventCount(): Promise<number> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const result = await client.query<{ count: number }>('SELECT count(*)::int AS count FROM audit_events');
    return result.rows[0]!.count;
  } finally {
    await client.end();
  }
}

async function createDatabase(): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${databaseName}`);
  } finally {
    await admin.end();
  }
}

async function resetDatabase(): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}
