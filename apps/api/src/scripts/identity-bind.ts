import { and, eq } from 'drizzle-orm';
import { AuditAnchorStore, loadAuditKey } from '@mima/crypto';
import { createDb, createPool } from '../db/client.ts';
import { runMigrations } from '../db/migrate.ts';
import { userIdentities, users } from '../db/schema.ts';
import { env } from '../env.ts';
import { auditStandalone } from '../services/audit.ts';

interface Arguments {
  apply: boolean;
  provider: 'feishu';
  tenantKey: string;
  subject: string;
  username: string;
}

function parseArguments(argv: string[]): Arguments {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === '--apply') continue;
    if (!argument.startsWith('--') || !argv[index + 1] || argv[index + 1]!.startsWith('--')) {
      throw new Error(`invalid argument: ${argument}`);
    }
    values.set(argument.slice(2), argv[index + 1]!);
    index += 1;
  }
  const provider = values.get('provider');
  const tenantKey = values.get('tenant-key');
  const subject = values.get('user-id');
  const username = values.get('username');
  if (provider !== 'feishu' || !tenantKey || !subject || !username) {
    throw new Error(
      'usage: identity-bind --provider feishu --tenant-key <tenant_key> --user-id <user_id> --username <domain_account> [--apply]',
    );
  }
  return { apply: argv.includes('--apply'), provider, tenantKey, subject, username };
}

const args = parseArguments(process.argv.slice(2));
await runMigrations();
const pool = createPool();
const db = createDb(pool);

try {
  const user = (
    await db.select().from(users).where(eq(users.username, args.username)).limit(1)
  )[0];
  if (!user || !user.active) throw new Error(`active domain account not found: ${args.username}`);

  const existingSubject = (
    await db
      .select()
      .from(userIdentities)
      .where(and(
        eq(userIdentities.provider, args.provider),
        eq(userIdentities.issuer, args.tenantKey),
        eq(userIdentities.subject, args.subject),
      ))
      .limit(1)
  )[0];
  if (existingSubject && existingSubject.userId !== user.id) {
    throw new Error('the exact Feishu identity is already bound to another domain account');
  }

  const existingUser = (
    await db
      .select()
      .from(userIdentities)
      .where(and(eq(userIdentities.provider, args.provider), eq(userIdentities.userId, user.id)))
      .limit(1)
  )[0];
  if (existingUser && (
    existingUser.issuer !== args.tenantKey || existingUser.subject !== args.subject
  )) {
    throw new Error('the domain account already has a different Feishu identity binding');
  }

  const report = {
    mode: args.apply ? 'apply' : 'dry-run',
    provider: args.provider,
    tenantKey: args.tenantKey,
    feishuUserId: args.subject,
    domainUsername: user.username,
    internalUserId: user.id,
    result: existingSubject ? 'already-bound' : 'ready-to-bind',
  };
  console.log(JSON.stringify(report, null, 2));
  if (!args.apply || existingSubject) process.exitCode = 0;
  else {
    await db.insert(userIdentities).values({
      provider: args.provider,
      issuer: args.tenantKey,
      subject: args.subject,
      userId: user.id,
    });
    const dbName = new URL(env.databaseUrl).pathname.replace(/^\//, '') || 'default';
    await auditStandalone(db, {
      hmacKey: loadAuditKey(env.auditKeyDir),
      anchors: new AuditAnchorStore(env.auditKeyDir, dbName),
    }, {
      actorUserId: null,
      action: 'identity.bind',
      success: true,
      details: { provider: args.provider, targetUserId: user.id },
    });
    console.log('identity binding applied');
  }
} finally {
  await pool.end();
}
