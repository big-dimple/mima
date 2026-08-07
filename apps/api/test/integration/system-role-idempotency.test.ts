import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../../src/db/migrate.ts';
import { testDbUrl } from './helpers.ts';

const root = resolve(import.meta.dirname, '../../../..');
const databaseName = 'mima_test_system_role_idempotency';
const databaseUrl = testDbUrl(databaseName);
const adminUrl = testDbUrl('mima');

describe('system-role CLI management', () => {
  afterAll(resetDatabase);

  it('lists assignments and keeps grant and revoke idempotent', async () => {
    await resetDatabase();
    await createDatabase();
    await runMigrations(databaseUrl);
    const keyDir = mkdtempSync(join(tmpdir(), 'mima-system-role-keys-'));
    writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    await client.query(`
      INSERT INTO users (id, username, display_name, email, source, active)
      VALUES ('system-role-user', 'system-role-user', 'System Role User', 'role@example.test', 'oidc', true)
    `);
    await client.end();
    const environment = {
      ...process.env,
      MIMA_AUDIT_KEY_DIR: keyDir,
      MIMA_DATABASE_URL: databaseUrl,
      MIMA_RUNTIME_KEY_DIR: keyDir,
    };
    try {
      const first = spawnSync('pnpm', [
        '--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/system-role.ts', 'grant', 'system-role-user',
      ], { cwd: root, encoding: 'utf8', env: environment });
      expect(first.status, `${first.stdout}\n${first.stderr}`).toBe(0);
      expect(first.stdout).toContain('granted platform-admin');

      const second = spawnSync('pnpm', [
        '--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/system-role.ts', 'grant', 'system-role-user',
      ], { cwd: root, encoding: 'utf8', env: environment });
      expect(second.status, `${second.stdout}\n${second.stderr}`).toBe(0);
      expect(second.stdout).toContain('unchanged platform-admin');

      const listed = spawnSync('pnpm', [
        '--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/system-role.ts', 'list',
      ], { cwd: root, encoding: 'utf8', env: environment });
      expect(listed.status, `${listed.stdout}\n${listed.stderr}`).toBe(0);
      expect(listed.stdout).toContain('USERNAME\tDISPLAY_NAME\tSOURCE\tSTATUS\tASSIGNED_AT');
      expect(listed.stdout).toContain('system-role-user\tSystem Role User\toidc\tactive\t');

      const revoked = spawnSync('pnpm', [
        '--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/system-role.ts', 'revoke', 'system-role-user',
      ], { cwd: root, encoding: 'utf8', env: environment });
      expect(revoked.status, `${revoked.stdout}\n${revoked.stderr}`).toBe(0);
      expect(revoked.stdout).toContain('revoked platform-admin');

      const revokedAgain = spawnSync('pnpm', [
        '--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/system-role.ts', 'revoke', 'system-role-user',
      ], { cwd: root, encoding: 'utf8', env: environment });
      expect(revokedAgain.status, `${revokedAgain.stdout}\n${revokedAgain.stderr}`).toBe(0);
      expect(revokedAgain.stdout).toContain('unchanged platform-admin');

      const verification = new pg.Client({ connectionString: databaseUrl });
      await verification.connect();
      const result = await verification.query<{
        assignments: number;
        grant_audit_events: number;
        revoke_audit_events: number;
      }>(`
        SELECT
          (SELECT count(*)::int FROM system_role_assignments
            WHERE user_id = 'system-role-user' AND role = 'platform-admin') AS assignments,
          (SELECT count(*)::int FROM audit_events
            WHERE action = 'system_role.grant' AND details->>'username' = 'system-role-user') AS grant_audit_events,
          (SELECT count(*)::int FROM audit_events
            WHERE action = 'system_role.revoke' AND details->>'username' = 'system-role-user') AS revoke_audit_events
      `);
      await verification.end();
      expect(result.rows[0]).toEqual({ assignments: 0, grant_audit_events: 1, revoke_audit_events: 1 });
    } finally {
      rmSync(keyDir, { recursive: true, force: true });
    }
  });

  it('allows two to six administrators and preserves two after recovery is active', async () => {
    await resetDatabase();
    await createDatabase();
    await runMigrations(databaseUrl);
    const keyDir = mkdtempSync(join(tmpdir(), 'mima-system-role-limits-'));
    writeFileSync(join(keyDir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    const usernames = Array.from({ length: 7 }, (_, index) => `recovery-admin-${index + 1}`);
    for (const [index, username] of usernames.entries()) {
      await client.query(`
        INSERT INTO users (id, username, display_name, email, source, active)
        VALUES ($1, $2, $3, $4, 'oidc', true)
      `, [`recovery-admin-id-${index + 1}`, username, `Recovery Admin ${index + 1}`, `${username}@example.test`]);
    }
    await client.end();
    const environment = {
      ...process.env,
      MIMA_AUDIT_KEY_DIR: keyDir,
      MIMA_DATABASE_URL: databaseUrl,
      MIMA_RUNTIME_KEY_DIR: keyDir,
    };
    try {
      for (const username of usernames.slice(0, 6)) {
        const granted = runSystemRole('grant', username, environment);
        expect(granted.status, `${granted.stdout}\n${granted.stderr}`).toBe(0);
      }
      const seventh = runSystemRole('grant', usernames[6]!, environment);
      expect(seventh.status).not.toBe(0);
      expect(`${seventh.stdout}\n${seventh.stderr}`).toContain('最多只能设置 6 位');

      const recoveryClient = new pg.Client({ connectionString: databaseUrl });
      await recoveryClient.connect();
      const ceremonyDigest = randomBytes(32);
      const recoveryKeyId = (await recoveryClient.query<{ id: string }>(`
        INSERT INTO enterprise_recovery_keys (
          ceremony_id, key_fingerprint, public_encryption_key, status,
          ceremony_evidence_digest, created_by_user_id
        ) VALUES ($1, $2, $3, 'pending', $4, $5)
        RETURNING id
      `, [
        'system-role-limit-ceremony',
        randomBytes(32).toString('base64url'),
        randomBytes(32),
        ceremonyDigest,
        'recovery-admin-id-1',
      ])).rows[0]!.id;
      await recoveryClient.query(`
        INSERT INTO enterprise_recovery_key_approvals (
          recovery_key_id, approver_user_id, ceremony_evidence_digest
        ) VALUES ($1, 'recovery-admin-id-1', $2), ($1, 'recovery-admin-id-2', $2)
      `, [recoveryKeyId, ceremonyDigest]);
      await recoveryClient.query(
        "UPDATE enterprise_recovery_keys SET status = 'active' WHERE id = $1",
        [recoveryKeyId],
      );
      await recoveryClient.end();

      for (const username of usernames.slice(2, 6).reverse()) {
        const revoked = runSystemRole('revoke', username, environment);
        expect(revoked.status, `${revoked.stdout}\n${revoked.stderr}`).toBe(0);
      }
      const belowMinimum = runSystemRole('revoke', usernames[1]!, environment);
      expect(belowMinimum.status).not.toBe(0);
      expect(`${belowMinimum.stdout}\n${belowMinimum.stderr}`).toContain('至少保留 2 位管理员');
    } finally {
      rmSync(keyDir, { recursive: true, force: true });
    }
  });
});

function runSystemRole(
  action: 'grant' | 'revoke',
  username: string,
  environment: NodeJS.ProcessEnv,
) {
  return spawnSync('pnpm', [
    '--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/system-role.ts', action, username,
  ], { cwd: root, encoding: 'utf8', env: environment });
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
