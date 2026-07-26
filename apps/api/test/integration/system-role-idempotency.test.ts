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
});

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
