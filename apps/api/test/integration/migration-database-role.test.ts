import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../../src/db/migrate.ts';
import { assertMigrationDatabaseRole } from '../../src/migration/database-role.ts';
import {
  migrationDatabaseRoleForJob,
  provisionMigrationDatabaseRole,
  revokeMigrationDatabaseRole,
} from '../../src/scripts/provision-migration-role.ts';
import { testDbUrl, testRoleDbUrl } from './helpers.ts';

const ADMIN_URL = testDbUrl('mima');
const JOB_A = '10000000-0000-4000-8000-000000000001';
const JOB_B = '10000000-0000-4000-8000-000000000002';
const VAULT_A = '20000000-0000-4000-8000-000000000001';
const VAULT_B = '20000000-0000-4000-8000-000000000002';
const suffix = randomBytes(5).toString('hex');
const databaseName = `mima_migration_role_${suffix}`;
const roleBase = `mima_migration_${suffix}`;
const role = migrationDatabaseRoleForJob(roleBase, JOB_A);
const roleB = migrationDatabaseRoleForJob(roleBase, JOB_B);
const password = randomBytes(32).toString('hex');
const workerUrl = testRoleDbUrl(databaseName, role, password);
let admin: pg.Pool;
let worker: pg.Pool;

describe.sequential('job-scoped migration worker PostgreSQL role', () => {
  beforeAll(async () => {
    const cluster = new pg.Client({ connectionString: ADMIN_URL });
    await cluster.connect();
    await cluster.query(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
    await cluster.end();
    await runMigrations(testDbUrl(databaseName));
    admin = new pg.Pool({ connectionString: testDbUrl(databaseName), max: 1 });
    await seedFrozenJobs(admin);
    await provisionMigrationDatabaseRole({
      databaseUrl: testDbUrl(databaseName),
      role: roleBase,
      password,
      jobId: JOB_A,
    });
    worker = new pg.Pool({ connectionString: workerUrl, max: 1 });
  });

  afterAll(async () => {
    await worker?.end().catch(() => undefined);
    await admin?.end();
    const cluster = new pg.Client({ connectionString: ADMIN_URL });
    await cluster.connect();
    await cluster.query(`ALTER ROLE ${quoteIdentifier(role)} NOSUPERUSER NOLOGIN`).catch(() => undefined);
    await cluster.query(`DROP DATABASE IF EXISTS ${quoteIdentifier(databaseName)} WITH (FORCE)`);
    await cluster.query(`DROP ROLE IF EXISTS ${quoteIdentifier(role)}`);
    await cluster.query(`DROP ROLE IF EXISTS ${quoteIdentifier(roleB)}`);
    await cluster.end();
  });

  it('exposes only the bound job through security-barrier views', async () => {
    await expect(assertMigrationDatabaseRole(worker, role, JOB_A)).resolves.toBeUndefined();
    const jobs = await worker.query<{ id: string }>('SELECT id FROM legacy_migration_jobs');
    expect(jobs.rows).toEqual([{ id: JOB_A }]);
    const vaults = await worker.query<{ id: string }>('SELECT id FROM vaults');
    expect(vaults.rows).toEqual([{ id: VAULT_A }]);
    const items = await worker.query<{ title: string }>('SELECT title FROM items');
    expect(items.rows).toEqual([{ title: 'Job A item' }]);
    await expect(worker.query('SELECT id FROM public.legacy_migration_jobs')).rejects.toMatchObject({
      code: '42501',
    });
  });

  it('cannot update or write another job', async () => {
    const update = await worker.query(`
      UPDATE legacy_migration_jobs
      SET state = 'encrypting', updated_at = now()
      WHERE id = $1
    `, [JOB_B]);
    expect(update.rowCount).toBe(0);
    await expect(worker.query(`
      INSERT INTO legacy_migration_exports (
        job_id, vault_id, recipient_user_id, recipient_key_version,
        recipient_key_digest, source_digest, sealed_export,
        sealed_export_digest, expires_at
      ) VALUES (
        $1, $2, 'migration-owner-b', 1,
        decode(repeat('22', 32), 'hex'), decode(repeat('bb', 32), 'hex'),
        decode(repeat('33', 49), 'hex'), decode(repeat('44', 32), 'hex'),
        now() + interval '1 hour'
      )
    `, [JOB_B, VAULT_B])).rejects.toMatchObject({
      code: 'P0001',
      message: 'migration export does not match the frozen job',
    });
  });

  it('rejects privilege drift outside the scoped views', async () => {
    await admin.query(`GRANT UPDATE ON public.items TO ${quoteIdentifier(role)}`);
    await expect(assertMigrationDatabaseRole(worker, role, JOB_A)).rejects.toMatchObject({
      message: 'database_role_not_restricted',
      reason: 'unexpected_privilege',
    });
    await admin.query(`REVOKE UPDATE ON public.items FROM ${quoteIdentifier(role)}`);
    await expect(assertMigrationDatabaseRole(worker, role, JOB_A)).resolves.toBeUndefined();
  });

  it('fails every scoped view closed when the bound job changes or expires', async () => {
    try {
      await admin.query(`
        UPDATE legacy_migration_jobs
        SET source_snapshot_hash = decode(repeat('cc', 32), 'hex')
        WHERE id = $1
      `, [JOB_A]);
      await expectScopedDataInvisible(worker);
      await admin.query(`
        UPDATE legacy_migration_jobs
        SET source_snapshot_hash = decode(repeat('aa', 32), 'hex')
        WHERE id = $1
      `, [JOB_A]);

      await admin.query(`
        UPDATE legacy_migration_jobs
        SET export_recipient_user_id = 'migration-owner-b'
        WHERE id = $1
      `, [JOB_A]);
      await expectScopedDataInvisible(worker);
      await admin.query(`
        UPDATE legacy_migration_jobs
        SET export_recipient_user_id = 'migration-owner-a'
        WHERE id = $1
      `, [JOB_A]);

      await admin.query(`
        UPDATE legacy_migration_jobs
        SET export_expires_at = created_at + interval '1 millisecond'
        WHERE id = $1
      `, [JOB_A]);
      await expectScopedDataInvisible(worker);
      await admin.query(`
        UPDATE legacy_migration_jobs
        SET export_expires_at = now() + interval '1 day'
        WHERE id = $1
      `, [JOB_A]);

      await admin.query(`UPDATE legacy_migration_jobs SET state = 'failed' WHERE id = $1`, [JOB_A]);
      await expectScopedDataInvisible(worker);
    } finally {
      await restoreFrozenJobA(admin);
    }
    expect((await worker.query('SELECT id FROM vaults')).rows).toEqual([{ id: VAULT_A }]);
  });

  it('caps authorization at export expiry and kills stale sessions before reauthorization', async () => {
    const firstPassword = randomBytes(32).toString('hex');
    const secondPassword = randomBytes(32).toString('hex');
    const exportExpiry = new Date(Date.now() + 5 * 60_000);
    const firstUrl = testRoleDbUrl(databaseName, roleB, firstPassword);
    const secondUrl = testRoleDbUrl(databaseName, roleB, secondPassword);
    let stale: pg.Client | null = null;
    let current: pg.Client | null = null;
    try {
      await admin.query(`UPDATE legacy_migration_jobs SET export_expires_at = $2 WHERE id = $1`, [
        JOB_B,
        exportExpiry,
      ]);
      const first = await provisionMigrationDatabaseRole({
        databaseUrl: testDbUrl(databaseName),
        role: roleBase,
        password: firstPassword,
        jobId: JOB_B,
        ttlMs: 6 * 60 * 60 * 1000,
      });
      expect(new Date(first.expiresAt).getTime()).toBeLessThanOrEqual(exportExpiry.getTime());
      const validUntil = await admin.query<{ rolvaliduntil: Date }>(`
        SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1
      `, [roleB]);
      expect(validUntil.rows[0]!.rolvaliduntil.getTime()).toBe(new Date(first.expiresAt).getTime());

      stale = new pg.Client({ connectionString: firstUrl });
      stale.on('error', () => undefined);
      await stale.connect();
      expect((await stale.query('SELECT id FROM vaults')).rows).toEqual([{ id: VAULT_B }]);
      await admin.query(`
        UPDATE mima_migration.job_bindings
        SET created_at = now() - interval '2 hours',
            expires_at = now() - interval '1 hour'
        WHERE job_id = $1
      `, [JOB_B]);

      await provisionMigrationDatabaseRole({
        databaseUrl: testDbUrl(databaseName),
        role: roleBase,
        password: secondPassword,
        jobId: JOB_B,
      });
      await expect(stale.query('SELECT 1')).rejects.toBeDefined();
      const oldReconnect = new pg.Client({ connectionString: firstUrl });
      expect(await oldReconnect.connect().then(() => true, () => false)).toBe(false);
      await oldReconnect.end().catch(() => undefined);

      current = new pg.Client({ connectionString: secondUrl });
      await current.connect();
      expect((await current.query('SELECT id FROM vaults')).rows).toEqual([{ id: VAULT_B }]);
    } finally {
      await stale?.end().catch(() => undefined);
      await current?.end().catch(() => undefined);
      await revokeMigrationDatabaseRole({
        databaseUrl: testDbUrl(databaseName),
        role: roleBase,
        jobId: JOB_B,
      }).catch(() => undefined);
    }
  });

  it('stays revoked and NOLOGIN when role cleanup cannot drop the role', async () => {
    const administrator = (await admin.query<{ current_user: string }>('SELECT current_user')).rows[0]!.current_user;
    worker.once('error', () => undefined);
    await admin.query(`ALTER DATABASE ${quoteIdentifier(databaseName)} OWNER TO ${quoteIdentifier(role)}`);
    try {
      await expect(revokeMigrationDatabaseRole({
        databaseUrl: testDbUrl(databaseName),
        role: roleBase,
        jobId: JOB_A,
      })).rejects.toBeDefined();
      const failClosed = await admin.query<{ state: string; revoked: boolean; can_login: boolean }>(`
        SELECT binding.state,
               binding.revoked_at IS NOT NULL AS revoked,
               database_role.rolcanlogin AS can_login
        FROM mima_migration.job_bindings binding
        JOIN pg_roles database_role ON database_role.rolname = binding.role_name
        WHERE binding.job_id = $1
      `, [JOB_A]);
      expect(failClosed.rows[0]).toEqual({ state: 'revoked', revoked: true, can_login: false });
    } finally {
      await admin.query(
        `ALTER DATABASE ${quoteIdentifier(databaseName)} OWNER TO ${quoteIdentifier(administrator)}`,
      );
    }

    await worker.end().catch(() => undefined);
    await revokeMigrationDatabaseRole({
      databaseUrl: testDbUrl(databaseName),
      role: roleBase,
      jobId: JOB_A,
    });
    await provisionMigrationDatabaseRole({
      databaseUrl: testDbUrl(databaseName),
      role: roleBase,
      password,
      jobId: JOB_A,
    });
    worker = new pg.Pool({ connectionString: workerUrl, max: 1 });
    await expect(assertMigrationDatabaseRole(worker, role, JOB_A)).resolves.toBeUndefined();
  });

  it('terminates the active session and makes old credentials unusable after revocation', async () => {
    const terminated = new Promise<string>((resolve) => {
      worker.once('error', (error: Error & { code?: string }) => resolve(error.code ?? 'unknown'));
    });
    await revokeMigrationDatabaseRole({
      databaseUrl: testDbUrl(databaseName),
      role: roleBase,
      jobId: JOB_A,
    });
    expect(await terminated).toBe('57P01');
    await worker.end();
    const reconnect = new pg.Client({ connectionString: workerUrl });
    const reconnected = await reconnect.connect().then(() => true, () => false);
    expect(reconnected).toBe(false);
    await reconnect.end().catch(() => undefined);
    const binding = await admin.query<{ state: string; revoked: boolean }>(`
      SELECT state, revoked_at IS NOT NULL AS revoked
      FROM mima_migration.job_bindings
      WHERE job_id = $1
    `, [JOB_A]);
    expect(binding.rows[0]).toEqual({ state: 'revoked', revoked: true });
  });
});

async function expectScopedDataInvisible(database: pg.Pool): Promise<void> {
  expect((await database.query('SELECT id FROM legacy_migration_jobs')).rows).toEqual([]);
  expect((await database.query('SELECT id FROM vaults')).rows).toEqual([]);
  expect((await database.query('SELECT id FROM items')).rows).toEqual([]);
  expect((await database.query('SELECT user_id FROM user_crypto_profiles')).rows).toEqual([]);
}

async function restoreFrozenJobA(database: pg.Pool): Promise<void> {
  await database.query(`
    UPDATE legacy_migration_jobs
    SET source_snapshot_hash = decode(repeat('aa', 32), 'hex'),
        export_recipient_user_id = 'migration-owner-a',
        export_expires_at = now() + interval '1 day'
    WHERE id = $1
  `, [JOB_A]);
  const state = (await database.query<{ state: string }>(
    'SELECT state FROM legacy_migration_jobs WHERE id = $1',
    [JOB_A],
  )).rows[0]?.state;
  if (state === 'failed') {
    await database.query(`UPDATE legacy_migration_jobs SET state = 'legacy' WHERE id = $1`, [JOB_A]);
  }
  if (state === 'failed' || state === 'legacy') {
    await database.query(`UPDATE legacy_migration_jobs SET state = 'preparing' WHERE id = $1`, [JOB_A]);
  }
  if (state === 'failed' || state === 'legacy' || state === 'preparing') {
    await database.query(`UPDATE legacy_migration_jobs SET state = 'frozen' WHERE id = $1`, [JOB_A]);
  }
}

async function seedFrozenJobs(database: pg.Pool): Promise<void> {
  await database.query(`
    INSERT INTO users (id, username, display_name, email) VALUES
      ('migration-owner-a', 'migration-owner-a', 'Migration Owner A', 'owner-a@example.test'),
      ('migration-owner-b', 'migration-owner-b', 'Migration Owner B', 'owner-b@example.test');

    INSERT INTO vaults (id, kind, name, owner_user_id) VALUES
      ('${VAULT_A}', 'personal', 'Job A vault', 'migration-owner-a'),
      ('${VAULT_B}', 'personal', 'Job B vault', 'migration-owner-b');

    INSERT INTO vault_memberships (vault_id, subject_kind, subject_id, role) VALUES
      ('${VAULT_A}', 'user', 'migration-owner-a', 'owner'),
      ('${VAULT_B}', 'user', 'migration-owner-b', 'owner');

    INSERT INTO user_crypto_profiles (
      user_id, kdf_salt, wrapped_account_key_ciphertext, wrapped_account_key_nonce,
      encrypted_private_key_bundle, private_key_bundle_nonce,
      public_encryption_key, public_signing_key, signing_key_fingerprint
    ) VALUES
      (
        'migration-owner-a', decode(repeat('01', 16), 'hex'), decode(repeat('02', 48), 'hex'),
        decode(repeat('03', 24), 'hex'), decode(repeat('04', 17), 'hex'), decode(repeat('05', 24), 'hex'),
        decode(repeat('11', 32), 'hex'), decode(repeat('12', 32), 'hex'), 'migration-owner-a-key'
      ),
      (
        'migration-owner-b', decode(repeat('06', 16), 'hex'), decode(repeat('07', 48), 'hex'),
        decode(repeat('08', 24), 'hex'), decode(repeat('09', 17), 'hex'), decode(repeat('0a', 24), 'hex'),
        decode(repeat('21', 32), 'hex'), decode(repeat('22', 32), 'hex'), 'migration-owner-b-key'
      );

    INSERT INTO vault_key_epochs (
      vault_id, epoch, status, reason, metadata_key_commitment,
      content_key_commitment, recipient_set_digest
    ) VALUES
      ('${VAULT_A}', 1, 'preparing', 'migration', decode(repeat('31', 32), 'hex'), decode(repeat('32', 32), 'hex'), decode(repeat('33', 32), 'hex')),
      ('${VAULT_B}', 1, 'preparing', 'migration', decode(repeat('41', 32), 'hex'), decode(repeat('42', 32), 'hex'), decode(repeat('43', 32), 'hex'));

    INSERT INTO legacy_migration_jobs (
      id, vault_id, state, target_epoch, source_snapshot_hash,
      export_recipient_user_id, export_recipient_key_version,
      export_recipient_key_digest, export_expires_at, frozen_at
    ) VALUES
      (
        '${JOB_A}', '${VAULT_A}', 'frozen', 1, decode(repeat('aa', 32), 'hex'),
        'migration-owner-a', 1, decode(repeat('11', 32), 'hex'), now() + interval '1 day', now()
      ),
      (
        '${JOB_B}', '${VAULT_B}', 'frozen', 1, decode(repeat('bb', 32), 'hex'),
        'migration-owner-b', 1, decode(repeat('22', 32), 'hex'), now() + interval '1 day', now()
      );

    INSERT INTO items (vault_id, kind, title, version, secret_version, updated_by) VALUES
      ('${VAULT_A}', 'secure_note', 'Job A item', 1, 1, 'migration-owner-a'),
      ('${VAULT_B}', 'secure_note', 'Job B item', 1, 1, 'migration-owner-b');

    UPDATE vault_crypto_states
    SET write_state = 'frozen'
    WHERE vault_id IN ('${VAULT_A}', '${VAULT_B}');
  `);
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}
