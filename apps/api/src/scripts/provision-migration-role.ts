import { lstatSync, readFileSync } from 'node:fs';
import pg from 'pg';
import { assertMigrationDatabaseRole, migrationDatabaseRoleContract } from '../migration/database-role.ts';

const ROLE_PATTERN = /^[a-z][a-z0-9_]{2,62}$/;
const JOB_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PASSWORD_PATTERN = /^[A-Za-z0-9._~-]{32,256}$/;
const DEFAULT_ROLE_TTL_MS = 2 * 60 * 60 * 1000;

export function migrationDatabaseRoleForJob(baseRole: string, jobId: string): string {
  if (!ROLE_PATTERN.test(baseRole) || !JOB_ID_PATTERN.test(jobId)) {
    throw new Error('migration_role_configuration_invalid');
  }
  return `${baseRole.slice(0, 30)}_${jobId.replaceAll('-', '').toLowerCase()}`;
}

export async function provisionMigrationDatabaseRole(options: {
  databaseUrl: string;
  role: string;
  password: string;
  jobId: string;
  ttlMs?: number;
}): Promise<{ database: string; role: string; jobId: string; expiresAt: string }> {
  if (
    !ROLE_PATTERN.test(options.role)
    || !PASSWORD_PATTERN.test(options.password)
    || !JOB_ID_PATTERN.test(options.jobId)
    || (options.ttlMs !== undefined && (
      !Number.isSafeInteger(options.ttlMs)
      || options.ttlMs < 60_000
      || options.ttlMs > 6 * 60 * 60 * 1000
    ))
  ) {
    throw new Error('migration_role_configuration_invalid');
  }
  const roleName = migrationDatabaseRoleForJob(options.role, options.jobId);
  let expiresAt = new Date(0);
  const admin = new pg.Pool({ connectionString: options.databaseUrl, max: 1 });
  const connection = await admin.connect();
  let databaseName = '';
  try {
    await connection.query('BEGIN');
    await connection.query("SELECT pg_advisory_xact_lock(hashtext('mima:migration-role:' || $1))", [options.jobId]);
    const context = await connection.query<{ current_user: string; current_database: string }>(
      'SELECT current_user, current_database() AS current_database',
    );
    const current = context.rows[0];
    if (!current || current.current_user === roleName) {
      throw new Error('migration_role_admin_connection_invalid');
    }
    databaseName = current.current_database;
    const jobResult = await connection.query<{
      id: string;
      vault_id: string;
      state: string;
      source_snapshot_hash: Buffer | null;
      export_recipient_user_id: string | null;
      export_recipient_key_version: number | null;
      export_recipient_key_digest: Buffer | null;
      export_expires_at: Date | null;
    }>(`
      SELECT
        id, vault_id, state, source_snapshot_hash,
        export_recipient_user_id, export_recipient_key_version,
        export_recipient_key_digest, export_expires_at
      FROM public.legacy_migration_jobs
      WHERE id = $1
      FOR UPDATE
    `, [options.jobId]);
    const job = jobResult.rows[0];
    if (
      !job
      || job.state !== 'frozen'
      || !job.source_snapshot_hash
      || !job.export_recipient_user_id
      || !job.export_recipient_key_version
      || !job.export_recipient_key_digest
      || !job.export_expires_at
      || job.export_expires_at.getTime() <= Date.now()
    ) {
      throw new Error('migration_job_not_authorizable');
    }
    expiresAt = new Date(Math.min(
      Date.now() + (options.ttlMs ?? DEFAULT_ROLE_TTL_MS),
      job.export_expires_at.getTime(),
    ));
    const existingBinding = await connection.query<{
      role_name: string;
      job_id: string;
      state: string;
      expires_at: Date;
    }>(`
      SELECT role_name, job_id, state, expires_at
      FROM mima_migration.job_bindings
      WHERE role_name = $1 OR job_id = $2
      FOR UPDATE
    `, [roleName, options.jobId]);
    if (existingBinding.rows.some((binding) => (
      binding.state === 'active' && binding.expires_at.getTime() > Date.now()
    ))) {
      throw new Error('migration_job_role_already_active');
    }

    const roleExists = await connection.query<{ exists: boolean }>(
      'SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1) AS exists',
      [roleName],
    );
    const matchingBinding = existingBinding.rows.find((binding) => (
      binding.role_name === roleName && binding.job_id === options.jobId
    ));
    if (roleExists.rows[0]?.exists && !matchingBinding) {
      throw new Error('migration_job_role_name_collision');
    }
    if (roleExists.rows[0]?.exists) {
      await connection.query(`ALTER ROLE ${quoteIdentifier(roleName)} NOLOGIN`);
      await connection.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE usename = $1 AND pid <> pg_backend_pid()
      `, [roleName]);
      await connection.query(`DROP OWNED BY ${quoteIdentifier(roleName)}`);
      await connection.query(`DROP ROLE ${quoteIdentifier(roleName)}`);
    }
    await connection.query(`CREATE ROLE ${quoteIdentifier(roleName)}`);
    await connection.query(`
      ALTER ROLE ${quoteIdentifier(roleName)} WITH
        LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
        NOINHERIT CONNECTION LIMIT 1 PASSWORD ${quoteLiteral(options.password)}
        VALID UNTIL ${quoteLiteral(expiresAt.toISOString())}
    `);
    await connection.query(
      `ALTER ROLE ${quoteIdentifier(roleName)} SET search_path = pg_catalog, mima_migration`,
    );

    const memberships = await connection.query<{ role: string }>(`
      SELECT parent.rolname AS role
      FROM pg_auth_members membership
      JOIN pg_roles parent ON parent.oid = membership.roleid
      JOIN pg_roles member ON member.oid = membership.member
      WHERE member.rolname = $1
      ORDER BY parent.rolname
    `, [roleName]);
    for (const membership of memberships.rows) {
      await connection.query(
        `REVOKE ${quoteIdentifier(membership.role)} FROM ${quoteIdentifier(roleName)}`,
      );
    }

    const database = quoteIdentifier(databaseName);
    const role = quoteIdentifier(roleName);
    await connection.query(`REVOKE CREATE, TEMPORARY ON DATABASE ${database} FROM PUBLIC`);
    await connection.query(`REVOKE ALL PRIVILEGES ON DATABASE ${database} FROM ${role}`);
    await connection.query(`GRANT CONNECT ON DATABASE ${database} TO ${role}`);

    const schemas = await connection.query<{ schema: string }>(`
      SELECT nspname AS schema
      FROM pg_namespace
      WHERE nspname <> 'information_schema' AND nspname !~ '^pg_'
      ORDER BY nspname
    `);
    for (const schemaRow of schemas.rows) {
      const schema = quoteIdentifier(schemaRow.schema);
      await connection.query(`REVOKE CREATE ON SCHEMA ${schema} FROM PUBLIC`);
      await connection.query(`REVOKE ALL PRIVILEGES ON SCHEMA ${schema} FROM ${role}`);
      await connection.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${schema} FROM PUBLIC`);
      await connection.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${schema} FROM ${role}`);
      await connection.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ${schema} FROM PUBLIC`);
      await connection.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ${schema} FROM ${role}`);
      await connection.query(`REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA ${schema} FROM PUBLIC`);
      await connection.query(`REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ${schema} FROM ${role}`);
    }
    await connection.query(`GRANT USAGE ON SCHEMA public, mima_migration TO ${role}`);
    for (const table of migrationDatabaseRoleContract.selectTables) {
      await connection.query(`GRANT SELECT ON TABLE ${quoteQualifiedName(table)} TO ${role}`);
    }
    const insertsByTable = new Map<string, string[]>();
    for (const value of migrationDatabaseRoleContract.insertColumns) {
      const parts = value.split('.');
      const table = parts.slice(0, 2).join('.');
      const column = parts[2];
      if (!column) throw new Error('migration_role_contract_invalid');
      insertsByTable.set(table, [...(insertsByTable.get(table) ?? []), column]);
    }
    for (const [table, columns] of insertsByTable) {
      await connection.query(
        `GRANT INSERT (${columns.map(quoteIdentifier).join(', ')}) ON TABLE ${quoteQualifiedName(table)} TO ${role}`,
      );
    }
    await connection.query(`
      GRANT UPDATE (state, updated_at)
      ON TABLE mima_migration.legacy_migration_jobs
      TO ${role}
    `);
    for (const identity of migrationDatabaseRoleContract.executeFunctions) {
      await connection.query(`GRANT EXECUTE ON FUNCTION ${quoteFunctionIdentity(identity)} TO ${role}`);
    }

    await connection.query(`
      INSERT INTO mima_migration.job_bindings (
        role_name, job_id, vault_id, recipient_user_id, source_digest,
        state, expires_at, revoked_at
      ) VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL)
      ON CONFLICT (role_name) DO UPDATE SET
        job_id = EXCLUDED.job_id,
        vault_id = EXCLUDED.vault_id,
        recipient_user_id = EXCLUDED.recipient_user_id,
        source_digest = EXCLUDED.source_digest,
        state = 'active',
        expires_at = EXCLUDED.expires_at,
        revoked_at = NULL
    `, [
      roleName,
      options.jobId,
      job.vault_id,
      job.export_recipient_user_id,
      job.source_snapshot_hash,
      expiresAt,
    ]);

    await connection.query('COMMIT');
  } catch (error) {
    await connection.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    connection.release();
    await admin.end();
  }

  const workerUrl = new URL(options.databaseUrl);
  workerUrl.username = roleName;
  workerUrl.password = options.password;
  const worker = new pg.Pool({ connectionString: workerUrl.toString(), max: 1 });
  let verificationError: unknown;
  try {
    await assertMigrationDatabaseRole(worker, roleName, options.jobId);
  } catch (error) {
    verificationError = error;
  } finally {
    await worker.end();
  }
  if (verificationError) {
    await revokeMigrationDatabaseRole({
      databaseUrl: options.databaseUrl,
      role: options.role,
      jobId: options.jobId,
    }).catch(() => undefined);
    throw verificationError;
  }
  return { database: databaseName, role: roleName, jobId: options.jobId, expiresAt: expiresAt.toISOString() };
}

export async function revokeMigrationDatabaseRole(options: {
  databaseUrl: string;
  role: string;
  jobId: string;
}): Promise<{ role: string; jobId: string; revoked: true }> {
  const roleName = migrationDatabaseRoleForJob(options.role, options.jobId);
  const admin = new pg.Pool({ connectionString: options.databaseUrl, max: 1 });
  const connection = await admin.connect();
  let advisoryLockHeld = false;
  let transactionOpen = false;
  try {
    await connection.query("SELECT pg_advisory_lock(hashtext('mima:migration-role:' || $1))", [options.jobId]);
    advisoryLockHeld = true;
    await connection.query('BEGIN');
    transactionOpen = true;
    await connection.query(`
      UPDATE mima_migration.job_bindings
      SET state = 'revoked', revoked_at = now()
      WHERE role_name = $1 AND job_id = $2 AND state = 'active'
    `, [roleName, options.jobId]);
    const roleExists = await connection.query<{ exists: boolean }>(
      'SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1) AS exists',
      [roleName],
    );
    if (roleExists.rows[0]?.exists) {
      await connection.query(`ALTER ROLE ${quoteIdentifier(roleName)} NOLOGIN`);
    }
    await connection.query('COMMIT');
    transactionOpen = false;

    if (roleExists.rows[0]?.exists) {
      await connection.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE usename = $1 AND pid <> pg_backend_pid()
      `, [roleName]);
      await connection.query('BEGIN');
      transactionOpen = true;
      await connection.query(`DROP OWNED BY ${quoteIdentifier(roleName)}`);
      await connection.query(`DROP ROLE ${quoteIdentifier(roleName)}`);
      await connection.query('COMMIT');
      transactionOpen = false;
    }
  } catch (error) {
    if (transactionOpen) await connection.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    if (advisoryLockHeld) {
      await connection.query(
        "SELECT pg_advisory_unlock(hashtext('mima:migration-role:' || $1))",
        [options.jobId],
      ).catch(() => undefined);
    }
    connection.release();
    await admin.end();
  }
  return { role: roleName, jobId: options.jobId, revoked: true };
}

export async function checkMigrationDatabaseRoleSchema(databaseUrl: string): Promise<{ ready: true }> {
  const admin = new pg.Pool({ connectionString: databaseUrl, max: 1 });
  try {
    const result = await admin.query<{ views: string; functions: string }>(`
      SELECT
        count(*) FILTER (WHERE relation.relkind = 'v')::text AS views,
        (
          SELECT count(*)::text
          FROM pg_proc routine
          JOIN pg_namespace routine_namespace ON routine_namespace.oid = routine.pronamespace
          WHERE routine_namespace.nspname = 'mima_migration'
        ) AS functions
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'mima_migration'
    `);
    if (result.rows[0]?.views !== '9' || result.rows[0]?.functions !== '3') {
      throw new Error('migration_role_schema_invalid');
    }
    return { ready: true };
  } finally {
    await admin.end();
  }
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function quoteLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function quoteQualifiedName(value: string): string {
  const parts = value.split('.');
  if (parts.length !== 2) throw new Error('migration_role_contract_invalid');
  return parts.map(quoteIdentifier).join('.');
}

function quoteFunctionIdentity(value: string): string {
  const match = /^([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)\(\)$/.exec(value);
  if (!match) throw new Error('migration_role_contract_invalid');
  return `${quoteIdentifier(match[1]!)}.${quoteIdentifier(match[2]!)}()`;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error('migration_role_configuration_invalid');
  return value;
}

function readPrivateValue(path: string): string {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error('migration_role_secret_file_not_private');
  }
  const value = readFileSync(path, 'utf8').trim();
  if (!value) throw new Error('migration_role_secret_file_empty');
  return value;
}

function parseJobId(args: string[]): string {
  const index = args.indexOf('--job');
  const jobId = index >= 0 ? args[index + 1] : undefined;
  if (!jobId || !JOB_ID_PATTERN.test(jobId)) throw new Error('migration_job_id_invalid');
  return jobId;
}

if (process.argv[1] && /provision-migration-role\.(?:ts|js)$/.test(process.argv[1])) {
  const args = process.argv.slice(2);
  const databaseUrl = readPrivateValue(requiredEnvironment('MIMA_DATABASE_URL_FILE'));
  const role = requiredEnvironment('MIMA_MIGRATION_DATABASE_ROLE');
  let operation: Promise<unknown>;
  if (args.includes('--authorize-job')) {
    const password = readPrivateValue(requiredEnvironment('MIMA_MIGRATION_DATABASE_PASSWORD_FILE'));
    operation = provisionMigrationDatabaseRole({ databaseUrl, role, password, jobId: parseJobId(args) });
  } else if (args.includes('--revoke-job')) {
    operation = revokeMigrationDatabaseRole({ databaseUrl, role, jobId: parseJobId(args) });
  } else if (args.includes('--check-schema')) {
    operation = checkMigrationDatabaseRoleSchema(databaseUrl);
  } else {
    operation = Promise.reject(new Error('migration_role_operation_required'));
  }
  operation
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error: unknown) => {
      const code = error instanceof Error ? error.message : 'migration_role_provision_failed';
      process.stderr.write(`[migration-role] ${code}\n`);
      process.exitCode = 1;
    });
}
