import type { Pool, PoolClient } from 'pg';

type Queryable = Pick<Pool | PoolClient, 'query'>;

const SELECT_TABLES = new Set([
  'mima_migration.item_secret_versions',
  'mima_migration.items',
  'mima_migration.legacy_migration_exports',
  'mima_migration.legacy_migration_jobs',
  'mima_migration.legacy_migration_records',
  'mima_migration.user_crypto_profiles',
  'mima_migration.vault_memberships',
  'mima_migration.vaults',
]);

const INSERT_COLUMNS = new Set([
  'mima_migration.legacy_migration_evidence.digest',
  'mima_migration.legacy_migration_evidence.evidence_type',
  'mima_migration.legacy_migration_evidence.job_id',
  'mima_migration.legacy_migration_evidence.record_count',
  'mima_migration.legacy_migration_evidence.stage',
  'mima_migration.legacy_migration_evidence.subject_id',
  'mima_migration.legacy_migration_evidence.subject_kind',
  'mima_migration.legacy_migration_exports.expires_at',
  'mima_migration.legacy_migration_exports.job_id',
  'mima_migration.legacy_migration_exports.recipient_key_digest',
  'mima_migration.legacy_migration_exports.recipient_key_version',
  'mima_migration.legacy_migration_exports.recipient_user_id',
  'mima_migration.legacy_migration_exports.sealed_export',
  'mima_migration.legacy_migration_exports.sealed_export_digest',
  'mima_migration.legacy_migration_exports.source_digest',
  'mima_migration.legacy_migration_exports.vault_id',
]);

const UPDATE_COLUMNS = new Set([
  'mima_migration.legacy_migration_jobs.state',
  'mima_migration.legacy_migration_jobs.updated_at',
]);

const EXECUTE_FUNCTIONS = new Set([
  'mima_migration.active_job_id()',
  'mima_migration.active_recipient_user_id()',
  'mima_migration.active_vault_id()',
]);

const DANGEROUS_PREDEFINED_ROLES = new Set([
  'pg_checkpoint',
  'pg_create_subscription',
  'pg_execute_server_program',
  'pg_maintain',
  'pg_monitor',
  'pg_read_all_data',
  'pg_read_all_settings',
  'pg_read_all_stats',
  'pg_read_server_files',
  'pg_signal_autovacuum_worker',
  'pg_signal_backend',
  'pg_stat_scan_tables',
  'pg_use_reserved_connections',
  'pg_write_all_data',
  'pg_write_server_files',
]);

export interface MigrationDatabaseRoleAudit {
  identity: {
    currentUser: string;
    currentDatabase: string;
    canLogin: boolean;
    inherit: boolean;
    superuser: boolean;
    createRole: boolean;
    createDatabase: boolean;
    replication: boolean;
    bypassRls: boolean;
    databaseConnect: boolean;
    databaseCreate: boolean;
    databaseTemporary: boolean;
  };
  memberships: Array<{
    role: string;
    superuser: boolean;
    createRole: boolean;
    createDatabase: boolean;
    replication: boolean;
    bypassRls: boolean;
  }>;
  schemas: Array<{ schema: string; usage: boolean; create: boolean }>;
  relationColumns: Array<{ schema: string; relation: string; column: string }>;
  columnPrivileges: Array<{
    schema: string;
    relation: string;
    column: string;
    privilege: 'SELECT' | 'INSERT' | 'UPDATE' | 'REFERENCES';
  }>;
  tablePrivileges: Array<{
    schema: string;
    relation: string;
    privilege: 'DELETE' | 'TRUNCATE' | 'TRIGGER';
  }>;
  sequencePrivileges: Array<{
    schema: string;
    sequence: string;
    privilege: 'USAGE' | 'SELECT' | 'UPDATE';
  }>;
  functionPrivileges: Array<{ schema: string; identity: string }>;
  jobBinding: {
    jobId: string | null;
    vaultId: string | null;
    recipientUserId: string | null;
  };
}

export class MigrationDatabaseRoleError extends Error {
  constructor(
    readonly reason:
      | 'identity_mismatch'
      | 'dangerous_attributes'
      | 'role_membership'
      | 'database_privilege'
      | 'schema_privilege'
      | 'job_binding'
      | 'required_privilege_missing'
      | 'unexpected_privilege',
  ) {
    super('database_role_not_restricted');
  }
}

export async function assertMigrationDatabaseRole(
  database: Queryable,
  expectedRole: string,
  expectedJobId: string,
): Promise<void> {
  const audit = await auditMigrationDatabaseRole(database);
  const reason = evaluateMigrationDatabaseRoleAudit(audit, expectedRole, expectedJobId);
  if (reason) throw new MigrationDatabaseRoleError(reason);
}

export function evaluateMigrationDatabaseRoleAudit(
  audit: MigrationDatabaseRoleAudit,
  expectedRole: string,
  expectedJobId: string,
): MigrationDatabaseRoleError['reason'] | null {
  const identity = audit.identity;
  if (identity.currentUser !== expectedRole || !identity.canLogin) return 'identity_mismatch';
  if (
    identity.inherit
    || identity.superuser
    || identity.createRole
    || identity.createDatabase
    || identity.replication
    || identity.bypassRls
  ) {
    return 'dangerous_attributes';
  }
  if (
    audit.memberships.some((membership) => (
      DANGEROUS_PREDEFINED_ROLES.has(membership.role)
      || membership.superuser
      || membership.createRole
      || membership.createDatabase
      || membership.replication
      || membership.bypassRls
    ))
    || audit.memberships.length > 0
  ) {
    return 'role_membership';
  }
  if (!identity.databaseConnect || identity.databaseCreate || identity.databaseTemporary) {
    return 'database_privilege';
  }
  const publicSchema = audit.schemas.find((schema) => schema.schema === 'public');
  const migrationSchema = audit.schemas.find((schema) => schema.schema === 'mima_migration');
  if (
    !publicSchema?.usage
    || !migrationSchema?.usage
    || audit.schemas.some((schema) => (
      schema.create
      || (!['public', 'mima_migration'].includes(schema.schema) && schema.usage)
    ))
  ) {
    return 'schema_privilege';
  }
  if (
    audit.jobBinding.jobId !== expectedJobId
    || !audit.jobBinding.vaultId
    || !audit.jobBinding.recipientUserId
  ) {
    return 'job_binding';
  }

  const columnsByRelation = new Map<string, string[]>();
  for (const column of audit.relationColumns) {
    const relation = `${column.schema}.${column.relation}`;
    const columns = columnsByRelation.get(relation) ?? [];
    columns.push(column.column);
    columnsByRelation.set(relation, columns);
  }
  const insertTables = new Set([...INSERT_COLUMNS].map((column) => column.split('.').slice(0, 2).join('.')));
  for (const relation of new Set([...SELECT_TABLES, ...insertTables])) {
    if (!columnsByRelation.has(relation)) return 'required_privilege_missing';
  }
  for (const column of INSERT_COLUMNS) {
    const parts = column.split('.');
    const relation = parts.slice(0, 2).join('.');
    if (!columnsByRelation.get(relation)?.includes(parts[2]!)) return 'required_privilege_missing';
  }

  const required = new Set<string>();
  for (const [relation, columns] of columnsByRelation) {
    for (const column of columns) {
      if (SELECT_TABLES.has(relation)) required.add(`${relation}.${column}:SELECT`);
      if (INSERT_COLUMNS.has(`${relation}.${column}`)) required.add(`${relation}.${column}:INSERT`);
    }
  }
  for (const column of UPDATE_COLUMNS) required.add(`${column}:UPDATE`);

  const actual = new Set(audit.columnPrivileges.map((privilege) => (
    `${privilege.schema}.${privilege.relation}.${privilege.column}:${privilege.privilege}`
  )));
  if ([...required].some((privilege) => !actual.has(privilege))) {
    return 'required_privilege_missing';
  }
  if (
    [...actual].some((privilege) => !required.has(privilege))
    || audit.tablePrivileges.length > 0
    || audit.sequencePrivileges.length > 0
    || audit.functionPrivileges.some((privilege) => (
      !EXECUTE_FUNCTIONS.has(`${privilege.schema}.${privilege.identity}`)
    ))
    || [...EXECUTE_FUNCTIONS].some((identity) => !audit.functionPrivileges.some((privilege) => (
      `${privilege.schema}.${privilege.identity}` === identity
    )))
  ) {
    return 'unexpected_privilege';
  }
  return null;
}

export async function auditMigrationDatabaseRole(
  database: Queryable,
): Promise<MigrationDatabaseRoleAudit> {
  const identityResult = await database.query<{
    current_user: string;
    current_database: string;
    rolcanlogin: boolean;
    rolinherit: boolean;
    rolsuper: boolean;
    rolcreaterole: boolean;
    rolcreatedb: boolean;
    rolreplication: boolean;
    rolbypassrls: boolean;
    database_connect: boolean;
    database_create: boolean;
    database_temporary: boolean;
  }>(`
    SELECT
      current_user,
      current_database() AS current_database,
      role.rolcanlogin,
      role.rolinherit,
      role.rolsuper,
      role.rolcreaterole,
      role.rolcreatedb,
      role.rolreplication,
      role.rolbypassrls,
      has_database_privilege(current_user, current_database(), 'CONNECT') AS database_connect,
      has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
      has_database_privilege(current_user, current_database(), 'TEMPORARY') AS database_temporary
    FROM pg_roles role
    WHERE role.rolname = current_user
  `);
  const identity = identityResult.rows[0];
  if (!identity) throw new MigrationDatabaseRoleError('identity_mismatch');

  const memberships = await database.query<{
    rolname: string;
    rolsuper: boolean;
    rolcreaterole: boolean;
    rolcreatedb: boolean;
    rolreplication: boolean;
    rolbypassrls: boolean;
  }>(`
    WITH RECURSIVE memberships(role_oid, path) AS (
      SELECT membership.roleid, ARRAY[membership.member, membership.roleid]
      FROM pg_auth_members membership
      WHERE membership.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
      UNION ALL
      SELECT membership.roleid, memberships.path || membership.roleid
      FROM memberships
      JOIN pg_auth_members membership ON membership.member = memberships.role_oid
      WHERE NOT membership.roleid = ANY(memberships.path)
    )
    SELECT DISTINCT
      role.rolname,
      role.rolsuper,
      role.rolcreaterole,
      role.rolcreatedb,
      role.rolreplication,
      role.rolbypassrls
    FROM memberships
    JOIN pg_roles role ON role.oid = memberships.role_oid
    ORDER BY role.rolname
  `);
  const schemas = await database.query<{ nspname: string; usage: boolean; create: boolean }>(`
    SELECT
      namespace.nspname,
      has_schema_privilege(current_user, namespace.oid, 'USAGE') AS usage,
      has_schema_privilege(current_user, namespace.oid, 'CREATE') AS create
    FROM pg_namespace namespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    ORDER BY namespace.nspname
  `);
  const relationColumns = await database.query<{
    nspname: string;
    relname: string;
    attname: string;
  }>(`
    SELECT namespace.nspname, relation.relname, attribute.attname
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_attribute attribute ON attribute.attrelid = relation.oid
    WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
    ORDER BY namespace.nspname, relation.relname, attribute.attnum
  `);
  const columnPrivileges = await database.query<{
    nspname: string;
    relname: string;
    attname: string;
    privilege: 'SELECT' | 'INSERT' | 'UPDATE' | 'REFERENCES';
  }>(`
    SELECT namespace.nspname, relation.relname, attribute.attname, privilege.name AS privilege
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_attribute attribute ON attribute.attrelid = relation.oid
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) privilege(name)
    WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND has_column_privilege(current_user, relation.oid, attribute.attnum, privilege.name)
    ORDER BY namespace.nspname, relation.relname, attribute.attnum, privilege.name
  `);
  const tablePrivileges = await database.query<{
    nspname: string;
    relname: string;
    privilege: 'DELETE' | 'TRUNCATE' | 'TRIGGER';
  }>(`
    SELECT namespace.nspname, relation.relname, privilege.name AS privilege
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN (VALUES ('DELETE'), ('TRUNCATE'), ('TRIGGER')) privilege(name)
    WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND has_table_privilege(current_user, relation.oid, privilege.name)
    ORDER BY namespace.nspname, relation.relname, privilege.name
  `);
  const sequencePrivileges = await database.query<{
    nspname: string;
    relname: string;
    privilege: 'USAGE' | 'SELECT' | 'UPDATE';
  }>(`
    SELECT namespace.nspname, sequence.relname, privilege.name AS privilege
    FROM pg_class sequence
    JOIN pg_namespace namespace ON namespace.oid = sequence.relnamespace
    CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) privilege(name)
    WHERE sequence.relkind = 'S'
      AND namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND has_sequence_privilege(current_user, sequence.oid, privilege.name)
    ORDER BY namespace.nspname, sequence.relname, privilege.name
  `);
  const functionPrivileges = await database.query<{ nspname: string; identity: string }>(`
    SELECT
      namespace.nspname,
      function.proname || '(' || pg_get_function_identity_arguments(function.oid) || ')' AS identity
    FROM pg_proc function
    JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
      AND has_function_privilege(current_user, function.oid, 'EXECUTE')
    ORDER BY namespace.nspname, identity
  `);
  const binding = await database.query<{
    job_id: string | null;
    vault_id: string | null;
    recipient_user_id: string | null;
  }>(`
    SELECT
      mima_migration.active_job_id() AS job_id,
      mima_migration.active_vault_id() AS vault_id,
      mima_migration.active_recipient_user_id() AS recipient_user_id
  `);

  return {
    identity: {
      currentUser: identity.current_user,
      currentDatabase: identity.current_database,
      canLogin: identity.rolcanlogin,
      inherit: identity.rolinherit,
      superuser: identity.rolsuper,
      createRole: identity.rolcreaterole,
      createDatabase: identity.rolcreatedb,
      replication: identity.rolreplication,
      bypassRls: identity.rolbypassrls,
      databaseConnect: identity.database_connect,
      databaseCreate: identity.database_create,
      databaseTemporary: identity.database_temporary,
    },
    memberships: memberships.rows.map((membership) => ({
      role: membership.rolname,
      superuser: membership.rolsuper,
      createRole: membership.rolcreaterole,
      createDatabase: membership.rolcreatedb,
      replication: membership.rolreplication,
      bypassRls: membership.rolbypassrls,
    })),
    schemas: schemas.rows.map((schema) => ({
      schema: schema.nspname,
      usage: schema.usage,
      create: schema.create,
    })),
    relationColumns: relationColumns.rows.map((column) => ({
      schema: column.nspname,
      relation: column.relname,
      column: column.attname,
    })),
    columnPrivileges: columnPrivileges.rows.map((privilege) => ({
      schema: privilege.nspname,
      relation: privilege.relname,
      column: privilege.attname,
      privilege: privilege.privilege,
    })),
    tablePrivileges: tablePrivileges.rows.map((privilege) => ({
      schema: privilege.nspname,
      relation: privilege.relname,
      privilege: privilege.privilege,
    })),
    sequencePrivileges: sequencePrivileges.rows.map((privilege) => ({
      schema: privilege.nspname,
      sequence: privilege.relname,
      privilege: privilege.privilege,
    })),
    functionPrivileges: functionPrivileges.rows.map((privilege) => ({
      schema: privilege.nspname,
      identity: privilege.identity,
    })),
    jobBinding: {
      jobId: binding.rows[0]?.job_id ?? null,
      vaultId: binding.rows[0]?.vault_id ?? null,
      recipientUserId: binding.rows[0]?.recipient_user_id ?? null,
    },
  };
}

export const migrationDatabaseRoleContract = {
  selectTables: [...SELECT_TABLES],
  insertColumns: [...INSERT_COLUMNS],
  updateColumns: [...UPDATE_COLUMNS],
  executeFunctions: [...EXECUTE_FUNCTIONS],
  sequences: [] as string[],
};
