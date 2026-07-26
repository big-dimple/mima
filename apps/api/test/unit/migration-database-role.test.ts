import { describe, expect, it } from 'vitest';
import {
  evaluateMigrationDatabaseRoleAudit,
  migrationDatabaseRoleContract,
  type MigrationDatabaseRoleAudit,
} from '../../src/migration/database-role.ts';

describe('migration database role contract', () => {
  it('accepts only the documented minimal privileges', () => {
    expect(evaluateMigrationDatabaseRoleAudit(minimalAudit(), ROLE, JOB_ID)).toBeNull();
  });

  it('rejects dangerous role attributes even when the role name matches', () => {
    const audit = minimalAudit();
    audit.identity.superuser = true;
    expect(evaluateMigrationDatabaseRoleAudit(audit, ROLE, JOB_ID))
      .toBe('dangerous_attributes');
  });

  it('rejects a write privilege outside the worker whitelist', () => {
    const audit = minimalAudit();
    audit.columnPrivileges.push({
      schema: 'mima_migration',
      relation: 'items',
      column: 'id',
      privilege: 'UPDATE',
    });
    expect(evaluateMigrationDatabaseRoleAudit(audit, ROLE, JOB_ID))
      .toBe('unexpected_privilege');
  });

  it('rejects a missing required read privilege', () => {
    const audit = minimalAudit();
    audit.columnPrivileges = audit.columnPrivileges.filter((privilege) => !(
      privilege.relation === 'vaults'
      && privilege.column === 'id'
      && privilege.privilege === 'SELECT'
    ));
    expect(evaluateMigrationDatabaseRoleAudit(audit, ROLE, JOB_ID))
      .toBe('required_privilege_missing');
  });

  it('rejects usage on any non-public application schema', () => {
    const audit = minimalAudit();
    audit.schemas.push({ schema: 'private_migration', usage: true, create: false });
    expect(evaluateMigrationDatabaseRoleAudit(audit, ROLE, JOB_ID))
      .toBe('schema_privilege');
  });

  it('rejects a role bound to a different migration job', () => {
    expect(evaluateMigrationDatabaseRoleAudit(
      minimalAudit(),
      ROLE,
      '22222222-2222-4222-8222-222222222222',
    )).toBe('job_binding');
  });
});

const ROLE = 'mima_migration_11111111111141118111111111111111';
const JOB_ID = '11111111-1111-4111-8111-111111111111';

function minimalAudit(): MigrationDatabaseRoleAudit {
  const relationColumns = new Map<string, string[]>();
  for (const relation of migrationDatabaseRoleContract.selectTables) {
    relationColumns.set(relation, relation.endsWith('legacy_migration_jobs')
      ? ['id', 'state', 'updated_at']
      : ['id']);
  }
  for (const value of migrationDatabaseRoleContract.insertColumns) {
    const parts = value.split('.');
    const relation = parts.slice(0, 2).join('.');
    const column = parts[2]!;
    relationColumns.set(relation, [...new Set([...(relationColumns.get(relation) ?? []), column])]);
  }
  const columnPrivileges: MigrationDatabaseRoleAudit['columnPrivileges'] = [];
  for (const [relation, columns] of relationColumns) {
    const [schema, table] = relation.split('.') as [string, string];
    for (const column of columns) {
      if (migrationDatabaseRoleContract.selectTables.includes(relation)) {
        columnPrivileges.push({ schema, relation: table, column, privilege: 'SELECT' });
      }
      if (migrationDatabaseRoleContract.insertColumns.includes(`${relation}.${column}`)) {
        columnPrivileges.push({ schema, relation: table, column, privilege: 'INSERT' });
      }
    }
  }
  columnPrivileges.push(
    { schema: 'mima_migration', relation: 'legacy_migration_jobs', column: 'state', privilege: 'UPDATE' },
    { schema: 'mima_migration', relation: 'legacy_migration_jobs', column: 'updated_at', privilege: 'UPDATE' },
  );
  return {
    identity: {
      currentUser: ROLE,
      currentDatabase: 'mima',
      canLogin: true,
      inherit: false,
      superuser: false,
      createRole: false,
      createDatabase: false,
      replication: false,
      bypassRls: false,
      databaseConnect: true,
      databaseCreate: false,
      databaseTemporary: false,
    },
    memberships: [],
    schemas: [
      { schema: 'mima_migration', usage: true, create: false },
      { schema: 'public', usage: true, create: false },
    ],
    relationColumns: [...relationColumns].flatMap(([relation, columns]) => {
      const [schema, table] = relation.split('.') as [string, string];
      return columns.map((column) => ({ schema, relation: table, column }));
    }),
    columnPrivileges,
    tablePrivileges: [],
    sequencePrivileges: [],
    functionPrivileges: migrationDatabaseRoleContract.executeFunctions.map((identity) => {
      const [schema, functionIdentity] = identity.split('.') as [string, string];
      return { schema, identity: functionIdentity };
    }),
    jobBinding: {
      jobId: JOB_ID,
      vaultId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      recipientUserId: 'migration-owner',
    },
  };
}
