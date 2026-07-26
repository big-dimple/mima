import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../../src/db/migrate.ts';
import { testDbUrl } from './helpers.ts';

const databaseName = 'mima_test_migrations_upgrade';
const comparisonDatabaseName = 'mima_test_migrations_upgrade_comparison';
const databaseUrl = testDbUrl(databaseName);
const comparisonDatabaseUrl = testDbUrl(comparisonDatabaseName);
const adminUrl = testDbUrl('mima');

describe('versioned migration upgrade acceptance', () => {
  afterAll(async () => {
    await resetDatabase();
    await resetDatabase(comparisonDatabaseName);
  });

  it('preserves frozen 0001 data through 0021 and an idempotent replay', async () => {
    await resetDatabase();
    await createDatabase();

    const baseline = readFileSync(resolve(import.meta.dirname, '../../src/db/schema.sql'), 'utf8');
    const baselineChecksum = createHash('sha256').update(baseline).digest('hex');
    let legacyDigestBefore = '';
    let usersContentDigestBefore = '';
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      await client.query(`
        CREATE TABLE schema_migrations (
          id text PRIMARY KEY,
          checksum text NOT NULL,
          applied_at timestamptz NOT NULL DEFAULT now()
        )
      `);
      await client.query(baseline);
      await client.query(
        'INSERT INTO schema_migrations (id, checksum) VALUES ($1, $2)',
        ['0001_base_schema', baselineChecksum],
      );
      await seedFrozenBaseline(client);
      legacyDigestBefore = await legacyContentDigest(client);
      usersContentDigestBefore = await usersSemanticContentDigest(client);
    } finally {
      await client.end();
    }

    await runMigrations(databaseUrl);
    await runMigrations(databaseUrl);

    const verification = new pg.Client({ connectionString: databaseUrl });
    await verification.connect();
    try {
      const counts = await verification.query<{
        users: number;
        identities: number;
        directory_groups: number;
        directory_states: number;
        vaults: number;
        memberships: number;
        items: number;
        history: number;
        audit: number;
        crypto_states: number;
        legacy_states: number;
      }>(`
        SELECT
          (SELECT count(*)::int FROM users) AS users,
          (SELECT count(*)::int FROM user_identities) AS identities,
          (SELECT count(*)::int FROM directory_groups) AS directory_groups,
          (SELECT count(*)::int FROM directory_sync_state) AS directory_states,
          (SELECT count(*)::int FROM vaults) AS vaults,
          (SELECT count(*)::int FROM vault_memberships) AS memberships,
          (SELECT count(*)::int FROM items) AS items,
          (SELECT count(*)::int FROM item_secret_versions) AS history,
          (SELECT count(*)::int FROM audit_events) AS audit,
          (SELECT count(*)::int FROM vault_crypto_states) AS crypto_states,
          (SELECT count(*)::int FROM vault_crypto_states WHERE storage_mode = 'legacy') AS legacy_states
      `);
      expect(counts.rows[0]).toEqual({
        users: 2,
        identities: 1,
        directory_groups: 1,
        directory_states: 1,
        vaults: 2,
        memberships: 2,
        items: 2,
        history: 3,
        audit: 1,
        crypto_states: 2,
        legacy_states: 2,
      });
      expect(await legacyContentDigest(verification)).toBe(legacyDigestBefore);
      expect(await usersSemanticContentDigest(verification)).toBe(usersContentDigestBefore);
      const projectSchema = await verification.query<{
        parent_column: boolean;
        parent_foreign_key: boolean;
        relation_guard: boolean;
        existing_roots: number;
      }>(`
        SELECT
          EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'vaults' AND column_name = 'parent_vault_id'
          ) AS parent_column,
          EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'vaults_parent_vault_fk'
          ) AS parent_foreign_key,
          EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'vaults_project_relation_guard' AND NOT tgisinternal
          ) AS relation_guard,
          (SELECT count(*)::int FROM vaults WHERE parent_vault_id IS NULL) AS existing_roots
      `);
      expect(projectSchema.rows[0]).toEqual({
        parent_column: true,
        parent_foreign_key: true,
        relation_guard: true,
        existing_roots: 2,
      });

      const migrations = await verification.query<{ count: number; head: string }>(`
        SELECT count(*)::int AS count, max(id) AS head FROM schema_migrations
      `);
      expect(migrations.rows[0]).toEqual({
        count: 21,
        head: '0021_team_vault_projects',
      });
    } finally {
      await verification.end();
    }
  });

  it('normalizes only reviewed volatile fields in logical-v4 and detects authorization changes', async () => {
    await resetDatabase();
    await resetDatabase(comparisonDatabaseName);
    await createDatabase();
    const baseline = readFileSync(resolve(import.meta.dirname, '../../src/db/schema.sql'), 'utf8');
    const baselineChecksum = createHash('sha256').update(baseline).digest('hex');
    const source = new pg.Client({ connectionString: databaseUrl });
    await source.connect();
    try {
      await source.query(`
        CREATE TABLE schema_migrations (
          id text PRIMARY KEY,
          checksum text NOT NULL,
          applied_at timestamptz NOT NULL DEFAULT now()
        )
      `);
      await source.query(baseline);
      await source.query(
        'INSERT INTO schema_migrations (id, checksum) VALUES ($1, $2)',
        ['0001_base_schema', baselineChecksum],
      );
      await seedFrozenBaseline(source);
    } finally {
      await source.end();
    }
    await cloneDatabase(comparisonDatabaseName, databaseName);

    await runMigrations(databaseUrl);
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
    await runMigrations(comparisonDatabaseUrl);

    const first = new pg.Client({ connectionString: databaseUrl });
    const second = new pg.Client({ connectionString: comparisonDatabaseUrl });
    await Promise.all([first.connect(), second.connect()]);
    try {
      await Promise.all([first, second].map((client) => client.query(`
        INSERT INTO custom_groups (id, owner_user_id, name, frozen, created_at, updated_at)
        VALUES (
          '30000000-0000-4000-8000-000000000001',
          'migration-user-1',
          'Migration Operators',
          false,
          '2026-01-02T03:04:05Z',
          '2026-01-02T03:04:05Z'
        )
      `)));
      const [firstTimes, secondTimes] = await Promise.all([
        first.query<{ applied_at: string; crypto_created_at: string }>(`
          SELECT
            (SELECT applied_at::text FROM schema_migrations WHERE id = '0002_standalone_auth_groups') AS applied_at,
            (SELECT min(created_at)::text FROM vault_crypto_states) AS crypto_created_at
        `),
        second.query<{ applied_at: string; crypto_created_at: string }>(`
          SELECT
            (SELECT applied_at::text FROM schema_migrations WHERE id = '0002_standalone_auth_groups') AS applied_at,
            (SELECT min(created_at)::text FROM vault_crypto_states) AS crypto_created_at
        `),
      ]);
      expect(secondTimes.rows[0]).not.toEqual(firstTimes.rows[0]);

      const firstDigest = await logicalV4Digest(first);
      const secondDigest = await logicalV4Digest(second);
      expect(secondDigest).toBe(firstDigest);

      await second.query(`
        UPDATE users
        SET directory_synced_at = '2030-02-03T04:05:06Z', updated_at = '2030-02-03T04:05:07Z'
        WHERE id = 'migration-user-1';
        UPDATE user_identities SET updated_at = '2030-02-03T04:05:08Z';
        UPDATE directory_groups SET synced_at = '2030-02-03T04:05:09Z';
        UPDATE directory_sync_state
        SET last_attempt_at = '2030-02-03T04:05:10Z', last_success_at = '2030-02-03T04:05:11Z';
        UPDATE custom_groups SET updated_at = '2030-02-03T04:05:12Z';
      `);
      expect(await logicalV4Digest(second)).toBe(firstDigest);

      for (const mutation of [
        `UPDATE users SET groups = '["security"]'::jsonb, active = false WHERE id = 'migration-user-1'`,
        `UPDATE user_identities SET subject = 'tenant-a:user-changed' WHERE user_id = 'migration-user-1'`,
        `UPDATE directory_groups SET active = false WHERE id = 'directory-group-1'`,
        `UPDATE directory_sync_state SET user_count = 999, last_error = 'directory failed' WHERE provider = 'oidc'`,
        `UPDATE custom_groups SET frozen = true WHERE id = '30000000-0000-4000-8000-000000000001'`,
      ]) {
        await second.query('BEGIN');
        try {
          await second.query(mutation);
          expect(await logicalV4Digest(second)).not.toBe(firstDigest);
        } finally {
          await second.query('ROLLBACK');
        }
      }
    } finally {
      await Promise.all([first.end(), second.end()]);
    }
  });

  it('keeps the logical-v4 digest stable across 0017 to 0018 while retaining non-null extension bindings', async () => {
    await resetDatabase();
    await createDatabase();
    await runMigrations(databaseUrl);
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      await client.query(`
        ALTER TABLE session_unlock_challenges
          DROP CONSTRAINT session_unlock_challenges_session_source_ck,
          DROP COLUMN extension_session_id,
          ALTER COLUMN session_id SET NOT NULL;
        DELETE FROM schema_migrations WHERE id = '0018_extension_session_unlock_challenges';

        INSERT INTO users (id, username, display_name, email, groups, source, active)
        VALUES ('digest-user', 'digest-user', 'Digest User', 'digest@example.test', '[]'::jsonb, 'dev', true);
        INSERT INTO sessions (id, token_hash, user_id, csrf_token, auth_provider, expires_at)
        VALUES (
          '10000000-0000-4000-8000-000000000001',
          'digest-web-session',
          'digest-user',
          'digest-csrf',
          'dev',
          '2126-01-01T00:00:00Z'
        );
        INSERT INTO user_devices (
          id, user_id, device_type, status, trust_method, key_fingerprint,
          public_encryption_key, public_signing_key, certificate_payload,
          certificate_signature, activated_at
        ) VALUES (
          '20000000-0000-4000-8000-000000000001',
          'digest-user',
          'extension',
          'active',
          'device_approval',
          'digest-extension-device',
          decode(repeat('11', 32), 'hex'),
          decode(repeat('22', 32), 'hex'),
          decode(repeat('33', 96), 'hex'),
          decode(repeat('44', 64), 'hex'),
          now()
        );
        INSERT INTO extension_sessions (
          id, token_hash, user_id, device_id, security_generation, expires_at
        ) VALUES (
          '30000000-0000-4000-8000-000000000001',
          'digest-extension-session',
          'digest-user',
          '20000000-0000-4000-8000-000000000001',
          1,
          '2126-01-01T00:00:00Z'
        );
        INSERT INTO session_unlock_challenges (
          id, session_id, user_id, device_id, purpose, challenge_hash,
          challenge_nonce, session_generation, profile_version, device_generation, expires_at
        ) VALUES (
          '40000000-0000-4000-8000-000000000001',
          '10000000-0000-4000-8000-000000000001',
          'digest-user',
          '20000000-0000-4000-8000-000000000001',
          'unlock',
          decode(repeat('55', 32), 'hex'),
          decode(repeat('66', 32), 'hex'),
          1,
          1,
          1,
          '2126-01-01T00:00:00Z'
        );
      `);
      const before = await logicalV4Digest(client);

      await runMigrations(databaseUrl);
      expect(await logicalV4Digest(client)).toBe(before);

      await client.query(`
        UPDATE session_unlock_challenges
        SET session_id = NULL,
            extension_session_id = '30000000-0000-4000-8000-000000000001'
        WHERE id = '40000000-0000-4000-8000-000000000001'
      `);
      expect(await logicalV4Digest(client)).not.toBe(before);
    } finally {
      await client.end();
    }
  });
});

async function seedFrozenBaseline(client: pg.Client): Promise<void> {
  await client.query(`
    INSERT INTO users (id, username, display_name, email) VALUES
      ('migration-user-1', 'migration-user-1', 'Migration User 1', 'migration-1@example.test'),
      ('migration-user-2', 'migration-user-2', 'Migration User 2', 'migration-2@example.test');

    INSERT INTO user_identities (provider, issuer, subject, user_id) VALUES
      ('oidc', 'https://identity.example.test/', 'tenant-a:user-001', 'migration-user-1');

    INSERT INTO directory_groups (id, provider, provider_group_id, display_name, synced_at) VALUES
      ('directory-group-1', 'oidc', 'platform-operators', 'Platform Operators', '2026-01-02T03:04:05Z');

    INSERT INTO directory_sync_state (
      provider, last_attempt_at, last_success_at, last_error, user_count, group_count
    ) VALUES (
      'oidc', '2026-01-02T03:04:05Z', '2026-01-02T03:04:05Z', NULL, 2, 1
    );

    INSERT INTO vaults (id, kind, name, owner_user_id) VALUES
      ('10000000-0000-4000-8000-000000000001', 'personal', 'Legacy Personal', 'migration-user-1'),
      ('10000000-0000-4000-8000-000000000002', 'team', 'Legacy Team', NULL);

    INSERT INTO vault_memberships (vault_id, subject_kind, subject_id, role) VALUES
      ('10000000-0000-4000-8000-000000000001', 'user', 'migration-user-1', 'owner'),
      ('10000000-0000-4000-8000-000000000002', 'user', 'migration-user-2', 'owner');

    INSERT INTO items (
      id, vault_id, kind, title, username, origin, version, secret_version, updated_by
    ) VALUES
      (
        '20000000-0000-4000-8000-000000000001',
        '10000000-0000-4000-8000-000000000001',
        'login', 'Legacy Login', 'legacy-user', 'https://legacy.example.test', 1, 2, 'migration-user-1'
      ),
      (
        '20000000-0000-4000-8000-000000000002',
        '10000000-0000-4000-8000-000000000002',
        'secure_note', 'Legacy Note', NULL, NULL, 1, 1, 'migration-user-2'
      );
  `);

  for (const [itemId, vaultId, itemKind, secretVersion, createdBy] of [
    [
      '20000000-0000-4000-8000-000000000001',
      '10000000-0000-4000-8000-000000000001',
      'login',
      1,
      'migration-user-1',
    ],
    [
      '20000000-0000-4000-8000-000000000001',
      '10000000-0000-4000-8000-000000000001',
      'login',
      2,
      'migration-user-1',
    ],
    [
      '20000000-0000-4000-8000-000000000002',
      '10000000-0000-4000-8000-000000000002',
      'secure_note',
      1,
      'migration-user-2',
    ],
  ] as const) {
    await client.query(
      `
        INSERT INTO item_secret_versions (
          item_id, vault_id, item_kind, secret_version,
          ciphertext, iv, auth_tag, wrapped_dek, key_version, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'v1', $9)
      `,
      [
        itemId,
        vaultId,
        itemKind,
        secretVersion,
        Buffer.alloc(64, secretVersion),
        Buffer.alloc(12, secretVersion),
        Buffer.alloc(16, secretVersion),
        Buffer.alloc(48, secretVersion),
        createdBy,
      ],
    );
  }

  await client.query(`
    INSERT INTO audit_events (
      actor_user_id, action, vault_id, item_id, success, details, prev_hash, hash
    ) VALUES (
      'migration-user-1',
      'legacy.seed',
      '10000000-0000-4000-8000-000000000001',
      '20000000-0000-4000-8000-000000000001',
      true,
      '{"source":"frozen-baseline"}',
      'GENESIS',
      'legacy-audit-hash'
    )
  `);
}

async function legacyContentDigest(client: pg.Client): Promise<string> {
  const queries = [
    `SELECT id, username, display_name, email, groups, source, active,
            directory_synced_at, created_at, updated_at
       FROM users ORDER BY id`,
    `SELECT id, provider, issuer, subject, user_id, created_at, updated_at
       FROM user_identities ORDER BY id`,
    `SELECT id, provider, provider_group_id, display_name, active, synced_at
       FROM directory_groups ORDER BY id`,
    `SELECT provider, last_attempt_at, last_success_at, last_error, user_count, group_count
       FROM directory_sync_state ORDER BY provider`,
    `SELECT id, kind, name, owner_user_id, created_at, updated_at
       FROM vaults ORDER BY id`,
    `SELECT id, vault_id, subject_kind, subject_id, role, created_at
       FROM vault_memberships ORDER BY id`,
    `SELECT id, vault_id, kind, title, username, origin, tags, favorite, sensitivity,
            version, secret_version, deleted, created_at, updated_at, updated_by
       FROM items ORDER BY id`,
    `SELECT id, item_id, vault_id, item_kind, secret_version, ciphertext, iv, auth_tag,
            wrapped_dek, key_version, created_at, created_by
       FROM item_secret_versions ORDER BY item_id, secret_version`,
    `SELECT id, ts, actor_user_id, action, vault_id, item_id, success, details, prev_hash, hash
       FROM audit_events ORDER BY id`,
  ];
  const hash = createHash('sha256');
  for (const query of queries) {
    const result = await client.query<Record<string, unknown>>(query);
    hash.update(JSON.stringify(result.rows, (_key, value) =>
      Buffer.isBuffer(value) ? value.toString('hex') : value));
    hash.update('\n');
  }
  return hash.digest('hex');
}

async function usersSemanticContentDigest(client: pg.Client): Promise<string> {
  const result = await client.query<{ value: string }>(`
    SELECT jsonb_build_array(
      row_data->'id', row_data->'username', row_data->'display_name',
      row_data->'email', row_data->'groups', row_data->'source',
      row_data->'active', row_data->'created_at',
      row_data->'directory_provider', row_data->'directory_dn',
      row_data->'directory_stable_id'
    )::text AS value
    FROM (SELECT to_jsonb(value) AS row_data FROM users value) rows
    ORDER BY (row_data->>'id') COLLATE "C"
  `);
  return createHash('sha256').update(result.rows.map((row) => `${row.value}\n`).join('')).digest('hex');
}

async function createDatabase(name = databaseName): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
}

async function cloneDatabase(name: string, template: string): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name} TEMPLATE ${template}`);
  } finally {
    await admin.end();
  }
}

async function resetDatabase(name = databaseName): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}

async function logicalV4Digest(client: pg.Client): Promise<string> {
  const extensionSessionColumn = (await client.query<{ exists: boolean }>(`
    SELECT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'session_unlock_challenges'
        AND column_name = 'extension_session_id'
    ) AS exists
  `)).rows[0]?.exists ?? false;
  const tables = await client.query<{ qualified: string }>(`
    SELECT format('%I.%I', namespace.nspname, relation.relname) AS qualified
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relkind = 'r'
      AND namespace.nspname IN ('public', 'mima_migration')
    ORDER BY namespace.nspname COLLATE "C", relation.relname COLLATE "C"
  `);
  const outer = createHash('sha256');
  for (const { qualified } of tables.rows) {
    const normalizedExpressions: Record<string, string> = {
      'public.users': "to_jsonb(value) - 'directory_synced_at' - 'updated_at'",
      'public.user_identities': "to_jsonb(value) - 'updated_at'",
      'public.directory_groups': "to_jsonb(value) - 'synced_at'",
      'public.directory_sync_state': "to_jsonb(value) - 'last_attempt_at' - 'last_success_at'",
      'public.custom_groups': "to_jsonb(value) - 'updated_at'",
      'public.schema_migrations': "to_jsonb(value) - 'applied_at'",
      'public.vault_crypto_states': "to_jsonb(value) - 'created_at' - 'updated_at'",
      ...(extensionSessionColumn ? {
        'public.session_unlock_challenges': "CASE WHEN value.extension_session_id IS NULL THEN to_jsonb(value) - 'extension_session_id' ELSE to_jsonb(value) END",
      } : {}),
    };
    const expression = normalizedExpressions[qualified] ?? 'to_jsonb(value)';
    const rows = await client.query<{ value: string }>(`
      SELECT (${expression})::text AS value
      FROM ${qualified} value
      ${qualified === 'public.schema_migrations'
        ? "WHERE id <> '0018_extension_session_unlock_challenges'"
        : ''}
      ORDER BY ((${expression})::text) COLLATE "C"
    `);
    const tableHash = createHash('sha256');
    for (const row of rows.rows) tableHash.update(`${row.value}\n`);
    outer.update(`${qualified}=${tableHash.digest('hex')}\n`);
  }
  const sequenceMetadata = await client.query<{ value: string }>(`
    SELECT concat_ws('|', schemaname, sequencename, start_value, min_value, max_value,
      increment_by, cycle, cache_size, COALESCE(last_value::text, 'null')) AS value
    FROM pg_sequences
    WHERE schemaname IN ('public', 'mima_migration')
    ORDER BY schemaname COLLATE "C", sequencename COLLATE "C"
  `);
  for (const row of sequenceMetadata.rows) outer.update(`sequence=${row.value}\n`);
  const sequences = await client.query<{ qualified: string }>(`
    SELECT format('%I.%I', namespace.nspname, relation.relname) AS qualified
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relkind = 'S'
      AND namespace.nspname IN ('public', 'mima_migration')
    ORDER BY namespace.nspname COLLATE "C", relation.relname COLLATE "C"
  `);
  for (const { qualified } of sequences.rows) {
    const state = await client.query<{ last_value: string; is_called: boolean }>(
      `SELECT last_value::text, is_called FROM ${qualified}`,
    );
    outer.update(`sequence-call-state:${qualified}=${JSON.stringify(state.rows[0])}\n`);
  }
  return outer.digest('hex');
}
