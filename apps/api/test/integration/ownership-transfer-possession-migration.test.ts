import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { testDbUrl } from './helpers.ts';

const databaseName = 'mima_test_ownership_possession_migration';
const databaseUrl = testDbUrl(databaseName);
const adminUrl = testDbUrl('mima');
const migrationDirectory = resolve(import.meta.dirname, '../../src/db/migrations');

describe('0014 vault key possession proof migration', () => {
  afterAll(resetDatabase);

  it('cancels pending legacy transfers and preserves compatible history', async () => {
    await resetDatabase();
    await createDatabase();
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      await applyThrough0013(client);
      await seedOwnershipTransfers(client);
      await client.query(readFileSync(
        resolve(migrationDirectory, '0014_vault_key_possession_proof.sql'),
        'utf8',
      ));

      const transfers = await client.query<{
        id: string;
        status: string;
        acceptance_required: boolean;
        cancelled_at: Date | null;
        key_possession_signature: Buffer | null;
        accepted_key_epoch: number | null;
      }>(`
        SELECT id, status, acceptance_required, cancelled_at,
               key_possession_signature, accepted_key_epoch
        FROM vault_ownership_transfer_requests
        ORDER BY id
      `);
      expect(transfers.rows).toMatchObject([
        {
          id: '40000000-0000-4000-8000-000000000001',
          status: 'cancelled',
          acceptance_required: true,
          key_possession_signature: null,
          accepted_key_epoch: null,
        },
        {
          id: '40000000-0000-4000-8000-000000000002',
          status: 'completed',
          acceptance_required: false,
          key_possession_signature: null,
          accepted_key_epoch: null,
        },
        {
          id: '40000000-0000-4000-8000-000000000003',
          status: 'cancelled',
          acceptance_required: false,
          key_possession_signature: null,
          accepted_key_epoch: null,
        },
      ]);
      expect(transfers.rows[0]!.cancelled_at).toBeInstanceOf(Date);

      await client.query(`
        UPDATE vault_key_epochs
        SET key_possession_public_key = decode(repeat('11', 32), 'hex')
        WHERE vault_id = '10000000-0000-4000-8000-000000000001' AND epoch = 1
      `);
      await expect(client.query(`
        UPDATE vault_key_epochs
        SET key_possession_public_key = decode(repeat('22', 31), 'hex')
        WHERE vault_id = '10000000-0000-4000-8000-000000000001' AND epoch = 1
      `)).rejects.toMatchObject({ code: '23514' });

      await client.query(`
        INSERT INTO vault_ownership_transfer_requests (
          id, vault_id, from_owner_user_id, to_owner_user_id, envelope_task_id,
          expected_access_generation, requested_by_device_id
        ) VALUES (
          '40000000-0000-4000-8000-000000000004',
          '10000000-0000-4000-8000-000000000001',
          'migration-owner', 'migration-target',
          '30000000-0000-4000-8000-000000000001', 1,
          '20000000-0000-4000-8000-000000000001'
        )
      `);
      await expect(client.query(`
        UPDATE vault_ownership_transfer_requests
        SET status = 'completed', completed_at = now()
        WHERE id = '40000000-0000-4000-8000-000000000004'
      `)).rejects.toMatchObject({ code: '23514' });
    } finally {
      await client.end();
    }
  });
});

async function applyThrough0013(client: pg.Client): Promise<void> {
  await client.query(readFileSync(resolve(import.meta.dirname, '../../src/db/schema.sql'), 'utf8'));
  const migrations = readdirSync(migrationDirectory)
    .filter((name) => /^\d+_[a-z0-9_]+\.sql$/.test(name) && name < '0014_')
    .sort();
  for (const migration of migrations) {
    await client.query(readFileSync(resolve(migrationDirectory, migration), 'utf8'));
  }
}

async function seedOwnershipTransfers(client: pg.Client): Promise<void> {
  await client.query(`
    INSERT INTO users (id, username, display_name, email) VALUES
      ('migration-owner', 'migration-owner', 'Migration Owner', 'owner@example.test'),
      ('migration-target', 'migration-target', 'Migration Target', 'target@example.test');

    INSERT INTO user_devices (
      id, user_id, device_type, status, trust_method, key_fingerprint,
      public_encryption_key, public_signing_key, certificate_payload,
      certificate_signature, activated_at
    ) VALUES (
      '20000000-0000-4000-8000-000000000001', 'migration-owner', 'web', 'active',
      'master_password', 'migration-device', decode(repeat('11', 32), 'hex'),
      decode(repeat('22', 32), 'hex'), decode('01', 'hex'),
      decode(repeat('33', 64), 'hex'), now()
    );

    INSERT INTO vaults (id, kind, name, owner_user_id) VALUES
      ('10000000-0000-4000-8000-000000000001', 'team', '', NULL),
      ('10000000-0000-4000-8000-000000000002', 'team', '', NULL),
      ('10000000-0000-4000-8000-000000000003', 'team', '', NULL);

    INSERT INTO vault_key_epochs (
      vault_id, epoch, status, reason, metadata_key_commitment,
      content_key_commitment, recipient_set_digest, activated_at
    ) VALUES
      ('10000000-0000-4000-8000-000000000001', 1, 'active', 'initial',
       decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'), now()),
      ('10000000-0000-4000-8000-000000000002', 1, 'active', 'initial',
       decode(repeat('04', 32), 'hex'), decode(repeat('05', 32), 'hex'), decode(repeat('06', 32), 'hex'), now()),
      ('10000000-0000-4000-8000-000000000003', 1, 'active', 'initial',
       decode(repeat('07', 32), 'hex'), decode(repeat('08', 32), 'hex'), decode(repeat('09', 32), 'hex'), now());

    INSERT INTO vault_envelope_tasks (
      id, vault_id, key_epoch, authorization_kind, authorization_ref,
      recipient_user_id, capability
    ) VALUES
      ('30000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001',
       1, 'direct', 'migration-target', 'migration-target', 'full'),
      ('30000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000002',
       1, 'direct', 'migration-target', 'migration-target', 'full'),
      ('30000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000003',
       1, 'direct', 'migration-target', 'migration-target', 'full');

    INSERT INTO vault_ownership_transfer_requests (
      id, vault_id, from_owner_user_id, to_owner_user_id, envelope_task_id,
      expected_access_generation, status, acceptance_required, requested_by_device_id,
      completed_at, cancelled_at
    ) VALUES
      ('40000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001',
       'migration-owner', 'migration-target', '30000000-0000-4000-8000-000000000001',
       1, 'pending', true, '20000000-0000-4000-8000-000000000001', NULL, NULL),
      ('40000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000002',
       'migration-owner', 'migration-target', '30000000-0000-4000-8000-000000000002',
       1, 'completed', false, '20000000-0000-4000-8000-000000000001', now(), NULL),
      ('40000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000003',
       'migration-owner', 'migration-target', '30000000-0000-4000-8000-000000000003',
       1, 'cancelled', false, '20000000-0000-4000-8000-000000000001', NULL, now());
  `);
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
