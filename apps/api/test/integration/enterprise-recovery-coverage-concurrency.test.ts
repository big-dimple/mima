import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  encryptedVaultHeaders,
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryKeys,
  systemRoleAssignments,
  userDevices,
  vaultKeyEpochs,
  vaultMemberships,
  vaults,
} from '../../src/db/schema.ts';
import { freshTestApp, login, testDbUrl, type TestSession } from './helpers.ts';

const databaseName = 'mima_test_enterprise_recovery_coverage_concurrency';
let app: FastifyInstance;
let owner: TestSession;
let secondAdmin: TestSession;

beforeAll(async () => {
  app = await freshTestApp(databaseName);
  owner = await login(app, 'bob');
  secondAdmin = await login(app, 'dave');
});

afterAll(async () => {
  await app.close();
});

describe('enterprise recovery coverage serialization', () => {
  it('blocks recovery activation until a concurrent e2ee cutover commits, then rejects incomplete coverage', async () => {
    const deviceId = randomUUID();
    await app.ctx.db.insert(userDevices).values({
      id: deviceId,
      userId: owner.userId,
      deviceType: 'web',
      status: 'active',
      trustMethod: 'master_password',
      keyFingerprint: `coverage-${deviceId}`,
      publicEncryptionKey: randomBytes(32),
      publicSigningKey: randomBytes(32),
      certificatePayload: randomBytes(96),
      certificateSignature: randomBytes(64),
      activatedAt: new Date(),
    });
    const vault = (await app.ctx.db.insert(vaults).values({
      kind: 'team', name: '', ownerUserId: null,
    }).returning())[0]!;
    await app.ctx.db.insert(vaultMemberships).values({
      vaultId: vault.id,
      subjectKind: 'user',
      subjectId: owner.userId,
      role: 'owner',
    });
    await app.ctx.db.insert(vaultKeyEpochs).values({
      vaultId: vault.id,
      epoch: 1,
      status: 'active',
      reason: 'initial',
      metadataKeyCommitment: randomBytes(32),
      contentKeyCommitment: randomBytes(32),
      recipientSetDigest: randomBytes(32),
      createdByUserId: owner.userId,
      createdByDeviceId: deviceId,
      activatedAt: new Date(),
    });
    await app.ctx.db.insert(encryptedVaultHeaders).values({
      vaultId: vault.id,
      headerVersion: 1,
      keyEpoch: 1,
      ciphertext: randomBytes(64),
      nonce: randomBytes(24),
      ciphertextDigest: randomBytes(32),
      createdByDeviceId: deviceId,
      signature: randomBytes(64),
    });

    await app.ctx.db.insert(systemRoleAssignments).values([
      { userId: owner.userId, role: 'platform-admin', assignedBy: 'test' },
      { userId: secondAdmin.userId, role: 'platform-admin', assignedBy: 'test' },
    ]).onConflictDoNothing();
    const evidenceDigest = randomBytes(32);
    const recoveryKey = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
      ceremonyId: `coverage-${randomUUID()}`,
      keyFingerprint: randomBytes(32).toString('base64url'),
      publicEncryptionKey: randomBytes(32),
      ceremonyEvidenceDigest: evidenceDigest,
      createdByUserId: owner.userId,
    }).returning())[0]!;
    await app.ctx.db.insert(enterpriseRecoveryKeyApprovals).values([
      { recoveryKeyId: recoveryKey.id, approverUserId: owner.userId, ceremonyEvidenceDigest: evidenceDigest },
      { recoveryKeyId: recoveryKey.id, approverUserId: secondAdmin.userId, ceremonyEvidenceDigest: evidenceDigest },
    ]);
    expect((await app.ctx.db.select().from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.id, recoveryKey.id)))[0]).toMatchObject({ status: 'staged' });

    const cutover = new pg.Client({ connectionString: testDbUrl(databaseName) });
    const activation = new pg.Client({ connectionString: testDbUrl(databaseName) });
    await Promise.all([cutover.connect(), activation.connect()]);
    try {
      await cutover.query('BEGIN');
      await cutover.query(`
        UPDATE vault_crypto_states
        SET storage_mode = 'e2ee', active_epoch = 1, active_header_version = 1,
            access_generation = 1, row_version = row_version + 1,
            cutover_at = now(), legacy_read_disabled_at = now(), updated_at = now()
        WHERE vault_id = $1
      `, [vault.id]);

      await activation.query('BEGIN');
      let activationSettled = false;
      const activating = activation.query(
        `UPDATE enterprise_recovery_keys SET status = 'active' WHERE id = $1`,
        [recoveryKey.id],
      ).then(
        (value) => ({ status: 'fulfilled' as const, value }),
        (reason: unknown) => ({ status: 'rejected' as const, reason }),
      ).finally(() => { activationSettled = true; });
      await delay(100);
      expect(activationSettled).toBe(false);

      await cutover.query('COMMIT');
      const activationResult = await activating;
      expect(activationResult.status).toBe('rejected');
      if (activationResult.status === 'rejected') {
        expect(activationResult.reason).toBeInstanceOf(Error);
        expect((activationResult.reason as Error).message).toMatch(/does not cover every e2ee vault/);
      }
      await activation.query('ROLLBACK');
    } finally {
      await Promise.all([
        cutover.query('ROLLBACK').catch(() => undefined),
        activation.query('ROLLBACK').catch(() => undefined),
      ]);
      await Promise.all([cutover.end(), activation.end()]);
    }

    expect((await app.ctx.db.select().from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.id, recoveryKey.id)))[0]).toMatchObject({ status: 'staged' });
  });
});

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
