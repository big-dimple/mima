import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq, inArray, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import pg from 'pg';
import {
  customGroupMembers,
  customGroups,
  encryptedVaultHeaders,
  enterpriseRecoveryKeys,
  extensionPairingCodes,
  extensionSessions,
  sessions,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultEnvelopeTasks,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaultRekeyJobs,
  vaults,
  vaultCustomGroupRoles,
} from '../../src/db/schema.ts';
import { hashToken } from '../../src/plugins/auth.ts';
import type { SyncEventRow } from '../../src/services/bus.ts';
import { reconcileDirectoryMembershipChange } from '../../src/services/vault-envelope-tasks.ts';
import { freshTestApp, login, testDbUrl, type TestSession } from './helpers.ts';

const TEST_DB_NAME = 'mima_test_directory_membership_reconcile';

let app: FastifyInstance;
let owner: TestSession;
let retainedUser: TestSession;
let downgradedUser: TestSession;
let reactivatedUser: TestSession;
let ownerDeviceId: string;
let retainedDeviceId: string;
let downgradedDeviceId: string;
let reactivatedDeviceId: string;
let recoveryKeyId: string;
let recoveryKeyFingerprint: string;

beforeAll(async () => {
  app = await freshTestApp(TEST_DB_NAME);
  owner = await login(app, 'bob');
  retainedUser = await login(app, 'dave');
  downgradedUser = await login(app, 'carol');
  reactivatedUser = await login(app, 'erin');

  ownerDeviceId = randomUUID();
  retainedDeviceId = randomUUID();
  downgradedDeviceId = randomUUID();
  reactivatedDeviceId = randomUUID();
  await app.ctx.db.insert(userCryptoProfiles).values([
    profile(retainedUser.userId),
    profile(downgradedUser.userId),
    profile(reactivatedUser.userId),
  ]);
  await app.ctx.db.insert(userDevices).values([
    device(ownerDeviceId, owner.userId),
    device(retainedDeviceId, retainedUser.userId),
    device(downgradedDeviceId, downgradedUser.userId),
    device(reactivatedDeviceId, reactivatedUser.userId),
  ]);
  recoveryKeyFingerprint = `directory-reconcile-recovery-${randomUUID()}`;
  recoveryKeyId = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: `directory-reconcile-${randomUUID()}`,
    keyFingerprint: recoveryKeyFingerprint,
    publicEncryptionKey: randomBytes(32),
    status: 'active',
    ceremonyEvidenceDigest: randomBytes(32),
    createdByUserId: owner.userId,
  }).returning())[0]!.id;
});

afterAll(async () => {
  await app.close();
});

describe('directory membership reconciliation', () => {
  it('keeps direct and alternate-group access, revokes old sessions, and publishes committed events', async () => {
    const removedGroup = 'group:test/removed-full';
    const remainingGroup = 'group:test/remaining-full';
    await app.ctx.db.update(users).set({ groups: [removedGroup, remainingGroup] })
      .where(eq(users.id, retainedUser.userId));

    const directVaultId = await createTeamVault([
      { subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
      { subjectKind: 'user', subjectId: retainedUser.userId, role: 'viewer' },
      { subjectKind: 'group', subjectId: removedGroup, role: 'editor' },
    ]);
    const groupVaultId = await createTeamVault([
      { subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
      { subjectKind: 'group', subjectId: removedGroup, role: 'editor' },
      { subjectKind: 'group', subjectId: remainingGroup, role: 'viewer' },
    ]);
    for (const vaultId of [directVaultId, groupVaultId]) {
      await insertEnvelope({
        vaultId,
        recipientKind: 'user',
        recipientUserId: retainedUser.userId,
        accessScope: 'full',
        authorizationKind: 'directory_group',
        authorizationRef: removedGroup,
      });
      await insertEnvelope({
        vaultId,
        recipientKind: 'device',
        recipientDeviceId: retainedDeviceId,
        accessScope: 'full',
        authorizationKind: 'directory_group',
        authorizationRef: removedGroup,
      });
    }
    await insertEnvelope({
      vaultId: directVaultId,
      recipientKind: 'user',
      recipientUserId: retainedUser.userId,
      accessScope: 'full',
      authorizationKind: 'direct',
      authorizationRef: retainedUser.userId,
    });
    await insertEnvelope({
      vaultId: groupVaultId,
      recipientKind: 'user',
      recipientUserId: retainedUser.userId,
      accessScope: 'full',
      authorizationKind: 'directory_group',
      authorizationRef: remainingGroup,
    });

    const oldToken = retainedUser.cookie.split('=')[1]!;
    const oldSession = (await app.ctx.db.select().from(sessions)
      .where(eq(sessions.tokenHash, hashToken(oldToken))).limit(1))[0]!;
    await app.ctx.db.insert(extensionSessions).values({
      tokenHash: hashToken('directory-reconcile-extension-session'),
      userId: retainedUser.userId,
      deviceId: retainedDeviceId,
      securityGeneration: 1,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await app.ctx.db.insert(extensionPairingCodes).values({
      code: 'directory-reconcile-pairing-code',
      userId: retainedUser.userId,
      sessionId: oldSession.id,
      expiresAt: new Date(Date.now() + 60_000),
    });

    const published: SyncEventRow[] = [];
    const unsubscribe = app.ctx.bus.subscribe((event) => published.push(event));
    const current = (await app.ctx.db.select().from(users)
      .where(eq(users.id, retainedUser.userId)).limit(1))[0]!;
    let created;
    try {
      created = await app.ctx.auth.sessions.create({
        id: current.id,
        username: current.username,
        displayName: current.displayName,
        email: current.email,
        groups: [remainingGroup],
        source: current.source,
        active: true,
      }, {
        method: 'password',
        provider: 'dev',
        authenticatedAt: new Date(),
      });
    } finally {
      unsubscribe();
    }

    const remainingSessions = await app.ctx.db.select().from(sessions)
      .where(eq(sessions.userId, retainedUser.userId));
    expect(remainingSessions).toHaveLength(1);
    expect(remainingSessions[0]!.tokenHash).toBe(hashToken(created!.token));
    expect((await app.inject({
      method: 'GET',
      url: '/api/session',
      headers: { cookie: retainedUser.cookie },
    })).statusCode).toBe(401);
    expect(await app.ctx.db.select().from(extensionSessions)
      .where(eq(extensionSessions.userId, retainedUser.userId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(extensionPairingCodes)
      .where(eq(extensionPairingCodes.userId, retainedUser.userId))).toHaveLength(0);

    const envelopes = await app.ctx.db.select().from(vaultKeyEnvelopes)
      .where(inArray(vaultKeyEnvelopes.vaultId, [directVaultId, groupVaultId]));
    expect(envelopes.filter((row) => row.authorizationRef === removedGroup)
      .every((row) => row.status === 'active')).toBe(true);
    expect(envelopes.find((row) =>
      row.vaultId === directVaultId && row.authorizationKind === 'direct')?.status).toBe('active');
    expect(envelopes.find((row) =>
      row.vaultId === groupVaultId && row.authorizationRef === remainingGroup)?.status).toBe('active');
    expect(await app.ctx.db.select().from(vaultRekeyJobs)
      .where(inArray(vaultRekeyJobs.vaultId, [directVaultId, groupVaultId]))).toHaveLength(0);
    const states = await app.ctx.db.select().from(vaultCryptoStates)
      .where(inArray(vaultCryptoStates.vaultId, [directVaultId, groupVaultId]));
    expect(states.every((state) => state.writeState === 'open' && state.accessGeneration === 2)).toBe(true);
    expect(published).toHaveLength(2);
    expect(new Set(published.map((event) => event.vaultId))).toEqual(new Set([directVaultId, groupVaultId]));
    expect(published.every((event) => event.type === 'vault.crypto_changed')).toBe(true);
  });

  it('requires rekey when removing full access leaves only metadata access', async () => {
    const removedGroup = 'group:test/downgrade-full';
    const auditorGroup = 'group:test/downgrade-auditor';
    await app.ctx.db.update(users).set({ groups: [removedGroup, auditorGroup] })
      .where(eq(users.id, downgradedUser.userId));
    const vaultId = await createTeamVault([
      { subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
      { subjectKind: 'group', subjectId: removedGroup, role: 'editor' },
      { subjectKind: 'group', subjectId: auditorGroup, role: 'auditor' },
    ]);
    await insertEnvelope({
      vaultId,
      recipientKind: 'user',
      recipientUserId: downgradedUser.userId,
      accessScope: 'full',
      authorizationKind: 'directory_group',
      authorizationRef: removedGroup,
    });
    await insertEnvelope({
      vaultId,
      recipientKind: 'device',
      recipientDeviceId: downgradedDeviceId,
      accessScope: 'full',
      authorizationKind: 'directory_group',
      authorizationRef: removedGroup,
    });
    await insertEnvelope({
      vaultId,
      recipientKind: 'user',
      recipientUserId: downgradedUser.userId,
      accessScope: 'metadata',
      authorizationKind: 'directory_group',
      authorizationRef: auditorGroup,
    });

    const result = await app.ctx.db.transaction(async (tx) => {
      await tx.update(users).set({ groups: [auditorGroup] }).where(eq(users.id, downgradedUser.userId));
      return reconcileDirectoryMembershipChange(
        tx,
        downgradedUser.userId,
        [removedGroup, auditorGroup],
        [auditorGroup],
      );
    });

    expect(result.rekeyVaultIds).toEqual([vaultId]);
    expect(result.events).toHaveLength(1);
    expect(result.events[0]).toMatchObject({ type: 'vault.rekey_required', vaultId });
    const envelopes = await app.ctx.db.select().from(vaultKeyEnvelopes)
      .where(and(
        eq(vaultKeyEnvelopes.vaultId, vaultId),
        eq(vaultKeyEnvelopes.recipientUserId, downgradedUser.userId),
      ));
    expect(envelopes).toHaveLength(2);
    expect(envelopes.every((envelope) => envelope.status === 'revoked')).toBe(true);
    const deviceEnvelope = (await app.ctx.db.select().from(vaultKeyEnvelopes)
      .where(and(
        eq(vaultKeyEnvelopes.vaultId, vaultId),
        eq(vaultKeyEnvelopes.recipientDeviceId, downgradedDeviceId),
      )))[0]!;
    expect(deviceEnvelope.status).toBe('revoked');
    const state = (await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, vaultId)))[0]!;
    expect(state.writeState).toBe('rekeying');
    expect(await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.vaultId, vaultId))).toHaveLength(1);
  });

  it('uses the locked epoch when directory revocation races a completed rekey', async () => {
    const removedGroup = `group:test/rekey-race-${randomUUID()}`;
    await app.ctx.db.update(users).set({ groups: [removedGroup] })
      .where(eq(users.id, downgradedUser.userId));
    const vaultId = await createTeamVault([
      { subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
      { subjectKind: 'group', subjectId: removedGroup, role: 'editor' },
    ]);
    await insertEnvelope({
      vaultId,
      recipientKind: 'user',
      recipientUserId: downgradedUser.userId,
      accessScope: 'full',
      authorizationKind: 'directory_group',
      authorizationRef: removedGroup,
    });
    await app.ctx.db.update(users).set({ groups: [] }).where(eq(users.id, downgradedUser.userId));

    const epochCommitter = new pg.Client({ connectionString: testDbUrl(TEST_DB_NAME) });
    const observer = new pg.Client({ connectionString: testDbUrl(TEST_DB_NAME) });
    await epochCommitter.connect();
    await observer.connect();
    let holderReleased = false;
    let reconcileSettled: Promise<void> | null = null;
    try {
      await epochCommitter.query('BEGIN');
      await epochCommitter.query(
        'SELECT vault_id FROM vault_crypto_states WHERE vault_id = $1 FOR UPDATE',
        [vaultId],
      );

      const applicationName = `directory-rekey-race-${randomUUID()}`;
      const reconcilePromise = app.ctx.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT set_config('application_name', ${applicationName}, true)`);
        return reconcileDirectoryMembershipChange(
          tx,
          downgradedUser.userId,
          [removedGroup],
          [],
        );
      });
      reconcileSettled = reconcilePromise.then(() => undefined, () => undefined);
      await waitForLockWait(observer, applicationName);

      await completeEpochOneToTwo(epochCommitter, vaultId);
      await epochCommitter.query('COMMIT');
      holderReleased = true;

      const result = await reconcilePromise;
      expect(result.rekeyVaultIds).toEqual([vaultId]);
      expect(result.events).toHaveLength(1);
      expect(result.events[0]?.payload).toMatchObject({ pendingEpoch: 3 });

      const state = (await app.ctx.db.select().from(vaultCryptoStates)
        .where(eq(vaultCryptoStates.vaultId, vaultId)))[0]!;
      const jobs = await app.ctx.db.select().from(vaultRekeyJobs)
        .where(eq(vaultRekeyJobs.vaultId, vaultId));
      const activeJobs = jobs.filter((job) =>
        ['pending', 'distributing', 'rewrapping', 'verifying', 'ready'].includes(job.status)
      );
      expect(jobs.find((job) => job.status === 'committed')).toMatchObject({
        fromEpoch: 1,
        toEpoch: 2,
      });
      expect(activeJobs).toHaveLength(1);
      expect(activeJobs[0]).toMatchObject({ fromEpoch: 2, toEpoch: 3, status: 'pending' });
      expect(state).toMatchObject({
        activeEpoch: 2,
        writeState: 'rekeying',
        accessGeneration: 3,
      });
      if (state.writeState === 'rekeying') {
        expect(activeJobs.some((job) => job.fromEpoch === state.activeEpoch)).toBe(true);
      }
      expect((await app.ctx.db.select().from(vaultKeyEpochs).where(and(
        eq(vaultKeyEpochs.vaultId, vaultId),
        eq(vaultKeyEpochs.epoch, 3),
      )))[0]).toMatchObject({ previousEpoch: 2, status: 'preparing' });
    } finally {
      if (!holderReleased) await epochCommitter.query('ROLLBACK').catch(() => undefined);
      await reconcileSettled;
      await observer.end();
      await epochCommitter.end();
    }
  });

  it('reactivates personal, direct, and custom-group vaults without losing their state', async () => {
    await app.ctx.db.update(users).set({ active: false, groups: [] })
      .where(eq(users.id, reactivatedUser.userId));
    const personalVaultId = (await app.ctx.db.select({ id: vaults.id }).from(vaults).where(and(
      eq(vaults.kind, 'personal'),
      eq(vaults.ownerUserId, reactivatedUser.userId),
    )).limit(1))[0]!.id;
    await activateE2eeVault(personalVaultId, reactivatedUser.userId, reactivatedDeviceId);
    const directVaultId = await createTeamVault([
      { subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
      { subjectKind: 'user', subjectId: reactivatedUser.userId, role: 'viewer' },
    ]);
    const customVaultId = await createTeamVault([
      { subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
    ]);
    const customGroup = (await app.ctx.db.insert(customGroups).values({
      ownerUserId: owner.userId,
      name: '重新激活测试组',
    }).returning())[0]!;
    await app.ctx.db.insert(customGroupMembers).values({
      groupId: customGroup.id,
      userId: reactivatedUser.userId,
      addedBy: owner.userId,
    });
    await app.ctx.db.insert(vaultCustomGroupRoles).values({
      vaultId: customVaultId,
      groupId: customGroup.id,
      role: 'viewer',
    });

    const result = await app.ctx.db.transaction(async (tx) => {
      await tx.update(users).set({ active: true }).where(eq(users.id, reactivatedUser.userId));
      return reconcileDirectoryMembershipChange(
        tx,
        reactivatedUser.userId,
        [],
        [],
        new Date(),
        true,
        false,
      );
    });

    const expectedVaultIds = [personalVaultId, directVaultId, customVaultId];
    expect(new Set(result.addedVaultIds)).toEqual(new Set(expectedVaultIds));
    expect(result.rekeyVaultIds).toEqual([]);
    expect(result.events).toHaveLength(3);
    expect(result.events.every((event) => event.type === 'vault.crypto_changed')).toBe(true);
    const states = await app.ctx.db.select().from(vaultCryptoStates)
      .where(inArray(vaultCryptoStates.vaultId, expectedVaultIds));
    expect(states.every((state) => state.accessGeneration === 2 && state.writeState === 'open')).toBe(true);
    const tasks = await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.recipientUserId, reactivatedUser.userId),
      inArray(vaultEnvelopeTasks.vaultId, expectedVaultIds),
    ));
    expect(tasks).toHaveLength(3);
    expect(new Set(tasks.map((task) => task.authorizationKind))).toEqual(
      new Set(['direct', 'custom_group']),
    );
  });
});

async function waitForLockWait(client: pg.Client, applicationName: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const waiting = await client.query<{ wait_event_type: string | null }>(`
      SELECT wait_event_type
      FROM pg_stat_activity
      WHERE application_name = $1 AND state = 'active'
    `, [applicationName]);
    if (waiting.rows.some((row) => row.wait_event_type === 'Lock')) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('directory reconciliation did not reach the vault state row lock');
}

async function completeEpochOneToTwo(client: pg.Client, vaultId: string): Promise<void> {
  const headerCiphertext = randomBytes(64);
  await client.query(`
    UPDATE vault_key_epochs
    SET status = 'retired', retired_at = now()
    WHERE vault_id = $1 AND epoch = 1
  `, [vaultId]);
  await client.query(`
    INSERT INTO vault_key_epochs (
      vault_id, epoch, previous_epoch, status, reason,
      metadata_key_commitment, content_key_commitment, recipient_set_digest,
      created_by_user_id, created_by_device_id, activated_at
    ) VALUES ($1, 2, 1, 'active', 'manual', $2, $3, $4, $5, $6, now())
  `, [
    vaultId,
    randomBytes(32),
    randomBytes(32),
    randomBytes(32),
    owner.userId,
    ownerDeviceId,
  ]);
  await client.query(`
    INSERT INTO encrypted_vault_headers (
      vault_id, header_version, key_epoch, ciphertext, nonce, ciphertext_digest,
      created_by_device_id, signature
    ) VALUES ($1, 2, 2, $2, $3, $4, $5, $6)
  `, [
    vaultId,
    headerCiphertext,
    randomBytes(24),
    createHash('sha256').update(headerCiphertext).digest(),
    ownerDeviceId,
    randomBytes(64),
  ]);
  await client.query(`
    INSERT INTO vault_key_envelopes (
      vault_id, key_epoch, recipient_kind, access_scope,
      recipient_user_id, recipient_device_id, recipient_recovery_key_id,
      recipient_key_fingerprint, authorization_kind, authorization_ref,
      algorithm, envelope_version, ciphertext, ciphertext_digest,
      sender_device_id, signature, status, activated_at
    )
    SELECT
      vault_id, 2, recipient_kind, access_scope,
      recipient_user_id, recipient_device_id, recipient_recovery_key_id,
      recipient_key_fingerprint, authorization_kind, authorization_ref,
      algorithm, envelope_version, ciphertext, ciphertext_digest,
      sender_device_id, signature, status, now()
    FROM vault_key_envelopes
    WHERE vault_id = $1 AND key_epoch = 1 AND status = 'active'
  `, [vaultId]);
  await client.query(`
    INSERT INTO vault_rekey_jobs (
      vault_id, from_epoch, to_epoch, reason, status, freeze_generation,
      initiated_by_user_id, initiated_by_device_id, started_at, committed_at
    ) VALUES ($1, 1, 2, 'manual', 'committed', 2, $2, $3, now(), now())
  `, [vaultId, owner.userId, ownerDeviceId]);
  await client.query(`
    UPDATE vault_crypto_states
    SET active_epoch = 2,
        active_header_version = 2,
        write_state = 'open',
        access_generation = 2,
        row_version = row_version + 1,
        updated_at = now()
    WHERE vault_id = $1
  `, [vaultId]);
}

async function createTeamVault(
  memberships: Array<{
    subjectKind: 'user' | 'group';
    subjectId: string;
    role: 'viewer' | 'editor' | 'owner' | 'auditor';
  }>,
): Promise<string> {
  const vault = (await app.ctx.db.insert(vaults).values({
    kind: 'team',
    name: '',
    ownerUserId: null,
  }).returning())[0]!;
  await app.ctx.db.insert(vaultMemberships).values(
    memberships.map((membership) => ({ vaultId: vault.id, ...membership })),
  );
  await activateE2eeVault(vault.id, owner.userId, ownerDeviceId);
  return vault.id;
}

async function activateE2eeVault(vaultId: string, userId: string, deviceId: string): Promise<void> {
  await app.ctx.db.update(vaults).set({ name: '' }).where(eq(vaults.id, vaultId));
  await app.ctx.db.insert(vaultKeyEpochs).values({
    vaultId,
    epoch: 1,
    status: 'active',
    reason: 'initial',
    metadataKeyCommitment: randomBytes(32),
    contentKeyCommitment: randomBytes(32),
    recipientSetDigest: randomBytes(32),
    createdByUserId: userId,
    createdByDeviceId: deviceId,
    activatedAt: new Date(),
  });
  const ciphertext = randomBytes(64);
  await app.ctx.db.insert(encryptedVaultHeaders).values({
    vaultId,
    headerVersion: 1,
    keyEpoch: 1,
    ciphertext,
    nonce: randomBytes(24),
    ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
    createdByDeviceId: deviceId,
    signature: randomBytes(64),
  });
  const recoveryCiphertext = randomBytes(96);
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId,
    keyEpoch: 1,
    recipientKind: 'enterprise_recovery',
    accessScope: 'recovery',
    recipientRecoveryKeyId: recoveryKeyId,
    recipientKeyFingerprint: recoveryKeyFingerprint,
    authorizationKind: 'recovery',
    authorizationRef: recoveryKeyId,
    envelopeVersion: 1,
    ciphertext: recoveryCiphertext,
    ciphertextDigest: createHash('sha256').update(recoveryCiphertext).digest(),
    senderDeviceId: deviceId,
    signature: randomBytes(64),
    status: 'active',
    activatedAt: new Date(),
  });
  await app.ctx.db.update(vaultCryptoStates).set({
    storageMode: 'e2ee',
    writeState: 'open',
    activeEpoch: 1,
    activeHeaderVersion: 1,
    accessGeneration: 1,
    rowVersion: 2,
    cutoverAt: new Date(),
    legacyReadDisabledAt: new Date(),
  }).where(eq(vaultCryptoStates.vaultId, vaultId));
}

async function insertEnvelope(input: {
  vaultId: string;
  recipientKind: 'user' | 'device';
  recipientUserId?: string;
  recipientDeviceId?: string;
  accessScope: 'metadata' | 'full';
  authorizationKind: 'direct' | 'directory_group';
  authorizationRef: string;
}): Promise<void> {
  const ciphertext = randomBytes(96);
  const recipientId = input.recipientUserId ?? input.recipientDeviceId!;
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId: input.vaultId,
    keyEpoch: 1,
    recipientKind: input.recipientKind,
    accessScope: input.accessScope,
    recipientUserId: input.recipientUserId ?? null,
    recipientDeviceId: input.recipientDeviceId ?? null,
    recipientKeyFingerprint: `${input.recipientKind}:${recipientId}`,
    authorizationKind: input.authorizationKind,
    authorizationRef: input.authorizationRef,
    envelopeVersion: 1,
    ciphertext,
    ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
    senderDeviceId: ownerDeviceId,
    signature: randomBytes(64),
    status: 'active',
    activatedAt: new Date(),
  });
}

function profile(userId: string) {
  return {
    userId,
    profileVersion: 1,
    cryptoGeneration: 1,
    kdfSalt: randomBytes(16),
    wrappedAccountKeyCiphertext: randomBytes(96),
    wrappedAccountKeyNonce: randomBytes(24),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    signingKeyFingerprint: `directory-reconcile-${userId}-${randomUUID()}`,
  };
}

function device(id: string, userId: string) {
  return {
    id,
    userId,
    deviceType: 'web' as const,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    keyFingerprint: `directory-reconcile-device-${id}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  };
}
