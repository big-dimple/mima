import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  encryptedVaultHeaders,
  enterpriseRecoveryKeys,
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
} from '../../src/db/schema.ts';
import {
  ensureEnvelopeTasks,
  reconcilePendingEnvelopeTasksForProfile,
  settleEnvelopeTasksAfterRekey,
} from '../../src/services/vault-envelope-tasks.ts';
import { freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let recipient: TestSession;
let vaultId: string;
let ownerDeviceId: string;
let recipientDeviceId: string;
let extensionDeviceId: string;
let ownerProfile: ReturnType<typeof profile>;

beforeAll(async () => {
  app = await freshTestApp('mima_test_vault_envelope_tasks_db');
  owner = await login(app, 'bob');
  recipient = await login(app, 'dave');
  ownerDeviceId = randomUUID();
  recipientDeviceId = randomUUID();
  extensionDeviceId = randomUUID();
  ownerProfile = profile(owner.userId);
  await app.ctx.db.insert(userCryptoProfiles).values(ownerProfile);
  await app.ctx.db.insert(userDevices).values([
    device(ownerDeviceId, owner.userId, 'web'),
    device(recipientDeviceId, recipient.userId, 'web'),
    device(extensionDeviceId, recipient.userId, 'extension'),
  ]);
  vaultId = (await app.ctx.db.insert(vaults).values({
    kind: 'team', name: '', ownerUserId: null,
  }).returning())[0]!.id;
  await app.ctx.db.insert(vaultMemberships).values([
    { vaultId, subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
    { vaultId, subjectKind: 'user', subjectId: recipient.userId, role: 'viewer' },
    { vaultId, subjectKind: 'group', subjectId: 'group:test/envelope', role: 'viewer' },
  ]);
  const commitments = { metadataKeyCommitment: randomBytes(32), contentKeyCommitment: randomBytes(32), recipientSetDigest: randomBytes(32) };
  await app.ctx.db.insert(vaultKeyEpochs).values({
    vaultId, epoch: 1, status: 'active', reason: 'initial', ...commitments,
    createdByUserId: owner.userId, createdByDeviceId: ownerDeviceId, activatedAt: new Date(),
  });
  const recovery = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: 'task-test-ceremony',
    keyFingerprint: randomBytes(32).toString('base64url'),
    publicEncryptionKey: randomBytes(32),
    status: 'active',
    ceremonyEvidenceDigest: randomBytes(32),
    createdByUserId: owner.userId,
  }).returning())[0]!;
  const recoveryCiphertext = randomBytes(96);
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId, keyEpoch: 1, recipientKind: 'enterprise_recovery', accessScope: 'recovery',
    recipientRecoveryKeyId: recovery.id, recipientKeyFingerprint: recovery.keyFingerprint,
    authorizationKind: 'recovery', authorizationRef: recovery.id, envelopeVersion: 1,
    ciphertext: recoveryCiphertext,
    ciphertextDigest: createHash('sha256').update(recoveryCiphertext).digest(),
    senderDeviceId: ownerDeviceId,
    signerUserId: owner.userId,
    signerKeyVersion: ownerProfile.cryptoGeneration,
    signerPublicKey: ownerProfile.publicSigningKey,
    signature: randomBytes(64), status: 'active', activatedAt: new Date(),
  });
  await app.ctx.db.insert(encryptedVaultHeaders).values({
    vaultId, headerVersion: 1, keyEpoch: 1,
    ciphertext: randomBytes(64), nonce: randomBytes(24), ciphertextDigest: randomBytes(32),
    createdByDeviceId: ownerDeviceId, signature: randomBytes(64),
  });
  await app.ctx.db.update(vaultCryptoStates).set({
    storageMode: 'e2ee', writeState: 'open', activeEpoch: 1, activeHeaderVersion: 1,
    accessGeneration: 1, rowVersion: 2, cutoverAt: new Date(), legacyReadDisabledAt: new Date(),
  }).where(eq(vaultCryptoStates.vaultId, vaultId));
});

afterAll(async () => {
  await app.close();
});

describe('vault envelope task persistence', () => {
  it('keeps a no-profile recipient pending and rebuilds exactly once for the new profile generation', async () => {
    const first = await ensureEnvelopeTasks(app.ctx.db, {
      vaultId,
      keyEpoch: 1,
      authorizationKind: 'direct',
      authorizationRef: recipient.userId,
      recipientUserIds: [recipient.userId],
      capability: 'full',
    });
    expect(first).toEqual({ pending: 1, completed: 0, withoutProfile: 1 });
    let pending = await pendingTasks('direct');
    expect(pending).toHaveLength(1);
    expect(pending[0]!.expectedProfileGeneration).toBeNull();

    await app.ctx.db.insert(userCryptoProfiles).values(profile(recipient.userId));
    const reconciliation = await app.ctx.db.transaction(
      (tx) => reconcilePendingEnvelopeTasksForProfile(tx, recipient.userId, 1),
    );
    expect(reconciliation).toEqual({ rebuilt: 1, vaultIds: [vaultId] });
    await Promise.all([
      ensureEnvelopeTasks(app.ctx.db, {
        vaultId, keyEpoch: 1, authorizationKind: 'direct', authorizationRef: recipient.userId,
        recipientUserIds: [recipient.userId], capability: 'full',
      }),
      ensureEnvelopeTasks(app.ctx.db, {
        vaultId, keyEpoch: 1, authorizationKind: 'direct', authorizationRef: recipient.userId,
        recipientUserIds: [recipient.userId], capability: 'full',
      }),
    ]);
    pending = await pendingTasks('direct');
    expect(pending).toHaveLength(1);
    expect(pending[0]!.expectedProfileGeneration).toBe(1);
  });

  it('does not satisfy a direct task with a directory-group envelope for the same user and epoch', async () => {
    const recipientProfile = (await app.ctx.db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, recipient.userId)).limit(1))[0]!;
    const directoryEnvelope = (await app.ctx.db.insert(vaultKeyEnvelopes).values(envelope({
      recipientKind: 'user',
      recipientUserId: recipient.userId,
      fingerprint: fingerprint(recipientProfile.publicEncryptionKey),
      senderDeviceId: ownerDeviceId,
    })).returning())[0]!;

    await ensureEnvelopeTasks(app.ctx.db, {
      vaultId,
      keyEpoch: 1,
      authorizationKind: 'direct',
      authorizationRef: recipient.userId,
      recipientUserIds: [recipient.userId],
      capability: 'full',
    });

    const directTasks = await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, vaultId),
      eq(vaultEnvelopeTasks.authorizationKind, 'direct'),
      eq(vaultEnvelopeTasks.authorizationRef, recipient.userId),
    ));
    expect(directTasks.filter((task) => task.status === 'pending')).toHaveLength(1);
    expect(directTasks.some((task) => task.completedEnvelopeId === directoryEnvelope.id)).toBe(false);

    await app.ctx.db.delete(vaultKeyEnvelopes).where(eq(vaultKeyEnvelopes.id, directoryEnvelope.id));
  });

  it('does not settle a direct task with a rekey envelope from another authorization source', async () => {
    const recipientProfile = (await app.ctx.db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, recipient.userId)).limit(1))[0]!;
    await app.ctx.db.insert(vaultKeyEpochs).values({
      vaultId,
      epoch: 2,
      previousEpoch: 1,
      status: 'preparing',
      reason: 'membership_change',
      metadataKeyCommitment: randomBytes(32),
      contentKeyCommitment: randomBytes(32),
      recipientSetDigest: randomBytes(32),
      createdByUserId: owner.userId,
      createdByDeviceId: ownerDeviceId,
    });
    const directoryEnvelope = (await app.ctx.db.insert(vaultKeyEnvelopes).values({
      ...envelope({
        recipientKind: 'user',
        recipientUserId: recipient.userId,
        fingerprint: fingerprint(recipientProfile.publicEncryptionKey),
        senderDeviceId: ownerDeviceId,
      }),
      keyEpoch: 2,
    }).returning())[0]!;

    await settleEnvelopeTasksAfterRekey(app.ctx.db, vaultId, 2, [directoryEnvelope]);

    const directTask = (await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, vaultId),
      eq(vaultEnvelopeTasks.keyEpoch, 2),
      eq(vaultEnvelopeTasks.authorizationKind, 'direct'),
      eq(vaultEnvelopeTasks.authorizationRef, recipient.userId),
    )))[0];
    expect(directTask).toMatchObject({ status: 'pending', completedEnvelopeId: null });

    await app.ctx.db.delete(vaultKeyEpochs).where(and(
      eq(vaultKeyEpochs.vaultId, vaultId),
      eq(vaultKeyEpochs.epoch, 2),
    ));
  });

  it('directory removal revokes user and extension envelopes, cancels tasks, and freezes for owner rekey', async () => {
    const recipientProfile = (await app.ctx.db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, recipient.userId)).limit(1))[0]!;
    await app.ctx.db.delete(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, recipient.userId),
    ));
    await app.ctx.db.update(users).set({ groups: ['group:test/envelope'] }).where(eq(users.id, recipient.userId));
    await app.ctx.db.insert(vaultKeyEnvelopes).values([
      envelope({
        recipientKind: 'user', recipientUserId: recipient.userId,
        fingerprint: fingerprint(recipientProfile.publicEncryptionKey), senderDeviceId: ownerDeviceId,
      }),
      envelope({
        recipientKind: 'device', recipientDeviceId: extensionDeviceId,
        fingerprint: `extension-${extensionDeviceId}`, senderDeviceId: ownerDeviceId,
      }),
    ]);
    await ensureEnvelopeTasks(app.ctx.db, {
      vaultId, keyEpoch: 1, authorizationKind: 'directory_group', authorizationRef: 'group:test/envelope',
      recipientUserIds: [recipient.userId], capability: 'full',
    });

    const published: Array<{ type: string; vaultId: string }> = [];
    const unsubscribe = app.ctx.bus.subscribe((event) => published.push(event));
    const current = (await app.ctx.db.select().from(users).where(eq(users.id, recipient.userId)).limit(1))[0]!;
    try {
      await app.ctx.auth.sessions.create({
        id: current.id,
        username: current.username,
        displayName: current.displayName,
        email: current.email,
        groups: [],
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

    const envelopes = await app.ctx.db.select().from(vaultKeyEnvelopes).where(eq(vaultKeyEnvelopes.vaultId, vaultId));
    const revokedTargets = envelopes.filter(
      (row) => row.recipientUserId === recipient.userId || row.recipientDeviceId === extensionDeviceId,
    );
    expect(revokedTargets).toHaveLength(2);
    expect(revokedTargets.every((row) => row.status === 'revoked')).toBe(true);
    expect(await pendingTasks()).toHaveLength(0);
    const state = (await app.ctx.db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, vaultId)))[0]!;
    expect(state.writeState).toBe('rekeying');
    const jobs = await app.ctx.db.select().from(vaultRekeyJobs).where(eq(vaultRekeyJobs.vaultId, vaultId));
    expect(jobs).toHaveLength(1);
    expect(jobs[0]).toMatchObject({ reason: 'membership_change', status: 'pending' });
    expect(jobs[0]!.initiatedByUserId).toBeNull();
    expect(jobs[0]!.initiatedByDeviceId).toBeNull();
    expect(published).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'vault.rekey_required', vaultId }),
    ]));
  });
});

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
    signingKeyFingerprint: randomBytes(32).toString('base64url'),
  };
}

function device(id: string, userId: string, deviceType: 'web' | 'extension') {
  return {
    id,
    userId,
    deviceType,
    status: 'active' as const,
    trustMethod: deviceType === 'extension' ? 'device_approval' as const : 'master_password' as const,
    keyFingerprint: `${deviceType}-${id}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  };
}

function envelope(input: {
  recipientKind: 'user' | 'device';
  recipientUserId?: string;
  recipientDeviceId?: string;
  fingerprint: string;
  senderDeviceId: string;
}) {
  const ciphertext = randomBytes(96);
  return {
    vaultId,
    keyEpoch: 1,
    recipientKind: input.recipientKind,
    accessScope: 'full' as const,
    recipientUserId: input.recipientUserId ?? null,
    recipientDeviceId: input.recipientDeviceId ?? null,
    recipientKeyFingerprint: input.fingerprint,
    authorizationKind: 'directory_group' as const,
    authorizationRef: 'group:test/envelope',
    envelopeVersion: 1,
    ciphertext,
    ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
    senderDeviceId: input.senderDeviceId,
    signerUserId: owner.userId,
    signerKeyVersion: ownerProfile.cryptoGeneration,
    signerPublicKey: ownerProfile.publicSigningKey,
    signature: randomBytes(64),
    status: 'active' as const,
    activatedAt: new Date(),
  };
}

function fingerprint(key: Uint8Array): string {
  return createHash('sha256').update(key).digest('base64url');
}

async function pendingTasks(kind?: 'direct' | 'directory_group') {
  return app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
    eq(vaultEnvelopeTasks.vaultId, vaultId),
    eq(vaultEnvelopeTasks.status, 'pending'),
    ...(kind ? [eq(vaultEnvelopeTasks.authorizationKind, kind)] : []),
  ));
}
