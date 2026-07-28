import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  encryptedVaultHeaders,
  userCryptoProfiles,
  userDevices,
  vaultCryptoStates,
  vaultEnvelopeTasks,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaultRekeyJobs,
  vaults,
} from '../../src/db/schema.ts';
import { publicKeyFingerprint } from '../../src/services/e2ee.ts';
import { recordAnchor, verifyAuditChain } from '../../src/services/audit.ts';
import {
  cancelNoopMembershipRekey,
  inspectNoopMembershipRekey,
  listActiveMembershipRekeys,
} from '../../src/services/rekey-repair.ts';
import { ensureMembershipRekeyTask } from '../../src/services/vault-envelope-tasks.ts';
import { freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let ownerDeviceId: string;
let ownerProfile: ReturnType<typeof profile>;

beforeAll(async () => {
  app = await freshTestApp('mima_test_rekey_noop_repair');
  owner = await login(app, 'bob');
  ownerDeviceId = randomUUID();
  ownerProfile = profile(owner.userId);
  await app.ctx.db.insert(userCryptoProfiles).values(ownerProfile);
  await app.ctx.db.insert(userDevices).values(device(ownerDeviceId, owner.userId));
});

afterAll(async () => {
  await app.close();
});

describe('no-op membership rekey repair', () => {
  it('lists, proves, and cancels only a pristine no-op membership rekey', async () => {
    const fixture = await createFixture();

    const listed = await listActiveMembershipRekeys(app.ctx.db);
    expect(listed).toContainEqual(expect.objectContaining({
      taskId: fixture.taskId,
      vaultId: fixture.vaultId,
      taskStatus: 'pending',
      diagnosis: 'repairable',
    }));
    await expect(inspectNoopMembershipRekey(app.ctx.db, fixture.taskId)).resolves.toMatchObject({
      taskId: fixture.taskId,
      status: 'repairable',
      targetArtifactCount: 0,
      revokedHolderEnvelopeCount: 0,
    });

    const result = await cancelNoopMembershipRekey(app.ctx.db, app.ctx.audit, fixture.taskId);
    recordAnchor(app.ctx.audit, result.auditHead);
    await expect(verifyAuditChain(app.ctx.db, app.ctx.audit)).resolves.toMatchObject({
      headId: result.auditHead.id,
    });
    expect((await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.id, fixture.taskId)))[0]).toMatchObject({
      status: 'cancelled',
      lastErrorCode: 'no_effective_key_reduction',
    });
    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, fixture.vaultId)))[0]).toMatchObject({
      writeState: 'open',
      activeEpoch: 1,
    });
    expect((await app.ctx.db.select().from(vaultKeyEpochs).where(and(
      eq(vaultKeyEpochs.vaultId, fixture.vaultId),
      eq(vaultKeyEpochs.epoch, 2),
    )))[0]).toMatchObject({ status: 'retired' });
    expect(await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, fixture.vaultId),
      eq(vaultEnvelopeTasks.status, 'completed'),
    ))).toHaveLength(1);
  });

  it('refuses cancellation after any target-epoch artifact exists', async () => {
    const fixture = await createFixture();
    await app.ctx.db.insert(encryptedVaultHeaders).values({
      vaultId: fixture.vaultId,
      headerVersion: 2,
      keyEpoch: 2,
      ciphertext: randomBytes(64),
      nonce: randomBytes(24),
      ciphertextDigest: randomBytes(32),
      createdByDeviceId: ownerDeviceId,
      signature: randomBytes(64),
    });

    await expect(inspectNoopMembershipRekey(app.ctx.db, fixture.taskId)).rejects.toMatchObject({
      code: 'target_epoch_has_artifacts',
    });
  });

  it('refuses cancellation after a current key holder was revoked', async () => {
    const fixture = await createFixture();
    await app.ctx.db.update(vaultKeyEnvelopes).set({
      status: 'revoked',
      revokedAt: new Date(),
      revocationReason: 'member_removed',
    }).where(eq(vaultKeyEnvelopes.id, fixture.envelopeId));

    await expect(inspectNoopMembershipRekey(app.ctx.db, fixture.taskId)).rejects.toMatchObject({
      code: 'current_holder_was_revoked',
    });
  });

  it('refuses cancellation when the expected recipient key generation changed', async () => {
    const fixture = await createFixture();
    await app.ctx.db.update(userCryptoProfiles).set({ cryptoGeneration: 2 })
      .where(eq(userCryptoProfiles.userId, owner.userId));

    await expect(inspectNoopMembershipRekey(app.ctx.db, fixture.taskId)).rejects.toMatchObject({
      code: 'recipient_descriptors_changed',
    });
    await app.ctx.db.update(userCryptoProfiles).set({ cryptoGeneration: 1 })
      .where(eq(userCryptoProfiles.userId, owner.userId));
  });

  it('allows a current extension device that has not received a vault envelope yet', async () => {
    const extensionDeviceId = randomUUID();
    await app.ctx.db.insert(userDevices).values(device(
      extensionDeviceId,
      owner.userId,
      'extension',
    ));
    const fixture = await createFixture();

    await expect(inspectNoopMembershipRekey(app.ctx.db, fixture.taskId)).resolves.toMatchObject({
      status: 'repairable',
      expectedRecipientDescriptorCount: 2,
      activeRecipientDescriptorCount: 1,
    });

    await app.ctx.db.delete(userDevices).where(eq(userDevices.id, extensionDeviceId));
  });

  it('refuses non-membership rekey reasons even when the target epoch is pristine', async () => {
    const fixture = await createFixture('device_compromise');

    await expect(inspectNoopMembershipRekey(app.ctx.db, fixture.taskId)).rejects.toMatchObject({
      code: 'rekey_task_not_pristine',
    });
  });
});

async function createFixture(
  reason: 'membership_change' | 'device_compromise' = 'membership_change',
): Promise<{ vaultId: string; taskId: string; envelopeId: string }> {
  const vault = (await app.ctx.db.insert(vaults).values({
    kind: 'team',
    name: '',
    ownerUserId: null,
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
    createdByDeviceId: ownerDeviceId,
    activatedAt: new Date(),
  });
  await app.ctx.db.insert(encryptedVaultHeaders).values({
    vaultId: vault.id,
    headerVersion: 1,
    keyEpoch: 1,
    ciphertext: randomBytes(64),
    nonce: randomBytes(24),
    ciphertextDigest: randomBytes(32),
    createdByDeviceId: ownerDeviceId,
    signature: randomBytes(64),
  });
  const ciphertext = randomBytes(96);
  const envelope = (await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId: vault.id,
    keyEpoch: 1,
    recipientKind: 'user',
    accessScope: 'full',
    recipientUserId: owner.userId,
    recipientKeyFingerprint: publicKeyFingerprint(
      Buffer.from(ownerProfile.publicEncryptionKey).toString('base64url'),
    ),
    authorizationKind: 'direct',
    authorizationRef: owner.userId,
    envelopeVersion: 1,
    ciphertext,
    ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
    senderDeviceId: ownerDeviceId,
    signerUserId: owner.userId,
    signerKeyVersion: ownerProfile.cryptoGeneration,
    signerPublicKey: ownerProfile.publicSigningKey,
    signature: randomBytes(64),
    status: 'active',
    activatedAt: new Date(),
  }).returning())[0]!;
  await app.ctx.db.update(vaultCryptoStates).set({
    storageMode: 'e2ee',
    writeState: 'open',
    activeEpoch: 1,
    activeHeaderVersion: 1,
    accessGeneration: 1,
    rowVersion: 2,
    cutoverAt: new Date(),
    legacyReadDisabledAt: new Date(),
  }).where(eq(vaultCryptoStates.vaultId, vault.id));
  const task = await app.ctx.db.transaction((tx) => ensureMembershipRekeyTask(
    tx,
    vault.id,
    owner.userId,
    ownerDeviceId,
    new Date(),
    reason,
  ));
  return { vaultId: vault.id, taskId: task.id, envelopeId: envelope.id };
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
    signingKeyFingerprint: randomBytes(32).toString('base64url'),
  };
}

function device(id: string, userId: string, deviceType: 'web' | 'extension' = 'web') {
  return {
    id,
    userId,
    deviceType,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    keyFingerprint: `web-${id}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  };
}
