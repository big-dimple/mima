import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { EnterpriseRecoveryWorkspace } from '@mima/contracts';
import {
  encryptedVaultHeaders,
  enterpriseRecoveryApprovals,
  enterpriseRecoveryKeys,
  enterpriseRecoveryRequests,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaults,
} from '../../src/db/schema.ts';
import { freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let target: TestSession;
let owner: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;
let adminThree: TestSession;
let vaultId: string;
let targetDeviceId: string;
let ownerDeviceId: string;
let targetProfile: ReturnType<typeof profile>;
let ownerProfile: ReturnType<typeof profile>;
let recoveryKeyId: string;

beforeAll(async () => {
  app = await freshTestApp('mima_test_enterprise_recovery_integrity');
  target = await login(app, 'bob');
  owner = await login(app, 'erin');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  adminThree = await login(app, 'carol');
  await app.ctx.db.insert(systemRoleAssignments).values(
    [adminOne, adminTwo, adminThree].map((admin) => ({
      userId: admin.userId,
      role: 'platform-admin' as const,
      assignedBy: 'test',
    })),
  ).onConflictDoNothing();

  targetProfile = profile(target.userId);
  ownerProfile = profile(owner.userId);
  targetDeviceId = randomUUID();
  ownerDeviceId = randomUUID();
  await app.ctx.db.insert(userCryptoProfiles).values([targetProfile, ownerProfile]);
  await app.ctx.db.insert(userDevices).values([
    device(targetDeviceId, target.userId),
    device(ownerDeviceId, owner.userId),
  ]);

  vaultId = (await app.ctx.db.insert(vaults).values({
    kind: 'team', name: '', ownerUserId: null,
  }).returning())[0]!.id;
  await app.ctx.db.insert(vaultMemberships).values([
    { vaultId, subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
    { vaultId, subjectKind: 'user', subjectId: target.userId, role: 'viewer' },
  ]);
  recoveryKeyId = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: `integrity-${randomUUID()}`,
    keyFingerprint: randomBytes(32).toString('base64url'),
    publicEncryptionKey: randomBytes(32),
    status: 'active',
    ceremonyEvidenceDigest: randomBytes(32),
    createdByUserId: adminOne.userId,
  }).returning())[0]!.id;
  await createEpoch(1, null);
  await app.ctx.db.update(vaultCryptoStates).set({
    storageMode: 'e2ee',
    writeState: 'open',
    activeEpoch: 1,
    activeHeaderVersion: 1,
    rowVersion: 2,
    cutoverAt: new Date(),
    legacyReadDisabledAt: new Date(),
  }).where(eq(vaultCryptoStates.vaultId, vaultId));
});

afterAll(async () => {
  await app.close();
});

describe('enterprise recovery integrity guards', () => {
  it('expires stale work, caps approvals, and rejects an epoch drifted package', async () => {
    const expiredRequest = await insertRequest({
      createdAt: new Date(Date.now() - 2 * 60 * 60_000),
      expiresAt: new Date(Date.now() - 60 * 60_000),
    });
    const request = await insertRequest();
    expect((await requestStatus(expiredRequest.id))).toBe('expired');
    expect(request.keyEpoch).toBe(1);

    await app.ctx.db.insert(enterpriseRecoveryApprovals).values([
      { requestId: request.id, approverUserId: adminOne.userId, requestDigest: request.requestDigest },
      { requestId: request.id, approverUserId: adminTwo.userId, requestDigest: request.requestDigest },
    ]);
    expect(await requestStatus(request.id)).toBe('approved');
    await expect(app.ctx.db.insert(enterpriseRecoveryApprovals).values({
      requestId: request.id,
      approverUserId: adminThree.userId,
      requestDigest: request.requestDigest,
    })).rejects.toThrow();
    await expect(app.ctx.db.update(enterpriseRecoveryRequests).set({ keyEpoch: 2 })
      .where(eq(enterpriseRecoveryRequests.id, request.id))).rejects.toThrow();

    const workspaceResponse = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/workspace',
      headers: { cookie: adminOne.cookie },
    });
    expect(workspaceResponse.statusCode, workspaceResponse.body).toBe(200);
    const workspace = workspaceResponse.json() as EnterpriseRecoveryWorkspace;
    expect(workspace.requests.find((candidate) => candidate.id === request.id)).toMatchObject({
      keyEpoch: 1,
      status: 'approved',
      approvalUserIds: [adminOne.userId, adminTwo.userId],
    });
    expect(workspace.requests.find((candidate) => candidate.id === expiredRequest.id)).toMatchObject({
      status: 'expired',
      lastErrorCode: 'request_expired',
    });

    await app.ctx.db.update(vaultKeyEpochs).set({ status: 'retired', retiredAt: new Date() }).where(and(
      eq(vaultKeyEpochs.vaultId, vaultId),
      eq(vaultKeyEpochs.epoch, 1),
    ));
    await createEpoch(2, 1);
    await app.ctx.db.update(vaultCryptoStates).set({
      activeEpoch: 2,
      activeHeaderVersion: 2,
      rowVersion: 3,
    }).where(eq(vaultCryptoStates.vaultId, vaultId));

    const packageResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/requests/${request.id}/package`,
      headers: { cookie: target.cookie },
    });
    expect(packageResponse.statusCode, packageResponse.body).toBe(409);
    expect((packageResponse.json() as { message: string }).message).toContain('已经变化');
  });

  it('keeps signer provenance immutable and rejects a mismatched profile snapshot', async () => {
    const envelope = (await app.ctx.db.select().from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, vaultId),
      eq(vaultKeyEnvelopes.keyEpoch, 2),
    )).limit(1))[0]!;
    await expect(app.ctx.db.update(vaultKeyEnvelopes).set({
      signerKeyVersion: envelope.signerKeyVersion! + 1,
    }).where(eq(vaultKeyEnvelopes.id, envelope.id))).rejects.toThrow();

    const ciphertext = randomBytes(96);
    await expect(app.ctx.db.insert(vaultKeyEnvelopes).values({
      vaultId,
      keyEpoch: 2,
      recipientKind: 'user',
      accessScope: 'metadata',
      recipientUserId: target.userId,
      recipientKeyFingerprint: randomBytes(32).toString('base64url'),
      authorizationKind: 'direct',
      authorizationRef: target.userId,
      envelopeVersion: targetProfile.cryptoGeneration,
      ciphertext,
      ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
      senderDeviceId: ownerDeviceId,
      signerUserId: owner.userId,
      signerKeyVersion: ownerProfile.cryptoGeneration,
      signerPublicKey: randomBytes(32),
      signature: randomBytes(64),
      status: 'active',
      activatedAt: new Date(),
    })).rejects.toThrow();
  });
});

async function createEpoch(epoch: number, previousEpoch: number | null): Promise<void> {
  await app.ctx.db.insert(vaultKeyEpochs).values({
    vaultId,
    epoch,
    previousEpoch,
    status: 'active',
    reason: epoch === 1 ? 'initial' : 'manual',
    metadataKeyCommitment: randomBytes(32),
    contentKeyCommitment: randomBytes(32),
    recipientSetDigest: randomBytes(32),
    createdByUserId: owner.userId,
    createdByDeviceId: ownerDeviceId,
    activatedAt: new Date(),
  });
  const headerCiphertext = randomBytes(64);
  await app.ctx.db.insert(encryptedVaultHeaders).values({
    vaultId,
    headerVersion: epoch,
    keyEpoch: epoch,
    ciphertext: headerCiphertext,
    nonce: randomBytes(24),
    ciphertextDigest: createHash('sha256').update(headerCiphertext).digest(),
    createdByDeviceId: ownerDeviceId,
    signature: randomBytes(64),
  });
  const ciphertext = randomBytes(96);
  const recoveryKey = (await app.ctx.db.select().from(enterpriseRecoveryKeys)
    .where(eq(enterpriseRecoveryKeys.id, recoveryKeyId)).limit(1))[0]!;
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId,
    keyEpoch: epoch,
    recipientKind: 'enterprise_recovery',
    accessScope: 'recovery',
    recipientRecoveryKeyId: recoveryKey.id,
    recipientKeyFingerprint: recoveryKey.keyFingerprint,
    authorizationKind: 'recovery',
    authorizationRef: recoveryKey.ceremonyId,
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
  });
}

async function insertRequest(times: { createdAt?: Date; expiresAt?: Date } = {}) {
  const createdAt = times.createdAt ?? new Date();
  return (await app.ctx.db.insert(enterpriseRecoveryRequests).values({
    vaultId,
    recoveryKeyId,
    keyEpoch: 1,
    targetUserId: target.userId,
    targetDeviceId,
    targetEncryptionPublicKey: targetProfile.publicEncryptionKey,
    targetKeyVersion: targetProfile.cryptoGeneration,
    targetCapability: 'full',
    reason: 'lost_all_devices',
    requestDigest: randomBytes(32),
    createdByUserId: adminOne.userId,
    createdAt,
    expiresAt: times.expiresAt ?? new Date(createdAt.getTime() + 60 * 60_000),
  }).returning())[0]!;
}

async function requestStatus(requestId: string) {
  return (await app.ctx.db.select({ status: enterpriseRecoveryRequests.status })
    .from(enterpriseRecoveryRequests)
    .where(eq(enterpriseRecoveryRequests.id, requestId)).limit(1))[0]?.status;
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

function device(id: string, userId: string) {
  return {
    id,
    userId,
    deviceType: 'web' as const,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    deviceGeneration: 1,
    keyFingerprint: randomBytes(32).toString('base64url'),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  };
}
