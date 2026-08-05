import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  EnterpriseRecoveryCase,
  EnterpriseRecoveryCasePackage,
  EnterpriseRecoveryCaseTransfer,
  OfflineRecoveryResult,
} from '@mima/contracts';
import { enterpriseRecoveryTransferEvidenceDigest } from '@mima/e2ee';
import {
  enterpriseRecoveryCases,
  enterpriseRecoveryKeys,
  enterpriseRecoveryRequests,
  encryptedVaultHeaders,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshTestApp, key, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let target: TestSession;
let owner: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;
let targetDeviceId: string;
let ownerDeviceId: string;
let targetProfile: ReturnType<typeof profile>;
let ownerProfile: ReturnType<typeof profile>;
let recoveryKey: {
  id: string;
  ceremonyId: string;
  keyFingerprint: string;
  ceremonyEvidenceDigest: string;
};
let recoveryCase: EnterpriseRecoveryCase;
let vaultIds: string[];

beforeAll(async () => {
  app = await freshTestApp('mima_test_enterprise_recovery_cases_api');
  target = await login(app, 'bob');
  owner = await login(app, 'erin');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values(
    [target, adminOne, adminTwo].map((session) => ({
      userId: session.userId,
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
    device(targetDeviceId, target.userId, targetProfile),
    device(ownerDeviceId, owner.userId, ownerProfile),
  ]);

  const recoveryPublicKey = randomBytes(32);
  const ceremonyEvidenceDigest = randomBytes(32);
  const insertedKey = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: `case-${randomUUID()}`,
    keyFingerprint: createHash('sha256').update(recoveryPublicKey).digest('base64url'),
    publicEncryptionKey: recoveryPublicKey,
    status: 'active',
    ceremonyEvidenceDigest,
    createdByUserId: adminOne.userId,
  }).returning())[0]!;
  recoveryKey = {
    id: insertedKey.id,
    ceremonyId: insertedKey.ceremonyId,
    keyFingerprint: insertedKey.keyFingerprint,
    ceremonyEvidenceDigest: ceremonyEvidenceDigest.toString('base64url'),
  };

  vaultIds = [await createRecoverableVault(), await createRecoverableVault()];
  recoveryCase = await createFinalizedCase(vaultIds);
});

afterAll(async () => {
  await app.close();
});

describe('enterprise recovery case safety', () => {
  it('uses two case approvals and never releases revoked or old-key results', async () => {
    const selfApproval = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/approve`,
      ...authed(target),
      payload: {
        idempotencyKey: key(),
        caseDigest: recoveryCase.caseDigest,
      },
    });
    expect(selfApproval.statusCode, selfApproval.body).toBe(403);

    for (const administrator of [adminOne, adminTwo]) {
      const approved = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/cases/${recoveryCase.id}/approve`,
        ...authed(administrator),
        payload: {
          idempotencyKey: key(),
          caseDigest: recoveryCase.caseDigest,
        },
      });
      expect(approved.statusCode, approved.body).toBe(200);
      recoveryCase = approved.json() as EnterpriseRecoveryCase;
    }
    expect(recoveryCase.status).toBe('approved');
    expect(recoveryCase.approvalUserIds).toEqual([adminOne.userId, adminTwo.userId]);
    expect(recoveryCase.items).toHaveLength(2);
    expect(recoveryCase.items.every((item) => item.status === 'approved')).toBe(true);

    const packaged = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/package`,
      ...authed(adminOne),
    });
    expect(packaged.statusCode, packaged.body).toBe(200);
    const recoveryPackage = packaged.json() as EnterpriseRecoveryCasePackage;
    expect(recoveryPackage.items).toHaveLength(2);

    const transfer = await caseTransfer(recoveryCase);
    const incomplete = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/transfers`,
      ...authed(adminOne),
      payload: {
        idempotencyKey: key(),
        caseDigest: recoveryCase.caseDigest,
        transfer: { ...transfer, results: transfer.results.slice(0, 1) },
      },
    });
    expect(incomplete.statusCode, incomplete.body).toBe(409);
    expect(incomplete.json()).toMatchObject({ message: expect.stringContaining('不完整') });

    const wrongCeremony = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/transfers`,
      ...authed(adminOne),
      payload: {
        idempotencyKey: key(),
        caseDigest: recoveryCase.caseDigest,
        transfer: {
          ...transfer,
          results: transfer.results.map((result) => ({ ...result, ceremonyId: 'wrong-ceremony' })),
        },
      },
    });
    expect(wrongCeremony.statusCode, wrongCeremony.body).toBe(409);

    const uploaded = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/transfers`,
      ...authed(adminOne),
      payload: {
        idempotencyKey: key(),
        caseDigest: recoveryCase.caseDigest,
        transfer,
      },
    });
    expect(uploaded.statusCode, uploaded.body).toBe(200);
    expect((uploaded.json() as EnterpriseRecoveryCase).status).toBe('processing');

    await app.ctx.db.delete(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, vaultIds[0]!),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, target.userId),
    ));
    const afterRevocation = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/transfer`,
      ...authed(target),
    });
    expect(afterRevocation.statusCode, afterRevocation.body).toBe(200);
    const filtered = afterRevocation.json() as EnterpriseRecoveryCaseTransfer;
    expect(filtered.results).toHaveLength(1);
    expect(filtered.results[0]?.vaultId).toBe(vaultIds[1]);
    expect(filtered.results.some((result) => result.vaultId === vaultIds[0])).toBe(false);
    expect(await requestStatus(vaultIds[0]!)).toMatchObject({
      status: 'cancelled',
      lastErrorCode: 'authorization_changed',
    });

    await app.ctx.db.update(userCryptoProfiles).set({
      cryptoGeneration: 2,
      publicEncryptionKey: randomBytes(32),
      publicSigningKey: randomBytes(32),
      signingKeyFingerprint: randomBytes(32).toString('base64url'),
      updatedAt: new Date(),
    }).where(eq(userCryptoProfiles.userId, target.userId));
    const afterKeyChange = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/transfer`,
      ...authed(target),
    });
    expect(afterKeyChange.statusCode, afterKeyChange.body).toBe(200);
    expect(afterKeyChange.json()).toBeNull();
    expect(await requestStatus(vaultIds[1]!)).toMatchObject({
      status: 'expired',
      lastErrorCode: 'recipient_key_changed',
    });
    const finalCase = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${recoveryCase.id}`,
      ...authed(target),
    });
    expect(finalCase.statusCode, finalCase.body).toBe(200);
    expect((finalCase.json() as EnterpriseRecoveryCase).status).toBe('completed_with_skips');
  });
});

async function createRecoverableVault(): Promise<string> {
  const vault = (await app.ctx.db.insert(vaults).values({
    kind: 'team',
    name: '',
    ownerUserId: null,
  }).returning())[0]!;
  await app.ctx.db.insert(vaultMemberships).values([
    { vaultId: vault.id, subjectKind: 'user', subjectId: owner.userId, role: 'owner' },
    { vaultId: vault.id, subjectKind: 'user', subjectId: target.userId, role: 'viewer' },
  ]);
  await app.ctx.db.insert(vaultKeyEpochs).values({
    vaultId: vault.id,
    epoch: 1,
    previousEpoch: null,
    status: 'active',
    reason: 'initial',
    metadataKeyCommitment: randomBytes(32),
    contentKeyCommitment: randomBytes(32),
    recipientSetDigest: randomBytes(32),
    createdByUserId: owner.userId,
    createdByDeviceId: ownerDeviceId,
    activatedAt: new Date(),
  });
  const headerCiphertext = randomBytes(64);
  await app.ctx.db.insert(encryptedVaultHeaders).values({
    vaultId: vault.id,
    headerVersion: 1,
    keyEpoch: 1,
    ciphertext: headerCiphertext,
    nonce: randomBytes(24),
    ciphertextDigest: createHash('sha256').update(headerCiphertext).digest(),
    createdByDeviceId: ownerDeviceId,
    signature: randomBytes(64),
  });
  const ciphertext = randomBytes(96);
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId: vault.id,
    keyEpoch: 1,
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
  await app.ctx.db.update(vaultCryptoStates).set({
    storageMode: 'e2ee',
    writeState: 'open',
    activeEpoch: 1,
    activeHeaderVersion: 1,
    rowVersion: 2,
    cutoverAt: new Date(),
    legacyReadDisabledAt: new Date(),
  }).where(eq(vaultCryptoStates.vaultId, vault.id));
  return vault.id;
}

async function createFinalizedCase(caseVaultIds: string[]): Promise<EnterpriseRecoveryCase> {
  const caseId = randomUUID();
  const caseDigest = randomBytes(32);
  const createdAt = new Date();
  await app.ctx.db.insert(enterpriseRecoveryCases).values({
    id: caseId,
    kind: 'interrupted_handoff',
    targetUserId: target.userId,
    recoveryKeyId: recoveryKey.id,
    status: 'pending_approval',
    caseDigest,
    targetDeviceId,
    targetEncryptionPublicKey: targetProfile.publicEncryptionKey,
    targetKeyVersion: targetProfile.cryptoGeneration,
    createdByUserId: adminOne.userId,
    createdAt,
    expiresAt: new Date(createdAt.getTime() + 60 * 60_000),
    finalizedAt: createdAt,
  });
  for (const vaultId of caseVaultIds) {
    await app.ctx.db.insert(enterpriseRecoveryRequests).values({
      vaultId,
      recoveryKeyId: recoveryKey.id,
      keyEpoch: 1,
      targetUserId: target.userId,
      targetDeviceId,
      targetEncryptionPublicKey: targetProfile.publicEncryptionKey,
      targetKeyFingerprint: createHash('sha256')
        .update(targetProfile.publicEncryptionKey)
        .digest('base64url'),
      targetKeyVersion: targetProfile.cryptoGeneration,
      targetCapability: 'full',
      reason: 'lost_all_devices',
      caseId,
      requestDigest: randomBytes(32),
      createdByUserId: adminOne.userId,
      createdAt,
      expiresAt: new Date(createdAt.getTime() + 60 * 60_000),
    });
  }
  const response = await app.inject({
    method: 'GET',
    url: `/api/v2/recovery/cases/${caseId}`,
    ...authed(target),
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as EnterpriseRecoveryCase;
}

async function caseTransfer(value: EnterpriseRecoveryCase): Promise<EnterpriseRecoveryCaseTransfer> {
  const results: OfflineRecoveryResult[] = [];
  for (const item of value.items) {
    const recoveredEnvelope = {
      vaultId: item.vaultId,
      epoch: item.keyEpoch,
      recipientKind: 'user' as const,
      recipientId: target.userId,
      recipientKeyVersion: targetProfile.cryptoGeneration,
      capability: item.targetCapability,
      sealedKeyBundle: randomBytes(96).toString('base64url'),
      signerUserId: target.userId,
      signerKeyVersion: targetProfile.cryptoGeneration,
    };
    const evidence = {
      requestId: item.id,
      requestDigest: item.requestDigest,
      vaultId: item.vaultId,
      epoch: item.keyEpoch,
      recoveryKeyId: recoveryKey.id,
      ceremonyId: recoveryKey.ceremonyId,
      recoveryCeremonyDigest: recoveryKey.ceremonyEvidenceDigest,
      targetUserId: target.userId,
      targetCapability: item.targetCapability,
      recoveredEnvelope,
    };
    results.push({
      protocol: 'lm-e2ee-v1',
      kind: 'enterprise-recovery-transfer',
      formatVersion: 1,
      ...evidence,
      toolEvidenceDigest: await enterpriseRecoveryTransferEvidenceDigest(evidence),
    });
  }
  return {
    protocol: 'mima-e2ee-v2',
    kind: 'enterprise-recovery-case-transfer',
    caseId: value.id,
    caseDigest: value.caseDigest!,
    results,
  };
}

async function requestStatus(vaultId: string) {
  return (await app.ctx.db.select({
    status: enterpriseRecoveryRequests.status,
    lastErrorCode: enterpriseRecoveryRequests.lastErrorCode,
  }).from(enterpriseRecoveryRequests).where(and(
    eq(enterpriseRecoveryRequests.caseId, recoveryCase.id),
    eq(enterpriseRecoveryRequests.vaultId, vaultId),
  )).limit(1))[0];
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

function device(id: string, userId: string, userProfile: ReturnType<typeof profile>) {
  return {
    id,
    userId,
    deviceType: 'web' as const,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    deviceGeneration: userProfile.cryptoGeneration,
    keyFingerprint: randomBytes(32).toString('base64url'),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  };
}
