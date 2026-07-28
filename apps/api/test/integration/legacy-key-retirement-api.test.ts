import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { LegacyKeyRetirementResponse } from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import { canonicalJson } from '@mima/e2ee';
import {
  encryptedVaultHeaders,
  enterpriseRecoveryKeys,
  legacyKeyRetirementApprovals,
  legacyKeyRetirementPlans,
  legacyMigrationEvidence,
  legacyMigrationJobs,
  systemRoleAssignments,
  userCryptoProfiles,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let alice: TestSession;
let dave: TestSession;
let aliceKeyring: E2eeKeyring;
let daveKeyring: E2eeKeyring;
let aliceDeviceId: string;
let daveDeviceId: string;

beforeAll(async () => {
  app = await freshTestApp('mima_test_legacy_key_retirement_api');
  alice = await login(app, 'alice');
  dave = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: alice.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: dave.userId, role: 'platform-admin', assignedBy: 'test' },
  ]);
  ({ keyring: aliceKeyring, deviceId: aliceDeviceId } = await setupCrypto(alice, 'alice retirement password'));
  ({ keyring: daveKeyring, deviceId: daveDeviceId } = await setupCrypto(dave, 'dave retirement password'));

  await app.ctx.db.update(vaults).set({ name: '' });
  const recovery = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: 'legacy-key-retirement-test',
    keyFingerprint: randomBytes(32).toString('base64url'),
    publicEncryptionKey: randomBytes(32),
    status: 'active',
    ceremonyEvidenceDigest: randomBytes(32),
    createdByUserId: alice.userId,
  }).returning())[0]!;
  const personalVaults = await app.ctx.db.select().from(vaults);
  for (const vault of personalVaults) {
    const owner = vault.ownerUserId === alice.userId
      ? { userId: alice.userId, deviceId: aliceDeviceId }
      : { userId: dave.userId, deviceId: daveDeviceId };
    await initializeEmptyE2eeVault(vault.id, owner, recovery);
  }
  const migratedVault = personalVaults.find((vault) => vault.ownerUserId === alice.userId)!;
  await app.ctx.db.insert(legacyMigrationJobs).values({
    vaultId: migratedVault.id,
    state: 'e2ee',
    targetEpoch: 1,
    sourceSnapshotHash: randomBytes(32),
    startedByUserId: alice.userId,
    startedByDeviceId: aliceDeviceId,
    startedAt: new Date(Date.now() - 60_000),
    completedAt: new Date(),
  });
});

afterAll(async () => {
  await Promise.all([aliceKeyring.lock(), daveKeyring.lock()]);
  await app.close();
});

describe('legacy KEK retirement API', () => {
  it('requires signed dual-admin approval and records evidence for every completed migration job', async () => {
    const initial = await app.inject({
      method: 'GET',
      url: '/api/v2/legacy-key-retirement',
      ...authed(alice),
    });
    expect(initial.statusCode).toBe(200);
    expect(initial.json()).toMatchObject({
      status: 'unplanned',
      migratedJobCount: 1,
      legacyKeyState: 'unknown',
    });

    const createRequest = await aliceKeyring.createLegacyKeyRetirementIntent(alice.userId, {
      reasonCode: 'rollback_window',
      retireBy: new Date(Date.now() + 7 * 86_400_000).toISOString(),
      copyInventoryDigest: randomBytes(32).toString('base64url'),
      copyManifestDigest: randomBytes(32).toString('base64url'),
      kekFingerprintDigest: randomBytes(32).toString('base64url'),
    });
    const invalidSignature = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement',
      ...authed(alice),
      payload: { ...createRequest, signature: randomBytes(64).toString('base64url') },
    });
    expect(invalidSignature.statusCode).toBe(401);
    const create = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement',
      ...authed(alice),
      payload: createRequest,
    });
    expect(create.statusCode, create.body).toBe(201);
    let plan = create.json() as LegacyKeyRetirementResponse;
    expect(plan).toMatchObject({ status: 'planned', approvalCount: 0, legacyKeyState: 'retained' });

    const earlyCompletion = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/complete',
      ...authed(alice),
      payload: await aliceKeyring.completeLegacyKeyRetirementIntent(
        alice.userId,
        plan.planDigest!,
        randomBytes(32).toString('base64url'),
      ),
    });
    expect(earlyCompletion.statusCode).toBe(409);

    const sharedCompletionEvidenceDigest = randomBytes(32).toString('base64url');

    const firstApproval = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/approve',
      ...authed(alice),
      payload: await aliceKeyring.approveLegacyKeyRetirementIntent(
        alice.userId,
        plan.planDigest!,
        sharedCompletionEvidenceDigest,
      ),
    });
    expect(firstApproval.statusCode, firstApproval.body).toBe(200);
    expect(firstApproval.json()).toMatchObject({ status: 'planned', approvalCount: 1 });

    const mismatchedApproval = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/approve',
      ...authed(dave),
      payload: await daveKeyring.approveLegacyKeyRetirementIntent(
        dave.userId,
        plan.planDigest!,
        randomBytes(32).toString('base64url'),
      ),
    });
    expect(mismatchedApproval.statusCode).toBe(409);

    const secondApproval = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/approve',
      ...authed(dave),
      payload: await daveKeyring.approveLegacyKeyRetirementIntent(
        dave.userId,
        plan.planDigest!,
        sharedCompletionEvidenceDigest,
      ),
    });
    expect(secondApproval.statusCode, secondApproval.body).toBe(200);
    plan = secondApproval.json() as LegacyKeyRetirementResponse;
    expect(plan).toMatchObject({ status: 'approved', approvalCount: 2 });

    const mismatchedCompletion = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/complete',
      ...authed(alice),
      payload: await aliceKeyring.completeLegacyKeyRetirementIntent(
        alice.userId,
        plan.planDigest!,
        randomBytes(32).toString('base64url'),
      ),
    });
    expect(mismatchedCompletion.statusCode).toBe(409);

    const complete = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/complete',
      ...authed(alice),
      payload: await aliceKeyring.completeLegacyKeyRetirementIntent(
        alice.userId,
        plan.planDigest!,
        sharedCompletionEvidenceDigest,
      ),
    });
    expect(complete.statusCode, complete.body).toBe(200);
    expect(complete.json()).toMatchObject({
      status: 'completed',
      approvalCount: 2,
      migratedJobCount: 1,
      evidenceJobCount: 1,
      legacyKeyState: 'retired',
      overdue: false,
    });

    const evidence = await app.ctx.db.select().from(legacyMigrationEvidence)
      .where(eq(legacyMigrationEvidence.evidenceType, 'legacy_key_retirement'));
    expect(evidence).toHaveLength(1);
    expect(evidence[0]).toMatchObject({
      stage: 'e2ee',
      subjectKind: 'deployment',
      subjectId: 'primary',
      recordCount: 1,
      signerDeviceId: aliceDeviceId,
    });
    expect(evidence[0]!.digest).toHaveLength(32);
    expect(Buffer.from(evidence[0]!.retirementManifestDigest!).toString('base64url'))
      .toBe(sharedCompletionEvidenceDigest);
    const migrationJob = (await app.ctx.db.select().from(legacyMigrationJobs)
      .where(eq(legacyMigrationJobs.id, evidence[0]!.jobId)))[0]!;
    const expectedJobDigest = createHash('sha256').update(canonicalJson({
      kind: 'legacy-key-retirement-evidence',
      protocol: 'lm-e2ee-v1',
      completionEvidenceDigest: sharedCompletionEvidenceDigest,
      deploymentId: 'primary',
      jobId: migrationJob.id,
      planDigest: plan.planDigest!,
      sourceDigest: Buffer.from(migrationJob.sourceSnapshotHash!).toString('base64url'),
    })).digest();
    expect(Buffer.from(evidence[0]!.digest).equals(expectedJobDigest)).toBe(true);
    expect(evidence[0]!.signature).toHaveLength(64);

    const bob = await login(app, 'bob');
    const visibleStatus = await app.inject({
      method: 'GET',
      url: '/api/v2/legacy-key-retirement',
      ...authed(bob),
    });
    expect(visibleStatus.statusCode).toBe(200);
    expect(visibleStatus.json()).toMatchObject({ status: 'completed', legacyKeyState: 'retired' });
    const forbiddenCreate = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement',
      ...authed(bob),
      payload: createRequest,
    });
    expect(forbiddenCreate.statusCode).toBe(403);
  });

  it('keeps approvals and completed plans append-only', async () => {
    const plan = (await app.ctx.db.select().from(legacyKeyRetirementPlans))[0]!;
    const approvals = await app.ctx.db.select().from(legacyKeyRetirementApprovals);
    expect(approvals).toHaveLength(2);
    await expect(app.ctx.db.update(legacyKeyRetirementApprovals).set({
      evidenceDigest: randomBytes(32),
    }).where(eq(legacyKeyRetirementApprovals.planId, plan.id))).rejects.toThrow();
    await expect(app.ctx.db.update(legacyKeyRetirementPlans).set({
      retireBy: new Date(Date.now() + 30 * 86_400_000),
    }).where(eq(legacyKeyRetirementPlans.id, plan.id))).rejects.toThrow();
  });
});

async function setupCrypto(session: TestSession, mainPassword: string) {
  const keyring = new E2eeKeyring();
  const setup = await keyring.setup(mainPassword, {
    accountId: session.userId,
    deviceId: crypto.randomUUID(),
    deviceName: 'Retirement API test',
    platform: 'test',
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(session),
    payload: setup.request,
  });
  expect(response.statusCode, response.body).toBe(201);
  return { keyring, deviceId: setup.deviceId };
}

async function initializeEmptyE2eeVault(
  vaultId: string,
  owner: { userId: string; deviceId: string },
  recovery: typeof enterpriseRecoveryKeys.$inferSelect,
) {
  const now = new Date();
  const signerProfile = (await app.ctx.db.select().from(userCryptoProfiles)
    .where(eq(userCryptoProfiles.userId, owner.userId)).limit(1))[0]!;
  await app.ctx.db.insert(vaultKeyEpochs).values({
    vaultId,
    epoch: 1,
    status: 'active',
    reason: 'initial',
    metadataKeyCommitment: randomBytes(32),
    contentKeyCommitment: randomBytes(32),
    recipientSetDigest: randomBytes(32),
    createdByUserId: owner.userId,
    createdByDeviceId: owner.deviceId,
    activatedAt: now,
  });
  const recoveryCiphertext = randomBytes(96);
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId,
    keyEpoch: 1,
    recipientKind: 'enterprise_recovery',
    accessScope: 'recovery',
    recipientRecoveryKeyId: recovery.id,
    recipientKeyFingerprint: recovery.keyFingerprint,
    authorizationKind: 'recovery',
    authorizationRef: recovery.id,
    envelopeVersion: 1,
    ciphertext: recoveryCiphertext,
    ciphertextDigest: createHash('sha256').update(recoveryCiphertext).digest(),
    senderDeviceId: owner.deviceId,
    signerUserId: owner.userId,
    signerKeyVersion: signerProfile.cryptoGeneration,
    signerPublicKey: signerProfile.publicSigningKey,
    signature: randomBytes(64),
    status: 'active',
    activatedAt: now,
  });
  const headerCiphertext = randomBytes(64);
  await app.ctx.db.insert(encryptedVaultHeaders).values({
    vaultId,
    headerVersion: 1,
    keyEpoch: 1,
    ciphertext: headerCiphertext,
    nonce: randomBytes(24),
    ciphertextDigest: createHash('sha256').update(headerCiphertext).digest(),
    createdByDeviceId: owner.deviceId,
    signature: randomBytes(64),
  });
  await app.ctx.db.update(vaultCryptoStates).set({
    storageMode: 'e2ee',
    writeState: 'open',
    activeEpoch: 1,
    activeHeaderVersion: 1,
    accessGeneration: 1,
    rowVersion: 2,
    cutoverAt: now,
    legacyReadDisabledAt: now,
    updatedAt: now,
  }).where(eq(vaultCryptoStates.vaultId, vaultId));
}
