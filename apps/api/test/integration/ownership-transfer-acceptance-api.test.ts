import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  AcceptVaultOwnershipTransferRequest,
  EncryptedBootstrapResponse,
  EnterpriseRecoveryKey,
  UserCryptoProfile,
  VaultEnvelopeTask,
  VaultOwnershipTransfer,
} from '@mima/contracts';
import {
  createVaultKeys,
  destroyVaultKeys,
  createEnterpriseRecoveryKit,
  ownershipTransferAcceptanceDigest,
  signVaultKeyPossession,
} from '@mima/e2ee';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  enterpriseRecoveryKeys,
  userDevices,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaultOwnershipTransferRequests,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let target: TestSession;
let outsider: TestSession;
let ownerKeyring: E2eeKeyring;
let targetKeyring: E2eeKeyring;
let ownerProfile: UserCryptoProfile;
let targetProfile: UserCryptoProfile;
let ownerDeviceId: string;
let targetDeviceId: string;
let recoveryKey: EnterpriseRecoveryKey;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_ownership_transfer_acceptance');
  owner = await login(app, 'bob');
  target = await login(app, 'dave');
  outsider = await login(app, 'erin');
  ({ keyring: ownerKeyring, deviceId: ownerDeviceId, profile: ownerProfile } = await setupCrypto(
    owner,
    'owner transfer password',
  ));
  ({ keyring: targetKeyring, deviceId: targetDeviceId, profile: targetProfile } = await setupCrypto(
    target,
    'target transfer password',
  ));

  const kit = await createEnterpriseRecoveryKit('ownership-transfer-test');
  const row = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: kit.ceremonyId,
    keyFingerprint: kit.publicKeyFingerprint,
    publicEncryptionKey: Buffer.from(kit.publicKey, 'base64url'),
    status: 'active',
    ceremonyEvidenceDigest: Buffer.from(kit.ceremonyDigest, 'base64url'),
    createdByUserId: owner.userId,
  }).returning())[0]!;
  recoveryKey = {
    id: row.id,
    ceremonyId: row.ceremonyId,
    keyFingerprint: row.keyFingerprint,
    publicEncryptionKey: kit.publicKey,
    threshold: 2,
    shareCount: 3,
    status: 'active',
    ceremonyEvidenceDigest: kit.ceremonyDigest,
    approvalUserIds: [],
    createdAt: row.createdAt.toISOString(),
    retiredAt: null,
    cancelledAt: null,
  };
});

afterAll(async () => {
  await Promise.all([ownerKeyring.lock(), targetKeyring.lock()]);
  await app.close();
});

describe('signed ownership transfer acceptance', () => {
  it('requires a key-possession public key on the active epoch', async () => {
    const vaultId = await initializeTeamVault('旧密钥版本');
    await setMember(vaultId, target.userId, 'viewer');
    await app.ctx.db.update(vaultKeyEpochs).set({ keyPossessionPublicKey: null }).where(and(
      eq(vaultKeyEpochs.vaultId, vaultId),
      eq(vaultKeyEpochs.epoch, 1),
    ));

    const response = await createTransfer(vaultId, target.userId, await accessGeneration(vaultId));
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({
      message: '当前密码库需要先完成一次安全更新，再转移所有权',
    });
  });

  it('requires an existing direct full member and supports signed decline/cancel with rebuild', async () => {
    const vaultId = await initializeTeamVault('可取消转移');
    const initialGeneration = await accessGeneration(vaultId);

    const nonMember = await createTransfer(vaultId, outsider.userId, initialGeneration);
    expect(nonMember.statusCode).toBe(409);

    await setMember(vaultId, outsider.userId, 'auditor');
    const auditor = await createTransfer(vaultId, outsider.userId, await accessGeneration(vaultId));
    expect(auditor.statusCode).toBe(409);

    await setMember(vaultId, target.userId, 'viewer');
    const transferGeneration = await accessGeneration(vaultId);
    const preparing = await createTransfer(vaultId, target.userId, transferGeneration);
    expect(preparing.statusCode).toBe(409);
    expect(preparing.json()).toMatchObject({
      message: '系统正在自动准备新拥有者的密码库访问，请稍后重试',
    });
    await completePendingTask(vaultId, target.userId);
    let transfer = await expectCreatedTransfer(vaultId, target.userId, transferGeneration);
    expect(transfer.envelopeReady).toBe(true);
    expect(await accessGeneration(vaultId)).toBe(transferGeneration);

    const declineRequest = await targetKeyring.prepareOwnershipTransferCancellation(
      target.userId,
      transfer,
      'decline',
    );
    const declined = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/cancel`,
      ...authed(target),
      payload: declineRequest,
    });
    expect(declined.statusCode, declined.body).toBe(200);
    expect(declined.json()).toMatchObject({ status: 'cancelled', acceptanceStatus: 'cancelled' });
    await expectMembership(vaultId, target.userId, 'viewer');

    transfer = await expectCreatedTransfer(vaultId, target.userId, transferGeneration);
    const cancelRequest = await ownerKeyring.prepareOwnershipTransferCancellation(
      owner.userId,
      transfer,
      'cancel',
    );
    const cancelled = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/cancel`,
      ...authed(owner),
      payload: cancelRequest,
    });
    expect(cancelled.statusCode, cancelled.body).toBe(200);
    expect(cancelled.json()).toMatchObject({ status: 'cancelled', acceptanceStatus: 'cancelled' });

    transfer = await expectCreatedTransfer(vaultId, target.userId, transferGeneration);
    expect(transfer.status).toBe('pending');
  });

  it('never finalizes after automatic envelope delivery and accepts only from an active target device with verified keys', async () => {
    const vaultId = await initializeTeamVault('接受签名转移');
    await setMember(vaultId, target.userId, 'viewer');
    const task = await pendingTask(vaultId, target.userId);
    const unrelatedCiphertext = randomBytes(96);
    const unrelatedEnvelope = (await app.ctx.db.insert(vaultKeyEnvelopes).values({
      vaultId,
      keyEpoch: task.keyEpoch,
      recipientKind: 'user',
      accessScope: 'full',
      recipientUserId: target.userId,
      recipientKeyFingerprint: createHash('sha256')
        .update(Buffer.from(targetProfile.encryptionPublicKey, 'base64url'))
        .digest('base64url'),
      authorizationKind: 'directory_group',
      authorizationRef: 'group:test/source-confusion',
      envelopeVersion: targetProfile.keyVersion,
      ciphertext: unrelatedCiphertext,
      ciphertextDigest: createHash('sha256').update(unrelatedCiphertext).digest(),
      senderDeviceId: ownerDeviceId,
      signerUserId: owner.userId,
      signerKeyVersion: ownerProfile.keyVersion,
      signerPublicKey: Buffer.from(ownerProfile.signingPublicKey, 'base64url'),
      signature: randomBytes(64),
      status: 'active',
      activatedAt: new Date(),
    }).returning())[0]!;
    const completionRequest = await ownerKeyring.prepareEnvelopeTaskCompletion(owner.userId, ownerProfile, task);
    await app.ctx.db.update(userDevices).set({ status: 'revoked', revokedAt: new Date() }).where(
      eq(userDevices.id, ownerDeviceId),
    );
    const revokedOwner = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/envelope-tasks/${task.id}/complete`,
      ...authed(owner),
      payload: completionRequest,
    });
    expect(revokedOwner.statusCode).toBe(423);
    await app.ctx.db.update(userDevices).set({ status: 'active', revokedAt: null }).where(
      eq(userDevices.id, ownerDeviceId),
    );
    const completedEnvelope = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/envelope-tasks/${task.id}/complete`,
      ...authed(owner),
      payload: completionRequest,
    });
    expect(completedEnvelope.statusCode, completedEnvelope.body).toBe(200);
    const completedTask = completedEnvelope.json() as VaultEnvelopeTask;
    expect(completedTask.completedEnvelopeId).not.toBe(unrelatedEnvelope.id);
    const directEnvelope = (await app.ctx.db.select().from(vaultKeyEnvelopes).where(
      eq(vaultKeyEnvelopes.id, completedTask.completedEnvelopeId!),
    ))[0]!;
    expect(directEnvelope).toMatchObject({
      authorizationKind: 'direct',
      authorizationRef: target.userId,
      recipientUserId: target.userId,
      accessScope: 'full',
    });
    await app.ctx.db.delete(vaultKeyEnvelopes).where(eq(vaultKeyEnvelopes.id, unrelatedEnvelope.id));

    await loadTargetVaultKeys();
    const transfer = await expectCreatedTransfer(vaultId, target.userId, await accessGeneration(vaultId));

    const storedPending = (await app.ctx.db.select().from(vaultOwnershipTransferRequests).where(
      eq(vaultOwnershipTransferRequests.id, transfer.id),
    ))[0]!;
    expect(storedPending.status).toBe('pending');
    expect(storedPending.acceptedAt).toBeNull();
    await expectMembership(vaultId, owner.userId, 'owner');
    await expectMembership(vaultId, target.userId, 'viewer');

    const readyResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer`,
      ...authed(target),
    });
    expect(readyResponse.statusCode, readyResponse.body).toBe(200);
    const readyTransfer = readyResponse.json() as VaultOwnershipTransfer;
    expect(readyTransfer).toMatchObject({
      id: transfer.id,
      keyEpoch: 1,
      envelopeReady: true,
      completedEnvelopeId: completedTask.completedEnvelopeId,
      keyPossessionProofAvailable: true,
      acceptanceStatus: 'waiting',
    });
    expect(readyTransfer.envelopeCiphertextDigest).toBe(
      Buffer.from(directEnvelope.ciphertextDigest).toString('base64url'),
    );

    const deviceOnlyAcceptance = await signAcceptanceWithoutVaultKeys(readyTransfer);
    const deviceOnly = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/accept`,
      ...authed(target),
      payload: deviceOnlyAcceptance,
    });
    expect(deviceOnly.statusCode, deviceOnly.body).toBe(409);

    const acceptance = await targetKeyring.prepareOwnershipTransferAcceptance(target.userId, readyTransfer);

    const invalidDeviceSignature = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/accept`,
      ...authed(target),
      payload: { ...acceptance, signature: randomBytes(64).toString('base64url') },
    });
    expect(invalidDeviceSignature.statusCode).toBe(401);

    for (const mutation of [
      { keyEpoch: readyTransfer.keyEpoch + 1 },
      { completedEnvelopeId: crypto.randomUUID() },
      { envelopeCiphertextDigest: randomBytes(32).toString('base64url') },
    ]) {
      const tampered = await possessionRequest(readyTransfer, mutation);
      const response = await app.inject({
        method: 'POST',
        url: `/api/v2/vaults/${vaultId}/ownership-transfer/accept`,
        ...authed(target),
        payload: tampered,
      });
      expect(response.statusCode, response.body).toBe(409);
    }

    await app.ctx.db.update(userDevices).set({ status: 'revoked', revokedAt: new Date() }).where(
      eq(userDevices.id, targetDeviceId),
    );
    const revokedDevice = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/accept`,
      ...authed(target),
      payload: acceptance,
    });
    expect(revokedDevice.statusCode).toBe(423);
    await app.ctx.db.update(userDevices).set({ status: 'active', revokedAt: null }).where(
      eq(userDevices.id, targetDeviceId),
    );

    const accepted = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/accept`,
      ...authed(target),
      payload: acceptance,
    });
    expect(accepted.statusCode, accepted.body).toBe(200);
    expect(accepted.json()).toMatchObject({
      id: transfer.id,
      status: 'completed',
      acceptanceStatus: 'accepted',
      acceptedByDeviceId: targetDeviceId,
      envelopeReady: true,
    });

    const replay = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/ownership-transfer/accept`,
      ...authed(target),
      payload: acceptance,
    });
    expect(replay.statusCode, replay.body).toBe(200);
    expect(replay.json()).toMatchObject({ id: transfer.id, status: 'completed' });

    const stored = (await app.ctx.db.select().from(vaultOwnershipTransferRequests).where(
      eq(vaultOwnershipTransferRequests.id, transfer.id),
    ))[0]!;
    expect(stored.acceptanceIdempotencyKey).toBe(acceptance.idempotencyKey);
    expect(Buffer.from(stored.acceptanceDigest!).toString('base64url')).toBe(acceptance.acceptanceDigest);
    expect(Buffer.from(stored.acceptanceSignature!).toString('base64url')).toBe(acceptance.signature);
    expect(Buffer.from(stored.keyPossessionSignature!).toString('base64url')).toBe(
      acceptance.keyPossessionSignature,
    );
    expect(stored.acceptedKeyEpoch).toBe(readyTransfer.keyEpoch);
    expect(stored.acceptedAt).not.toBeNull();
    await expectMembership(vaultId, owner.userId, 'editor');
    await expectMembership(vaultId, target.userId, 'owner');
    expect((await app.ctx.db.select().from(vaultCryptoStates).where(
      eq(vaultCryptoStates.vaultId, vaultId),
    ))[0]!.writeState).toBe('rekeying');
  });
});

async function setupCrypto(session: TestSession, mainPassword: string) {
  const keyring = new E2eeKeyring();
  const setup = await keyring.setup(mainPassword, {
    accountId: session.userId,
    deviceId: crypto.randomUUID(),
    deviceName: 'Ownership transfer test',
    platform: 'integration:test',
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(session),
    payload: setup.request,
  });
  expect(response.statusCode, response.body).toBe(201);
  return {
    keyring,
    deviceId: setup.deviceId,
    profile: response.json() as UserCryptoProfile,
  };
}

async function initializeTeamVault(name: string): Promise<string> {
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
  const request = await ownerKeyring.initializeVault(
    owner.userId,
    vault.id,
    name,
    ownerProfile,
    recoveryKey,
  );
  const response = await app.inject({
    method: 'POST',
    url: `/api/v2/vaults/${vault.id}/initialize`,
    ...authed(owner),
    payload: request,
  });
  expect(response.statusCode, response.body).toBe(200);
  return vault.id;
}

async function setMember(vaultId: string, userId: string, role: 'viewer' | 'auditor'): Promise<void> {
  const request = await ownerKeyring.prepareMembershipSet(owner.userId, vaultId, {
    subjectKind: 'user',
    subjectId: userId,
    role,
    expectedAccessGeneration: await accessGeneration(vaultId),
  });
  const response = await app.inject({
    method: 'PUT',
    url: `/api/v2/vaults/${vaultId}/members`,
    ...authed(owner),
    payload: request,
  });
  expect(response.statusCode, response.body).toBe(200);
}

async function createTransfer(vaultId: string, userId: string, generation: number) {
  const request = await ownerKeyring.prepareOwnershipTransfer(owner.userId, vaultId, userId, generation);
  return app.inject({
    method: 'POST',
    url: `/api/v2/vaults/${vaultId}/ownership-transfer`,
    ...authed(owner),
    payload: request,
  });
}

async function expectCreatedTransfer(
  vaultId: string,
  userId: string,
  generation: number,
): Promise<VaultOwnershipTransfer> {
  const response = await createTransfer(vaultId, userId, generation);
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as VaultOwnershipTransfer;
}

async function pendingTask(vaultId: string, userId: string): Promise<VaultEnvelopeTask> {
  const response = await app.inject({
    method: 'GET',
    url: `/api/v2/vaults/${vaultId}/envelope-tasks`,
    ...authed(owner),
  });
  expect(response.statusCode, response.body).toBe(200);
  const task = (response.json() as VaultEnvelopeTask[]).find((candidate) => candidate.recipientUserId === userId);
  expect(task).toBeDefined();
  return task!;
}

async function completePendingTask(vaultId: string, userId: string): Promise<VaultEnvelopeTask> {
  const task = await pendingTask(vaultId, userId);
  const request = await ownerKeyring.prepareEnvelopeTaskCompletion(owner.userId, ownerProfile, task);
  const response = await app.inject({
    method: 'POST',
    url: `/api/v2/vaults/${vaultId}/envelope-tasks/${task.id}/complete`,
    ...authed(owner),
    payload: request,
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as VaultEnvelopeTask;
}

async function signAcceptanceWithoutVaultKeys(
  transfer: VaultOwnershipTransfer,
): Promise<AcceptVaultOwnershipTransferRequest> {
  const idempotencyKey = crypto.randomUUID();
  const acceptanceDigest = await ownershipTransferAcceptanceDigest({
    transferId: transfer.id,
    vaultId: transfer.vaultId,
    keyEpoch: transfer.keyEpoch,
    envelopeTaskId: transfer.envelopeTaskId,
    fromOwnerUserId: transfer.fromOwnerUserId,
    toOwnerUserId: transfer.toOwnerUserId,
    expectedAccessGeneration: transfer.expectedAccessGeneration,
    actorDeviceId: targetDeviceId,
    idempotencyKey,
    completedEnvelopeId: transfer.completedEnvelopeId ?? crypto.randomUUID(),
    envelopeCiphertextDigest: transfer.envelopeCiphertextDigest ?? randomBytes(32).toString('base64url'),
  });
  const unsigned = {
    idempotencyKey,
    transferId: transfer.id,
    envelopeTaskId: transfer.envelopeTaskId,
    expectedAccessGeneration: transfer.expectedAccessGeneration,
    acceptanceDigest,
    keyPossessionSignature: randomBytes(64).toString('base64url'),
    actorDeviceId: targetDeviceId,
  };
  const signer = targetKeyring as unknown as {
    signCommand: (
      kind: string,
      userId: string,
      scope: { vaultId: string },
      request: object,
    ) => Promise<string>;
  };
  return {
    ...unsigned,
    signature: await signer.signCommand(
      'vault.ownership-transfer.accept',
      target.userId,
      { vaultId: transfer.vaultId },
      unsigned,
    ),
  };
}

async function possessionRequest(
  transfer: VaultOwnershipTransfer,
  mutation: Partial<Pick<VaultOwnershipTransfer,
    'keyEpoch' | 'completedEnvelopeId' | 'envelopeCiphertextDigest'>>,
): Promise<AcceptVaultOwnershipTransferRequest> {
  const idempotencyKey = crypto.randomUUID();
  const evidence = {
    transferId: transfer.id,
    vaultId: transfer.vaultId,
    keyEpoch: mutation.keyEpoch ?? transfer.keyEpoch,
    envelopeTaskId: transfer.envelopeTaskId,
    fromOwnerUserId: transfer.fromOwnerUserId,
    toOwnerUserId: transfer.toOwnerUserId,
    expectedAccessGeneration: transfer.expectedAccessGeneration,
    actorDeviceId: targetDeviceId,
    idempotencyKey,
    completedEnvelopeId: mutation.completedEnvelopeId ?? transfer.completedEnvelopeId!,
    envelopeCiphertextDigest: mutation.envelopeCiphertextDigest ?? transfer.envelopeCiphertextDigest!,
  };
  const keys = await createVaultKeys(evidence.keyEpoch);
  try {
    const unsigned = {
      idempotencyKey,
      transferId: transfer.id,
      envelopeTaskId: transfer.envelopeTaskId,
      expectedAccessGeneration: transfer.expectedAccessGeneration,
      acceptanceDigest: await ownershipTransferAcceptanceDigest(evidence),
      keyPossessionSignature: await signVaultKeyPossession(keys, evidence),
      actorDeviceId: targetDeviceId,
    };
    return {
      ...unsigned,
      signature: await signTargetCommand('vault.ownership-transfer.accept', transfer.vaultId, unsigned),
    };
  } finally {
    await destroyVaultKeys(keys);
  }
}

async function signTargetCommand(kind: string, vaultId: string, request: object): Promise<string> {
  const signer = targetKeyring as unknown as {
    signCommand: (
      kind: string,
      userId: string,
      scope: { vaultId: string },
      request: object,
    ) => Promise<string>;
  };
  return signer.signCommand(kind, target.userId, { vaultId }, request);
}

async function loadTargetVaultKeys(): Promise<void> {
  const response = await app.inject({ method: 'GET', url: '/api/v2/bootstrap', ...authed(target) });
  expect(response.statusCode, response.body).toBe(200);
  const bootstrap = response.json() as EncryptedBootstrapResponse & {
    signerProfiles: Array<{ userId: string; signingPublicKey: string }>;
  };
  await targetKeyring.decryptBootstrap(
    bootstrap,
    Object.fromEntries(bootstrap.signerProfiles.map((profile) => [profile.userId, profile.signingPublicKey])),
  );
}

async function accessGeneration(vaultId: string): Promise<number> {
  return (await app.ctx.db.select({ generation: vaultCryptoStates.accessGeneration })
    .from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, vaultId)))[0]!.generation;
}

async function expectMembership(
  vaultId: string,
  userId: string,
  role: 'viewer' | 'editor' | 'owner',
): Promise<void> {
  const membership = (await app.ctx.db.select().from(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, vaultId),
    eq(vaultMemberships.subjectKind, 'user'),
    eq(vaultMemberships.subjectId, userId),
  )))[0];
  expect(membership?.role).toBe(role);
}
