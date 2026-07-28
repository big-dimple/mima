import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  EncryptedBootstrapResponse,
  EncryptedSyncEvent,
  EnterpriseRecoveryCandidate,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
  RekeyMaterial,
  UnlockChallenge,
  UserCryptoProfile,
} from '@mima/contracts';
import {
  destroyKeyPair,
  destroyVaultKeys,
  fromBase64Url,
  generateEncryptionKeyPair,
  openVaultKeyGrant,
} from '@mima/e2ee';
import {
  E2eeKeyring,
  parseOfflineRecoveryResult,
} from '../../../../packages/client-core/src/e2ee-keyring.ts';
import { parseRecoveryInput } from '../../../recovery-tool/src/protocol.ts';
import { createRecoveryTransfer } from '../../../recovery-tool/src/transfer.ts';
import {
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryKeys,
  systemRoleAssignments,
  users,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaults,
} from '../../src/db/schema.ts';
import { reconcileDirectoryMembershipChange } from '../../src/services/vault-envelope-tasks.ts';
import {
  TEST_API_HOST,
  authed,
  freshStrictTestApp,
  key,
  login,
  testServerOrigin,
  type TestSession,
} from './helpers.ts';

const MAIN_PASSWORD = 'personal recovery integration password';

let app: FastifyInstance;
let baseUrl: string;
let initialSession: TestSession;
let recoveredSession: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;
let initialKeyring: E2eeKeyring;
let recoveredKeyring: E2eeKeyring;
let recoveryKeyPair: Awaited<ReturnType<typeof generateEncryptionKeyPair>>;
let recoveryKey: EnterpriseRecoveryKey;
let profile: UserCryptoProfile;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_personal_vault_recovery_api');
  await app.listen({ port: 0, host: TEST_API_HOST });
  const address = app.server.address();
  baseUrl = testServerOrigin(typeof address === 'object' && address ? address.port : 0);
  initialSession = await login(app, 'bob');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: adminOne.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: adminTwo.userId, role: 'platform-admin', assignedBy: 'test' },
  ]).onConflictDoNothing();

  initialKeyring = new E2eeKeyring();
  recoveredKeyring = new E2eeKeyring();
  const setup = await initialKeyring.setup(MAIN_PASSWORD, {
    accountId: initialSession.userId,
    deviceId: randomUUID(),
    deviceName: 'Personal recovery original device',
    platform: 'integration:test',
  });
  const profileResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(initialSession),
    payload: setup.request,
  });
  expect(profileResponse.statusCode, profileResponse.body).toBe(201);
  profile = profileResponse.json() as UserCryptoProfile;

  recoveryKeyPair = await generateEncryptionKeyPair();
  recoveryKey = await stageRecoveryKey(recoveryKeyPair.publicKey);
});

afterAll(async () => {
  await initialKeyring.lock();
  await recoveredKeyring.lock();
  await destroyKeyPair(recoveryKeyPair);
  await app.close();
});

describe('personal vault recovery after directory reactivation', () => {
  it('keeps a ciphertext-only recovery candidate visible and completes approved recovery plus rekey', async () => {
    const personalVault = (await app.ctx.db.select().from(vaults).where(and(
      eq(vaults.kind, 'personal'),
      eq(vaults.ownerUserId, initialSession.userId),
    )).limit(1))[0]!;
    const initialized = await initialKeyring.initializeVault(
      initialSession.userId,
      personalVault.id,
      '个人密码库',
      profile,
      recoveryKey,
    );
    const initializeResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${personalVault.id}/initialize`,
      ...authed(initialSession),
      payload: initialized,
    });
    expect(initializeResponse.statusCode, initializeResponse.body).toBe(200);

    const encryptedItem = await initialKeyring.encryptCreate(initialSession.userId, personalVault.id, {
      kind: 'login',
      title: '恢复后仍应存在的条目',
      username: 'bob',
      origin: 'https://personal-recovery.example.test',
      tags: ['recovery'],
      favorite: false,
      sensitivity: 'high',
      secretValue: 'must-never-appear-in-bootstrap',
    });
    const createItemResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${personalVault.id}/items`,
      ...authed(initialSession),
      payload: encryptedItem,
    });
    expect(createItemResponse.statusCode, createItemResponse.body).toBe(201);

    const previousUser = (await app.ctx.db.select().from(users)
      .where(eq(users.id, initialSession.userId)).limit(1))[0]!;
    const deactivated = await app.ctx.db.transaction(async (tx) => {
      await tx.update(users).set({ active: false, groups: [] }).where(eq(users.id, initialSession.userId));
      return reconcileDirectoryMembershipChange(
        tx,
        initialSession.userId,
        previousUser.groups,
        [],
        new Date(),
        false,
        true,
      );
    });
    expect(deactivated.rekeyVaultIds).toContain(personalVault.id);
    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, personalVault.id)))[0]).toMatchObject({
      writeState: 'rekeying',
      activeEpoch: 1,
    });
    expect((await app.ctx.db.select().from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, personalVault.id),
      eq(vaultKeyEnvelopes.recipientUserId, initialSession.userId),
    ))).every((envelope) => envelope.status !== 'active')).toBe(true);
    await initialKeyring.lock();

    const reactivated = await app.ctx.db.transaction(async (tx) => {
      await tx.update(users).set({ active: true, groups: previousUser.groups })
        .where(eq(users.id, initialSession.userId));
      return reconcileDirectoryMembershipChange(
        tx,
        initialSession.userId,
        [],
        previousUser.groups,
        new Date(),
        true,
        false,
      );
    });
    expect(reactivated.addedVaultIds).not.toContain(personalVault.id);

    recoveredSession = await login(app, 'bob');
    const recoveredDeviceId = randomUUID();
    const enrollment = await recoveredKeyring.enrollWebDevice(MAIN_PASSWORD, profile, recoveredDeviceId);
    const registerDeviceResponse = await app.inject({
      method: 'POST',
      url: '/api/v2/devices',
      ...authed(recoveredSession),
      payload: enrollment.request,
    });
    expect(registerDeviceResponse.statusCode, registerDeviceResponse.body).toBe(201);
    await unlockSession(recoveredSession, recoveredKeyring, recoveredDeviceId);

    const candidateBootstrap = await encryptedBootstrap(recoveredSession);
    const candidateVault = candidateBootstrap.vaults.find((vault) => vault.id === personalVault.id);
    expect(candidateVault?.crypto).toMatchObject({
      status: 'rekey_required',
      recoveryRequired: true,
      recoveryReason: 'missing_current_full_envelope',
      rekeyTaskId: null,
    });
    expect(candidateBootstrap.headers.some((header) => header.vaultId === personalVault.id)).toBe(true);
    expect(candidateBootstrap.envelopes.filter((envelope) => envelope.vaultId === personalVault.id)).toEqual([]);
    expect(candidateBootstrap.items.filter((item) => item.vaultId === personalVault.id)).toEqual([]);
    expect(JSON.stringify(candidateBootstrap)).not.toContain(encryptedItem.itemId);
    expect(JSON.stringify(candidateBootstrap)).not.toContain('must-never-appear-in-bootstrap');
    const streamed = await syncUntilReady(recoveredSession, candidateBootstrap.cursor);
    expect(streamed.ready.vaultIds).toContain(personalVault.id);
    expect(streamed.events.some((event) =>
      event.type === 'vault.revoked' && event.vaultId === personalVault.id)).toBe(false);

    const contentIntent = await recoveredKeyring.contentIntent(recoveredSession.userId, {
      id: encryptedItem.itemId,
      vaultId: personalVault.id,
      kind: 'login',
      title: '客户端占位',
      username: null,
      origin: null,
      tags: [],
      favorite: false,
      sensitivity: 'high',
      version: 1,
      secretVersion: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      updatedBy: recoveredSession.userId,
    }, 'view');
    const deniedContent = await app.inject({
      method: 'POST',
      url: `/api/v2/items/${encryptedItem.itemId}/content`,
      ...authed(recoveredSession),
      payload: contentIntent,
    });
    expect(deniedContent.statusCode, deniedContent.body).toBe(403);

    const targetCandidateResponse = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/candidates',
      ...authed(recoveredSession),
    });
    expect(targetCandidateResponse.statusCode).toBe(403);
    const adminCandidatesResponse = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/candidates',
      ...authed(adminOne),
    });
    expect(adminCandidatesResponse.statusCode, adminCandidatesResponse.body).toBe(200);
    expect(adminCandidatesResponse.body).not.toContain(encryptedItem.itemId);
    expect(adminCandidatesResponse.body).not.toContain('must-never-appear-in-bootstrap');
    const candidate = (adminCandidatesResponse.json() as EnterpriseRecoveryCandidate[])
      .find((entry) => entry.vaultId === personalVault.id)!;
    expect(candidate).toMatchObject({
      targetUserId: recoveredSession.userId,
      targetDeviceId: recoveredDeviceId,
      targetCapability: 'full',
      reason: 'personal_owner_missing_current_full_envelope',
    });

    const createdRecovery = await app.inject({
      method: 'POST',
      url: '/api/v2/recovery/requests',
      ...authed(adminOne),
      payload: {
        idempotencyKey: key(),
        vaultId: candidate.vaultId,
        targetUserId: candidate.targetUserId,
        targetDeviceId: candidate.targetDeviceId,
        targetEncryptionPublicKey: candidate.targetEncryptionPublicKey,
        targetKeyVersion: candidate.targetKeyVersion,
        reason: 'lost_all_devices',
      },
    });
    expect(createdRecovery.statusCode, createdRecovery.body).toBe(201);
    let recoveryRequest = createdRecovery.json() as EnterpriseRecoveryRequest;
    for (const admin of [adminOne, adminTwo]) {
      const approval = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/requests/${recoveryRequest.id}/approve`,
        ...authed(admin),
        payload: { idempotencyKey: key(), requestDigest: recoveryRequest.requestDigest },
      });
      expect(approval.statusCode, approval.body).toBe(200);
      recoveryRequest = approval.json() as EnterpriseRecoveryRequest;
    }
    expect(recoveryRequest.status).toBe('approved');

    const recoveryPackageResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/requests/${recoveryRequest.id}/package`,
      ...authed(recoveredSession),
    });
    expect(recoveryPackageResponse.statusCode, recoveryPackageResponse.body).toBe(200);
    const recoveryInput = parseRecoveryInput(recoveryPackageResponse.body);
    const recoveredVaultKeys = await openVaultKeyGrant(
      recoveryInput.recoveryEnvelope,
      recoveryKeyPair,
      recoveryInput.trustedOwnerSigningPublicKey,
      {
        vaultId: personalVault.id,
        recipientId: recoveryKey.id,
        epoch: recoveryInput.epoch,
        recipientKeyVersion: 1,
      },
    );
    try {
      const transfer = await createRecoveryTransfer(
        recoveryInput,
        recoveredVaultKeys as Required<typeof recoveredVaultKeys>,
      );
      const recoveryPackage = recoveryPackageResponse.json() as {
        encryptedHeader: Parameters<E2eeKeyring['completeRecovery']>[3];
      };
      const completion = await recoveredKeyring.completeRecovery(
        recoveredSession.userId,
        recoveryRequest,
        recoveryKey,
        recoveryPackage.encryptedHeader,
        parseOfflineRecoveryResult(transfer),
      );
      const completeResponse = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/requests/${recoveryRequest.id}/complete`,
        ...authed(recoveredSession),
        payload: completion,
      });
      expect(completeResponse.statusCode, completeResponse.body).toBe(200);
    } finally {
      await destroyVaultKeys(recoveredVaultKeys);
    }

    const restoredBootstrap = await encryptedBootstrap(recoveredSession);
    const restoredVault = restoredBootstrap.vaults.find((vault) => vault.id === personalVault.id)!;
    expect(restoredVault.crypto.recoveryRequired).toBe(false);
    expect(restoredVault.crypto.recoveryReason).toBeNull();
    expect(restoredVault.crypto.rekeyTaskId).not.toBeNull();
    expect(restoredBootstrap.items.some((item) => item.itemId === encryptedItem.itemId)).toBe(true);

    const materialIntent = await recoveredKeyring.rekeyMaterialIntent(
      recoveredSession.userId,
      personalVault.id,
      restoredVault.crypto.rekeyTaskId!,
    );
    const materialResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/vaults/${personalVault.id}/rekey-material`,
      ...authed(recoveredSession),
      query: materialIntent,
    });
    expect(materialResponse.statusCode, materialResponse.body).toBe(200);
    const rekeyRequest = await recoveredKeyring.prepareVaultRekey(
      recoveredSession.userId,
      personalVault.id,
      profile,
      materialResponse.json() as RekeyMaterial,
    );
    const rekeyResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${personalVault.id}/rekey`,
      ...authed(recoveredSession),
      payload: rekeyRequest,
    });
    expect(rekeyResponse.statusCode, rekeyResponse.body).toBe(200);
    await recoveredKeyring.commitVaultRekey(personalVault.id);
    expect(rekeyResponse.json()).toMatchObject({
      status: 'e2ee',
      activeEpoch: 2,
      recoveryRequired: false,
      recoveryReason: null,
    });
  });
});

async function unlockSession(session: TestSession, keyring: E2eeKeyring, deviceId: string): Promise<void> {
  const challengeResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/session/unlock-challenge',
    ...authed(session),
    payload: { deviceId },
  });
  expect(challengeResponse.statusCode, challengeResponse.body).toBe(200);
  const completion = await keyring.signServerChallenge(challengeResponse.json() as UnlockChallenge);
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/session/crypto-unlock',
    ...authed(session),
    payload: completion,
  });
  expect(response.statusCode, response.body).toBe(200);
}

async function encryptedBootstrap(session: TestSession): Promise<EncryptedBootstrapResponse> {
  const response = await app.inject({
    method: 'GET',
    url: '/api/v2/bootstrap',
    ...authed(session),
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as EncryptedBootstrapResponse;
}

async function syncUntilReady(
  session: TestSession,
  cursor: number,
): Promise<{ ready: Extract<EncryptedSyncEvent, { type: 'sync.ready' }>; events: EncryptedSyncEvent[] }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(`${baseUrl}/api/v2/events?cursor=${cursor}`, {
      headers: { cookie: session.cookie, accept: 'text/event-stream' },
      signal: controller.signal,
    });
    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    const events: EncryptedSyncEvent[] = [];
    let buffer = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) throw new Error('SSE 在 sync.ready 前结束');
      buffer += decoder.decode(value, { stream: true });
      let separator = buffer.indexOf('\n\n');
      while (separator >= 0) {
        const frame = buffer.slice(0, separator);
        buffer = buffer.slice(separator + 2);
        const data = frame.split('\n')
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trim())
          .join('');
        if (data) {
          const event = JSON.parse(data) as EncryptedSyncEvent;
          events.push(event);
          if (event.type === 'sync.ready') return { ready: event, events };
        }
        separator = buffer.indexOf('\n\n');
      }
    }
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}

async function stageRecoveryKey(publicKey: string): Promise<EnterpriseRecoveryKey> {
  const publicKeyBytes = Buffer.from(await fromBase64Url(publicKey, 32));
  const evidenceDigest = randomBytes(32);
  const row = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: `personal-recovery-${randomUUID()}`,
    keyFingerprint: createHash('sha256').update(publicKeyBytes).digest('base64url'),
    publicEncryptionKey: publicKeyBytes,
    ceremonyEvidenceDigest: evidenceDigest,
    createdByUserId: adminOne.userId,
  }).returning())[0]!;
  await app.ctx.db.insert(enterpriseRecoveryKeyApprovals).values([
    { recoveryKeyId: row.id, approverUserId: adminOne.userId, ceremonyEvidenceDigest: evidenceDigest },
    { recoveryKeyId: row.id, approverUserId: adminTwo.userId, ceremonyEvidenceDigest: evidenceDigest },
  ]);
  const active = (await app.ctx.db.update(enterpriseRecoveryKeys).set({ status: 'active' })
    .where(eq(enterpriseRecoveryKeys.id, row.id)).returning())[0]!;
  return {
    id: active.id,
    ceremonyId: active.ceremonyId,
    keyFingerprint: active.keyFingerprint,
    publicEncryptionKey: publicKey,
    threshold: 2,
    shareCount: 3,
    status: 'active',
    ceremonyEvidenceDigest: evidenceDigest.toString('base64url'),
    approvalUserIds: [adminOne.userId, adminTwo.userId],
    createdAt: active.createdAt.toISOString(),
    retiredAt: null,
    cancelledAt: null,
  };
}
