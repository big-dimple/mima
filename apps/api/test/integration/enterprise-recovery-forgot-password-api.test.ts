import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  AccountCryptoResetRequest,
  EncryptedBootstrapResponse,
  EnterpriseRecoveryCase,
  EnterpriseRecoveryCaseTransfer,
  EnterpriseRecoveryKey,
  UnlockChallenge,
  UserCryptoProfile,
} from '@mima/contracts';
import {
  destroyKeyPair,
  destroyVaultKeys,
  generateEncryptionKeyPair,
  openVaultKeyGrant,
} from '@mima/e2ee';
import {
  E2eeKeyring,
  parseOfflineRecoveryResult,
} from '../../../../packages/client-core/src/e2ee-keyring.ts';
import { parseRecoveryCaseInput } from '../../../recovery-tool/src/protocol.ts';
import { createRecoveryTransfer } from '../../../recovery-tool/src/transfer.ts';
import {
  accountCryptoResetRequests,
  enterpriseRecoveryKeys,
  systemRoleAssignments,
  userCryptoProfiles,
  vaultMemberships,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshTestApp, key, login, type TestSession } from './helpers.ts';

const OLD_PASSWORD = 'old correct horse battery staple';
const NEW_PASSWORD = 'new correct horse battery staple';

let app: FastifyInstance;
let target: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;
let recoveryKeyPair: Awaited<ReturnType<typeof generateEncryptionKeyPair>> | null = null;

beforeAll(async () => {
  app = await freshTestApp('mima_test_enterprise_recovery_forgot_password_api');
  target = await login(app, 'carol');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: adminOne.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: adminTwo.userId, role: 'platform-admin', assignedBy: 'test' },
  ]).onConflictDoNothing();
});

afterAll(async () => {
  if (recoveryKeyPair) await destroyKeyPair(recoveryKeyPair);
  if (app) await app.close();
});

describe('forgot-password enterprise recovery', () => {
  it('activates after two approvals and allows a fresh browser to use the new password', async () => {
    const oldKeyring = new E2eeKeyring();
    const oldDeviceId = randomUUID();
    const setup = await oldKeyring.setup(OLD_PASSWORD, {
      accountId: target.userId,
      deviceId: oldDeviceId,
      deviceName: 'Original browser',
      platform: 'test',
    });
    const createdProfile = await app.inject({
      method: 'POST',
      url: '/api/v2/crypto/profile',
      ...authed(target),
      payload: setup.request,
    });
    expect(createdProfile.statusCode, createdProfile.body).toBe(201);
    const oldProfile = createdProfile.json() as UserCryptoProfile;

    recoveryKeyPair = await generateEncryptionKeyPair();
    const recoveryPublicKey = Buffer.from(recoveryKeyPair.publicKey, 'base64url');
    const recoveryKeyRow = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
      ceremonyId: `forgot-${randomUUID()}`,
      keyFingerprint: createHash('sha256').update(recoveryPublicKey).digest('base64url'),
      publicEncryptionKey: recoveryPublicKey,
      status: 'active',
      ceremonyEvidenceDigest: randomBytes(32),
      createdByUserId: adminOne.userId,
    }).returning())[0]!;
    const recoveryKey: EnterpriseRecoveryKey = {
      id: recoveryKeyRow.id,
      ceremonyId: recoveryKeyRow.ceremonyId,
      keyFingerprint: recoveryKeyRow.keyFingerprint,
      publicEncryptionKey: recoveryKeyPair.publicKey,
      threshold: 2,
      shareCount: 3,
      status: 'active',
      ceremonyEvidenceDigest: recoveryKeyRow.ceremonyEvidenceDigest.toString('base64url'),
      approvalUserIds: [adminOne.userId, adminTwo.userId],
      createdAt: recoveryKeyRow.createdAt.toISOString(),
      retiredAt: null,
      cancelledAt: null,
    };
    const recoveryVault = (await app.ctx.db.insert(vaults).values({
      kind: 'team',
      name: '',
      ownerUserId: null,
    }).returning())[0]!;
    await app.ctx.db.insert(vaultMemberships).values({
      vaultId: recoveryVault.id,
      subjectKind: 'user',
      subjectId: target.userId,
      role: 'owner',
    });
    const initializedVault = await oldKeyring.initializeVault(
      target.userId,
      recoveryVault.id,
      '跨浏览器恢复测试库',
      oldProfile,
      recoveryKey,
    );
    const initializeResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${recoveryVault.id}/initialize`,
      ...authed(target),
      payload: initializedVault,
    });
    expect(initializeResponse.statusCode, initializeResponse.body).toBe(200);

    const createdCaseResponse = await app.inject({
      method: 'POST',
      url: '/api/v2/recovery/cases',
      ...authed(adminOne),
      payload: {
        idempotencyKey: key(),
        kind: 'forgot_password',
        targetUserId: target.userId,
      },
    });
    expect(createdCaseResponse.statusCode, createdCaseResponse.body).toBe(201);
    let recoveryCase = createdCaseResponse.json() as EnterpriseRecoveryCase;

    expect((await app.inject({
      method: 'POST',
      url: '/api/session/lock',
      ...authed(target),
    })).statusCode).toBe(200);
    const lockedCaseList = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/cases',
      ...authed(target),
    });
    expect(lockedCaseList.statusCode, lockedCaseList.body).toBe(200);

    const candidateKeyring = new E2eeKeyring();
    const candidate = await candidateKeyring.prepareAccountCryptoReset(
      NEW_PASSWORD,
      oldProfile,
      randomUUID(),
    );
    const createdResetResponse = await app.inject({
      method: 'POST',
      url: '/api/v2/account-crypto-resets',
      ...authed(target),
      payload: candidate.request,
    });
    expect(createdResetResponse.statusCode, createdResetResponse.body).toBe(201);
    const reset = createdResetResponse.json() as AccountCryptoResetRequest;
    const activation = await candidateKeyring.prepareAccountCryptoResetActivation(target.userId, reset);
    const finalizedResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/target`,
      ...authed(target),
      payload: {
        idempotencyKey: key(),
        kind: 'forgot_password',
        accountResetRequestId: reset.id,
        activation: activation.request,
      },
    });
    expect(finalizedResponse.statusCode, finalizedResponse.body).toBe(200);
    recoveryCase = finalizedResponse.json() as EnterpriseRecoveryCase;
    expect(recoveryCase.status).toBe('pending_approval');

    for (const administrator of [adminOne, adminTwo]) {
      const approvedResponse = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/cases/${recoveryCase.id}/approve`,
        ...authed(administrator),
        payload: {
          idempotencyKey: key(),
          caseDigest: recoveryCase.caseDigest,
        },
      });
      expect(approvedResponse.statusCode, approvedResponse.body).toBe(200);
      recoveryCase = approvedResponse.json() as EnterpriseRecoveryCase;
    }

    const activatedReset = (await app.ctx.db.select().from(accountCryptoResetRequests)
      .where(eq(accountCryptoResetRequests.id, reset.id)).limit(1))[0]!;
    expect(activatedReset.status).toBe('activated');
    expect(activatedReset.recoveryActivationDeviceSignature).toHaveLength(64);
    const updatedProfile = (await app.ctx.db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, target.userId)).limit(1))[0]!;
    expect(updatedProfile.cryptoGeneration).toBe(2);
    expect((await app.inject({
      method: 'GET',
      url: '/api/session',
      headers: { cookie: target.cookie },
    })).statusCode).toBe(401);

    const freshSession = await login(app, 'carol');
    const profileResponse = await app.inject({
      method: 'GET',
      url: '/api/v2/crypto/profile',
      ...authed(freshSession),
    });
    expect(profileResponse.statusCode, profileResponse.body).toBe(200);
    const recoveredProfile = profileResponse.json() as UserCryptoProfile;
    const freshBrowser = new E2eeKeyring();
    const freshDeviceId = randomUUID();
    const enrollment = await freshBrowser.enrollWebDevice(NEW_PASSWORD, recoveredProfile, freshDeviceId);
    const registered = await app.inject({
      method: 'POST',
      url: '/api/v2/devices',
      ...authed(freshSession),
      payload: enrollment.request,
    });
    expect(registered.statusCode, registered.body).toBe(201);
    expect(freshDeviceId).not.toBe(recoveryCase.targetDeviceId);
    await unlockSession(freshSession, freshBrowser, freshDeviceId);

    const recoveryPackageResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/package`,
      ...authed(adminOne),
    });
    expect(recoveryPackageResponse.statusCode, recoveryPackageResponse.body).toBe(200);
    const recoveryPackage = parseRecoveryCaseInput(recoveryPackageResponse.body);
    const results: EnterpriseRecoveryCaseTransfer['results'] = [];
    for (const item of recoveryPackage.items) {
      const vaultKeys = await openVaultKeyGrant(
        item.recoveryEnvelope,
        recoveryKeyPair,
        item.trustedOwnerSigningPublicKey,
        {
          vaultId: item.vaultId,
          recipientId: recoveryKey.id,
          epoch: item.epoch,
          recipientKeyVersion: 1,
        },
      );
      try {
        results.push(await createRecoveryTransfer(item, vaultKeys as Required<typeof vaultKeys>));
      } finally {
        await destroyVaultKeys(vaultKeys);
      }
    }
    const transfer: EnterpriseRecoveryCaseTransfer = {
      protocol: 'mima-e2ee-v2',
      kind: 'enterprise-recovery-case-transfer',
      caseId: recoveryPackage.caseId,
      caseDigest: recoveryPackage.caseDigest,
      results,
    };
    const uploadResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/transfers`,
      ...authed(adminOne),
      payload: {
        idempotencyKey: key(),
        caseDigest: recoveryPackage.caseDigest,
        transfer,
      },
    });
    expect(uploadResponse.statusCode, uploadResponse.body).toBe(200);
    recoveryCase = uploadResponse.json() as EnterpriseRecoveryCase;

    const bootstrapBeforeRecovery = await encryptedBootstrap(freshSession);
    for (const request of recoveryCase.items.filter((item) => item.status === 'approved')) {
      const result = transfer.results.find((entry) => entry.requestId === request.id);
      const header = bootstrapBeforeRecovery.headers.find((entry) => entry.vaultId === request.vaultId);
      expect(result).toBeDefined();
      expect(header).toBeDefined();
      const completion = await freshBrowser.prepareRecovery(
        target.userId,
        request,
        recoveryKey,
        header!,
        parseOfflineRecoveryResult(result!),
      );
      const completeResponse = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/requests/${request.id}/complete`,
        ...authed(freshSession),
        payload: completion,
      });
      expect(completeResponse.statusCode, completeResponse.body).toBe(200);
      await freshBrowser.commitRecovery(request.id);
    }

    const restoredBootstrap = await encryptedBootstrap(freshSession);
    const projection = await freshBrowser.decryptBootstrap(restoredBootstrap);
    expect(projection.vaults.find((vault) => vault.id === recoveryVault.id)?.name)
      .toBe('跨浏览器恢复测试库');

    await oldKeyring.lock();
    await candidateKeyring.abortAccountCryptoReset();
    await freshBrowser.lock();
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
