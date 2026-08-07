import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  AccountCryptoResetRequest,
  EncryptedBootstrapResponse,
  EnterpriseRecoveryCase,
  EnterpriseRecoveryCaseApprovalMaterial,
  EnterpriseRecoveryCaseTransfer,
  EnterpriseRecoveryCustodyShare,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
  UnlockChallenge,
  UserCryptoProfile,
} from '@mima/contracts';
import { E2eeKeyring, parseOfflineRecoveryResult } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  accountCryptoResetRequests,
  systemRoleAssignments,
  users,
  vaultKeyEnvelopes,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshTestApp, key, login, type TestSession } from './helpers.ts';

const TARGET_OLD_PASSWORD = 'managed target old password';
const TARGET_NEW_PASSWORD = 'managed target new password';
const EMPTY_OLD_PASSWORD = 'managed empty old password';
const EMPTY_NEW_PASSWORD = 'managed empty new password';
const TOUCHED_OLD_PASSWORD = 'managed touched old password';
const TOUCHED_NEW_PASSWORD = 'managed touched new password';

let app: FastifyInstance;
let administratorOne: CryptoSession;
let administratorTwo: CryptoSession;
let target: CryptoSession;
let emptyTarget: CryptoSession;
let touchedTarget: CryptoSession;
let recoveryKey: EnterpriseRecoveryKey;

beforeAll(async () => {
  app = await freshTestApp('mima_test_enterprise_recovery_managed_v2');
  const administratorOneSession = await login(app, 'alice');
  const administratorTwoSession = await login(app, 'dave');
  const targetSession = await login(app, 'bob');
  const emptyTargetSession = await login(app, 'carol');
  const touchedTargetSession = await login(app, 'erin');

  await app.ctx.db.update(users).set({ source: 'oidc' }).where(inArray(
    users.id,
    [administratorOneSession.userId, administratorTwoSession.userId],
  ));
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: administratorOneSession.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: administratorTwoSession.userId, role: 'platform-admin', assignedBy: 'test' },
  ]);

  administratorOne = await setupCrypto(administratorOneSession, 'administrator one password');
  administratorTwo = await setupCrypto(administratorTwoSession, 'administrator two password');
  target = await setupCrypto(targetSession, TARGET_OLD_PASSWORD);
  emptyTarget = await setupCrypto(emptyTargetSession, EMPTY_OLD_PASSWORD);
  touchedTarget = await setupCrypto(touchedTargetSession, TOUCHED_OLD_PASSWORD);

  const readinessResponse = await app.inject({
    method: 'GET',
    url: '/api/v2/recovery/readiness',
    headers: { cookie: administratorOne.session.cookie },
  });
  expect(readinessResponse.statusCode, readinessResponse.body).toBe(200);
  const readiness = readinessResponse.json() as EnterpriseRecoveryReadiness;
  expect(readiness).toMatchObject({
    requiredAdministratorCount: 2,
    maximumAdministratorCount: 6,
    administratorCount: 2,
    readyAdministratorCount: 2,
    ready: true,
  });

  const registerRequest = await administratorOne.keyring.prepareManagedEnterpriseRecoveryKey(
    administratorOne.session.userId,
    readiness.administrators,
  );
  const registeredResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/recovery/custody',
    ...authed(administratorOne.session),
    payload: registerRequest,
  });
  expect(registeredResponse.statusCode, registeredResponse.body).toBe(201);
  recoveryKey = registeredResponse.json() as EnterpriseRecoveryKey;
  expect(recoveryKey).toMatchObject({
    custodyMode: 'administrator_accounts',
    custodyUserIds: [administratorOne.session.userId, administratorTwo.session.userId],
    status: 'pending',
    approvalUserIds: [administratorOne.session.userId],
  });

  const custodyResponse = await app.inject({
    method: 'GET',
    url: `/api/v2/recovery/keys/${recoveryKey.id}/custody/share`,
    ...authed(administratorTwo.session),
  });
  expect(custodyResponse.statusCode, custodyResponse.body).toBe(200);
  const approvalRequest = await administratorTwo.keyring.prepareManagedEnterpriseRecoveryKeyApproval(
    administratorTwo.session.userId,
    recoveryKey,
    custodyResponse.json() as EnterpriseRecoveryCustodyShare,
  );
  const approvedResponse = await app.inject({
    method: 'POST',
    url: `/api/v2/recovery/keys/${recoveryKey.id}/approve`,
    ...authed(administratorTwo.session),
    payload: approvalRequest,
  });
  expect(approvedResponse.statusCode, approvedResponse.body).toBe(200);
  recoveryKey = approvedResponse.json() as EnterpriseRecoveryKey;
  expect(recoveryKey).toMatchObject({
    status: 'active',
    approvalUserIds: [administratorOne.session.userId, administratorTwo.session.userId],
  });
});

afterAll(async () => {
  await Promise.all([
    administratorOne?.keyring.lock(),
    administratorTwo?.keyring.lock(),
    target?.keyring.lock(),
    emptyTarget?.keyring.lock(),
    touchedTarget?.keyring.lock(),
  ]);
  if (app) await app.close();
});

describe('administrator-account enterprise recovery', () => {
  it('restores a protected vault after two administrator confirmations', async () => {
    const vaultId = randomUUID();
    const vaultName = '双人自动恢复测试库';
    const creation = await target.keyring.prepareVaultCreation(
      target.session.userId,
      vaultId,
      vaultName,
      target.profile,
      recoveryKey,
      [],
    );
    const createdResponse = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(target.session),
      payload: creation,
    });
    expect(createdResponse.statusCode, createdResponse.body).toBe(201);

    const { recoveryCase, candidateKeyring } = await prepareForgotPasswordCase(
      target,
      TARGET_NEW_PASSWORD,
    );
    expect(recoveryCase).toMatchObject({
      status: 'pending_approval',
      resolutionKind: 'recover_access',
    });
    expect(recoveryCase.items.map((item) => item.vaultId)).toContain(vaultId);

    const approvedCase = await approveManagedCase(recoveryCase);
    expect(approvedCase.status).toBe('processing');
    expect(approvedCase.approvalUserIds).toEqual([
      administratorOne.session.userId,
      administratorTwo.session.userId,
    ]);
    expect((await app.ctx.db.select().from(accountCryptoResetRequests).where(eq(
      accountCryptoResetRequests.id,
      approvedCase.accountResetRequestId!,
    )).limit(1))[0]?.status).toBe('activated');

    const freshSession = await login(app, 'bob');
    const freshBrowser = await enrollCrypto(freshSession, TARGET_NEW_PASSWORD);
    const transferResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${approvedCase.id}/transfer`,
      ...authed(freshSession),
    });
    expect(transferResponse.statusCode, transferResponse.body).toBe(200);
    const transfer = transferResponse.json() as EnterpriseRecoveryCaseTransfer;
    expect(transfer.results).toHaveLength(approvedCase.items.length);

    const bootstrap = await encryptedBootstrap(freshSession);
    const activeRecoveryKey = bootstrap.recoveryKey;
    expect(activeRecoveryKey?.id).toBe(recoveryKey.id);
    for (const request of approvedCase.items.filter((item) => item.status === 'approved')) {
      const result = transfer.results.find((entry) => entry.requestId === request.id);
      const header = bootstrap.headers.find((entry) => entry.vaultId === request.vaultId);
      expect(result).toBeDefined();
      expect(header).toBeDefined();
      const completion = await freshBrowser.keyring.prepareRecovery(
        freshSession.userId,
        request,
        activeRecoveryKey!,
        header!,
        parseOfflineRecoveryResult(result!),
      );
      const completedResponse = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/requests/${request.id}/complete`,
        ...authed(freshSession),
        payload: completion,
      });
      expect(completedResponse.statusCode, completedResponse.body).toBe(200);
      await freshBrowser.keyring.commitRecovery(request.id);
    }

    const restoredBootstrap = await encryptedBootstrap(freshSession);
    const projection = await freshBrowser.keyring.decryptBootstrap(restoredBootstrap);
    expect(projection.vaults.find((vault) => vault.id === vaultId)?.name).toBe(vaultName);
    const completedCaseResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${approvedCase.id}`,
      ...authed(freshSession),
    });
    expect(completedCaseResponse.statusCode, completedCaseResponse.body).toBe(200);
    expect((completedCaseResponse.json() as EnterpriseRecoveryCase).status).toBe('completed');

    await candidateKeyring.abortAccountCryptoReset();
    await freshBrowser.keyring.lock();
  });

  it('replaces an empty personal vault without requiring key recovery', async () => {
    const oldVault = (await app.ctx.db.select().from(vaults).where(eq(
      vaults.ownerUserId,
      emptyTarget.session.userId,
    )).limit(1))[0]!;
    const initialization = await emptyTarget.keyring.initializeVault(
      emptyTarget.session.userId,
      oldVault.id,
      '我的密码库',
      emptyTarget.profile,
      recoveryKey,
    );
    const initializedResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${oldVault.id}/initialize`,
      ...authed(emptyTarget.session),
      payload: initialization,
    });
    expect(initializedResponse.statusCode, initializedResponse.body).toBe(200);

    const { recoveryCase, candidateKeyring } = await prepareForgotPasswordCase(
      emptyTarget,
      EMPTY_NEW_PASSWORD,
    );
    expect(recoveryCase).toMatchObject({
      status: 'pending_approval',
      resolutionKind: 'replace_empty_personal',
      items: [],
    });

    const completedCase = await approveManagedCase(recoveryCase);
    expect(completedCase).toMatchObject({
      status: 'completed',
      resolutionKind: 'replace_empty_personal',
    });
    const personalVaults = await app.ctx.db.select().from(vaults).where(eq(
      vaults.ownerUserId,
      emptyTarget.session.userId,
    ));
    expect(personalVaults).toHaveLength(1);
    expect(personalVaults[0]!.id).not.toBe(oldVault.id);

    const freshSession = await login(app, 'carol');
    const freshBrowser = await enrollCrypto(freshSession, EMPTY_NEW_PASSWORD);
    const replacement = personalVaults[0]!;
    const replacementInitialization = await freshBrowser.keyring.initializeVault(
      freshSession.userId,
      replacement.id,
      '我的密码库',
      freshBrowser.profile,
      recoveryKey,
    );
    const replacementResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${replacement.id}/initialize`,
      ...authed(freshSession),
      payload: replacementInitialization,
    });
    expect(replacementResponse.statusCode, replacementResponse.body).toBe(200);
    const recoveryEnvelope = await app.ctx.db.select().from(vaultKeyEnvelopes).where(eq(
      vaultKeyEnvelopes.recipientRecoveryKeyId,
      recoveryKey.id,
    ));
    expect(recoveryEnvelope.some((envelope) => (
      envelope.vaultId === replacement.id && envelope.status === 'active'
    ))).toBe(true);
    const projection = await freshBrowser.keyring.decryptBootstrap(await encryptedBootstrap(freshSession));
    expect(projection.vaults.find((vault) => vault.id === replacement.id)?.name).toBe('我的密码库');

    await candidateKeyring.abortAccountCryptoReset();
    await freshBrowser.keyring.lock();
  });

  it('keeps a personal vault that has encrypted header history', async () => {
    const personalVault = (await app.ctx.db.select().from(vaults).where(eq(
      vaults.ownerUserId,
      touchedTarget.session.userId,
    )).limit(1))[0]!;
    const initialization = await touchedTarget.keyring.initializeVault(
      touchedTarget.session.userId,
      personalVault.id,
      '我的密码库',
      touchedTarget.profile,
      recoveryKey,
    );
    const initializedResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${personalVault.id}/initialize`,
      ...authed(touchedTarget.session),
      payload: initialization,
    });
    expect(initializedResponse.statusCode, initializedResponse.body).toBe(200);
    const renamed = await touchedTarget.keyring.encryptVaultRename(
      touchedTarget.session.userId,
      personalVault.id,
      '曾经改名的空库',
      {
        ...initialization.header,
        updatedAt: new Date().toISOString(),
        updatedBy: touchedTarget.session.userId,
      },
    );
    const renamedResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/vaults/${personalVault.id}/header`,
      ...authed(touchedTarget.session),
      payload: renamed,
    });
    expect(renamedResponse.statusCode, renamedResponse.body).toBe(200);

    const { recoveryCase, candidateKeyring } = await prepareForgotPasswordCase(
      touchedTarget,
      TOUCHED_NEW_PASSWORD,
    );
    expect(recoveryCase).toMatchObject({
      status: 'pending_approval',
      resolutionKind: 'recover_access',
    });
    expect(recoveryCase.items.map((item) => item.vaultId)).toEqual([personalVault.id]);
    await candidateKeyring.abortAccountCryptoReset();
  });
});

interface CryptoSession {
  session: TestSession;
  keyring: E2eeKeyring;
  profile: UserCryptoProfile;
  deviceId: string;
}

async function setupCrypto(session: TestSession, password: string): Promise<CryptoSession> {
  const keyring = new E2eeKeyring();
  const setup = await keyring.setup(password, {
    accountId: session.userId,
    deviceId: randomUUID(),
    deviceName: 'Managed recovery test',
    platform: 'test',
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(session),
    payload: setup.request,
  });
  expect(response.statusCode, response.body).toBe(201);
  return {
    session,
    keyring,
    profile: response.json() as UserCryptoProfile,
    deviceId: setup.deviceId,
  };
}

async function enrollCrypto(session: TestSession, password: string): Promise<CryptoSession> {
  const profileResponse = await app.inject({
    method: 'GET',
    url: '/api/v2/crypto/profile',
    ...authed(session),
  });
  expect(profileResponse.statusCode, profileResponse.body).toBe(200);
  const profile = profileResponse.json() as UserCryptoProfile;
  const keyring = new E2eeKeyring();
  const deviceId = randomUUID();
  const enrollment = await keyring.enrollWebDevice(password, profile, deviceId);
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/devices',
    ...authed(session),
    payload: enrollment.request,
  });
  expect(response.statusCode, response.body).toBe(201);
  await unlockSession(session, keyring, deviceId);
  return { session, keyring, profile, deviceId };
}

async function prepareForgotPasswordCase(
  targetCrypto: CryptoSession,
  newPassword: string,
): Promise<{ recoveryCase: EnterpriseRecoveryCase; candidateKeyring: E2eeKeyring }> {
  const createdCaseResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/recovery/cases',
    ...authed(administratorOne.session),
    payload: {
      idempotencyKey: key(),
      kind: 'forgot_password',
      targetUserId: targetCrypto.session.userId,
    },
  });
  expect(createdCaseResponse.statusCode, createdCaseResponse.body).toBe(201);
  const createdCase = createdCaseResponse.json() as EnterpriseRecoveryCase;

  const lockedResponse = await app.inject({
    method: 'POST',
    url: '/api/session/lock',
    ...authed(targetCrypto.session),
  });
  expect(lockedResponse.statusCode, lockedResponse.body).toBe(200);

  const candidateKeyring = new E2eeKeyring();
  const candidate = await candidateKeyring.prepareAccountCryptoReset(
    newPassword,
    targetCrypto.profile,
    randomUUID(),
  );
  const resetResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/account-crypto-resets',
    ...authed(targetCrypto.session),
    payload: candidate.request,
  });
  expect(resetResponse.statusCode, resetResponse.body).toBe(201);
  const reset = resetResponse.json() as AccountCryptoResetRequest;
  const activation = await candidateKeyring.prepareAccountCryptoResetActivation(
    targetCrypto.session.userId,
    reset,
  );
  const finalizedResponse = await app.inject({
    method: 'POST',
    url: `/api/v2/recovery/cases/${createdCase.id}/target`,
    ...authed(targetCrypto.session),
    payload: {
      idempotencyKey: key(),
      kind: 'forgot_password',
      accountResetRequestId: reset.id,
      activation: activation.request,
    },
  });
  expect(finalizedResponse.statusCode, finalizedResponse.body).toBe(200);
  return {
    recoveryCase: finalizedResponse.json() as EnterpriseRecoveryCase,
    candidateKeyring,
  };
}

async function approveManagedCase(initialCase: EnterpriseRecoveryCase): Promise<EnterpriseRecoveryCase> {
  let recoveryCase = initialCase;
  for (const administrator of [administratorOne, administratorTwo]) {
    const materialResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/approval-material`,
      ...authed(administrator.session),
    });
    expect(materialResponse.statusCode, materialResponse.body).toBe(200);
    const request = await administrator.keyring.prepareManagedRecoveryCaseApproval(
      administrator.session.userId,
      materialResponse.json() as EnterpriseRecoveryCaseApprovalMaterial,
    );
    const approvedResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${recoveryCase.id}/approve`,
      ...authed(administrator.session),
      payload: request,
    });
    expect(approvedResponse.statusCode, approvedResponse.body).toBe(200);
    recoveryCase = approvedResponse.json() as EnterpriseRecoveryCase;
  }
  return recoveryCase;
}

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
