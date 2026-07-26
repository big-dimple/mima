import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
  UserCryptoProfile,
} from '@mima/contracts';
import { createEnterpriseRecoveryKit } from '@mima/e2ee';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  sessions,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultRekeyJobs,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, key, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let administratorOne: TestSession;
let administratorTwo: TestSession;
let administratorThree: TestSession;
let ownerKeyring: E2eeKeyring;
let ownerProfile: UserCryptoProfile;
let vaultIds: string[];
let stagedKey: EnterpriseRecoveryKey;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_enterprise_recovery_readiness_coverage');
  owner = await login(app, 'bob');
  administratorOne = await login(app, 'alice');
  administratorTwo = await login(app, 'dave');
  administratorThree = await login(app, 'carol');
  const administrators = [administratorOne, administratorTwo, administratorThree];
  await app.ctx.db.insert(systemRoleAssignments).values(administrators.map((administrator) => ({
    userId: administrator.userId,
    role: 'platform-admin' as const,
    assignedBy: 'test',
  }))).onConflictDoNothing();
  await markRecoveryAdministratorsReady(administrators);

  ownerKeyring = new E2eeKeyring();
  const setup = await ownerKeyring.setup('owner recovery coverage password', {
    accountId: owner.userId,
    deviceId: randomUUID(),
    deviceName: 'Coverage owner',
    platform: 'test',
  });
  const profileResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(owner),
    payload: setup.request,
  });
  expect(profileResponse.statusCode, profileResponse.body).toBe(201);
  ownerProfile = profileResponse.json() as UserCryptoProfile;
  vaultIds = [
    await createInitializedVault('Recovery coverage one'),
    await createInitializedVault('Recovery coverage two'),
  ];

  const kit = await createEnterpriseRecoveryKit(`coverage-${randomUUID()}`);
  const registered = await app.inject({
    method: 'POST',
    url: '/api/v2/recovery/key',
    ...authed(administratorOne),
    payload: {
      ceremonyId: kit.ceremonyId,
      publicEncryptionKey: kit.publicKey,
      keyFingerprint: kit.publicKeyFingerprint,
      threshold: 2,
      shareCount: 3,
      ceremonyEvidenceDigest: kit.ceremonyDigest,
    },
  });
  expect(registered.statusCode, registered.body).toBe(201);
  let recoveryKey = registered.json() as EnterpriseRecoveryKey;
  expect(recoveryKey.approvalUserIds).toEqual([]);
  for (const administrator of [administratorOne, administratorTwo]) {
    const approved = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/keys/${recoveryKey.id}/approve`,
      ...authed(administrator),
      payload: {
        idempotencyKey: key(),
        ceremonyEvidenceDigest: recoveryKey.ceremonyEvidenceDigest,
      },
    });
    expect(approved.statusCode, approved.body).toBe(200);
    recoveryKey = approved.json() as EnterpriseRecoveryKey;
  }
  expect(recoveryKey).toMatchObject({
    status: 'staged',
    approvalUserIds: [administratorOne.userId, administratorTwo.userId],
  });
  stagedKey = recoveryKey;
});

afterAll(async () => {
  await ownerKeyring.lock();
  await app.close();
});

describe('enterprise recovery readiness and initial coverage', () => {
  it('requires three ready administrators and complete opaque vault coverage before first activation', async () => {
    const readinessResponse = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/readiness',
      headers: { cookie: administratorOne.cookie },
    });
    expect(readinessResponse.statusCode, readinessResponse.body).toBe(200);
    const readiness = readinessResponse.json() as EnterpriseRecoveryReadiness;
    expect(readiness).toMatchObject({
      requiredAdministratorCount: 3,
      administratorCount: 3,
      readyAdministratorCount: 3,
      ready: true,
    });
    expect(readiness.administrators.every((administrator) =>
      administrator.identitySource === 'oidc'
      && administrator.hasCryptoProfile
      && administrator.activeDeviceCount === 1
      && administrator.ready
    )).toBe(true);

    const initialCoverage = await recoveryCoverage(administratorOne);
    expect(initialCoverage).toMatchObject({
      totalVaultCount: 2,
      coveredVaultCount: 0,
      complete: false,
    });
    expect(initialCoverage.vaults.every((vault) =>
      vault.epoch === 1 && !vault.covered && !vault.canManage
    )).toBe(true);
    expect(initialCoverage.vaults.flatMap((vault) => vault.ownerUserIds))
      .toEqual([owner.userId, owner.userId]);

    const ownerCoverage = await recoveryCoverage(owner);
    expect(ownerCoverage.vaults).toHaveLength(2);
    expect(ownerCoverage.vaults.every((vault) => vault.canManage)).toBe(true);

    const firstRequest = await ownerKeyring.prepareEnterpriseRecoveryEnvelope(
      owner.userId,
      ownerProfile,
      stagedKey,
      vaultIds[0]!,
      1,
    );
    const invalidResponses = await Promise.all([
      app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${stagedKey.id}/vaults/${vaultIds[0]}/envelope`,
        ...authed(administratorThree),
        payload: firstRequest,
      }),
      app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${stagedKey.id}/vaults/${vaultIds[0]}/envelope`,
        ...authed(owner),
        payload: { ...firstRequest, envelope: { ...firstRequest.envelope, epoch: 2 } },
      }),
      app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${randomUUID()}/vaults/${vaultIds[0]}/envelope`,
        ...authed(owner),
        payload: firstRequest,
      }),
      app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${stagedKey.id}/vaults/${vaultIds[0]}/envelope`,
        ...authed(owner),
        payload: { ...firstRequest, signature: randomBytes(64).toString('base64url') },
      }),
    ]);
    expect(invalidResponses.map((response) => response.statusCode)).toEqual([403, 400, 409, 401]);

    await app.ctx.db.update(sessions).set({ locked: true })
      .where(eq(sessions.userId, owner.userId));
    const locked = await uploadEnvelope(vaultIds[0]!, firstRequest);
    expect(locked.statusCode, locked.body).toBe(423);
    await app.ctx.db.update(sessions).set({
      locked: false,
      unlockedDeviceId: ownerKeyring.deviceId,
      unlockedAt: new Date(),
    }).where(eq(sessions.userId, owner.userId));

    const firstUpload = await uploadEnvelope(vaultIds[0]!, firstRequest);
    expect(firstUpload.statusCode, firstUpload.body).toBe(201);
    expect(firstUpload.json()).toEqual({ ok: true, alreadyCovered: false });
    const duplicateRequest = await ownerKeyring.prepareEnterpriseRecoveryEnvelope(
      owner.userId,
      ownerProfile,
      stagedKey,
      vaultIds[0]!,
      1,
    );
    const duplicate = await uploadEnvelope(vaultIds[0]!, duplicateRequest);
    expect(duplicate.statusCode, duplicate.body).toBe(201);
    expect(duplicate.json()).toEqual({ ok: true, alreadyCovered: true });

    expect(await recoveryCoverage(administratorOne)).toMatchObject({
      totalVaultCount: 2,
      coveredVaultCount: 1,
      complete: false,
    });
    const incompleteActivation = await activateRecoveryKey();
    expect(incompleteActivation.statusCode, incompleteActivation.body).toBe(409);
    expect((incompleteActivation.json() as { message: string }).message).toContain('仍有密码库');

    const secondRequest = await ownerKeyring.prepareEnterpriseRecoveryEnvelope(
      owner.userId,
      ownerProfile,
      stagedKey,
      vaultIds[1]!,
      1,
    );
    const secondUpload = await uploadEnvelope(vaultIds[1]!, secondRequest);
    expect(secondUpload.statusCode, secondUpload.body).toBe(201);
    expect(await recoveryCoverage(administratorOne)).toMatchObject({
      totalVaultCount: 2,
      coveredVaultCount: 2,
      complete: true,
    });

    const activated = await activateRecoveryKey();
    expect(activated.statusCode, activated.body).toBe(200);
    expect((activated.json() as EnterpriseRecoveryKey).status).toBe('active');
    expect(await app.ctx.db.select().from(vaultRekeyJobs)).toHaveLength(0);
    const states = await app.ctx.db.select().from(vaultCryptoStates)
      .where(inArray(vaultCryptoStates.vaultId, vaultIds));
    expect(states).toHaveLength(2);
    expect(states.every((state) => state.writeState === 'open' && state.activeEpoch === 1)).toBe(true);

    const administratorBootstrap = await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      headers: { cookie: administratorOne.cookie },
    });
    expect(administratorBootstrap.statusCode, administratorBootstrap.body).toBe(200);
    const visibleVaultIds = (administratorBootstrap.json() as { vaults: Array<{ id: string }> })
      .vaults.map((vault) => vault.id);
    expect(visibleVaultIds).not.toEqual(expect.arrayContaining(vaultIds));
  });
});

async function createInitializedVault(name: string): Promise<string> {
  const vaultId = randomUUID();
  const request = await ownerKeyring.prepareVaultCreation(
    owner.userId,
    vaultId,
    name,
    ownerProfile,
    null,
    [],
  );
  const created = await app.inject({
    method: 'POST',
    url: '/api/v2/vaults',
    ...authed(owner),
    payload: request,
  });
  expect(created.statusCode, created.body).toBe(201);
  return vaultId;
}

async function recoveryCoverage(session: TestSession): Promise<EnterpriseRecoveryCoverage> {
  const response = await app.inject({
    method: 'GET',
    url: `/api/v2/recovery/keys/${stagedKey.id}/coverage`,
    headers: { cookie: session.cookie },
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as EnterpriseRecoveryCoverage;
}

function uploadEnvelope(
  vaultId: string,
  request: Awaited<ReturnType<E2eeKeyring['prepareEnterpriseRecoveryEnvelope']>>,
) {
  return app.inject({
    method: 'POST',
    url: `/api/v2/recovery/keys/${stagedKey.id}/vaults/${vaultId}/envelope`,
    ...authed(owner),
    payload: request,
  });
}

function activateRecoveryKey() {
  return app.inject({
    method: 'POST',
    url: `/api/v2/recovery/keys/${stagedKey.id}/activate`,
    ...authed(administratorOne),
    payload: {
      idempotencyKey: key(),
      ceremonyEvidenceDigest: stagedKey.ceremonyEvidenceDigest,
    },
  });
}

async function markRecoveryAdministratorsReady(administrators: TestSession[]) {
  await app.ctx.db.update(users).set({ source: 'oidc' })
    .where(inArray(users.id, administrators.map((administrator) => administrator.userId)));
  await app.ctx.db.insert(userCryptoProfiles).values(administrators.map((administrator) => ({
    userId: administrator.userId,
    profileVersion: 1,
    cryptoGeneration: 1,
    kdfSalt: randomBytes(16),
    wrappedAccountKeyCiphertext: randomBytes(96),
    wrappedAccountKeyNonce: randomBytes(24),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    signingKeyFingerprint: `coverage-admin-${administrator.userId}-${randomUUID()}`,
  })));
  await app.ctx.db.insert(userDevices).values(administrators.map((administrator) => ({
    id: randomUUID(),
    userId: administrator.userId,
    deviceType: 'web' as const,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    deviceGeneration: 1,
    keyFingerprint: `coverage-device-${administrator.userId}-${randomUUID()}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  })));
}
