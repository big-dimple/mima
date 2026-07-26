import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
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
  syncEvents,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultMemberships,
  vaultRekeyJobs,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, key, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let target: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;
let adminThree: TestSession;
let keyring: E2eeKeyring;
let recoveryKeyPair: Awaited<ReturnType<typeof generateEncryptionKeyPair>>;
let recoveryKey: EnterpriseRecoveryKey;
let profile: UserCryptoProfile;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_enterprise_recovery_rekey_api');
  target = await login(app, 'bob');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  adminThree = await login(app, 'carol');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: adminOne.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: adminTwo.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: adminThree.userId, role: 'platform-admin', assignedBy: 'test' },
  ]).onConflictDoNothing();
  await markRecoveryAdministratorsReady([adminOne, adminTwo, adminThree]);

  keyring = new E2eeKeyring();
  const setup = await keyring.setup('correct horse battery staple', {
    accountId: target.userId,
    deviceId: crypto.randomUUID(),
    deviceName: 'Recovery target',
    platform: 'test',
  });
  const profileResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(target),
    payload: setup.request,
  });
  expect(profileResponse.statusCode, profileResponse.body).toBe(201);
  profile = profileResponse.json() as UserCryptoProfile;

  recoveryKeyPair = await generateEncryptionKeyPair();
  recoveryKey = await stageRecoveryKey('recovery-rekey-initial', recoveryKeyPair.publicKey, true);
});

afterAll(async () => {
  await keyring.lock();
  await destroyKeyPair(recoveryKeyPair);
  await app.close();
});

describe('enterprise recovery rekey boundary', () => {
  it('freezes full recovery, keeps metadata recovery open, and freezes every vault on key rotation', async () => {
    const fullVaultId = await createInitializedVault('Full recovery vault');
    const metadataVaultId = await createInitializedVault('Metadata recovery vault');
    await app.ctx.db.update(vaultMemberships).set({ role: 'auditor' }).where(and(
      eq(vaultMemberships.vaultId, metadataVaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, target.userId),
    ));

    const fullCompletion = await completeRecovery(fullVaultId, 'lost_all_devices');
    expect(fullCompletion.response.statusCode, fullCompletion.response.body).toBe(200);
    const fullState = await cryptoState(fullVaultId);
    expect(fullState.writeState).toBe('rekeying');
    const fullJobs = await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.vaultId, fullVaultId));
    expect(fullJobs).toHaveLength(1);
    expect(fullJobs[0]).toMatchObject({
      fromEpoch: 1,
      toEpoch: 2,
      reason: 'device_compromise',
      status: 'pending',
    });
    await expectRekeyEvent(fullVaultId, fullJobs[0]!.id, 2);
    const materialIntent = await keyring.rekeyMaterialIntent(
      target.userId,
      fullVaultId,
      fullJobs[0]!.id,
    );
    const material = await app.inject({
      method: 'GET',
      url: `/api/v2/vaults/${fullVaultId}/rekey-material`,
      ...authed(target),
      query: materialIntent,
    });
    expect(material.statusCode, material.body).toBe(200);
    const recipients = (material.json() as { recipients: Array<{ userId: string }> }).recipients;
    expect(recipients.filter((recipient) => recipient.userId === target.userId)).toHaveLength(1);

    const recoveredRows = await app.ctx.db.select().from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, fullVaultId),
      eq(vaultKeyEnvelopes.authorizationKind, 'recovery'),
      eq(vaultKeyEnvelopes.authorizationRef, fullCompletion.request.id),
    ));
    expect(recoveredRows).toHaveLength(1);
    const recoveredRow = recoveredRows[0]!;
    await expect(app.ctx.db.insert(vaultKeyEnvelopes).values({
      vaultId: recoveredRow.vaultId,
      keyEpoch: recoveredRow.keyEpoch,
      recipientKind: recoveredRow.recipientKind,
      accessScope: recoveredRow.accessScope,
      recipientUserId: recoveredRow.recipientUserId,
      recipientDeviceId: recoveredRow.recipientDeviceId,
      recipientRecoveryKeyId: recoveredRow.recipientRecoveryKeyId,
      recipientKeyFingerprint: recoveredRow.recipientKeyFingerprint,
      authorizationKind: recoveredRow.authorizationKind,
      authorizationRef: recoveredRow.authorizationRef,
      envelopeVersion: recoveredRow.envelopeVersion,
      ciphertext: randomBytes(96),
      ciphertextDigest: randomBytes(32),
      senderDeviceId: recoveredRow.senderDeviceId,
      signature: randomBytes(64),
      status: 'active',
      activatedAt: new Date(),
    })).rejects.toMatchObject({ cause: { code: '23505' } });

    const fullReplay = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/requests/${fullCompletion.request.id}/complete`,
      ...authed(target),
      payload: fullCompletion.payload,
    });
    expect(fullReplay.statusCode, fullReplay.body).toBe(200);
    expect(await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.vaultId, fullVaultId))).toHaveLength(1);
    expect(await rekeyEvents(fullVaultId)).toHaveLength(1);
    expect(await app.ctx.db.select().from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, fullVaultId),
      eq(vaultKeyEnvelopes.authorizationKind, 'recovery'),
      eq(vaultKeyEnvelopes.authorizationRef, fullCompletion.request.id),
    ))).toHaveLength(1);

    const metadataCompletion = await completeRecovery(metadataVaultId, 'suspected_compromise');
    expect(metadataCompletion.request.targetCapability).toBe('metadata');
    expect(metadataCompletion.response.statusCode, metadataCompletion.response.body).toBe(200);
    expect((await cryptoState(metadataVaultId)).writeState).toBe('open');
    expect(await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.vaultId, metadataVaultId))).toHaveLength(0);
    expect(await rekeyEvents(metadataVaultId)).toHaveLength(0);

    const rotatedPair = await generateEncryptionKeyPair();
    try {
      const rotatedKey = await stageRecoveryKey('recovery-rekey-rotated', rotatedPair.publicKey, false);
      for (const vaultId of [fullVaultId, metadataVaultId]) {
        const ciphertext = randomBytes(96);
        await app.ctx.db.insert(vaultKeyEnvelopes).values({
          vaultId,
          keyEpoch: 1,
          recipientKind: 'enterprise_recovery',
          accessScope: 'recovery',
          recipientRecoveryKeyId: rotatedKey.id,
          recipientKeyFingerprint: rotatedKey.keyFingerprint,
          authorizationKind: 'recovery',
          authorizationRef: rotatedKey.ceremonyId,
          envelopeVersion: 1,
          ciphertext,
          ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
          senderDeviceId: keyring.deviceId!,
          signature: randomBytes(64),
          status: 'active',
          activatedAt: new Date(),
        });
      }
      const activationPayload = {
        idempotencyKey: key(),
        ceremonyEvidenceDigest: rotatedKey.ceremonyEvidenceDigest,
      };
      const eventCountBefore = (await app.ctx.db.select().from(syncEvents)
        .where(eq(syncEvents.type, 'vault.rekey_required'))).length;
      const activated = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${rotatedKey.id}/activate`,
        ...authed(adminOne),
        payload: activationPayload,
      });
      expect(activated.statusCode, activated.body).toBe(200);

      const states = await app.ctx.db.select().from(vaultCryptoStates)
        .where(inArray(vaultCryptoStates.vaultId, [fullVaultId, metadataVaultId]));
      expect(states).toHaveLength(2);
      expect(states.every((state) => state.writeState === 'rekeying')).toBe(true);
      const jobs = await app.ctx.db.select().from(vaultRekeyJobs)
        .where(inArray(vaultRekeyJobs.vaultId, [fullVaultId, metadataVaultId]));
      expect(jobs).toHaveLength(2);
      expect(jobs.every((job) => job.reason === 'device_compromise')).toBe(true);
      const oldEnvelopes = await app.ctx.db.select().from(vaultKeyEnvelopes)
        .where(eq(vaultKeyEnvelopes.recipientRecoveryKeyId, recoveryKey.id));
      expect(oldEnvelopes).toHaveLength(2);
      expect(oldEnvelopes.every((envelope) =>
        envelope.status === 'revoked' && envelope.revocationReason === 'recovery_key_rotated'
      )).toBe(true);
      expect((await app.ctx.db.select().from(syncEvents)
        .where(eq(syncEvents.type, 'vault.rekey_required'))).length).toBe(eventCountBefore + 2);

      const stateVersions = new Map(states.map((state) => [state.vaultId, state.rowVersion]));
      const replay = await app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${rotatedKey.id}/activate`,
        ...authed(adminOne),
        payload: activationPayload,
      });
      expect(replay.statusCode, replay.body).toBe(200);
      const replayedStates = await app.ctx.db.select().from(vaultCryptoStates)
        .where(inArray(vaultCryptoStates.vaultId, [fullVaultId, metadataVaultId]));
      expect(replayedStates.every((state) => state.rowVersion === stateVersions.get(state.vaultId))).toBe(true);
      expect((await app.ctx.db.select().from(syncEvents)
        .where(eq(syncEvents.type, 'vault.rekey_required'))).length).toBe(eventCountBefore + 2);
    } finally {
      await destroyKeyPair(rotatedPair);
    }
  });
});

async function createInitializedVault(name: string): Promise<string> {
  const vaultId = randomUUID();
  const request = await keyring.prepareVaultCreation(
    target.userId,
    vaultId,
    name,
    profile,
    recoveryKey,
    [],
  );
  const created = await app.inject({
    method: 'POST',
    url: '/api/v2/vaults',
    ...authed(target),
    payload: request,
  });
  expect(created.statusCode, created.body).toBe(201);
  return vaultId;
}

async function completeRecovery(
  vaultId: string,
  reason: 'lost_all_devices' | 'suspected_compromise',
) {
  const created = await app.inject({
    method: 'POST',
    url: '/api/v2/recovery/requests',
    ...authed(adminOne),
    payload: {
      idempotencyKey: key(),
      vaultId,
      targetUserId: target.userId,
      targetDeviceId: keyring.deviceId,
      targetEncryptionPublicKey: profile.encryptionPublicKey,
      targetKeyVersion: profile.keyVersion,
      reason,
    },
  });
  expect(created.statusCode, created.body).toBe(201);
  let request = created.json() as EnterpriseRecoveryRequest;
  for (const admin of [adminOne, adminTwo]) {
    const approved = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/requests/${request.id}/approve`,
      ...authed(admin),
      payload: { idempotencyKey: key(), requestDigest: request.requestDigest },
    });
    expect(approved.statusCode, approved.body).toBe(200);
    request = approved.json() as EnterpriseRecoveryRequest;
  }
  expect(request.status).toBe('approved');

  const packaged = await app.inject({
    method: 'GET',
    url: `/api/v2/recovery/requests/${request.id}/package`,
    ...authed(target),
  });
  expect(packaged.statusCode, packaged.body).toBe(200);
  const input = parseRecoveryInput(packaged.body);
  const recoveredKeys = await openVaultKeyGrant(
    input.recoveryEnvelope,
    recoveryKeyPair,
    input.trustedOwnerSigningPublicKey,
    {
      vaultId,
      recipientId: recoveryKey.id,
      epoch: input.epoch,
      recipientKeyVersion: 1,
    },
  );
  try {
    const transfer = await createRecoveryTransfer(input, recoveredKeys as Required<typeof recoveredKeys>);
    const payload = await keyring.completeRecovery(
      target.userId,
      request,
      recoveryKey,
      (packaged.json() as { encryptedHeader: Parameters<E2eeKeyring['completeRecovery']>[3] }).encryptedHeader,
      parseOfflineRecoveryResult(transfer),
    );
    const response = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/requests/${request.id}/complete`,
      ...authed(target),
      payload,
    });
    return { request, payload, response };
  } finally {
    await destroyVaultKeys(recoveredKeys);
  }
}

async function stageRecoveryKey(
  ceremonyId: string,
  publicKey: string,
  activate: boolean,
): Promise<EnterpriseRecoveryKey> {
  const publicKeyBytes = Buffer.from(await fromBase64Url(publicKey, 32));
  const evidenceDigest = randomBytes(32);
  const row = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId,
    keyFingerprint: createHash('sha256').update(publicKeyBytes).digest('base64url'),
    publicEncryptionKey: publicKeyBytes,
    ceremonyEvidenceDigest: evidenceDigest,
    createdByUserId: adminOne.userId,
  }).returning())[0]!;
  await app.ctx.db.insert(enterpriseRecoveryKeyApprovals).values([
    { recoveryKeyId: row.id, approverUserId: adminOne.userId, ceremonyEvidenceDigest: evidenceDigest },
    { recoveryKeyId: row.id, approverUserId: adminTwo.userId, ceremonyEvidenceDigest: evidenceDigest },
  ]);
  const staged = (await app.ctx.db.select().from(enterpriseRecoveryKeys)
    .where(eq(enterpriseRecoveryKeys.id, row.id)))[0]!;
  const result = activate
    ? (await app.ctx.db.update(enterpriseRecoveryKeys).set({ status: 'active' })
        .where(eq(enterpriseRecoveryKeys.id, row.id)).returning())[0]!
    : staged;
  return {
    id: result.id,
    ceremonyId: result.ceremonyId,
    keyFingerprint: result.keyFingerprint,
    publicEncryptionKey: publicKey,
    threshold: 2,
    shareCount: 3,
    status: result.status,
    ceremonyEvidenceDigest: evidenceDigest.toString('base64url'),
    approvalUserIds: [adminOne.userId, adminTwo.userId],
    createdAt: result.createdAt.toISOString(),
    retiredAt: result.retiredAt?.toISOString() ?? null,
  };
}

async function cryptoState(vaultId: string) {
  return (await app.ctx.db.select().from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.vaultId, vaultId)))[0]!;
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
    signingKeyFingerprint: `recovery-rekey-admin-${administrator.userId}-${crypto.randomUUID()}`,
  })));
  await app.ctx.db.insert(userDevices).values(administrators.map((administrator) => ({
    id: crypto.randomUUID(),
    userId: administrator.userId,
    deviceType: 'web' as const,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    deviceGeneration: 1,
    keyFingerprint: `recovery-rekey-device-${administrator.userId}-${crypto.randomUUID()}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  })));
}

async function rekeyEvents(vaultId: string) {
  return app.ctx.db.select().from(syncEvents).where(and(
    eq(syncEvents.vaultId, vaultId),
    eq(syncEvents.type, 'vault.rekey_required'),
  ));
}

async function expectRekeyEvent(vaultId: string, taskId: string, pendingEpoch: number) {
  const events = await rekeyEvents(vaultId);
  expect(events).toHaveLength(1);
  expect(events[0]!.payload).toEqual({ pendingEpoch, taskId });
}
