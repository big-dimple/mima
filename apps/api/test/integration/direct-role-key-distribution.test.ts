import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  EncryptedBootstrapResponse,
  EncryptedItemMetadata,
  EnterpriseRecoveryKey,
  RekeyMaterial,
  UserCryptoProfile,
  VaultEnvelopeTask,
} from '@mima/contracts';
import { ITEM_METADATA_FORMAT_HEADER, ITEM_METADATA_FORMAT_VERSION } from '@mima/contracts';
import { createEnterpriseRecoveryKit } from '@mima/e2ee';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  customGroupMembers,
  customGroups,
  auditEvents,
  encryptedVaultHeaders,
  enterpriseRecoveryKeys,
  extensionSessions,
  legacyMigrationJobs,
  items,
  syncEvents,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultEnvelopeTasks,
  vaultKeyEnvelopes,
  vaultMemberships,
  vaultRekeyJobs,
  vaults,
} from '../../src/db/schema.ts';
import { hashToken } from '../../src/plugins/auth.ts';
import {
  ensureEnvelopeTasks,
  ensureMembershipRekeyTask,
  isEnvelopeTaskAuthorizationActive,
} from '../../src/services/vault-envelope-tasks.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let target: TestSession;
let ownerKeyring: E2eeKeyring;
let targetKeyring: E2eeKeyring;
let ownerProfile: UserCryptoProfile;
let targetProfile: UserCryptoProfile;
let ownerDeviceId: string;
let targetDeviceId: string;
let extensionDeviceId: string;
let extensionToken: string;
let recoveryKey: EnterpriseRecoveryKey;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_direct_role_key_distribution');
  owner = await login(app, 'bob');
  target = await login(app, 'dave');
  ({ keyring: ownerKeyring, deviceId: ownerDeviceId, profile: ownerProfile } = await setupCrypto(
    owner,
    'direct override owner password',
  ));
  const targetSetup = await setupCrypto(
    target,
    'direct override target password',
  );
  targetKeyring = targetSetup.keyring;
  targetDeviceId = targetSetup.deviceId;
  targetProfile = targetSetup.profile;

  extensionDeviceId = randomUUID();
  await app.ctx.db.insert(userDevices).values({
    id: extensionDeviceId,
    userId: target.userId,
    deviceType: 'extension',
    status: 'active',
    trustMethod: 'device_approval',
    keyFingerprint: `direct-override-extension-${extensionDeviceId}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    approvedByDeviceId: targetDeviceId,
    activatedAt: new Date(),
  });
  extensionToken = `direct-override-${randomUUID()}`;
  await app.ctx.db.insert(extensionSessions).values({
    tokenHash: hashToken(extensionToken),
    userId: target.userId,
    deviceId: extensionDeviceId,
    securityGeneration: 1,
    expiresAt: new Date(Date.now() + 60_000),
  });

  const kit = await createEnterpriseRecoveryKit('direct-role-key-distribution');
  const recoveryRow = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: kit.ceremonyId,
    keyFingerprint: kit.publicKeyFingerprint,
    publicEncryptionKey: Buffer.from(kit.publicKey, 'base64url'),
    status: 'active',
    ceremonyEvidenceDigest: Buffer.from(kit.ceremonyDigest, 'base64url'),
    createdByUserId: owner.userId,
  }).returning())[0]!;
  recoveryKey = {
    id: recoveryRow.id,
    ceremonyId: recoveryRow.ceremonyId,
    keyFingerprint: recoveryRow.keyFingerprint,
    publicEncryptionKey: kit.publicKey,
    threshold: 2,
    shareCount: 3,
    status: 'active',
    ceremonyEvidenceDigest: kit.ceremonyDigest,
    approvalUserIds: [],
    createdAt: recoveryRow.createdAt.toISOString(),
    retiredAt: null,
    cancelledAt: null,
  };
});

afterAll(async () => {
  await Promise.all([ownerKeyring.lock(), targetKeyring.lock()]);
  await app.close();
});

describe('direct membership key capability override', () => {
  it('requires current metadata support before serving extension ciphertext', async () => {
    const bootstrap = await app.inject({
      method: 'GET',
      url: '/api/v2/extension/bootstrap',
      headers: { authorization: `Bearer ${extensionToken}` },
    });
    expect(bootstrap.statusCode, bootstrap.body).toBe(426);
    expect(bootstrap.json()).toMatchObject({
      code: 'extension_update_required',
      message: '扩展版本较旧，请更新扩展后继续使用；当前设备授权仍然保留，无需重新配对',
    });

    const content = await app.inject({
      method: 'POST',
      url: `/api/v2/extension/items/${randomUUID()}/content`,
      headers: {
        authorization: `Bearer ${extensionToken}`,
        [ITEM_METADATA_FORMAT_HEADER]: '3',
      },
      payload: {
        purpose: 'copy',
        secretVersion: 1,
        deviceId: extensionDeviceId,
        intentSignature: 'c2lnbmF0dXJl',
      },
    });
    expect(content.statusCode, content.body).toBe(426);

    const compatibleBootstrap = await app.inject({
      method: 'GET',
      url: '/api/v2/extension/bootstrap',
      headers: {
        authorization: `Bearer ${extensionToken}`,
        [ITEM_METADATA_FORMAT_HEADER]: '4',
      },
    });
    expect(compatibleBootstrap.statusCode, compatibleBootstrap.body).toBe(200);
  });

  it('keeps directory and custom-group grants below a direct auditor role in tasks and bootstraps', async () => {
    const vaultId = await initializeTeamVault('直接角色覆盖');
    await setMembership(vaultId, 'user', target.userId, 'auditor');
    await completePendingTask(vaultId, 'direct', target.userId);

    const viewerGroup = `group:test/direct-viewer-${randomUUID()}`;
    const editorGroup = `group:test/direct-editor-${randomUUID()}`;
    await app.ctx.db.update(users).set({ groups: [viewerGroup, editorGroup] })
      .where(eq(users.id, target.userId));
    await setMembership(vaultId, 'group', viewerGroup, 'viewer');
    await setMembership(vaultId, 'group', editorGroup, 'editor');

    const customGroup = (await app.ctx.db.insert(customGroups).values({
      ownerUserId: owner.userId,
      name: `直接角色覆盖-${randomUUID()}`,
    }).returning())[0]!;
    await app.ctx.db.insert(customGroupMembers).values({
      groupId: customGroup.id,
      userId: target.userId,
      addedBy: owner.userId,
    });
    await setMembership(vaultId, 'custom_group', customGroup.id, 'viewer');

    const tasks = await app.ctx.db.select().from(vaultEnvelopeTasks)
      .where(eq(vaultEnvelopeTasks.vaultId, vaultId));
    expect(tasks.filter((task) => task.authorizationKind !== 'direct')).toHaveLength(0);

    const overriddenAuthorizations = [
      { authorizationKind: 'directory_group' as const, authorizationRef: viewerGroup },
      { authorizationKind: 'directory_group' as const, authorizationRef: editorGroup },
      { authorizationKind: 'custom_group' as const, authorizationRef: customGroup.id },
    ];
    for (const input of overriddenAuthorizations) {
      expect(await isEnvelopeTaskAuthorizationActive(app.ctx.db, {
        vaultId,
        keyEpoch: 1,
        ...input,
        recipientUserId: target.userId,
        capability: 'full',
      })).toBe(false);
      expect(await ensureEnvelopeTasks(app.ctx.db, {
        vaultId,
        keyEpoch: 1,
        ...input,
        recipientUserIds: [target.userId],
        capability: 'full',
      })).toEqual({ pending: 0, completed: 0, withoutProfile: 0 });
    }

    await insertEnvelope(vaultId, {
      recipientKind: 'device',
      recipientDeviceId: extensionDeviceId,
      accessScope: 'metadata',
      authorizationKind: 'direct',
      authorizationRef: target.userId,
    });
    for (const authorizationRef of [viewerGroup, editorGroup]) {
      await insertEnvelope(vaultId, {
        recipientKind: 'user',
        recipientUserId: target.userId,
        accessScope: 'full',
        authorizationKind: 'directory_group',
        authorizationRef,
      });
      await insertEnvelope(vaultId, {
        recipientKind: 'device',
        recipientDeviceId: extensionDeviceId,
        accessScope: 'full',
        authorizationKind: 'directory_group',
        authorizationRef,
      });
    }
    await insertEnvelope(vaultId, {
      recipientKind: 'user',
      recipientUserId: target.userId,
      accessScope: 'full',
      authorizationKind: 'custom_group',
      authorizationRef: customGroup.id,
    });
    for (const input of overriddenAuthorizations) {
      expect(await ensureEnvelopeTasks(app.ctx.db, {
        vaultId,
        keyEpoch: 1,
        ...input,
        recipientUserIds: [target.userId],
        capability: 'full',
      })).toEqual({ pending: 0, completed: 0, withoutProfile: 0 });
    }
    expect((await app.ctx.db.select().from(vaultEnvelopeTasks)
      .where(eq(vaultEnvelopeTasks.vaultId, vaultId)))
      .filter((task) => task.authorizationKind !== 'direct')).toHaveLength(0);

    const webBootstrap = await encryptedWebBootstrap(target);
    expectVaultEnvelopesAreMetadataOnly(webBootstrap, vaultId);
    const extensionBootstrap = await encryptedExtensionBootstrap();
    expectVaultEnvelopesAreMetadataOnly(extensionBootstrap, vaultId);
    await expectAuditorWriteForbidden(vaultId);

    const rekeyTask = await app.ctx.db.transaction((tx) => ensureMembershipRekeyTask(
      tx,
      vaultId,
      owner.userId,
      ownerDeviceId,
    ));
    const material = await rekeyMaterial(vaultId, rekeyTask.id);
    expect(material.recipients.find((recipient) => recipient.userId === target.userId)).toMatchObject({
      role: 'auditor',
      capability: 'metadata',
    });
    expect(material.devices?.filter((device) => device.userId === target.userId)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ deviceId: extensionDeviceId, capability: 'metadata' }),
      ]),
    );
    expect(material.recipients.some((recipient) =>
      recipient.userId === target.userId && recipient.capability === 'full'
    )).toBe(false);
  });

  it('treats adding direct auditor over directory full access as a rekey reduction with empty envelopes', async () => {
    const vaultId = await initializeTeamVault('新增直接审计角色');
    const editorGroup = `group:test/direct-reduction-${randomUUID()}`;
    await app.ctx.db.update(users).set({ groups: [editorGroup] }).where(eq(users.id, target.userId));
    await setMembership(vaultId, 'group', editorGroup, 'editor');
    await completePendingTask(vaultId, 'directory_group', editorGroup);

    const before = await encryptedWebBootstrap(target);
    expect(before.envelopes.some((envelope) =>
      envelope.vaultId === vaultId && envelope.capability === 'full'
    )).toBe(true);

    const request = await ownerKeyring.prepareMembershipSet(owner.userId, vaultId, {
      subjectKind: 'user',
      subjectId: target.userId,
      role: 'auditor',
      expectedAccessGeneration: await accessGeneration(vaultId),
    });
    expect(request.envelopes).toEqual([]);
    const response = await app.inject({
      method: 'PUT',
      url: `/api/v2/vaults/${vaultId}/members`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(200);
    const body = response.json() as {
      rekeyTask: { id: string; fromEpoch: number; toEpoch: number } | null;
      envelopeTasks: unknown;
    };
    expect(body.rekeyTask).toMatchObject({ fromEpoch: 1, toEpoch: 2 });
    expect(body.envelopeTasks).toBeNull();

    const direct = (await app.ctx.db.select().from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, target.userId),
    )))[0]!;
    expect(direct.role).toBe('auditor');
    const oldEnvelopes = await app.ctx.db.select().from(vaultKeyEnvelopes).where(and(
      eq(vaultKeyEnvelopes.vaultId, vaultId),
      eq(vaultKeyEnvelopes.recipientUserId, target.userId),
    ));
    expect(oldEnvelopes.some((envelope) => envelope.accessScope === 'full')).toBe(true);
    expect(oldEnvelopes.every((envelope) => envelope.status === 'revoked')).toBe(true);
    expect((await app.ctx.db.select().from(vaultCryptoStates).where(
      eq(vaultCryptoStates.vaultId, vaultId),
    ))[0]).toMatchObject({ writeState: 'rekeying', activeEpoch: 1 });

    const after = await encryptedWebBootstrap(target);
    expect(after.envelopes.filter((envelope) => envelope.vaultId === vaultId)).toEqual([]);
    const material = await rekeyMaterial(vaultId, body.rekeyTask!.id);
    expect(material.recipients.find((recipient) => recipient.userId === target.userId)).toMatchObject({
      role: 'auditor',
      capability: 'metadata',
    });
    await expectAuditorWriteForbidden(vaultId);
  });

  it('does not freeze when an unprepared user loses redundant direct access but keeps group access', async () => {
    const unprepared = await login(app, 'erin');
    const vaultId = await initializeTeamVault('未登录成员重复授权');
    const group = (await app.ctx.db.insert(customGroups).values({
      ownerUserId: owner.userId,
      name: `未登录成员-${randomUUID()}`,
    }).returning())[0]!;
    await app.ctx.db.insert(customGroupMembers).values({
      groupId: group.id,
      userId: unprepared.userId,
      addedBy: owner.userId,
    });
    await setMembership(vaultId, 'user', unprepared.userId, 'editor');
    await setMembership(vaultId, 'custom_group', group.id, 'editor');
    expect(await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, vaultId),
      eq(vaultEnvelopeTasks.authorizationKind, 'direct'),
      eq(vaultEnvelopeTasks.recipientUserId, unprepared.userId),
      eq(vaultEnvelopeTasks.status, 'pending'),
    ))).toHaveLength(1);

    const removal = await ownerKeyring.prepareMembershipRemoval(owner.userId, vaultId, {
      subjectKind: 'user',
      subjectId: unprepared.userId,
      expectedAccessGeneration: await accessGeneration(vaultId),
    });
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}/members`,
      ...authed(owner),
      payload: removal,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({
      rekeyRequired: false,
      retainedAccess: true,
      rekeyTask: null,
    });
    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, vaultId)))[0]).toMatchObject({ writeState: 'open' });
    expect(await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.vaultId, vaultId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, vaultId),
      eq(vaultEnvelopeTasks.authorizationKind, 'custom_group'),
      eq(vaultEnvelopeTasks.authorizationRef, group.id),
      eq(vaultEnvelopeTasks.recipientUserId, unprepared.userId),
      eq(vaultEnvelopeTasks.status, 'pending'),
    ))).toHaveLength(1);
  });

  it('does not let an unkeyed owner replace the last usable owner', async () => {
    const vaultId = await initializeTeamVault('拥有者密钥就绪门禁');
    await setMembership(vaultId, 'user', target.userId, 'owner');

    const demotion = await ownerKeyring.prepareMembershipSet(owner.userId, vaultId, {
      subjectKind: 'user',
      subjectId: owner.userId,
      role: 'editor',
      expectedAccessGeneration: await accessGeneration(vaultId),
    });
    const blocked = await app.inject({
      method: 'PUT',
      url: `/api/v2/vaults/${vaultId}/members`,
      ...authed(owner),
      payload: demotion,
    });
    expect(blocked.statusCode, blocked.body).toBe(409);
    expect(blocked.json()).toMatchObject({
      message: '移除或降权前，请先为另一位拥有者开通访问，并确认对方可以打开当前密码库',
    });
    expect((await app.ctx.db.select().from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, vaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, owner.userId),
    )))[0]).toMatchObject({ role: 'owner' });

    await completePendingTask(vaultId, 'direct', target.userId);
    const removal = await ownerKeyring.prepareMembershipRemoval(owner.userId, vaultId, {
      subjectKind: 'user',
      subjectId: owner.userId,
      expectedAccessGeneration: await accessGeneration(vaultId),
    });
    const removed = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}/members`,
      ...authed(owner),
      payload: removal,
    });
    expect(removed.statusCode, removed.body).toBe(200);
  });

  it('grants a prepared second owner role and current key in one transaction', async () => {
    const vaultId = await initializeTeamVault('原子增加第二拥有者');
    const request = await ownerKeyring.prepareMembershipSet(owner.userId, vaultId, {
      subjectKind: 'user',
      subjectId: target.userId,
      role: 'owner',
      expectedAccessGeneration: await accessGeneration(vaultId),
      distribution: {
        signerKeyVersion: ownerProfile.keyVersion,
        recipientProfile: {
          userId: targetProfile.userId,
          keyVersion: targetProfile.keyVersion,
          encryptionPublicKey: targetProfile.encryptionPublicKey,
          signingPublicKey: targetProfile.signingPublicKey,
        },
      },
    });
    expect(request.envelopes).toHaveLength(1);
    const response = await app.inject({
      method: 'PUT',
      url: `/api/v2/vaults/${vaultId}/members`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({
      envelopeTasks: { pending: 0, completed: 1, withoutProfile: 0 },
    });
    expect(await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
      eq(vaultEnvelopeTasks.vaultId, vaultId),
      eq(vaultEnvelopeTasks.recipientUserId, target.userId),
      eq(vaultEnvelopeTasks.status, 'pending'),
    ))).toHaveLength(0);
    const bootstrap = await encryptedWebBootstrap(target);
    expect(bootstrap.envelopes.some((envelope) =>
      envelope.vaultId === vaultId && envelope.recipientId === target.userId && envelope.capability === 'full'
    )).toBe(true);
  });

  it('excludes deleted tombstones from rekey material and commit coverage', async () => {
    const vaultId = await initializeTeamVault('墓碑换钥覆盖');
    const liveRequest = await ownerKeyring.encryptCreate(owner.userId, vaultId, itemInput('保留条目'));
    const liveResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/items`,
      ...authed(owner),
      payload: liveRequest,
    });
    expect(liveResponse.statusCode, liveResponse.body).toBe(201);

    const deletedRequest = await ownerKeyring.encryptCreate(owner.userId, vaultId, itemInput('删除条目'));
    const deletedResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/items`,
      ...authed(owner),
      payload: deletedRequest,
    });
    expect(deletedResponse.statusCode, deletedResponse.body).toBe(201);
    const deletedItem = await ownerKeyring.decryptMetadataRecord(
      deletedResponse.json() as EncryptedItemMetadata,
    );
    const deleteRequest = await ownerKeyring.encryptDelete(owner.userId, deletedItem);
    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: `/api/v2/items/${deletedItem.id}`,
      ...authed(owner),
      payload: deleteRequest,
    });
    expect(deleteResponse.statusCode, deleteResponse.body).toBe(200);

    const task = await app.ctx.db.transaction((tx) => ensureMembershipRekeyTask(
      tx,
      vaultId,
      owner.userId,
      ownerDeviceId,
    ));
    const material = await rekeyMaterial(vaultId, task.id);
    expect(material.metadata.map((record) => record.itemId)).toEqual([liveRequest.itemId]);
    expect(new Set(material.keyWraps.map((record) => record.itemId))).toEqual(new Set([liveRequest.itemId]));

    const request = await ownerKeyring.prepareVaultRekey(owner.userId, vaultId, ownerProfile, material);
    const response = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/rekey`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(200);
    await ownerKeyring.commitVaultRekey(vaultId);
    expect(response.json()).toMatchObject({ status: 'e2ee', activeEpoch: 2 });
    expect((await app.ctx.db.select().from(vaultRekeyJobs)
      .where(eq(vaultRekeyJobs.id, task.id)))[0]).toMatchObject({
      status: 'committed',
      expectedSecretVersionCount: 1,
      expectedMetadataVersionCount: 1,
    });
  });

  it('deletes an owned encrypted team vault only with a current signed command', async () => {
    const vaultId = await initializeTeamVault('顺丰到付的说法');
    const access = await accessGeneration(vaultId);
    const header = await currentVaultHeader(vaultId);
    const staleRequest = await ownerKeyring.prepareVaultDeletion(owner.userId, vaultId, access - 1, header);
    const stale = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: staleRequest,
    });
    expect(stale.statusCode, stale.body).toBe(409);
    expect(stale.json()).toMatchObject({ message: '密码库刚被其他人修改，请刷新后确认最新状态再删除' });

    const preparedLegacyRequest = await ownerKeyring.prepareVaultDeletion(owner.userId, vaultId, access, header);
    const legacyRequest = {
      idempotencyKey: preparedLegacyRequest.idempotencyKey,
      expectedAccessGeneration: preparedLegacyRequest.expectedAccessGeneration,
      actorDeviceId: preparedLegacyRequest.actorDeviceId,
      signature: preparedLegacyRequest.signature,
    };
    const legacy = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: legacyRequest,
    });
    expect(legacy.statusCode, legacy.body).toBe(409);
    expect(legacy.json()).toMatchObject({
      code: 'header_format_outdated',
      message: '当前页面版本较旧，请刷新页面并确认密码库已经清空后再删除',
    });

    const staleHeaderRequest = await ownerKeyring.prepareVaultDeletion(owner.userId, vaultId, access, header);
    const detailsRequest = await ownerKeyring.encryptVaultDetails(owner.userId, vaultId, {
      name: '顺丰到付的说法（已核对）',
      vaultGroupName: null,
    }, header);
    const detailsResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/vaults/${vaultId}/header`,
      ...authed(owner),
      payload: detailsRequest,
    });
    expect(detailsResponse.statusCode, detailsResponse.body).toBe(200);
    const staleHeader = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: staleHeaderRequest,
    });
    expect(staleHeader.statusCode, staleHeader.body).toBe(409);
    expect(staleHeader.json()).toMatchObject({
      message: '密码库刚被其他人修改，请刷新后确认最新状态再删除',
    });

    const currentHeader = await currentVaultHeader(vaultId);
    const deniedRequest = await ownerKeyring.prepareVaultDeletion(owner.userId, vaultId, access, currentHeader);
    const denied = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(target),
      payload: deniedRequest,
    });
    expect(denied.statusCode, denied.body).toBe(403);

    const request = await ownerKeyring.prepareVaultDeletion(owner.userId, vaultId, access, currentHeader);
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toEqual({ ok: true });
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(syncEvents).where(and(
      eq(syncEvents.vaultId, vaultId),
      eq(syncEvents.type, 'vault.deleted'),
    ))).toHaveLength(1);
    expect(await app.ctx.db.select().from(auditEvents).where(and(
      eq(auditEvents.vaultId, vaultId),
      eq(auditEvents.action, 'vault.delete'),
    ))).toHaveLength(1);
  });

  it('blocks deletion while an active encrypted item remains', async () => {
    const vaultId = await initializeTeamVault('非空密码库');
    const createRequest = await ownerKeyring.encryptCreate(owner.userId, vaultId, itemInput('必须先清理'));
    const created = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/items`,
      ...authed(owner),
      payload: createRequest,
    });
    expect(created.statusCode, created.body).toBe(201);

    const request = await ownerKeyring.prepareVaultDeletion(
      owner.userId,
      vaultId,
      await accessGeneration(vaultId),
      await currentVaultHeader(vaultId),
    );
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(409);
    expect(response.json()).toMatchObject({
      code: 'vault_not_empty',
      message: '删除前必须先清空密码库。当前还有 1 个条目、0 个目录，请清理后重试',
    });
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(1);
  });

  it('blocks deletion while the current encrypted header still contains directories', async () => {
    const vaultId = await initializeTeamVault('目录未清空');
    const header = await currentVaultHeader(vaultId);
    const directoryRequest = await ownerKeyring.encryptVaultDirectories(owner.userId, vaultId, [
      { path: '公共', aliases: [] },
    ], header);
    const updated = await app.inject({
      method: 'PATCH',
      url: `/api/v2/vaults/${vaultId}/header`,
      ...authed(owner),
      payload: directoryRequest,
    });
    expect(updated.statusCode, updated.body).toBe(200);

    const request = await ownerKeyring.prepareVaultDeletion(
      owner.userId,
      vaultId,
      await accessGeneration(vaultId),
      await currentVaultHeader(vaultId),
    );
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(409);
    expect(response.json()).toMatchObject({
      code: 'vault_not_empty',
      message: '删除前必须先清空密码库。当前还有 0 个条目、1 个目录，请清理后重试',
    });
  });

  it('allows deletion when only soft-deleted item tombstones remain', async () => {
    const vaultId = await initializeTeamVault('仅剩删除墓碑');
    const createRequest = await ownerKeyring.encryptCreate(owner.userId, vaultId, itemInput('先删除再删库'));
    const created = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/items`,
      ...authed(owner),
      payload: createRequest,
    });
    expect(created.statusCode, created.body).toBe(201);
    const item = await ownerKeyring.decryptMetadataRecord(created.json() as EncryptedItemMetadata);
    const deleteItemRequest = await ownerKeyring.encryptDelete(owner.userId, item);
    const deletedItem = await app.inject({
      method: 'DELETE',
      url: `/api/v2/items/${item.id}`,
      ...authed(owner),
      payload: deleteItemRequest,
    });
    expect(deletedItem.statusCode, deletedItem.body).toBe(200);

    const request = await ownerKeyring.prepareVaultDeletion(
      owner.userId,
      vaultId,
      await accessGeneration(vaultId),
      await currentVaultHeader(vaultId),
    );
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(0);
  });

  it('serializes concurrent item creation and vault deletion without orphaned data', async () => {
    const vaultId = await initializeTeamVault('并发删除保护');
    const header = await currentVaultHeader(vaultId);
    const createRequest = await ownerKeyring.encryptCreate(owner.userId, vaultId, itemInput('并发写入'));
    const deleteRequest = await ownerKeyring.prepareVaultDeletion(
      owner.userId,
      vaultId,
      await accessGeneration(vaultId),
      header,
    );

    const [created, deleted] = await Promise.all([
      app.inject({
        method: 'POST',
        url: `/api/v2/vaults/${vaultId}/items`,
        ...authed(owner),
        payload: createRequest,
      }),
      app.inject({
        method: 'DELETE',
        url: `/api/v2/vaults/${vaultId}`,
        ...authed(owner),
        payload: deleteRequest,
      }),
    ]);

    expect(Number(created.statusCode >= 200 && created.statusCode < 300) +
      Number(deleted.statusCode >= 200 && deleted.statusCode < 300)).toBe(1);
    expect(created.statusCode).toBeLessThan(500);
    expect(deleted.statusCode).toBeLessThan(500);
    if (created.statusCode === 201) {
      expect(deleted.statusCode).toBe(409);
      expect(deleted.json()).toMatchObject({ code: 'vault_not_empty' });
      expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(1);
      expect(await app.ctx.db.select().from(items).where(eq(items.id, createRequest.itemId))).toHaveLength(1);
    } else {
      expect(deleted.statusCode).toBe(200);
      expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(0);
      expect(await app.ctx.db.select().from(items).where(eq(items.id, createRequest.itemId))).toHaveLength(0);
    }
  });

  it('prevents an old client from downgrading the active encrypted header format', async () => {
    const vaultId = await initializeTeamVault('头部格式防降级');
    const current = (await app.ctx.db.select().from(encryptedVaultHeaders)
      .where(eq(encryptedVaultHeaders.vaultId, vaultId)))[0]!;

    await expect(app.ctx.db.insert(encryptedVaultHeaders).values({
      vaultId,
      headerVersion: current.headerVersion + 1,
      keyEpoch: current.keyEpoch,
      protocolVersion: current.protocolVersion,
      schemaVersion: 2,
      ciphertext: current.ciphertext,
      nonce: current.nonce,
      ciphertextDigest: current.ciphertextDigest,
      createdByDeviceId: current.createdByDeviceId,
      signature: current.signature,
    })).rejects.toMatchObject({
      cause: expect.objectContaining({
        code: '23514',
        message: 'vault header format downgrade is not allowed',
      }),
    });
  });

  it('explains why immutable migration history blocks encrypted vault deletion', async () => {
    const vaultId = await initializeTeamVault('保留迁移证据');
    await app.ctx.db.insert(legacyMigrationJobs).values({
      vaultId,
      targetEpoch: 1,
      state: 'e2ee',
    });
    const request = await ownerKeyring.prepareVaultDeletion(
      owner.userId,
      vaultId,
      await accessGeneration(vaultId),
      await currentVaultHeader(vaultId),
    );
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(409);
    expect(response.json()).toMatchObject({
      message: '该密码库保留了旧数据迁移记录，为避免破坏恢复与审计证据，暂时不能删除',
    });
  });
});

function itemInput(title: string) {
  return {
    kind: 'login' as const,
    title,
    username: 'operator',
    origin: 'https://example.test',
    loginUrl: 'https://example.test/login',
    tags: [],
    favorite: false,
    sensitivity: 'medium' as const,
    secretValue: 'test-secret',
  };
}

async function setupCrypto(session: TestSession, mainPassword: string) {
  const keyring = new E2eeKeyring();
  const setup = await keyring.setup(mainPassword, {
    accountId: session.userId,
    deviceId: randomUUID(),
    deviceName: 'Direct override integration',
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

async function setMembership(
  vaultId: string,
  subjectKind: 'user' | 'group' | 'custom_group',
  subjectId: string,
  role: 'viewer' | 'editor' | 'owner' | 'auditor',
): Promise<void> {
  const request = await ownerKeyring.prepareMembershipSet(owner.userId, vaultId, {
    subjectKind,
    subjectId,
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

async function completePendingTask(
  vaultId: string,
  authorizationKind: 'direct' | 'directory_group',
  authorizationRef: string,
): Promise<void> {
  const rows = await app.ctx.db.select().from(vaultEnvelopeTasks).where(and(
    eq(vaultEnvelopeTasks.vaultId, vaultId),
    eq(vaultEnvelopeTasks.authorizationKind, authorizationKind),
    eq(vaultEnvelopeTasks.authorizationRef, authorizationRef),
    eq(vaultEnvelopeTasks.status, 'pending'),
  ));
  expect(rows).toHaveLength(1);
  const taskResponse = await app.inject({
    method: 'GET',
    url: `/api/v2/vaults/${vaultId}/envelope-tasks`,
    ...authed(owner),
  });
  expect(taskResponse.statusCode, taskResponse.body).toBe(200);
  const task = (taskResponse.json() as VaultEnvelopeTask[]).find((candidate) => candidate.id === rows[0]!.id)!;
  const request = await ownerKeyring.prepareEnvelopeTaskCompletion(owner.userId, ownerProfile, task);
  const response = await app.inject({
    method: 'POST',
    url: `/api/v2/vaults/${vaultId}/envelope-tasks/${task.id}/complete`,
    ...authed(owner),
    payload: request,
  });
  expect(response.statusCode, response.body).toBe(200);
}

async function insertEnvelope(
  vaultId: string,
  input: {
    recipientKind: 'user' | 'device';
    recipientUserId?: string;
    recipientDeviceId?: string;
    accessScope: 'metadata' | 'full';
    authorizationKind: 'direct' | 'directory_group' | 'custom_group';
    authorizationRef: string;
  },
): Promise<void> {
  const recipient = input.recipientKind === 'user'
    ? (await app.ctx.db.select().from(userCryptoProfiles).where(
        eq(userCryptoProfiles.userId, input.recipientUserId!),
      ))[0]!
    : (await app.ctx.db.select().from(userDevices).where(
        eq(userDevices.id, input.recipientDeviceId!),
      ))[0]!;
  const publicEncryptionKey = recipient.publicEncryptionKey;
  const ciphertext = randomBytes(96);
  await app.ctx.db.insert(vaultKeyEnvelopes).values({
    vaultId,
    keyEpoch: 1,
    recipientKind: input.recipientKind,
    accessScope: input.accessScope,
    recipientUserId: input.recipientUserId ?? null,
    recipientDeviceId: input.recipientDeviceId ?? null,
    recipientKeyFingerprint: createHash('sha256').update(publicEncryptionKey).digest('base64url'),
    authorizationKind: input.authorizationKind,
    authorizationRef: input.authorizationRef,
    envelopeVersion: 1,
    ciphertext,
    ciphertextDigest: createHash('sha256').update(ciphertext).digest(),
    senderDeviceId: ownerDeviceId,
    signerUserId: owner.userId,
    signerKeyVersion: ownerProfile.keyVersion,
    signerPublicKey: Buffer.from(ownerProfile.signingPublicKey, 'base64url'),
    signature: randomBytes(64),
    status: 'active',
    activatedAt: new Date(),
  });
}

async function encryptedWebBootstrap(session: TestSession): Promise<EncryptedBootstrapResponse> {
  const response = await app.inject({
    method: 'GET',
    url: '/api/v2/bootstrap',
    ...authed(session),
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as EncryptedBootstrapResponse;
}

async function currentVaultHeader(vaultId: string) {
  const bootstrap = await encryptedWebBootstrap(owner);
  const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
  const header = bootstrap.headers
    .filter((candidate) => candidate.vaultId === vaultId && candidate.keyEpoch === vault?.crypto.activeEpoch)
    .sort((left, right) => right.version - left.version)[0];
  if (!header) throw new Error('test vault header missing');
  return header;
}

async function encryptedExtensionBootstrap(): Promise<EncryptedBootstrapResponse> {
  const response = await app.inject({
    method: 'GET',
    url: '/api/v2/extension/bootstrap',
    headers: {
      authorization: `Bearer ${extensionToken}`,
      [ITEM_METADATA_FORMAT_HEADER]: String(ITEM_METADATA_FORMAT_VERSION),
    },
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as EncryptedBootstrapResponse;
}

function expectVaultEnvelopesAreMetadataOnly(bootstrap: EncryptedBootstrapResponse, vaultId: string): void {
  const envelopes = bootstrap.envelopes.filter((envelope) => envelope.vaultId === vaultId);
  expect(envelopes.length).toBeGreaterThan(0);
  expect(envelopes.every((envelope) => envelope.epoch === 1 && envelope.capability === 'metadata')).toBe(true);
  expect(envelopes.some((envelope) => envelope.capability === 'full')).toBe(false);
}

async function rekeyMaterial(vaultId: string, taskId: string): Promise<RekeyMaterial> {
  const query = await ownerKeyring.rekeyMaterialIntent(owner.userId, vaultId, taskId);
  const response = await app.inject({
    method: 'GET',
    url: `/api/v2/vaults/${vaultId}/rekey-material`,
    ...authed(owner),
    query,
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json() as RekeyMaterial;
}

async function expectAuditorWriteForbidden(vaultId: string): Promise<void> {
  const blob = () => ({
    suite: 'lm-e2ee-v1' as const,
    aadVersion: 1 as const,
    nonce: randomBytes(24).toString('base64url'),
    ciphertext: randomBytes(64).toString('base64url'),
  });
  const response = await app.inject({
    method: 'POST',
    url: `/api/v2/vaults/${vaultId}/items`,
    ...authed(target),
    payload: {
      idempotencyKey: randomUUID(),
      itemId: randomUUID(),
      keyEpoch: 1,
      metadata: blob(),
      encryptedValue: blob(),
      wrappedDek: blob(),
      actorDeviceId: targetDeviceId,
      signature: randomBytes(64).toString('base64url'),
    },
  });
  expect(response.statusCode, response.body).toBe(403);
}

async function accessGeneration(vaultId: string): Promise<number> {
  return (await app.ctx.db.select({ generation: vaultCryptoStates.accessGeneration })
    .from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, vaultId)))[0]!.generation;
}
