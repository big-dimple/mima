import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  EncryptedBootstrapResponseSchema,
  EncryptedVaultHeaderSchema,
  LegacyMigrationStatusResponseSchema,
  type RekeyMaterial,
  type UserCryptoProfile,
  type VaultEnvelopeTask,
} from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  customGroupMembers,
  customGroups,
  encryptedVaultHeaders,
  items,
  systemRoleAssignments,
  vaultCustomGroupRoles,
  vaultCryptoStates,
  vaultKeyEnvelopes,
  vaultMemberships,
  vaults,
} from '../../src/db/schema.ts';
import { auditStandalone } from '../../src/services/audit.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let noRecoveryOwner: TestSession;
let noRecoveryKeyring: E2eeKeyring;
let noRecoveryProfile: UserCryptoProfile;
let platformAdmin: TestSession;
let platformAdminKeyring: E2eeKeyring;
let platformAdminProfile: UserCryptoProfile;
let noRecoveryTeamVaultId: string;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_legacy_empty_vault_eligibility');
  owner = await login(app, 'erin');
  noRecoveryOwner = await login(app, 'bob');
  platformAdmin = await login(app, 'alice');
  await app.ctx.db.insert(systemRoleAssignments).values({
    userId: platformAdmin.userId,
    role: 'platform-admin',
    assignedBy: 'test',
  });
  noRecoveryKeyring = new E2eeKeyring();
  const setup = await noRecoveryKeyring.setup('no recovery integration password', {
    accountId: noRecoveryOwner.userId,
    deviceId: randomUUID(),
    deviceName: 'No recovery integration browser',
    platform: 'integration:test',
  });
  const profileResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(noRecoveryOwner),
    payload: setup.request,
  });
  expect(profileResponse.statusCode, profileResponse.body).toBe(201);
  noRecoveryProfile = profileResponse.json() as UserCryptoProfile;

  platformAdminKeyring = new E2eeKeyring();
  const platformSetup = await platformAdminKeyring.setup('platform admin integration password', {
    accountId: platformAdmin.userId,
    deviceId: randomUUID(),
    deviceName: 'Platform admin integration browser',
    platform: 'integration:test',
  });
  const platformProfileResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(platformAdmin),
    payload: platformSetup.request,
  });
  expect(platformProfileResponse.statusCode, platformProfileResponse.body).toBe(201);
  platformAdminProfile = platformProfileResponse.json() as UserCryptoProfile;
});

afterAll(async () => {
  await noRecoveryKeyring.lock();
  await platformAdminKeyring.lock();
  await app.close();
});

describe('legacy empty-vault initialization eligibility', () => {
  it('rejects deprecated two-step creation with zero writes', async () => {
    const before = (await app.ctx.db.select().from(vaults).where(eq(vaults.kind, 'team'))).length;
    const response = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(owner),
      payload: { idempotencyKey: randomUUID() },
    });
    expect(response.statusCode, response.body).toBe(409);
    expect(response.json()).toMatchObject({
      code: 'client_upgrade_required',
      message: expect.stringContaining('本次没有写入任何数据'),
    });
    expect((await app.ctx.db.select().from(vaults).where(eq(vaults.kind, 'team'))).length).toBe(before);
  });

  it('rejects every deprecated initial-owner variant without leaving a pending vault', async () => {
    const before = (await app.ctx.db.select().from(vaults).where(eq(vaults.kind, 'team'))).length;
    const compatible = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(noRecoveryOwner),
      payload: {
        idempotencyKey: randomUUID(),
        initialOwnerUserId: noRecoveryOwner.userId,
      },
    });
    expect(compatible.statusCode, compatible.body).toBe(409);
    expect(compatible.json()).toMatchObject({ code: 'client_upgrade_required' });
    const rejected = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(noRecoveryOwner),
      payload: {
        idempotencyKey: randomUUID(),
        initialOwnerUserId: platformAdmin.userId,
      },
    });
    expect(rejected.statusCode, rejected.body).toBe(409);
    expect(rejected.json()).toMatchObject({ code: 'client_upgrade_required' });
    expect((await app.ctx.db.select().from(vaults).where(eq(vaults.kind, 'team'))).length).toBe(before);
  });

  it('initializes personal and team vaults without enterprise recovery', async () => {
    const personalVault = (await app.ctx.db.select().from(vaults).where(and(
      eq(vaults.kind, 'personal'),
      eq(vaults.ownerUserId, noRecoveryOwner.userId),
    )).limit(1))[0]!;
    const status = await migrationStatus(noRecoveryOwner, personalVault.id);
    expect(status.emptyVaultInitializationAllowed).toBe(true);
    expect(status.materials?.recoveryKey).toBeNull();
    expect(status.materials?.recipients).toEqual([
      expect.objectContaining({ userId: noRecoveryOwner.userId, role: 'owner', capability: 'full' }),
    ]);

    const initializeRequest = await noRecoveryKeyring.initializeVault(
      noRecoveryOwner.userId,
      personalVault.id,
      '个人密码库',
      noRecoveryProfile,
      null,
      'legacy',
      [],
      status.materials!,
    );
    expect(initializeRequest.envelopes).toHaveLength(1);
    const initializeResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${personalVault.id}/initialize`,
      ...authed(noRecoveryOwner),
      payload: initializeRequest,
    });
    expect(initializeResponse.statusCode, initializeResponse.body).toBe(200);

    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, personalVault.id)))[0]).toMatchObject({
      storageMode: 'e2ee',
      writeState: 'open',
      activeEpoch: 1,
    });
    expect(await app.ctx.db.select().from(encryptedVaultHeaders)
      .where(eq(encryptedVaultHeaders.vaultId, personalVault.id))).toHaveLength(1);
    const envelopes = await app.ctx.db.select().from(vaultKeyEnvelopes)
      .where(eq(vaultKeyEnvelopes.vaultId, personalVault.id));
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({ recipientKind: 'user', recipientUserId: noRecoveryOwner.userId });

    const renamed = '研发个人密码库';
    const renameRequest = await noRecoveryKeyring.encryptVaultRename(
      noRecoveryOwner.userId,
      personalVault.id,
      renamed,
      {
        ...initializeRequest.header,
        updatedAt: new Date().toISOString(),
        updatedBy: noRecoveryOwner.userId,
      },
    );
    expect(JSON.stringify(renameRequest)).not.toContain(renamed);
    const legacyRenameRequest = { ...renameRequest } as Record<string, unknown>;
    delete legacyRenameRequest.headerFormatVersion;
    delete legacyRenameRequest.operation;
    const legacyRenameResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/vaults/${personalVault.id}/header`,
      ...authed(noRecoveryOwner),
      payload: legacyRenameRequest,
    });
    expect(legacyRenameResponse.statusCode, legacyRenameResponse.body).toBe(400);
    const renameResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/vaults/${personalVault.id}/header`,
      ...authed(noRecoveryOwner),
      payload: renameRequest,
    });
    expect(renameResponse.statusCode, renameResponse.body).toBe(200);
    expect((await app.ctx.db.select().from(vaults).where(eq(vaults.id, personalVault.id)))[0]?.name).toBe('');
    expect(await app.ctx.db.select().from(encryptedVaultHeaders)
      .where(eq(encryptedVaultHeaders.vaultId, personalVault.id))).toHaveLength(2);
    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, personalVault.id)))[0]?.activeHeaderVersion).toBe(2);
    const bootstrapResponse = await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      ...authed(noRecoveryOwner),
    });
    expect(bootstrapResponse.statusCode, bootstrapResponse.body).toBe(200);
    const projection = await noRecoveryKeyring.decryptBootstrap(
      EncryptedBootstrapResponseSchema.parse(bootstrapResponse.json()),
    );
    expect(projection.vaults.find((vault) => vault.id === personalVault.id)?.name).toBe(renamed);

    const directoryRequest = await noRecoveryKeyring.encryptVaultDirectories(
      noRecoveryOwner.userId,
      personalVault.id,
      [
        { path: '工作', aliases: [] },
        { path: '工作/云服务', aliases: [] },
      ],
      EncryptedVaultHeaderSchema.parse(renameResponse.json()),
    );
    expect(JSON.stringify(directoryRequest)).not.toContain('云服务');
    const directoryResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/vaults/${personalVault.id}/header`,
      ...authed(noRecoveryOwner),
      payload: directoryRequest,
    });
    expect(directoryResponse.statusCode, directoryResponse.body).toBe(200);
    expect(await app.ctx.db.select().from(encryptedVaultHeaders)
      .where(eq(encryptedVaultHeaders.vaultId, personalVault.id))).toHaveLength(3);
    const directoryBootstrap = EncryptedBootstrapResponseSchema.parse((await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      ...authed(noRecoveryOwner),
    })).json());
    const directoryProjection = await noRecoveryKeyring.decryptBootstrap(directoryBootstrap);
    expect(directoryProjection.vaultDirectories[personalVault.id]).toContainEqual({
      path: '工作/云服务',
      aliases: [],
    });

    const createRequest = await noRecoveryKeyring.encryptCreate(noRecoveryOwner.userId, personalVault.id, {
      kind: 'login',
      title: '无恢复首条记录',
      username: 'bob',
      origin: 'https://no-recovery.example.test',
      folderPath: '工作/云服务',
      tags: ['first-run'],
      favorite: false,
      sensitivity: 'high',
      secretValue: 'NO-RECOVERY-PLAINTEXT-CANARY',
    });
    const createResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${personalVault.id}/items`,
      ...authed(noRecoveryOwner),
      payload: createRequest,
    });
    expect(createResponse.statusCode, createResponse.body).toBe(201);
    const storedItems = await app.ctx.db.select().from(items).where(eq(items.vaultId, personalVault.id));
    expect(storedItems).toHaveLength(1);
    expect(JSON.stringify(storedItems)).not.toContain('无恢复首条记录');
    expect(JSON.stringify(storedItems)).not.toContain('NO-RECOVERY-PLAINTEXT-CANARY');

    const teamVault = (await app.ctx.db.insert(vaults).values({
      kind: 'team',
      name: '',
      ownerUserId: null,
    }).returning())[0]!;
    noRecoveryTeamVaultId = teamVault.id;
    await app.ctx.db.insert(vaultMemberships).values({
      vaultId: teamVault.id,
      subjectKind: 'user',
      subjectId: noRecoveryOwner.userId,
      role: 'owner',
    });
    const teamStatus = await migrationStatus(noRecoveryOwner, teamVault.id);
    expect(teamStatus.emptyVaultInitializationAllowed).toBe(true);
    expect(teamStatus.materials?.recoveryKey).toBeNull();
    const teamRequest = await noRecoveryKeyring.initializeVault(
      noRecoveryOwner.userId,
      teamVault.id,
      '无恢复团队库',
      noRecoveryProfile,
      null,
      'legacy',
      [],
      teamStatus.materials!,
    );
    const teamResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${teamVault.id}/initialize`,
      ...authed(noRecoveryOwner),
      payload: teamRequest,
    });
    expect(teamResponse.statusCode, teamResponse.body).toBe(200);
    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, teamVault.id)))[0]).toMatchObject({
      storageMode: 'e2ee',
      writeState: 'open',
      activeEpoch: 1,
    });
    const teamEnvelopes = await app.ctx.db.select().from(vaultKeyEnvelopes)
      .where(eq(vaultKeyEnvelopes.vaultId, teamVault.id));
    expect(teamEnvelopes).toHaveLength(1);
    expect(teamEnvelopes[0]).toMatchObject({ recipientKind: 'user', recipientUserId: noRecoveryOwner.userId });
  });

  it('lets a platform admin explicitly create and own a team vault without gaining automatic access elsewhere', async () => {
    const teamVaultId = randomUUID();
    const request = await platformAdminKeyring.prepareVaultCreation(
      platformAdmin.userId,
      teamVaultId,
      '管理员自用团队库',
      platformAdminProfile,
      null,
      [],
    );
    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(platformAdmin),
      payload: request,
    });
    expect(createResponse.statusCode, createResponse.body).toBe(201);
    const memberships = await app.ctx.db.select().from(vaultMemberships)
      .where(eq(vaultMemberships.vaultId, teamVaultId));
    expect(memberships).toEqual([
      expect.objectContaining({
        subjectKind: 'user',
        subjectId: platformAdmin.userId,
        role: 'owner',
      }),
    ]);

    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, teamVaultId)))[0]).toMatchObject({
      storageMode: 'e2ee',
      activeEpoch: 1,
    });

    const unrelatedBootstrap = await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      ...authed(platformAdmin),
    });
    expect(unrelatedBootstrap.statusCode, unrelatedBootstrap.body).toBe(200);
    expect((unrelatedBootstrap.json() as { vaults: Array<{ id: string }> }).vaults
      .some((vault) => vault.id === noRecoveryTeamVaultId)).toBe(false);

    const group = (await app.ctx.db.insert(customGroups).values({
      ownerUserId: platformAdmin.userId,
      name: '包含管理员的运维部',
    }).returning())[0]!;
    await app.ctx.db.insert(customGroupMembers).values([
      { groupId: group.id, userId: platformAdmin.userId, addedBy: platformAdmin.userId },
      { groupId: group.id, userId: noRecoveryOwner.userId, addedBy: platformAdmin.userId },
    ]);

    const addRequest = await platformAdminKeyring.prepareMembershipSet(
      platformAdmin.userId,
      teamVaultId,
      {
        subjectKind: 'custom_group',
        subjectId: group.id,
        role: 'viewer',
        expectedAccessGeneration: 1,
      },
    );
    const addResponse = await app.inject({
      method: 'PUT',
      url: `/api/v2/vaults/${teamVaultId}/members`,
      ...authed(platformAdmin),
      payload: addRequest,
    });
    expect(addResponse.statusCode, addResponse.body).toBe(200);
    expect((await app.ctx.db.select().from(vaultMemberships).where(and(
      eq(vaultMemberships.vaultId, teamVaultId),
      eq(vaultMemberships.subjectKind, 'user'),
      eq(vaultMemberships.subjectId, platformAdmin.userId),
    )))[0]).toMatchObject({ role: 'owner' });
    expect((await app.ctx.db.select().from(vaultCustomGroupRoles).where(and(
      eq(vaultCustomGroupRoles.vaultId, teamVaultId),
      eq(vaultCustomGroupRoles.groupId, group.id),
    )))[0]).toMatchObject({ role: 'viewer' });

    const tasksResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/vaults/${teamVaultId}/envelope-tasks`,
      ...authed(platformAdmin),
    });
    expect(tasksResponse.statusCode, tasksResponse.body).toBe(200);
    const task = (tasksResponse.json() as VaultEnvelopeTask[]).find(
      (candidate) => candidate.recipientUserId === noRecoveryOwner.userId,
    );
    expect((tasksResponse.json() as VaultEnvelopeTask[]).some(
      (candidate) => candidate.recipientUserId === platformAdmin.userId,
    )).toBe(false);
    expect(task?.recipientProfile).not.toBeNull();
    const completeRequest = await platformAdminKeyring.prepareEnvelopeTaskCompletion(
      platformAdmin.userId,
      platformAdminProfile,
      task!,
    );
    const completeResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${teamVaultId}/envelope-tasks/${task!.id}/complete`,
      ...authed(platformAdmin),
      payload: completeRequest,
    });
    expect(completeResponse.statusCode, completeResponse.body).toBe(200);

    const groupMemberBootstrap = await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      ...authed(noRecoveryOwner),
    });
    expect(groupMemberBootstrap.statusCode, groupMemberBootstrap.body).toBe(200);
    expect((groupMemberBootstrap.json() as { vaults: Array<{ id: string }> }).vaults
      .some((vault) => vault.id === teamVaultId)).toBe(true);

    const removeRequest = await platformAdminKeyring.prepareMembershipRemoval(
      platformAdmin.userId,
      teamVaultId,
      {
        subjectKind: 'custom_group',
        subjectId: group.id,
        expectedAccessGeneration: 2,
      },
    );
    const removeResponse = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${teamVaultId}/members`,
      ...authed(platformAdmin),
      payload: removeRequest,
    });
    expect(removeResponse.statusCode, removeResponse.body).toBe(200);
    const taskId = (removeResponse.json() as { rekeyTask: { id: string } }).rekeyTask.id;
    const materialIntent = await platformAdminKeyring.rekeyMaterialIntent(
      platformAdmin.userId,
      teamVaultId,
      taskId,
    );
    const query = new URLSearchParams(materialIntent).toString();
    const materialResponse = await app.inject({
      method: 'GET',
      url: `/api/v2/vaults/${teamVaultId}/rekey-material?${query}`,
      ...authed(platformAdmin),
    });
    expect(materialResponse.statusCode, materialResponse.body).toBe(200);
    const material = materialResponse.json() as RekeyMaterial;
    expect(material.recoveryKey).toBeNull();
    const rekeyRequest = await platformAdminKeyring.prepareVaultRekey(
      platformAdmin.userId,
      teamVaultId,
      platformAdminProfile,
      material,
    );
    const { manifestSignature: _manifestSignature, ...currentUnsigned } = rekeyRequest;
    const outdatedUnsigned = { ...currentUnsigned, metadataFormatVersion: 3 as const };
    const rekeySigner = platformAdminKeyring as unknown as {
      signCommand(
        commandKind: string,
        userId: string,
        scope: { vaultId: string },
        body: object,
      ): Promise<string>;
    };
    const outdatedRekeyResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${teamVaultId}/rekey`,
      ...authed(platformAdmin),
      payload: {
        ...outdatedUnsigned,
        manifestSignature: await rekeySigner.signCommand(
          'vault.rekey',
          platformAdmin.userId,
          { vaultId: teamVaultId },
          outdatedUnsigned,
        ),
      },
    });
    expect(outdatedRekeyResponse.statusCode, outdatedRekeyResponse.body).toBe(409);
    expect(outdatedRekeyResponse.json()).toMatchObject({
      code: 'metadata_format_outdated',
      message: '当前页面版本较旧，请刷新页面后重新完成安全更新',
    });
    expect(rekeyRequest.envelopes).toHaveLength(1);
    expect(rekeyRequest.envelopes[0]).toMatchObject({
      recipientKind: 'user',
      recipientId: platformAdmin.userId,
    });
    const rekeyResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${teamVaultId}/rekey`,
      ...authed(platformAdmin),
      payload: rekeyRequest,
    });
    expect(rekeyResponse.statusCode, rekeyResponse.body).toBe(200);
    await platformAdminKeyring.commitVaultRekey(teamVaultId);
    expect((await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, teamVaultId)))[0]).toMatchObject({
      writeState: 'open',
      activeEpoch: 2,
    });
  });

  it('is true only when the server finds neither legacy items nor non-empty legacy audit details', async () => {
    const personalVault = (await app.ctx.db.select().from(vaults)
      .where(eq(vaults.ownerUserId, owner.userId)).limit(1))[0]!;

    const personalStatus = await migrationStatus(owner, personalVault.id);
    expect(personalStatus.emptyVaultInitializationAllowed).toBe(true);
    expect(personalStatus.materials?.recoveryKey).toBeNull();

    await app.ctx.db.insert(items).values({
      vaultId: personalVault.id,
      kind: 'secure_note',
      title: '旧条目',
      username: null,
      origin: null,
      tags: [],
      favorite: false,
      sensitivity: 'medium',
      updatedBy: owner.userId,
    });
    expect((await migrationStatus(owner, personalVault.id)).emptyVaultInitializationAllowed).toBe(false);

    const auditedVault = (await app.ctx.db.insert(vaults).values({
      kind: 'team',
      name: '',
      ownerUserId: null,
    }).returning())[0]!;
    await app.ctx.db.insert(vaultMemberships).values({
      vaultId: auditedVault.id,
      subjectKind: 'user',
      subjectId: owner.userId,
      role: 'owner',
    });
    const teamStatus = await migrationStatus(owner, auditedVault.id);
    expect(teamStatus.emptyVaultInitializationAllowed).toBe(true);
    expect(teamStatus.materials?.recoveryKey).toBeNull();

    await auditStandalone(app.ctx.db, app.ctx.audit, {
      actorUserId: owner.userId,
      action: 'legacy.audit.with_details',
      vaultId: auditedVault.id,
      success: true,
      details: { legacyTitle: '服务端旧审计正文' },
    });
    expect((await migrationStatus(owner, auditedVault.id)).emptyVaultInitializationAllowed).toBe(false);
  });
});

async function migrationStatus(session: TestSession, vaultId: string) {
  const response = await app.inject({
    method: 'GET',
    url: `/api/v2/vaults/${vaultId}/migration`,
    ...authed(session),
  });
  expect(response.statusCode, response.body).toBe(200);
  return LegacyMigrationStatusResponseSchema.parse(response.json());
}
