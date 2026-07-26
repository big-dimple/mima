import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  AtomicCreateEncryptedVaultRequest,
  CreateEncryptedProjectRequest,
  UserCryptoProfile,
} from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  customGroupMembers,
  customGroups,
  vaultCustomGroupRoles,
  vaultCryptoStates,
  vaultMemberships,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let owner: TestSession;
let member: TestSession;
let ownerKeyring: E2eeKeyring;
let memberKeyring: E2eeKeyring;
let ownerProfile: UserCryptoProfile;
let memberProfile: UserCryptoProfile;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_team_vault_projects');
  owner = await login(app, 'bob');
  member = await login(app, 'erin');
  ownerKeyring = new E2eeKeyring();
  memberKeyring = new E2eeKeyring();
  ownerProfile = await createProfile(owner, ownerKeyring, 'project owner password');
  memberProfile = await createProfile(member, memberKeyring, 'project member password');
});

afterAll(async () => {
  if (ownerKeyring) await ownerKeyring.lock();
  if (memberKeyring) await memberKeyring.lock();
  if (app) await app.close();
});

describe('atomic team vault projects', () => {
  it('lets the direct owner clean an untouched legacy team vault and nothing else', async () => {
    const vaultId = randomUUID();
    await app.ctx.db.insert(vaults).values({ id: vaultId, kind: 'team', name: '', ownerUserId: null });
    await app.ctx.db.insert(vaultMemberships).values({
      vaultId,
      subjectKind: 'user',
      subjectId: owner.userId,
      role: 'owner',
    });
    const request = await ownerKeyring.prepareUninitializedVaultDeletion(owner.userId, vaultId, 0);
    const response = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${vaultId}/uninitialized`,
      ...authed(owner),
      payload: request,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(0);
  });

  it('rolls back every row when recipient validation fails inside the creation transaction', async () => {
    const vaultId = randomUUID();
    const prepared = await ownerKeyring.prepareVaultCreation(
      owner.userId,
      vaultId,
      '不会残留的库',
      ownerProfile,
      null,
      [],
    ) as AtomicCreateEncryptedVaultRequest;
    const { manifestSignature: _signature, ...unsigned } = {
      ...prepared,
      envelopes: [...prepared.envelopes, prepared.envelopes[0]!],
    };
    const manifestSignature = await privateSign(ownerKeyring)(
      'vault.create',
      owner.userId,
      { vaultId },
      unsigned,
    );
    const response = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(owner),
      payload: { ...unsigned, manifestSignature },
    });
    expect(response.statusCode, response.body).toBe(409);
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, vaultId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(vaultMemberships)
      .where(eq(vaultMemberships.vaultId, vaultId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, vaultId))).toHaveLength(0);
  });

  it('creates root and project atomically, replays safely, and hides an inaccessible parent', async () => {
    const root = await createRoot('运维');
    const replay = await app.inject({
      method: 'POST',
      url: '/api/v2/vaults',
      ...authed(owner),
      payload: root.request,
    });
    expect(replay.statusCode, replay.body).toBe(201);
    expect((replay.json() as { id: string }).id).toBe(root.id);
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, root.id))).toHaveLength(1);

    const projectId = randomUUID();
    const projectRequest = await ownerKeyring.prepareVaultCreation(
      owner.userId,
      projectId,
      '斗罗大陆',
      ownerProfile,
      null,
      [],
      { parentVaultId: root.id, expectedParentAccessGeneration: 1 },
    ) as CreateEncryptedProjectRequest;
    const projectResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${root.id}/projects`,
      ...authed(owner),
      payload: projectRequest,
    });
    expect(projectResponse.statusCode, projectResponse.body).toBe(201);
    expect((await app.ctx.db.select().from(vaults).where(eq(vaults.id, projectId)))[0])
      .toMatchObject({ parentVaultId: root.id, kind: 'team' });

    const nestedId = randomUUID();
    const nestedRequest = await ownerKeyring.prepareVaultCreation(
      owner.userId,
      nestedId,
      '不允许的二级项目',
      ownerProfile,
      null,
      [],
      { parentVaultId: projectId, expectedParentAccessGeneration: 1 },
    ) as CreateEncryptedProjectRequest;
    const nestedResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${projectId}/projects`,
      ...authed(owner),
      payload: nestedRequest,
    });
    expect(nestedResponse.statusCode, nestedResponse.body).toBe(409);
    expect(await app.ctx.db.select().from(vaults).where(eq(vaults.id, nestedId))).toHaveLength(0);

    const customGroup = (await app.ctx.db.insert(customGroups).values({
      ownerUserId: owner.userId,
      name: '项目批量授权防降权测试组',
    }).returning())[0]!;
    await app.ctx.db.insert(customGroupMembers).values({
      groupId: customGroup.id,
      userId: member.userId,
      addedBy: owner.userId,
    });
    await app.ctx.db.insert(vaultCustomGroupRoles).values({
      vaultId: projectId,
      groupId: customGroup.id,
      role: 'editor',
    });
    const unsafeGrant = await ownerKeyring.prepareMembershipSet(owner.userId, projectId, {
      subjectKind: 'user',
      subjectId: member.userId,
      role: 'viewer',
      mode: 'grant_or_upgrade',
      expectedAccessGeneration: 1,
      distribution: {
        signerKeyVersion: ownerProfile.keyVersion,
        recipientProfile: {
          userId: member.userId,
          keyVersion: memberProfile.keyVersion,
          encryptionPublicKey: memberProfile.encryptionPublicKey,
          signingPublicKey: memberProfile.signingPublicKey,
        },
      },
    });
    const unsafeGrantResponse = await app.inject({
      method: 'PUT',
      url: `/api/v2/vaults/${projectId}/members`,
      ...authed(owner),
      payload: unsafeGrant,
    });
    expect(unsafeGrantResponse.statusCode, unsafeGrantResponse.body).toBe(409);
    expect(unsafeGrantResponse.json()).toMatchObject({ code: 'grant_would_reduce_access' });
    expect(await app.ctx.db.select().from(vaultMemberships).where(eq(
      vaultMemberships.vaultId,
      projectId,
    ))).not.toContainEqual(expect.objectContaining({ subjectId: member.userId }));
    await app.ctx.db.delete(vaultCustomGroupRoles).where(eq(
      vaultCustomGroupRoles.groupId,
      customGroup.id,
    ));
    await app.ctx.db.delete(customGroups).where(eq(customGroups.id, customGroup.id));

    const grant = await ownerKeyring.prepareMembershipSet(owner.userId, projectId, {
      subjectKind: 'user',
      subjectId: member.userId,
      role: 'viewer',
      mode: 'grant_or_upgrade',
      expectedAccessGeneration: 1,
      distribution: {
        signerKeyVersion: ownerProfile.keyVersion,
        recipientProfile: {
          userId: member.userId,
          keyVersion: memberProfile.keyVersion,
          encryptionPublicKey: memberProfile.encryptionPublicKey,
          signingPublicKey: memberProfile.signingPublicKey,
        },
      },
    });
    const granted = await app.inject({
      method: 'PUT',
      url: `/api/v2/vaults/${projectId}/members`,
      ...authed(owner),
      payload: grant,
    });
    expect(granted.statusCode, granted.body).toBe(200);

    const ownerBootstrap = (await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      ...authed(owner),
    })).json() as { vaults: Array<{ id: string; projectContext?: unknown }> };
    expect(ownerBootstrap.vaults.find((vault) => vault.id === root.id)?.projectContext)
      .toEqual({ kind: 'root' });
    expect(ownerBootstrap.vaults.find((vault) => vault.id === projectId)?.projectContext)
      .toEqual({ kind: 'project', visibleParentVaultId: root.id });

    const memberBootstrap = (await app.inject({
      method: 'GET',
      url: '/api/v2/bootstrap',
      ...authed(member),
    })).json() as { vaults: Array<{ id: string; projectContext?: unknown }> };
    expect(memberBootstrap.vaults.some((vault) => vault.id === root.id)).toBe(false);
    expect(memberBootstrap.vaults.find((vault) => vault.id === projectId)?.projectContext)
      .toEqual({ kind: 'project', visibleParentVaultId: null });

    const deletionRequest = await ownerKeyring.prepareVaultDeletion(
      owner.userId,
      root.id,
      1,
      {
        ...root.request.header,
        updatedAt: new Date().toISOString(),
        updatedBy: owner.userId,
      },
    );
    const deletion = await app.inject({
      method: 'DELETE',
      url: `/api/v2/vaults/${root.id}`,
      ...authed(owner),
      payload: deletionRequest,
    });
    expect(deletion.statusCode, deletion.body).toBe(409);
    expect(deletion.json()).toMatchObject({ code: 'vault_has_projects' });
  });
});

async function createProfile(
  session: TestSession,
  keyring: E2eeKeyring,
  password: string,
): Promise<UserCryptoProfile> {
  const setup = await keyring.setup(password, {
    accountId: session.userId,
    deviceId: randomUUID(),
    deviceName: 'Project integration browser',
    platform: 'integration:test',
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(session),
    payload: setup.request,
  });
  expect(response.statusCode, response.body).toBe(201);
  return response.json() as UserCryptoProfile;
}

async function createRoot(name: string): Promise<{
  id: string;
  request: AtomicCreateEncryptedVaultRequest;
}> {
  const id = randomUUID();
  const request = await ownerKeyring.prepareVaultCreation(
    owner.userId,
    id,
    name,
    ownerProfile,
    null,
    [],
  ) as AtomicCreateEncryptedVaultRequest;
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/vaults',
    ...authed(owner),
    payload: request,
  });
  expect(response.statusCode, response.body).toBe(201);
  return { id, request };
}

function privateSign(keyring: E2eeKeyring) {
  return (keyring as unknown as {
    signCommand(
      action: string,
      userId: string,
      scope: { vaultId?: string },
      request: unknown,
    ): Promise<string>;
  }).signCommand.bind(keyring);
}
