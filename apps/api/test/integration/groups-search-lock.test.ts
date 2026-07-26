import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { authed, freshTestApp, key, login, type TestSession } from './helpers.ts';
import { customGroups, systemRoleAssignments } from '../../src/db/schema.ts';

let app: FastifyInstance;
let alice: TestSession;
let bob: TestSession;
let carol: TestSession;
let dave: TestSession;

beforeAll(async () => {
  app = await freshTestApp('mima_test_groups_search_lock');
  alice = await login(app, 'alice');
  bob = await login(app, 'bob');
  carol = await login(app, 'carol');
  dave = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values({
    userId: alice.userId,
    role: 'platform-admin',
    assignedBy: 'test',
  });
});

afterAll(async () => {
  await app.close();
});

describe('locked workspace boundary', () => {
  it('allows session inspection and unlock while blocking every business endpoint', async () => {
    const lock = await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(bob) });
    expect(lock.statusCode).toBe(200);

    const session = await app.inject({ method: 'GET', url: '/api/session', headers: { cookie: bob.cookie } });
    expect(session.statusCode).toBe(200);
    expect((session.json() as { locked: boolean }).locked).toBe(true);

    for (const url of ['/api/bootstrap', '/api/directory', '/api/users/search?q=bob']) {
      const response = await app.inject({ method: 'GET', url, headers: { cookie: bob.cookie } });
      expect(response.statusCode, url).toBe(423);
      expect((response.json() as { message: string }).message).toContain('工作台已锁定');
    }

    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    expect(pairing.statusCode).toBe(423);

    const unlock = await app.inject({
      method: 'POST',
      url: '/api/session/unlock',
      ...authed(bob),
      payload: { password: 'dev' },
    });
    expect(unlock.statusCode).toBe(200);
    const bootstrap = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: bob.cookie } });
    expect(bootstrap.statusCode).toBe(200);
  });
});

describe('server-side user search', () => {
  it('returns only matching users, honors explicit selected IDs, and caps results', async () => {
    const match = await app.inject({
      method: 'GET',
      url: `/api/users/search?q=dav&includeIds=${carol.userId}&limit=2`,
      headers: { cookie: bob.cookie },
    });
    expect(match.statusCode).toBe(200);
    const users = (match.json() as { users: Array<{ id: string; username: string }> }).users;
    expect(users).toHaveLength(2);
    expect(users.map((user) => user.id)).toContain(carol.userId);
    expect(users.map((user) => user.username)).toContain('dave');

    const capped = await app.inject({
      method: 'GET',
      url: '/api/users/search?q=&limit=2',
      headers: { cookie: bob.cookie },
    });
    expect((capped.json() as { users: unknown[] }).users).toHaveLength(2);
  });
});

describe('custom groups', () => {
  it('applies membership changes immediately and protects owner/in-use invariants', async () => {
    const createGroup = await app.inject({
      method: 'POST',
      url: '/api/groups',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '发布值班组', memberUserIds: [dave.userId] },
    });
    expect(createGroup.statusCode).toBe(201);
    const group = createGroup.json() as {
      id: string;
      name: string;
      revision: string;
      isOwner: boolean;
      isMember: boolean;
      members: Array<{ id: string }>;
    };
    expect(group).toMatchObject({ isOwner: true, isMember: false });
    expect(group.members.map((member) => member.id)).toEqual([dave.userId]);

    const duplicate = await app.inject({
      method: 'POST',
      url: '/api/groups',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '发布值班组', memberUserIds: [] },
    });
    expect(duplicate.statusCode).toBe(409);
    expect((duplicate.json() as { message: string }).message).toContain('同名用户组');

    const joined = await app.inject({
      method: 'GET',
      url: '/api/groups?scope=joined&q=发布',
      headers: { cookie: dave.cookie },
    });
    expect((joined.json() as Array<{ id: string }>).map((item) => item.id)).toContain(group.id);

    const createVault = await app.inject({
      method: 'POST',
      url: '/api/vaults',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '组授权测试库', initialOwnerUserId: bob.userId },
    });
    expect(createVault.statusCode).toBe(201);
    const vaultId = (createVault.json() as { id: string }).id;

    const ownerRole = await app.inject({
      method: 'PUT',
      url: `/api/vaults/${vaultId}/members`,
      ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'custom_group', subjectId: group.id, role: 'owner' },
    });
    expect(ownerRole.statusCode).toBe(400);

    const attach = await app.inject({
      method: 'PUT',
      url: `/api/vaults/${vaultId}/members`,
      ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'custom_group', subjectId: group.id, role: 'viewer' },
    });
    expect(attach.statusCode).toBe(200);
    expect(await visibleVaultIds(dave)).toContain(vaultId);
    expect(await visibleVaultIds(carol)).not.toContain(vaultId);

    const inUseDelete = await app.inject({
      method: 'DELETE',
      url: `/api/groups/${group.id}`,
      ...authed(bob),
      payload: { idempotencyKey: key(), expectedRevision: group.revision },
    });
    expect(inUseDelete.statusCode).toBe(409);

    const changeMembers = await app.inject({
      method: 'PUT',
      url: `/api/groups/${group.id}`,
      ...authed(bob),
      payload: {
        idempotencyKey: key(),
        expectedRevision: group.revision,
        name: group.name,
        memberUserIds: [carol.userId],
      },
    });
    expect(changeMembers.statusCode).toBe(200);
    const changedGroup = changeMembers.json() as { revision: string };
    expect(await visibleVaultIds(dave)).not.toContain(vaultId);
    expect(await visibleVaultIds(carol)).toContain(vaultId);

    const detach = await app.inject({
      method: 'DELETE',
      url: `/api/vaults/${vaultId}/members`,
      ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'custom_group', subjectId: group.id },
    });
    expect(detach.statusCode).toBe(200);
    const deleteGroup = await app.inject({
      method: 'DELETE',
      url: `/api/groups/${group.id}`,
      ...authed(bob),
      payload: { idempotencyKey: key(), expectedRevision: changedGroup.revision },
    });
    expect(deleteGroup.statusCode).toBe(200);
  });

  it('allows only one save from the same revision and never mixes fields', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/groups',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '并发编辑组', memberUserIds: [dave.userId] },
    });
    expect(created.statusCode).toBe(201);
    const baseline = created.json() as { id: string; revision: string };

    const [left, right] = await Promise.all([
      app.inject({
        method: 'PUT',
        url: `/api/groups/${baseline.id}`,
        ...authed(bob),
        payload: {
          idempotencyKey: key(),
          expectedRevision: baseline.revision,
          name: '并发编辑组-A',
          memberUserIds: [carol.userId],
        },
      }),
      app.inject({
        method: 'PUT',
        url: `/api/groups/${baseline.id}`,
        ...authed(bob),
        payload: {
          idempotencyKey: key(),
          expectedRevision: baseline.revision,
          name: '并发编辑组-B',
          memberUserIds: [dave.userId],
        },
      }),
    ]);

    expect([left.statusCode, right.statusCode].sort()).toEqual([200, 409]);
    const winner = (left.statusCode === 200 ? left : right).json() as {
      name: string;
      members: Array<{ id: string }>;
    };
    const loser = left.statusCode === 409 ? left : right;
    expect(loser.json()).toMatchObject({ code: 'group_version_conflict' });

    const current = await app.inject({
      method: 'GET',
      url: `/api/groups/${baseline.id}`,
      headers: { cookie: bob.cookie },
    });
    expect(current.statusCode).toBe(200);
    expect(current.json()).toMatchObject({
      name: winner.name,
      members: winner.members,
    });
  });

  it('serializes simultaneous ownership transfers without false success', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/groups',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '并发转移组', memberUserIds: [] },
    });
    const baseline = created.json() as { id: string; revision: string };
    const [left, right] = await Promise.all([
      app.inject({
        method: 'POST',
        url: `/api/groups/${baseline.id}/transfer`,
        ...authed(bob),
        payload: {
          idempotencyKey: key(),
          expectedRevision: baseline.revision,
          newOwnerUserId: carol.userId,
        },
      }),
      app.inject({
        method: 'POST',
        url: `/api/groups/${baseline.id}/transfer`,
        ...authed(bob),
        payload: {
          idempotencyKey: key(),
          expectedRevision: baseline.revision,
          newOwnerUserId: dave.userId,
        },
      }),
    ]);
    expect([left.statusCode, right.statusCode].sort()).toEqual([200, 409]);
    const loser = left.statusCode === 409 ? left : right;
    expect(loser.json()).toMatchObject({ code: 'group_version_conflict' });

    const staleDelete = await app.inject({
      method: 'DELETE',
      url: `/api/groups/${baseline.id}`,
      ...authed(bob),
      payload: { idempotencyKey: key(), expectedRevision: baseline.revision },
    });
    expect(staleDelete.statusCode).toBe(409);
    expect(staleDelete.json()).toMatchObject({ code: 'group_version_conflict' });

    const visibleToCarol = await app.inject({
      method: 'GET',
      url: `/api/groups/${baseline.id}`,
      headers: { cookie: carol.cookie },
    });
    const visibleToDave = await app.inject({
      method: 'GET',
      url: `/api/groups/${baseline.id}`,
      headers: { cookie: dave.cookie },
    });
    expect([visibleToCarol.statusCode, visibleToDave.statusCode].sort()).toEqual([200, 404]);
  });

  it('lets a platform admin load and recover only a frozen group', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/groups',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '冻结恢复组', memberUserIds: [] },
    });
    const baseline = created.json() as { id: string };

    const hiddenWhileActive = await app.inject({
      method: 'GET',
      url: `/api/groups/${baseline.id}`,
      headers: { cookie: alice.cookie },
    });
    expect(hiddenWhileActive.statusCode).toBe(404);

    await app.ctx.db.update(customGroups).set({ frozen: true }).where(eq(customGroups.id, baseline.id));
    const frozen = await app.inject({
      method: 'GET',
      url: `/api/groups/${baseline.id}`,
      headers: { cookie: alice.cookie },
    });
    expect(frozen.statusCode).toBe(200);
    const frozenDetail = frozen.json() as { revision: string; frozen: boolean };
    expect(frozenDetail.frozen).toBe(true);

    const transfer = await app.inject({
      method: 'POST',
      url: `/api/groups/${baseline.id}/transfer`,
      ...authed(alice),
      payload: {
        idempotencyKey: key(),
        expectedRevision: frozenDetail.revision,
        newOwnerUserId: carol.userId,
      },
    });
    expect(transfer.statusCode).toBe(200);

    const recovered = await app.inject({
      method: 'GET',
      url: `/api/groups/${baseline.id}`,
      headers: { cookie: carol.cookie },
    });
    expect(recovered.statusCode).toBe(200);
    expect(recovered.json()).toMatchObject({ ownerUserId: carol.userId, frozen: false });
  });

  it('blocks legacy mutation requests that cannot prove the loaded revision', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/groups',
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '旧页面保护组', memberUserIds: [] },
    });
    const groupId = (created.json() as { id: string }).id;
    const response = await app.inject({
      method: 'PATCH',
      url: `/api/groups/${groupId}`,
      ...authed(bob),
      payload: { idempotencyKey: key(), name: '不允许覆盖' },
    });
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ code: 'client_upgrade_required' });
  });
});

async function visibleVaultIds(session: TestSession): Promise<string[]> {
  const response = await app.inject({
    method: 'GET',
    url: '/api/bootstrap',
    headers: { cookie: session.cookie },
  });
  expect(response.statusCode).toBe(200);
  return (response.json() as { vaults: Array<{ id: string }> }).vaults.map((vault) => vault.id);
}
