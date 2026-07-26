// 最终收口回归：S4 锁定彻底撤销扩展（配对码绑定来源会话 + 原子 lock）
// 与 S5 权限收口（owner 不变量 + 原子转移所有权）。
// 使用独立数据库 mima_test_lockdown（DROP 重建），绝不触碰开发库。
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { freshTestApp, login, authed, key, type TestSession } from './helpers.ts';

let app: FastifyInstance;

beforeAll(async () => {
  app = await freshTestApp('mima_test_lockdown');
});

afterAll(async () => {
  await app.close();
});

async function createTeamVault(owner: TestSession, name: string): Promise<string> {
  const res = await app.inject({
    method: 'POST', url: '/api/vaults', ...authed(owner),
    payload: { idempotencyKey: key(), name, initialOwnerUserId: owner.userId },
  });
  expect(res.statusCode).toBe(201);
  return (res.json() as { id: string }).id;
}

describe('S4 配对码绑定来源会话 + 原子锁定', () => {
  it('锁定中的会话不得生成配对码（423 并审计）', async () => {
    const bob = await login(app, 'bob');
    await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(bob) });
    const res = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    expect(res.statusCode).toBe(423);
    await app.inject({ method: 'POST', url: '/api/session/unlock', ...authed(bob), payload: { password: 'dev' } });
  });

  it('code → lock → claim：锁定原子删除未消费配对码，领取一律失败', async () => {
    const bob = await login(app, 'bob');
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    expect(pairing.statusCode).toBe(200);
    const code = (pairing.json() as { code: string }).code;
    // 锁定：同一事务内 设置锁定 + 撤销扩展会话 + 删除未消费配对码
    const lock = await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(bob) });
    expect(lock.statusCode).toBe(200);
    const claim = await app.inject({
      method: 'POST', url: '/api/extension/sessions', payload: { code },
    });
    expect(claim.statusCode).toBe(401);
    await app.inject({ method: 'POST', url: '/api/session/unlock', ...authed(bob), payload: { password: 'dev' } });
  });

  it('来源会话退出后配对码不可领取（绑定 Web session）', async () => {
    const bob = await login(app, 'bob');
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    const code = (pairing.json() as { code: string }).code;
    await app.inject({ method: 'DELETE', url: '/api/session', ...authed(bob) });
    const claim = await app.inject({
      method: 'POST', url: '/api/extension/sessions', payload: { code },
    });
    expect(claim.statusCode).toBe(401);
  });

  it('并发领取同一配对码：恰好一个成功（used_at 原子占用）', async () => {
    const bob = await login(app, 'bob');
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    const code = (pairing.json() as { code: string }).code;
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        app.inject({ method: 'POST', url: '/api/extension/sessions', payload: { code } }),
      ),
    );
    const ok = results.filter((r) => r.statusCode === 200);
    const denied = results.filter((r) => r.statusCode === 401);
    expect(ok.length).toBe(1);
    expect(denied.length).toBe(3);
  });

  it('锁定同时撤销已配对的扩展会话（原子事务）', async () => {
    const bob = await login(app, 'bob');
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    const code = (pairing.json() as { code: string }).code;
    const claim = await app.inject({ method: 'POST', url: '/api/extension/sessions', payload: { code } });
    expect(claim.statusCode).toBe(200);
    const token = (claim.json() as { token: string }).token;
    const before = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: `Bearer ${token}` },
    });
    expect(before.statusCode).toBe(200);
    await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(bob) });
    const after = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: `Bearer ${token}` },
    });
    expect(after.statusCode).toBe(401);
    await app.inject({ method: 'POST', url: '/api/session/unlock', ...authed(bob), payload: { password: 'dev' } });
  });
});

describe('S5 owner 不变量 + 原子转移所有权', () => {
  it('不得移除最后一个直接用户 owner（组 owner 不算数）', async () => {
    const bob = await login(app, 'bob');
    const vaultId = await createTeamVault(bob, '不变量库');
    // 加一个组 owner：仍不允许删掉唯一的直接用户 owner
    await app.inject({
      method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'group', subjectId: 'group:default/ops', role: 'owner' },
    });
    const res = await app.inject({
      method: 'DELETE', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: bob.userId },
    });
    expect(res.statusCode).toBe(400);
    // 事务回滚：bob 仍是 owner，还能管理成员
    const still = await app.inject({
      method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: 'u-dave', role: 'viewer' },
    });
    expect(still.statusCode).toBe(200);
  });

  it('不得把最后一个直接用户 owner 降级', async () => {
    const bob = await login(app, 'bob');
    const vaultId = await createTeamVault(bob, '降级拒绝库');
    const res = await app.inject({
      method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: bob.userId, role: 'editor' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('转移所有权：原子完成（新 owner 生效 + 原 owner 降为 editor）', async () => {
    const bob = await login(app, 'bob');
    const dave = await login(app, 'dave');
    const vaultId = await createTeamVault(bob, '转移库');
    const res = await app.inject({
      method: 'POST', url: `/api/vaults/${vaultId}/transfer`, ...authed(bob),
      payload: { idempotencyKey: key(), newOwnerUserId: dave.userId },
    });
    expect(res.statusCode).toBe(200);
    const members = await app.inject({
      method: 'GET', url: `/api/vaults/${vaultId}/members`, headers: { cookie: dave.cookie },
    });
    const rows = members.json() as { subjectKind: string; subjectId: string; role: string }[];
    expect(rows.find((m) => m.subjectId === dave.userId)?.role).toBe('owner');
    expect(rows.find((m) => m.subjectId === bob.userId)?.role).toBe('editor');
    // 原 owner 不再能管理成员；新 owner 可以
    const bobTry = await app.inject({
      method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: 'u-erin', role: 'viewer' },
    });
    expect(bobTry.statusCode).toBe(403);
    const daveTry = await app.inject({
      method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(dave),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: 'u-erin', role: 'viewer' },
    });
    expect(daveTry.statusCode).toBe(200);
  });

  it('转移给自己 / 非 owner 发起转移：一律拒绝', async () => {
    const bob = await login(app, 'bob');
    const carol = await login(app, 'carol');
    const vaultId = await createTeamVault(bob, '转移拒绝库');
    const self = await app.inject({
      method: 'POST', url: `/api/vaults/${vaultId}/transfer`, ...authed(bob),
      payload: { idempotencyKey: key(), newOwnerUserId: bob.userId },
    });
    expect(self.statusCode).toBe(400);
    const outsider = await app.inject({
      method: 'POST', url: `/api/vaults/${vaultId}/transfer`, ...authed(carol),
      payload: { idempotencyKey: key(), newOwnerUserId: carol.userId },
    });
    expect(outsider.statusCode).toBe(403);
  });
});
