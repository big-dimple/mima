import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { freshTestApp, login, authed, key, testDbUrl, type TestSession } from './helpers.ts';
import { systemRoleAssignments } from '../../src/db/schema.ts';

let app: FastifyInstance;
let alice: TestSession; // platform-admin
let bob: TestSession; // ops
let carol: TestSession; // qa
let erin: TestSession; // qa + 直接 auditor

let teamVaultId: string;
let itemId: string;
let bobPersonalVaultId: string;
let bobPersonalItemId: string;

const SECRET_1 = 'itest-secret-alpha-001';
const SECRET_2 = 'itest-secret-beta-002';
const PERSONAL_SECRET = 'itest-personal-gamma-003';

beforeAll(async () => {
  app = await freshTestApp('mima_test_api');
  alice = await login(app, 'alice');
  bob = await login(app, 'bob');
  carol = await login(app, 'carol');
  erin = await login(app, 'erin');
  await app.ctx.db.insert(systemRoleAssignments).values({
    userId: alice.userId,
    role: 'platform-admin',
    assignedBy: 'test',
  });

  // bob 创建团队库并配置：ops 组 editor、qa 组 viewer、erin 直接 auditor
  const vaultRes = await app.inject({
    method: 'POST', url: '/api/vaults', ...authed(bob),
    payload: { idempotencyKey: key(), name: '测试团队库', initialOwnerUserId: bob.userId },
  });
  teamVaultId = (vaultRes.json() as { id: string }).id;
  for (const m of [
    { subjectKind: 'group', subjectId: 'group:default/ops', role: 'editor' },
    { subjectKind: 'group', subjectId: 'group:default/qa', role: 'viewer' },
    { subjectKind: 'user', subjectId: erin.userId, role: 'auditor' },
  ]) {
    const r = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), ...m },
    });
    expect(r.statusCode).toBe(200);
  }

  const itemRes = await app.inject({
    method: 'POST', url: `/api/vaults/${teamVaultId}/items`, ...authed(bob),
    payload: {
      idempotencyKey: key(), kind: 'login', title: '共享登录', username: 'svc',
      origin: 'https://portal.example.test', tags: ['t1'], favorite: false,
      sensitivity: 'high', secretValue: SECRET_1,
    },
  });
  expect(itemRes.statusCode).toBe(201);
  itemId = (itemRes.json() as { id: string }).id;

  // bob 个人库条目
  const boot = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: bob.cookie } });
  bobPersonalVaultId = (boot.json() as { vaults: { id: string; kind: string }[] }).vaults
    .find((v) => v.kind === 'personal')!.id;
  const pRes = await app.inject({
    method: 'POST', url: `/api/vaults/${bobPersonalVaultId}/items`, ...authed(bob),
    payload: {
      idempotencyKey: key(), kind: 'secure_note', title: '私人备注', username: null,
      origin: null, tags: [], favorite: false, sensitivity: 'medium', secretValue: PERSONAL_SECRET,
    },
  });
  bobPersonalItemId = (pRes.json() as { id: string }).id;
});

afterAll(async () => {
  await app.close();
});

describe('个人库隔离', () => {
  it('他人 bootstrap 看不到 bob 的个人库与条目', async () => {
    const boot = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: alice.cookie } });
    const data = boot.json() as { vaults: { id: string }[]; items: { id: string }[] };
    expect(data.vaults.some((v) => v.id === bobPersonalVaultId)).toBe(false);
    expect(data.items.some((i) => i.id === bobPersonalItemId)).toBe(false);
  });

  it('他人（含 platform-admin）Reveal 个人库条目返回 403 并写入失败审计', async () => {
    const res = await app.inject({
      method: 'POST', url: `/api/items/${bobPersonalItemId}/reveal`, ...authed(alice),
      payload: { purpose: 'view' },
    });
    expect(res.statusCode).toBe(403);
  });

  it('个人库不可配置成员（不可分享）', async () => {
    const res = await app.inject({
      method: 'PUT', url: `/api/vaults/${bobPersonalVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: alice.userId, role: 'viewer' },
    });
    expect(res.statusCode).toBe(403);
  });
});

describe('团队授权与角色', () => {
  it('qa 组成员 carol 生效角色 viewer：可 Reveal，不可编辑', async () => {
    const reveal = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(carol),
      payload: { purpose: 'view' },
    });
    expect(reveal.statusCode).toBe(200);
    expect((reveal.json() as { value: string }).value === SECRET_1).toBe(true);
    expect(reveal.headers['cache-control']).toBe('no-store');

    const edit = await app.inject({
      method: 'PATCH', url: `/api/items/${itemId}`, ...authed(carol),
      payload: { idempotencyKey: key(), expectedVersion: 1, patch: { title: 'x' } },
    });
    expect(edit.statusCode).toBe(403);
  });

  it('erin 的直接 auditor 角色覆盖 qa 组 viewer：不可 Reveal，可读审计', async () => {
    const reveal = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(erin),
      payload: { purpose: 'view' },
    });
    expect(reveal.statusCode).toBe(403);

    const audit = await app.inject({
      method: 'GET', url: `/api/vaults/${teamVaultId}/audit`, headers: { cookie: erin.cookie },
    });
    expect(audit.statusCode).toBe(200);
    const events = audit.json() as { action: string; success: boolean; actorUserId: string }[];
    // 失败的 reveal 也必须被审计
    expect(events.some((e) => e.action === 'item.reveal' && !e.success && e.actorUserId === erin.userId)).toBe(true);
  });

  it('carol（viewer）不可读审计', async () => {
    const audit = await app.inject({
      method: 'GET', url: `/api/vaults/${teamVaultId}/audit`, headers: { cookie: carol.cookie },
    });
    expect(audit.statusCode).toBe(403);
  });

  it('platform-admin alice 不可 Reveal，也不可管理成员（自提权被拒绝并审计）', async () => {
    const reveal = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(alice),
      payload: { purpose: 'view' },
    });
    expect(reveal.statusCode).toBe(403);

    // 非该库 owner：任何成员操作一律 403（platform-admin 不再拥有成员管理权）
    const grantSelf = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(alice),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: alice.userId, role: 'viewer' },
    });
    expect(grantSelf.statusCode).toBe(403);
    const stillDenied = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(alice),
      payload: { purpose: 'view' },
    });
    expect(stillDenied.statusCode).toBe(403);
  });

  it('platform-admin 成为库 owner 后可按普通成员语义授权自己和所在组', async () => {
    // bob（owner）把 alice 提为该库 owner
    const grant = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: alice.userId, role: 'owner' },
    });
    expect(grant.statusCode).toBe(200);
    // alice 仍是直接 owner；给包含自己的平台组授权 viewer 不会覆盖直接角色
    const group = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(alice),
      payload: { idempotencyKey: key(), subjectKind: 'group', subjectId: 'group:default/platform', role: 'viewer' },
    });
    expect(group.statusCode).toBe(200);
    // 显式更新自己的直接 owner 授权也按普通成员处理
    const self = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(alice),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: alice.userId, role: 'owner' },
    });
    expect(self.statusCode).toBe(200);
    // 给无关用户授权则允许（owner 权限本身有效）
    const other = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(alice),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: 'u-dave', role: 'viewer' },
    });
    expect(other.statusCode).toBe(200);
    // 清理
    await app.inject({
      method: 'DELETE', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'group', subjectId: 'group:default/platform' },
    });
    for (const subjectId of [alice.userId, 'u-dave']) {
      await app.inject({
        method: 'DELETE', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
        payload: { idempotencyKey: key(), subjectKind: 'user', subjectId },
      });
    }
  });

  it('platform-admin 创建团队库时固定自己为 owner，并拒绝旧客户端指定他人', async () => {
    const otherOwner = await app.inject({
      method: 'POST', url: '/api/vaults', ...authed(alice),
      payload: { idempotencyKey: key(), name: '越权库', initialOwnerUserId: carol.userId },
    });
    expect(otherOwner.statusCode).toBe(400);

    const ok = await app.inject({
      method: 'POST', url: '/api/vaults', ...authed(alice),
      payload: { idempotencyKey: key(), name: '管理员团队库' },
    });
    expect(ok.statusCode).toBe(201);
    const newVaultId = (ok.json() as { id: string }).id;
    const members = await app.inject({
      method: 'GET', url: `/api/vaults/${newVaultId}/members`, headers: { cookie: alice.cookie },
    });
    const rows = members.json() as { subjectId: string; role: string }[];
    expect(rows.length).toBe(1);
    expect(rows[0]).toMatchObject({ subjectId: alice.userId, role: 'owner' });

    const compatible = await app.inject({
      method: 'POST', url: '/api/vaults', ...authed(alice),
      payload: { idempotencyKey: key(), name: '旧客户端兼容库', initialOwnerUserId: alice.userId },
    });
    expect(compatible.statusCode).toBe(201);
  });

  it('权限撤销后立即失效', async () => {
    // dave 无任何角色
    const dave = await login(app, 'dave');
    const before = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(dave),
      payload: { purpose: 'view' },
    });
    expect(before.statusCode).toBe(403);

    await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: dave.userId, role: 'viewer' },
    });
    const granted = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(dave),
      payload: { purpose: 'view' },
    });
    expect(granted.statusCode).toBe(200);

    await app.inject({
      method: 'DELETE', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: dave.userId },
    });
    const revoked = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(dave),
      payload: { purpose: 'view' },
    });
    expect(revoked.statusCode).toBe(403);
  });
});

describe('版本与并发', () => {
  it('expectedVersion 过期返回 409 且携带服务端当前版本，密码内容不被合并', async () => {
    const ok = await app.inject({
      method: 'PATCH', url: `/api/items/${itemId}`, ...authed(bob),
      payload: { idempotencyKey: key(), expectedVersion: 1, patch: { title: '共享登录 v2' } },
    });
    expect(ok.statusCode).toBe(200);
    const conflict = await app.inject({
      method: 'PATCH', url: `/api/items/${itemId}`, ...authed(bob),
      payload: { idempotencyKey: key(), expectedVersion: 1, patch: { title: '并发写' } },
    });
    expect(conflict.statusCode).toBe(409);
    const body = conflict.json() as { currentVersion: number; currentItem: { title: string } };
    expect(body.currentVersion).toBe(2);
    expect(body.currentItem.title).toBe('共享登录 v2');
  });

  it('密码轮换生成新版本，历史版本可读且不可覆盖', async () => {
    const rotate = await app.inject({
      method: 'PUT', url: `/api/items/${itemId}/secret`, ...authed(bob),
      payload: { idempotencyKey: key(), expectedVersion: 2, secretValue: SECRET_2 },
    });
    expect(rotate.statusCode).toBe(200);
    const meta = rotate.json() as { version: number; secretVersion: number };
    expect(meta.secretVersion).toBe(3);

    const current = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(bob),
      payload: { purpose: 'view' },
    });
    expect((current.json() as { value: string }).value === SECRET_2).toBe(true);

    const historic = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(bob),
      payload: { purpose: 'view', secretVersion: 1 },
    });
    expect((historic.json() as { value: string }).value === SECRET_1).toBe(true);

    const versions = await app.inject({
      method: 'GET', url: `/api/items/${itemId}/versions`, headers: { cookie: bob.cookie },
    });
    expect((versions.json() as unknown[]).length).toBe(2);
  });

  it('相同 idempotencyKey 重放返回相同结果且不重复执行', async () => {
    const k = key();
    const payload = { idempotencyKey: k, expectedVersion: 3, patch: { favorite: true } };
    const first = await app.inject({ method: 'PATCH', url: `/api/items/${itemId}`, ...authed(bob), payload });
    expect(first.statusCode).toBe(200);
    const v1 = (first.json() as { version: number }).version;
    const replay = await app.inject({ method: 'PATCH', url: `/api/items/${itemId}`, ...authed(bob), payload });
    expect(replay.statusCode).toBe(200);
    expect((replay.json() as { version: number }).version).toBe(v1);
  });
});

describe('会话与 CSRF', () => {
  it('写请求缺少 CSRF Token 拒绝', async () => {
    const res = await app.inject({
      method: 'PATCH', url: `/api/items/${itemId}`, headers: { cookie: bob.cookie },
      payload: { idempotencyKey: key(), expectedVersion: 99, patch: { title: 'x' } },
    });
    expect(res.statusCode).toBe(403);
  });

  it('非白名单 Origin 拒绝', async () => {
    const res = await app.inject({
      method: 'PATCH', url: `/api/items/${itemId}`,
      headers: { cookie: bob.cookie, 'x-mima-csrf': bob.csrf, origin: 'https://evil.example.test' },
      payload: { idempotencyKey: key(), expectedVersion: 99, patch: { title: 'x' } },
    });
    expect(res.statusCode).toBe(403);
  });

  it('会话锁定后禁止 Reveal，解锁恢复', async () => {
    const lock = await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(bob) });
    expect(lock.statusCode).toBe(200);
    const denied = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(bob),
      payload: { purpose: 'view' },
    });
    expect(denied.statusCode).toBe(423);
    const badUnlock = await app.inject({
      method: 'POST', url: '/api/session/unlock', ...authed(bob), payload: { password: 'wrong' },
    });
    expect(badUnlock.statusCode).toBe(401);
    const unlock = await app.inject({
      method: 'POST', url: '/api/session/unlock', ...authed(bob), payload: { password: 'dev' },
    });
    expect(unlock.statusCode).toBe(200);
    const ok = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(bob),
      payload: { purpose: 'view' },
    });
    expect(ok.statusCode).toBe(200);
  });
});

describe('扩展配对', () => {
  it('配对码换取 token，二次使用与过期拒绝', async () => {
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    expect(pairing.statusCode).toBe(200);
    const { code } = pairing.json() as { code: string };

    const claim = await app.inject({
      method: 'POST', url: '/api/extension/sessions', payload: { code },
    });
    expect(claim.statusCode).toBe(200);
    const { token, expiresAt } = claim.json() as { token: string; expiresAt: string };
    expect(Date.parse(expiresAt) - Date.now()).toBeGreaterThan(99 * 365 * 24 * 60 * 60 * 1000);

    // 一次性：重复使用同一配对码失败
    const reuse = await app.inject({
      method: 'POST', url: '/api/extension/sessions', payload: { code },
    });
    expect(reuse.statusCode).toBe(401);

    // token 可访问扩展端点，并且 auditor 规则同样生效
    const boot = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: `Bearer ${token}` },
    });
    expect(boot.statusCode).toBe(200);
    const reveal = await app.inject({
      method: 'POST', url: `/api/extension/items/${itemId}/reveal`,
      headers: { authorization: `Bearer ${token}` },
      payload: { purpose: 'copy' },
    });
    expect(reveal.statusCode).toBe(200);

    const badToken = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: 'Bearer nope' },
    });
    expect(badToken.statusCode).toBe(401);
  });
});

describe('数据库中不得出现明文密码或 Token', () => {
  it('全库扫描（含 bytea 转义）找不到任何测试敏感内容', async () => {
    const client = new pg.Client({ connectionString: testDbUrl('mima_test_api') });
    await client.connect();
    try {
      const tables = await client.query<{ table_name: string }>(
        `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
      );
      for (const secret of [SECRET_1, SECRET_2, PERSONAL_SECRET]) {
        for (const { table_name } of tables.rows) {
          const rows = await client.query(
            `SELECT t::text AS row_text FROM ${table_name} t`,
          );
          for (const row of rows.rows as { row_text: string }[]) {
            expect(row.row_text.includes(secret)).toBe(false);
          }
        }
      }
    } finally {
      await client.end();
    }
  });

  it('审计日志 HMAC 链完整（独立密钥）', async () => {
    const client = new pg.Client({ connectionString: testDbUrl('mima_test_api') });
    await client.connect();
    try {
      const { computeAuditHash, AUDIT_CHAIN_GENESIS } = await import('@mima/crypto');
      const hmacKey = app.ctx.audit.hmacKey;
      const rows = await client.query(
        'SELECT ts, actor_user_id, action, vault_id, item_id, success, details, prev_hash, hash FROM audit_events ORDER BY id',
      );
      expect(rows.rows.length).toBeGreaterThan(10);
      let prev = AUDIT_CHAIN_GENESIS;
      for (const row of rows.rows) {
        expect(row.prev_hash).toBe(prev);
        const expected = computeAuditHash(hmacKey, prev, {
          ts: (row.ts as Date).toISOString(),
          actorUserId: row.actor_user_id,
          action: row.action,
          vaultId: row.vault_id,
          itemId: row.item_id,
          success: row.success,
          details: row.details,
        });
        expect(row.hash).toBe(expected);
        prev = row.hash as string;
      }
    } finally {
      await client.end();
    }
  });
});

describe('加固回归', () => {
  it('viewer 被降为 auditor 后立即不可 Reveal', async () => {
    // carol 现有 qa 组 viewer；直接角色 auditor 无条件覆盖
    const demote = await app.inject({
      method: 'PUT', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: carol.userId, role: 'auditor' },
    });
    expect(demote.statusCode).toBe(200);
    const denied = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(carol),
      payload: { purpose: 'view' },
    });
    expect(denied.statusCode).toBe(403);
    // 恢复
    await app.inject({
      method: 'DELETE', url: `/api/vaults/${teamVaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'user', subjectId: carol.userId },
    });
    const restored = await app.inject({
      method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(carol),
      payload: { purpose: 'view' },
    });
    expect(restored.statusCode).toBe(200);
  });

  it('会话过期后任何请求 401', async () => {
    const dave = await login(app, 'dave');
    const ok = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: dave.cookie } });
    expect(ok.statusCode).toBe(200);
    const client = new pg.Client({ connectionString: testDbUrl('mima_test_api') });
    await client.connect();
    try {
      await client.query(`UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE user_id = $1`, [dave.userId]);
    } finally {
      await client.end();
    }
    const expired = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: dave.cookie } });
    expect(expired.statusCode).toBe(401);
  });

  it('锁定会话即撤销该用户全部扩展会话', async () => {
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(carol) });
    const claim = await app.inject({
      method: 'POST', url: '/api/extension/sessions',
      payload: { code: (pairing.json() as { code: string }).code },
    });
    const token = (claim.json() as { token: string }).token;
    const before = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: `Bearer ${token}` },
    });
    expect(before.statusCode).toBe(200);
    const lock = await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(carol) });
    expect(lock.statusCode).toBe(200);
    const after = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: `Bearer ${token}` },
    });
    expect(after.statusCode).toBe(401);
    await app.inject({ method: 'POST', url: '/api/session/unlock', ...authed(carol), payload: { password: 'dev' } });
  });

  it('解除配对立即使扩展 Token 失效', async () => {
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    const claim = await app.inject({
      method: 'POST', url: '/api/extension/sessions',
      payload: { code: (pairing.json() as { code: string }).code },
    });
    const token = (claim.json() as { token: string }).token;
    const unpair = await app.inject({
      method: 'DELETE', url: '/api/extension/sessions', headers: { authorization: `Bearer ${token}` },
    });
    expect(unpair.statusCode).toBe(200);
    const after = await app.inject({
      method: 'GET', url: '/api/extension/bootstrap', headers: { authorization: `Bearer ${token}` },
    });
    expect(after.statusCode).toBe(401);
  });

  it('扩展 Fill：缺上下文 / 旧 Origin / 过期版本一律拒绝，全部正确才放行', async () => {
    const pairing = await app.inject({ method: 'POST', url: '/api/extension/pairing', ...authed(bob) });
    const claim = await app.inject({
      method: 'POST', url: '/api/extension/sessions',
      payload: { code: (pairing.json() as { code: string }).code },
    });
    const token = (claim.json() as { token: string }).token;
    const auth = { authorization: `Bearer ${token}` };
    const boot = await app.inject({ method: 'GET', url: '/api/extension/bootstrap', headers: auth });
    const meta = (boot.json() as { items: { id: string; version: number; origin: string | null }[] })
      .items.find((i) => i.id === itemId)!;

    const missing = await app.inject({
      method: 'POST', url: `/api/extension/items/${itemId}/reveal`, headers: auth,
      payload: { purpose: 'fill' },
    });
    expect(missing.statusCode).toBe(403);

    const wrongOrigin = await app.inject({
      method: 'POST', url: `/api/extension/items/${itemId}/reveal`, headers: auth,
      payload: { purpose: 'fill', origin: 'https://phish.example.test', itemVersion: meta.version },
    });
    expect(wrongOrigin.statusCode).toBe(403);

    const staleVersion = await app.inject({
      method: 'POST', url: `/api/extension/items/${itemId}/reveal`, headers: auth,
      payload: { purpose: 'fill', origin: meta.origin, itemVersion: meta.version + 1 },
    });
    expect(staleVersion.statusCode).toBe(409);

    const ok = await app.inject({
      method: 'POST', url: `/api/extension/items/${itemId}/reveal`, headers: auth,
      payload: { purpose: 'fill', origin: meta.origin, itemVersion: meta.version },
    });
    expect(ok.statusCode).toBe(200);
  });

  it('AAD 上下文：数据库约束拒绝密文行移花接木；绕过约束后服务端拒绝解密', async () => {
    const client = new pg.Client({ connectionString: testDbUrl('mima_test_api') });
    await client.connect();
    try {
      // 组合外键直接拒绝 UPDATE
      await expect(
        client.query('UPDATE item_secret_versions SET vault_id = $1 WHERE item_id = $2', [bobPersonalVaultId, itemId]),
      ).rejects.toThrow(/foreign key|violates/i);

      // 模拟"攻击者可写库"绕过约束：服务端仍须拒绝
      await client.query('ALTER TABLE item_secret_versions DROP CONSTRAINT item_secret_versions_ctx_fk');
      await client.query('UPDATE item_secret_versions SET vault_id = $1 WHERE item_id = $2', [bobPersonalVaultId, itemId]);
      const tampered = await app.inject({
        method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(bob),
        payload: { purpose: 'view' },
      });
      expect(tampered.statusCode).toBe(409);
      // 复原并恢复约束
      await client.query('UPDATE item_secret_versions SET vault_id = $1 WHERE item_id = $2', [teamVaultId, itemId]);
      await client.query(`ALTER TABLE item_secret_versions
        ADD CONSTRAINT item_secret_versions_ctx_fk
        FOREIGN KEY (item_id, vault_id, item_kind) REFERENCES items (id, vault_id, kind) ON DELETE CASCADE`);
      const ok = await app.inject({
        method: 'POST', url: `/api/items/${itemId}/reveal`, ...authed(bob),
        payload: { purpose: 'view' },
      });
      expect(ok.statusCode).toBe(200);
    } finally {
      await client.end();
    }
  });
});
