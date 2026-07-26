import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { SyncEvent } from '@mima/contracts';
import {
  TEST_API_HOST,
  freshTestApp,
  login,
  authed,
  key,
  testServerOrigin,
  type TestSession,
} from './helpers.ts';

let app: FastifyInstance;
let baseUrl: string;
let bob: TestSession;
let carol: TestSession;
let vaultId: string;

beforeAll(async () => {
  app = await freshTestApp('mima_test_sse');
  await app.listen({ port: 0, host: TEST_API_HOST });
  const addr = app.server.address();
  baseUrl = testServerOrigin(typeof addr === 'object' && addr ? addr.port : 0);

  bob = await login(app, 'bob');
  carol = await login(app, 'carol');
  const vaultRes = await app.inject({
    method: 'POST', url: '/api/vaults', ...authed(bob),
    payload: { idempotencyKey: key(), name: 'SSE 测试库', initialOwnerUserId: bob.userId },
  });
  vaultId = (vaultRes.json() as { id: string }).id;
  await app.inject({
    method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
    payload: { idempotencyKey: key(), subjectKind: 'group', subjectId: 'group:default/qa', role: 'viewer' },
  });
});

afterAll(async () => {
  await app.close();
});

/** 打开 SSE 流并把事件推入队列。 */
async function openStream(session: TestSession, cursor: number) {
  const controller = new AbortController();
  const res = await fetch(`${baseUrl}/api/events?cursor=${cursor}`, {
    headers: { cookie: session.cookie, accept: 'text/event-stream' },
    signal: controller.signal,
  });
  expect(res.status).toBe(200);
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  const queue: SyncEvent[] = [];
  let buffer = '';
  void (async () => {
    for (;;) {
      const { done, value } = await reader.read().catch(() => ({ done: true, value: undefined }));
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      let sep: number;
      while ((sep = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const data = frame.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('');
        if (data) queue.push(JSON.parse(data) as SyncEvent);
      }
    }
  })();

  const waitFor = async (pred: (e: SyncEvent) => boolean, timeoutMs = 5000): Promise<SyncEvent> => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = queue.find(pred);
      if (found) return found;
      if (Date.now() > deadline) throw new Error(`SSE 等待超时；已收到: ${JSON.stringify(queue.map((e) => e.type))}`);
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  return { queue, waitFor, close: () => controller.abort() };
}

describe('SSE 实时同步', () => {
  it('两个客户端在线：修改事件实时投递，权限撤销投递 vault.revoked', async () => {
    const boot = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: carol.cookie } });
    const cursor = (boot.json() as { cursor: number }).cursor;
    const stream = await openStream(carol, cursor);
    try {
      // bob 创建条目 → carol 收到 item.upserted（元数据，不含密码或 Token 内容）
      const createRes = await app.inject({
        method: 'POST', url: `/api/vaults/${vaultId}/items`, ...authed(bob),
        payload: {
          idempotencyKey: key(), kind: 'login', title: '实时条目', username: 'rt',
          origin: 'https://rt.example.test', tags: [], favorite: false,
          sensitivity: 'low', secretValue: 'sse-secret-realtime-001',
        },
      });
      const created = createRes.json() as { id: string };
      const ev1 = await stream.waitFor((e) => e.type === 'item.upserted' && e.item.id === created.id);
      expect(JSON.stringify(ev1)).not.toContain('sse-secret-realtime-001');

      // bob 轮换密码 → carol 收到版本更新（客户端据此销毁旧 Lease）
      await app.inject({
        method: 'PUT', url: `/api/items/${created.id}/secret`, ...authed(bob),
        payload: { idempotencyKey: key(), expectedVersion: 1, secretValue: 'sse-secret-realtime-002' },
      });
      const ev2 = await stream.waitFor(
        (e) => e.type === 'item.upserted' && e.item.id === created.id && e.item.secretVersion === 2,
      );
      expect(ev2.type).toBe('item.upserted');

      // 撤销 qa 组授权 → carol 收到 vault.revoked
      await app.inject({
        method: 'DELETE', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
        payload: { idempotencyKey: key(), subjectKind: 'group', subjectId: 'group:default/qa' },
      });
      const ev3 = await stream.waitFor((e) => e.type === 'vault.revoked');
      expect(ev3.type === 'vault.revoked' && ev3.vaultId).toBe(vaultId);
    } finally {
      stream.close();
    }
  });

  it('断点续传：cursor 之后的事件重放', async () => {
    // 重新授权 carol
    await app.inject({
      method: 'PUT', url: `/api/vaults/${vaultId}/members`, ...authed(bob),
      payload: { idempotencyKey: key(), subjectKind: 'group', subjectId: 'group:default/qa', role: 'viewer' },
    });
    // 先产生事件，再用旧 cursor 连接
    const createRes = await app.inject({
      method: 'POST', url: `/api/vaults/${vaultId}/items`, ...authed(bob),
      payload: {
        idempotencyKey: key(), kind: 'secure_note', title: '回放条目', username: null,
        origin: null, tags: [], favorite: false, sensitivity: 'low', secretValue: 'replay-note-001',
      },
    });
    const created = createRes.json() as { id: string };
    const stream = await openStream(carol, 0);
    try {
      const ev = await stream.waitFor((e) => e.type === 'item.upserted' && e.item.id === created.id);
      expect(ev.type).toBe('item.upserted');
    } finally {
      stream.close();
    }
  });
});

describe('SSE 加固回归', () => {
  it('先订阅后回放：连接期间并发写入不丢事件、高水位去重不重复，最后收到 sync.ready', async () => {
    // 从 cursor=0 打开流，同时并发产生 5 个事件（落在 backlog/缓冲的竞争窗口内）
    const streamPromise = openStream(carol, 0);
    const createdIds: string[] = [];
    const writes = Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        app.inject({
          method: 'POST', url: `/api/vaults/${vaultId}/items`, ...authed(bob),
          payload: {
            idempotencyKey: key(), kind: 'secure_note', title: `竞争窗口 ${i}`, username: null,
            origin: null, tags: [], favorite: false, sensitivity: 'low', secretValue: `race-note-00${i}`,
          },
        }).then((r) => {
          expect(r.statusCode).toBe(201);
          createdIds.push((r.json() as { id: string }).id);
        }),
      ),
    );
    const stream = await streamPromise;
    try {
      await writes;
      await stream.waitFor((e) => e.type === 'sync.ready');
      for (const id of createdIds) {
        await stream.waitFor((e) => e.type === 'item.upserted' && e.item.id === id);
      }
      // 高水位去重：每个条目的创建事件（version 1）只出现一次
      for (const id of createdIds) {
        const count = stream.queue.filter(
          (e) => e.type === 'item.upserted' && e.item.id === id && e.item.version === 1,
        ).length;
        expect(count).toBe(1);
      }
      // S2：sync_events 分配 cursor 前持有统一事务锁（提交时释放），
      // 已提交的事件 id 即提交顺序——投递到客户端的事件 cursor 必须严格单调递增
      // （sync.ready 的 cursor 是最后水位的重复，排除在外）。
      const cursors = stream.queue.filter((e) => e.type !== 'sync.ready').map((e) => e.cursor);
      for (let i = 1; i < cursors.length; i++) {
        expect(cursors[i]! > cursors[i - 1]!).toBe(true);
      }
    } finally {
      stream.close();
    }
  });

  it('sync.ready 携带权威可访问 vault 列表，且不含无权库', async () => {
    const stream = await openStream(carol, 0);
    try {
      const ready = await stream.waitFor((e) => e.type === 'sync.ready');
      if (ready.type !== 'sync.ready') throw new Error('unreachable');
      // carol 可访问：个人库 + 通过 qa 组的 vaultId
      expect(ready.vaultIds).toContain(vaultId);
      // bob 的个人库绝不能出现在 carol 的权威列表里
      const bobBoot = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: bob.cookie } });
      const bobPersonal = (bobBoot.json() as { vaults: { id: string; kind: string }[] }).vaults
        .find((v) => v.kind === 'personal')!;
      expect(ready.vaultIds).not.toContain(bobPersonal.id);
    } finally {
      stream.close();
    }
  });

  it('无权事件仅推进 cursor，不泄露 vault ID', async () => {
    const boot = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: carol.cookie } });
    const cursor = (boot.json() as { cursor: number }).cursor;
    const stream = await openStream(carol, cursor);
    try {
      await stream.waitFor((e) => e.type === 'sync.ready');
      // bob 在个人库写入：carol 无权
      const bobBoot = await app.inject({ method: 'GET', url: '/api/bootstrap', headers: { cookie: bob.cookie } });
      const personal = (bobBoot.json() as { vaults: { id: string; kind: string }[] }).vaults
        .find((v) => v.kind === 'personal')!;
      const created = await app.inject({
        method: 'POST', url: `/api/vaults/${personal.id}/items`, ...authed(bob),
        payload: {
          idempotencyKey: key(), kind: 'secure_note', title: '私有事件', username: null,
          origin: null, tags: [], favorite: false, sensitivity: 'low', secretValue: 'private-note-009',
        },
      });
      expect(created.statusCode).toBe(201);
      // carol 收到 sync.cursor（游标推进）而非任何带 vault/item 标识的事件
      const cursorEvent = await stream.waitFor((e) => e.type === 'sync.cursor' && e.cursor > cursor);
      expect(cursorEvent.type).toBe('sync.cursor');
      expect(JSON.stringify(stream.queue)).not.toContain(personal.id);
      expect(JSON.stringify(stream.queue)).not.toContain((created.json() as { id: string }).id);
    } finally {
      stream.close();
    }
  });
});
