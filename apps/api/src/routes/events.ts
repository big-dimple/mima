import { asc, eq, gt } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { SyncEvent } from '@mima/contracts';
import { sessions, syncEvents } from '../db/schema.ts';
import {
  getVaultAccess,
  listAccessibleVaults,
  listVaultItems,
  listVaultMemberships,
} from '../services/access.ts';
import { toItemMeta, toMembershipDto, toVaultDto } from '../services/mappers.ts';
import type { SyncEventRow } from '../services/bus.ts';

/**
 * SSE 事件流。顺序保证（消除竞争窗口）：
 * 1. 先订阅总线（实时事件进入缓冲区）；
 * 2. 回放 cursor 之后的 backlog；
 * 3. 冲刷缓冲区（按事件 id 去重，跳过 backlog 已覆盖的行）；
 * 4. 发送 sync.ready（附带权威可访问 vault ID 列表）——客户端据此清理
 *    离线期间被撤权/删除的缓存，此后才可标记在线并冲刷 Outbox。
 *
 * cursor 单调性：recordSyncEvent 在分配 id 前获取事务级 advisory lock（提交时释放），
 * 已提交的事件 id 即提交顺序，断点续传的高水位语义严格成立。
 *
 * 每次投递即时重校验会话与该库权限：
 * - 有权访问 → 投递元数据事件（永不含敏感内容明文）；
 * - 权限被撤销 / 库删除（且此前投递过该库）→ vault.revoked；
 * - 无权且从未见过该库 → 仅 sync.cursor 推进游标，不泄露 vault ID；
 * - 会话失效 → 立即断流（客户端重连拿到 401）；
 * - 单条投递失败 → 立即断流且不推进 cursor，客户端重连后回放，绝不静默跳过。
 */
export function registerEventRoutes(app: FastifyInstance): void {
  const { db, bus } = app.ctx;

  app.get('/api/events', { preHandler: [app.requireSession] }, async (req, reply) => {
    if (app.ctx.e2eeRequired) {
      return reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '旧版事件流已停用，请刷新页面',
      });
    }
    const q = req.query as { cursor?: string };
    const cursor = Number(q.cursor ?? '0') || 0;
    const user = req.user;
    const sessionId = req.sessionRow.id;

    reply.raw.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    reply.hijack();
    reply.raw.write(':connected\n\n');

    let closed = false;
    let lastSent = cursor;
    // 建立阶段（backlog+缓冲）按事件 id 显式去重：bigserial 在并发事务下可能乱序提交
    // （id 更大的行先可见），单纯高水位会把迟到的小 id 永久丢弃。ready 之后事件
    // 全部来自总线的单次投递，无需去重，置空该集合释放内存。
    let setupSeen: Set<number> | null = new Set();
    const close = () => {
      if (closed) return;
      closed = true;
      clearInterval(ping);
      unsubscribe();
      reply.raw.end();
    };

    const send = (event: SyncEvent) => {
      if (closed) return;
      reply.raw.write(`id: ${event.cursor}\ndata: ${JSON.stringify(event)}\n\n`);
    };

    const sessionStillValid = async (): Promise<boolean> => {
      const rows = await db
        .select({ expiresAt: sessions.expiresAt, locked: sessions.locked })
        .from(sessions)
        .where(eq(sessions.id, sessionId))
        .limit(1);
      return rows[0] !== undefined && !rows[0].locked && rows[0].expiresAt.getTime() > Date.now();
    };

    // 该连接已投递过（因此允许收到 vault.revoked）的库集合
    const known = new Set<string>();
    for (const a of await listAccessibleVaults(db, user)) known.add(a.vault.id);

    const deliver = async (row: SyncEventRow) => {
      if (closed) return;
      if (row.id <= cursor) return; // 客户端已确认的历史
      if (setupSeen) {
        if (setupSeen.has(row.id)) return; // backlog 与缓冲的重叠行
        setupSeen.add(row.id);
      }
      try {
        if (!(await sessionStillValid())) {
          close();
          return;
        }
        if (row.type === 'item.encrypted_upserted' || row.type === 'vault.crypto_changed' || row.type === 'vault.rekey_required' || row.type === 'device.revoked') {
          send({ type: 'sync.cursor', cursor: row.id });
          lastSent = Math.max(lastSent, row.id);
          return;
        }
        const access = await getVaultAccess(db, user, row.vaultId);
        const hasAccess = access !== null && access.role !== null;
        if (row.type === 'item.upserted' || row.type === 'item.deleted') {
          if (hasAccess) {
            known.add(row.vaultId);
            if (row.type === 'item.upserted') {
              send({ type: 'item.upserted', cursor: row.id, item: row.payload.item as never });
            } else {
              send({ type: 'item.deleted', cursor: row.id, vaultId: row.vaultId, itemId: row.itemId! });
            }
          } else if (known.has(row.vaultId)) {
            known.delete(row.vaultId);
            send({ type: 'vault.revoked', cursor: row.id, vaultId: row.vaultId });
          } else {
            send({ type: 'sync.cursor', cursor: row.id });
          }
        } else if (row.type === 'vault.deleted' || !hasAccess) {
          if (known.has(row.vaultId)) {
            known.delete(row.vaultId);
            send({ type: 'vault.revoked', cursor: row.id, vaultId: row.vaultId });
          } else {
            // 从未投递过该库：不泄露 vault ID，仅推进游标
            send({ type: 'sync.cursor', cursor: row.id });
          }
        } else {
          // vault.upserted：附带最新成员表；权限可能刚授予，附带条目快照
          known.add(row.vaultId);
          const memberships = (await listVaultMemberships(db, row.vaultId)).map(toMembershipDto);
          const accessChanged = row.payload.accessChanged === true;
          const items = accessChanged
            ? (await listVaultItems(db, row.vaultId)).map(toItemMeta)
            : undefined;
          send({
            type: 'vault.upserted',
            cursor: row.id,
            vault: toVaultDto(access!.vault),
            memberships,
            ...(items ? { items } : {}),
          });
        }
        lastSent = Math.max(lastSent, row.id);
      } catch (err) {
        // 单条投递失败：立即断流、不推进 cursor。客户端将带着最后一条
        // "已应用"的 cursor 重连并回放缺失事件——绝不静默跳过任何事件。
        req.log.error({ err }, 'sse deliver failed, closing stream for replay');
        close();
      }
    };

    // 1) 先订阅：ready 前的实时事件进缓冲；ready 后串行投递
    const buffer: SyncEventRow[] = [];
    let readyToStream = false;
    let chain = Promise.resolve();
    const unsubscribe = bus.subscribe((row) => {
      if (!readyToStream) {
        buffer.push(row);
        return;
      }
      chain = chain.then(() => deliver(row));
    });
    const ping = setInterval(() => {
      if (closed) return;
      void sessionStillValid().then((ok) => {
        if (!ok) {
          close();
          return;
        }
        if (!closed) reply.raw.write(':ping\n\n');
      });
    }, 15_000);

    req.raw.on('close', close);

    // 2) 回放 backlog
    const backlog = await db
      .select()
      .from(syncEvents)
      .where(gt(syncEvents.id, cursor))
      .orderBy(asc(syncEvents.id));
    for (const row of backlog) {
      await deliver(row as SyncEventRow);
    }
    // 3) 冲刷缓冲（deliver 内部按 setupSeen 去重）
    while (buffer.length > 0) {
      await deliver(buffer.shift()!);
    }
    if (closed) return;
    readyToStream = true;
    setupSeen = null;
    // 4) backlog 完毕：附带此刻权威可访问的 vault ID 列表，客户端据此
    //    删除离线期间被撤权/删除的本地缓存（最终一致），随后才上线并冲刷 Outbox。
    const authoritative = await listAccessibleVaults(db, user);
    for (const a of authoritative) known.add(a.vault.id);
    send({
      type: 'sync.ready',
      cursor: lastSent,
      vaultIds: authoritative.map((a) => a.vault.id),
    });
  });
}
