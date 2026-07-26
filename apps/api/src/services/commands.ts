import { and, desc, eq, sql } from 'drizzle-orm';
import type { ItemMeta } from '@mima/contracts';
import type { Db } from '../db/client.ts';
import { auditEvents, commandDedup, syncEvents } from '../db/schema.ts';
import { recordAnchor, type AuditContext, type DbOrTx } from './audit.ts';
import type { SyncBus, SyncEventRow } from './bus.ts';

/** expectedVersion 不匹配时抛出；路由层转换为 409，敏感内容不得自动合并。 */
export class VersionConflictError extends Error {
  constructor(
    public currentVersion: number,
    public currentItem?: ItemMeta,
  ) {
    super('version conflict');
  }
}

export class AccessDeniedError extends Error {
  constructor(
    message: string,
    public action: string,
    public vaultId?: string | null,
    public itemId?: string | null,
  ) {
    super(message);
  }
}

export interface CommandResult<T> {
  statusCode: number;
  response: T;
}

/** sync_events 游标分配锁：持锁到事务提交，保证"已提交的 cursor 单调"。 */
const SYNC_CURSOR_LOCK_KEY = 815002;

/**
 * 在事务内追加 sync_events 行，返回可发布的事件（提交后再 publish）。
 * 分配 id 前先获取统一事务级 advisory lock（提交时才释放）：并发事务不再可能
 * "大 id 先提交、小 id 后提交"，客户端与 SSE 的高水位/断点续传因此严格可靠。
 */
export async function recordSyncEvent(
  tx: DbOrTx,
  event: Omit<SyncEventRow, 'id'>,
): Promise<SyncEventRow> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${SYNC_CURSOR_LOCK_KEY})`);
  const inserted = await tx
    .insert(syncEvents)
    .values({
      type: event.type,
      vaultId: event.vaultId,
      itemId: event.itemId,
      payload: event.payload,
    })
    .returning({ id: syncEvents.id });
  return { ...event, id: inserted[0]!.id };
}

/**
 * 幂等命令执行器：同 (idempotencyKey, userId) 的成功命令直接重放缓存响应。
 * fn 在事务中执行业务写入并返回 {statusCode, response}；
 * 事务内通过 collect() 汇集 sync 事件，提交后统一发布到 SSE 总线。
 */
export async function runCommand<T extends Record<string, unknown>>(
  db: Db,
  bus: SyncBus,
  audit: AuditContext,
  userId: string,
  idempotencyKey: string,
  fn: (tx: DbOrTx, collect: (e: SyncEventRow) => void) => Promise<CommandResult<T>>,
): Promise<CommandResult<T>> {
  const pending: SyncEventRow[] = [];
  const execution = await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`${userId}:${idempotencyKey}`}))`);
    const replay = await tx
      .select()
      .from(commandDedup)
      .where(and(eq(commandDedup.idempotencyKey, idempotencyKey), eq(commandDedup.userId, userId)))
      .limit(1);
    if (replay[0]) {
      return {
        result: { statusCode: replay[0].statusCode, response: replay[0].response as T },
        replayed: true,
      };
    }
    const r = await fn(tx, (e) => pending.push(e));
    if (r.statusCode >= 200 && r.statusCode < 300) {
      await tx.insert(commandDedup).values({
        idempotencyKey,
        userId,
        statusCode: r.statusCode,
        response: r.response,
      });
    }
    return { result: r, replayed: false };
  });
  if (!execution.replayed) bus.publish(pending);
  // 提交后把审计链头锚定到数据库之外（单调、best-effort）
  const head = await db
    .select({ id: auditEvents.id, hash: auditEvents.hash })
    .from(auditEvents)
    .orderBy(desc(auditEvents.id))
    .limit(1);
  if (head[0]) recordAnchor(audit, head[0]);
  return execution.result;
}
