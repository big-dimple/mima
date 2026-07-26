import { asc, desc, sql } from 'drizzle-orm';
import {
  AUDIT_CHAIN_GENESIS,
  computeAuditHash,
  type AuditAnchorStore,
} from '@mima/crypto';
import type { Db } from '../db/client.ts';
import { auditEvents } from '../db/schema.ts';

export type DbOrTx = Db | Parameters<Parameters<Db['transaction']>[0]>[0];

/** 审计上下文：独立 HMAC 密钥（不同于 KEK）+ 数据库外锚点存储。 */
export interface AuditContext {
  hmacKey: Buffer;
  anchors: AuditAnchorStore;
}

export interface AuditInput {
  actorUserId: string | null;
  action: string;
  vaultId?: string | null;
  itemId?: string | null;
  success: boolean;
  details?: Record<string, unknown>;
}

export interface AuditHead {
  id: number;
  hash: string;
}

/** 审计链专用 advisory lock key，保证 prev_hash 串行推进。 */
const AUDIT_LOCK_KEY = 815001;

export type AuditChainVerificationFailure =
  | 'chain-link-mismatch'
  | 'hmac-mismatch'
  | 'anchor-missing'
  | 'anchor-ahead'
  | 'anchor-record-missing'
  | 'anchor-hash-mismatch'
  | 'anchor-behind';

export class AuditChainVerificationError extends Error {
  readonly code: AuditChainVerificationFailure;

  constructor(code: AuditChainVerificationFailure) {
    super(`audit chain startup verification failed: ${code}`);
    this.name = 'AuditChainVerificationError';
    this.code = code;
  }
}

export interface AuditChainVerificationResult {
  recordCount: number;
  headId: number | null;
  anchorId: number | null;
}

export interface AuditAnchorRepairResult extends AuditChainVerificationResult {
  status: 'advanced' | 'already-current' | 'empty';
}

/**
 * 在持有审计写锁时校验完整数据库链、配置 HMAC key 与库外锚点。
 * 空库允许没有锚点；任何非空链缺锚点、落后锚点或不一致都失败关闭。
 * 此函数只校验，不推进锚点、不重签历史，也不在错误中包含事件正文、hash 或密钥路径。
 */
export async function verifyAuditChain(
  db: Db,
  audit: AuditContext,
): Promise<AuditChainVerificationResult> {
  return db.transaction((tx) => inspectAuditChain(tx, audit, false));
}

/**
 * 仅用于写入已冻结后的显式运维恢复：完整验证 HMAC 链与现有锚点前缀后，
 * 把库外锚点单调推进到已提交链头。缺失、超前或不匹配的锚点仍失败关闭。
 */
export async function repairAuditAnchor(
  db: Db,
  audit: AuditContext,
): Promise<AuditAnchorRepairResult> {
  return db.transaction(async (tx) => {
    const inspected = await inspectAuditChain(tx, audit, true);
    const result = withoutHeadHash(inspected);
    if (inspected.headId === null) return { ...result, status: 'empty' };
    if (inspected.anchorId === inspected.headId) return { ...result, status: 'already-current' };
    audit.anchors.record(inspected.headId, inspected.headHash!);
    return { ...result, status: 'advanced' };
  });
}

interface InspectedAuditChain extends AuditChainVerificationResult {
  headHash?: string;
}

async function inspectAuditChain(
  tx: DbOrTx,
  audit: AuditContext,
  allowAnchorBehind: boolean,
): Promise<InspectedAuditChain> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_KEY})`);
  const rows = await tx.select().from(auditEvents).orderBy(asc(auditEvents.id));
  let previousHash = AUDIT_CHAIN_GENESIS;
  const hashesById = new Map<number, string>();

  for (const row of rows) {
    if (row.prevHash !== previousHash) throw new AuditChainVerificationError('chain-link-mismatch');
    const expectedHash = computeAuditHash(audit.hmacKey, previousHash, {
      ts: row.ts.toISOString(),
      actorUserId: row.actorUserId,
      action: row.action,
      vaultId: row.vaultId,
      itemId: row.itemId,
      success: row.success,
      details: row.details,
    });
    if (row.hash !== expectedHash) throw new AuditChainVerificationError('hmac-mismatch');
    hashesById.set(row.id, row.hash);
    previousHash = row.hash;
  }

  const anchor = audit.anchors.read();
  const head = rows.at(-1) ?? null;
  if (!head) {
    if (anchor) throw new AuditChainVerificationError('anchor-ahead');
    return { recordCount: 0, headId: null, anchorId: null };
  }
  if (!anchor) throw new AuditChainVerificationError('anchor-missing');
  if (anchor.id > head.id) throw new AuditChainVerificationError('anchor-ahead');
  const anchoredHash = hashesById.get(anchor.id);
  if (!anchoredHash) throw new AuditChainVerificationError('anchor-record-missing');
  if (anchoredHash !== anchor.hash) throw new AuditChainVerificationError('anchor-hash-mismatch');
  if (!allowAnchorBehind && anchor.id < head.id) throw new AuditChainVerificationError('anchor-behind');
  return { recordCount: rows.length, headId: head.id, anchorId: anchor.id, headHash: head.hash };
}

function withoutHeadHash(result: InspectedAuditChain): AuditChainVerificationResult {
  return { recordCount: result.recordCount, headId: result.headId, anchorId: result.anchorId };
}

/**
 * 追加一条审计记录（独立密钥 HMAC-SHA256 链）。必须在事务内调用；
 * 通过 pg_advisory_xact_lock 保证并发写入时链不分叉。
 * 返回新链头；调用方应在事务提交后调用 recordAnchor 更新库外锚点。
 */
export async function appendAudit(tx: DbOrTx, audit: AuditContext, input: AuditInput): Promise<AuditHead> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_KEY})`);
  const last = await tx
    .select({ hash: auditEvents.hash })
    .from(auditEvents)
    .orderBy(desc(auditEvents.id))
    .limit(1);
  const prevHash = last[0]?.hash ?? AUDIT_CHAIN_GENESIS;
  const ts = new Date();
  const details = input.details ?? {};
  const hash = computeAuditHash(audit.hmacKey, prevHash, {
    ts: ts.toISOString(),
    actorUserId: input.actorUserId,
    action: input.action,
    vaultId: input.vaultId ?? null,
    itemId: input.itemId ?? null,
    success: input.success,
    details,
  });
  const inserted = await tx
    .insert(auditEvents)
    .values({
      ts,
      actorUserId: input.actorUserId,
      action: input.action,
      vaultId: input.vaultId ?? null,
      itemId: input.itemId ?? null,
      success: input.success,
      details,
      prevHash,
      hash,
    })
    .returning({ id: auditEvents.id });
  return { id: inserted[0]!.id, hash };
}

/** 事务提交后调用：把已提交的链头写入库外锚点（单调递增，best-effort）。 */
export function recordAnchor(audit: AuditContext, head: AuditHead): void {
  audit.anchors.record(head.id, head.hash);
}

/** 独立事务写入一条审计（用于失败鉴权等非命令路径），提交后即锚定。 */
export async function auditStandalone(db: Db, audit: AuditContext, input: AuditInput): Promise<void> {
  const head = await db.transaction(async (tx) => appendAudit(tx, audit, input));
  recordAnchor(audit, head);
}
