import { createHmac } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { dirname, join } from 'node:path';

/** 审计链首条记录的 prev_hash。 */
export const AUDIT_CHAIN_GENESIS = 'genesis';

export interface AuditHashInput {
  ts: string;
  actorUserId: string | null;
  action: string;
  vaultId: string | null;
  itemId: string | null;
  success: boolean;
  details: unknown;
}

/** 键序稳定的 JSON，保证同一事件在校验时得到相同哈希。 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/**
 * 审计链哈希 = HMAC-SHA256(auditKey, prev_hash + "\n" + canonicalJson(event))。
 * 密钥独立于 KEK，存放在数据库之外；仅持有数据库的攻击者无法重算合法链。
 */
export function computeAuditHash(key: Buffer, prevHash: string, input: AuditHashInput): string {
  return createHmac('sha256', key)
    .update(prevHash)
    .update('\n')
    .update(canonicalJson(input))
    .digest('hex');
}

const AUDIT_KEY_FILE = 'audit-hmac.key';

/**
 * 读取审计 HMAC 密钥：<dir>/audit-hmac.key（64 hex，0600）。
 * 密钥只允许由 `pnpm keys:init` 创建——运行时与校验器缺钥即失败，
 * 绝不静默生成新密钥（那会让已有链在换钥后全部"校验失败"却查不出原因）。
 */
export function loadAuditKey(dir: string): Buffer {
  const path = join(dir, AUDIT_KEY_FILE);
  if (!existsSync(path)) {
    throw new Error(`audit HMAC key missing: ${path}（请先运行 pnpm keys:init）`);
  }
  const hex = readFileSync(path, 'utf8').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`${path} must contain exactly 64 hex characters`);
  }
  return Buffer.from(hex, 'hex');
}

export interface AuditAnchor {
  id: number;
  hash: string;
  ts: string;
}

function anchorPath(dir: string, dbName: string): string {
  return join(dir, `audit-anchor-${dbName.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`);
}

/**
 * 删除某个数据库的锚点文件。仅供测试基建在 DROP/重建该数据库时调用
 * （链从头重建，旧锚点必然"落后于现实"，保留会让新链永远无法锚定）。
 */
export function resetAuditAnchor(dir: string, dbName: string): void {
  rmSync(anchorPath(dir, dbName), { force: true });
}

/**
 * 审计锚点：最近一次已提交审计记录的 (id, hash)，保存在数据库之外（默认与密钥同目录）。
 * 锚点按数据库命名（audit-anchor-<db>.json）——同一密钥目录服务多个库（开发/测试）时互不污染。
 * 校验要求：锚点存在（链非空时）、可解析、记录仍在链上且哈希一致、且不落后于链头。
 * 写入使用临时文件 + fsync + 原子 rename；任何失败都向上抛出，不静默吞错。
 */
export class AuditAnchorStore {
  private path: string;
  private current: AuditAnchor | null = null;

  constructor(dir: string, dbName = 'default') {
    this.path = anchorPath(dir, dbName);
    if (existsSync(this.path)) {
      const raw = readFileSync(this.path, 'utf8');
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new Error(`audit anchor corrupt (invalid JSON): ${this.path}`);
      }
      const a = parsed as Partial<AuditAnchor>;
      if (
        typeof a !== 'object' || a === null ||
        !Number.isInteger(a.id) || (a.id as number) <= 0 ||
        typeof a.hash !== 'string' || !/^[0-9a-f]{64}$/.test(a.hash)
      ) {
        throw new Error(`audit anchor corrupt (invalid shape): ${this.path}`);
      }
      this.current = { id: a.id as number, hash: a.hash, ts: typeof a.ts === 'string' ? a.ts : '' };
    }
  }

  read(): AuditAnchor | null {
    return this.current;
  }

  /**
   * 记录新链头。锚点单调递增：链头倒退（id 变小）说明数据库被重建而锚点未清理，
   * 或者链被截断——这不是可忽略的状态，直接抛错。
   */
  record(id: number, hash: string): void {
    if (this.current && this.current.id > id) {
      throw new Error(
        `audit anchor regression: on-disk anchor #${this.current.id} > new head #${id} ` +
        `(${this.path}；数据库被重建时必须同时清理锚点)`
      );
    }
    if (this.current && this.current.id === id) return; // 幂等重放
    const next: AuditAnchor = { id, hash, ts: new Date().toISOString() };
    const tmp = `${this.path}.tmp`;
    // 临时文件 + fsync + 原子 rename：崩溃后要么是旧锚点、要么是新锚点，绝无半截文件
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, JSON.stringify(next));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
    // 目录 fsync：确保 rename 本身持久化（部分文件系统上崩溃可能丢 rename）
    try {
      const dirFd = openSync(dirname(this.path), 'r');
      try {
        fsyncSync(dirFd);
      } finally {
        closeSync(dirFd);
      }
    } catch {
      // 目录不可 fsync 的平台（极少数）：rename 已完成，锚点内容本身已 fsync
    }
    this.current = next;
  }
}
