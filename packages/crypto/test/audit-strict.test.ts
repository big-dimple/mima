import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditAnchorStore, loadAuditKey, resetAuditAnchor } from '../src/audit-chain.ts';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'mima-audit-strict-'));
}

describe('审计密钥严格化（S5）', () => {
  it('密钥缺失直接抛错（只允许 keys:init 创建，不静默生成）', () => {
    const dir = tmp();
    expect(() => loadAuditKey(dir)).toThrow(/keys:init/);
  });

  it('密钥存在且格式合法时正常加载', () => {
    const dir = tmp();
    writeFileSync(join(dir, 'audit-hmac.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    expect(loadAuditKey(dir).length).toBe(32);
  });

  it('密钥内容非法（非 64 hex）抛错', () => {
    const dir = tmp();
    writeFileSync(join(dir, 'audit-hmac.key'), 'not-a-key', { mode: 0o600 });
    expect(() => loadAuditKey(dir)).toThrow(/64 hex/);
  });
});

describe('审计锚点严格化（S5）', () => {
  it('原子写入：record 后可读回，重启（新实例）后仍在', () => {
    const dir = tmp();
    const store = new AuditAnchorStore(dir, 'db1');
    store.record(3, HASH_A);
    expect(store.read()).toMatchObject({ id: 3, hash: HASH_A });
    const reopened = new AuditAnchorStore(dir, 'db1');
    expect(reopened.read()).toMatchObject({ id: 3, hash: HASH_A });
    // 无残留临时文件
    expect(() => readFileSync(join(dir, 'audit-anchor-db1.json.tmp'))).toThrow();
  });

  it('锚点文件损坏（非法 JSON / 非法结构）在构造时抛错，不静默吞掉', () => {
    const dir = tmp();
    writeFileSync(join(dir, 'audit-anchor-db1.json'), '{broken', { mode: 0o600 });
    expect(() => new AuditAnchorStore(dir, 'db1')).toThrow(/corrupt/);

    const dir2 = tmp();
    writeFileSync(join(dir2, 'audit-anchor-db1.json'), JSON.stringify({ id: -1, hash: 'zz' }), { mode: 0o600 });
    expect(() => new AuditAnchorStore(dir2, 'db1')).toThrow(/corrupt/);
  });

  it('链头倒退（数据库被重建而锚点未清理）抛错；resetAuditAnchor 后恢复', () => {
    const dir = tmp();
    const store = new AuditAnchorStore(dir, 'db1');
    store.record(10, HASH_A);
    expect(() => store.record(2, HASH_B)).toThrow(/regression/);
    resetAuditAnchor(dir, 'db1');
    const fresh = new AuditAnchorStore(dir, 'db1');
    fresh.record(1, HASH_B);
    expect(fresh.read()).toMatchObject({ id: 1, hash: HASH_B });
  });

  it('同一链头重复 record 幂等；不同数据库锚点互不影响', () => {
    const dir = tmp();
    const a = new AuditAnchorStore(dir, 'db_a');
    const b = new AuditAnchorStore(dir, 'db_b');
    a.record(5, HASH_A);
    a.record(5, HASH_A);
    b.record(1, HASH_B);
    expect(a.read()).toMatchObject({ id: 5 });
    expect(b.read()).toMatchObject({ id: 1 });
  });
});
