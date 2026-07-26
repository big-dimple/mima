// 校验审计日志 HMAC 链的完整性（独立密钥 + 数据库外锚点）。
// 任何插入/篡改/删除都会导致校验失败；截断到旧前缀会被锚点检测到。
// 严格模式：密钥缺失、锚点缺失（链非空时）、锚点损坏、锚点落后于链头均判失败。
// 用法：pnpm audit:verify
import {
  AuditAnchorStore,
  loadAuditKey,
} from '@mima/crypto';
import { createDb, createPool } from '../db/client.ts';
import { env } from '../env.ts';
import { AuditChainVerificationError, verifyAuditChain } from '../services/audit.ts';

const pool = createPool();
const db = createDb(pool);
// 缺钥即抛错退出：审计密钥只允许 keys:init 创建
const hmacKey = loadAuditKey(env.auditKeyDir);
const dbName = new URL(env.databaseUrl).pathname.replace(/^\//, '') || 'default';
// 锚点文件损坏（JSON/结构非法）会在构造时直接抛错
const anchors = new AuditAnchorStore(env.auditKeyDir, dbName);

try {
  const result = await verifyAuditChain(db, { hmacKey, anchors });
  const anchorInfo = result.anchorId === null
    ? '; empty chain, no anchor required'
    : `; anchor at #${result.anchorId} confirmed`;
  console.log(`✓ audit chain intact: ${result.recordCount} record(s) verified${anchorInfo}`);
} catch (error) {
  if (error instanceof AuditChainVerificationError) {
    console.error(`✗ audit chain verification failed: ${error.code}`);
  } else {
    console.error('✗ audit chain verification could not complete');
  }
  process.exitCode = 1;
} finally {
  await pool.end();
}
