import { AuditAnchorStore, loadAuditKey } from '@mima/crypto';
import { createDb, createPool } from '../db/client.ts';
import { env } from '../env.ts';
import { repairAuditAnchor } from '../services/audit.ts';

if (process.argv[2] !== 'advance-verified-prefix') {
  throw new Error('usage: repair-audit-anchor advance-verified-prefix');
}

const pool = createPool();
const db = createDb(pool);
const databaseName = new URL(env.databaseUrl).pathname.replace(/^\//, '') || 'default';
const audit = {
  hmacKey: loadAuditKey(env.auditKeyDir),
  anchors: new AuditAnchorStore(env.auditKeyDir, databaseName),
};

try {
  const result = await repairAuditAnchor(db, audit);
  console.log(JSON.stringify({
    ok: true,
    status: result.status,
    recordCount: result.recordCount,
    previousAnchorId: result.anchorId,
    repairedAnchorId: result.headId,
  }));
} finally {
  await pool.end();
}
