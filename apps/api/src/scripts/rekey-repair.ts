import { AuditAnchorStore, loadAuditKey } from '@mima/crypto';
import { createDb, createPool } from '../db/client.ts';
import { env } from '../env.ts';
import { recordAnchor, verifyAuditChain } from '../services/audit.ts';
import {
  cancelNoopMembershipRekey,
  inspectNoopMembershipRekey,
  listActiveMembershipRekeys,
  NoopRekeyRepairError,
} from '../services/rekey-repair.ts';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const [action, taskId] = process.argv.slice(2);
if (
  (action === 'list' && taskId !== undefined) ||
  ((action === 'inspect' || action === 'cancel-noop') && (!taskId || !UUID_PATTERN.test(taskId))) ||
  (action !== 'list' && action !== 'inspect' && action !== 'cancel-noop')
) {
  throw new Error('usage: rekey-repair list | rekey-repair <inspect|cancel-noop> <task-id>');
}

const pool = createPool();
const db = createDb(pool);
const databaseName = new URL(env.databaseUrl).pathname.replace(/^\//, '') || 'default';
const audit = {
  hmacKey: loadAuditKey(env.auditKeyDir),
  anchors: new AuditAnchorStore(env.auditKeyDir, databaseName),
};

try {
  await verifyAuditChain(db, audit);
  if (action === 'list') {
    const tasks = await db.transaction((tx) => listActiveMembershipRekeys(tx));
    console.log(JSON.stringify({ ok: true, action, count: tasks.length, tasks }));
  } else if (action === 'inspect') {
    const proof = await db.transaction((tx) => inspectNoopMembershipRekey(tx, taskId!));
    console.log(JSON.stringify({ ok: true, action, ...proof }));
  } else {
    const result = await cancelNoopMembershipRekey(db, audit, taskId!);
    recordAnchor(audit, result.auditHead);
    const verified = await verifyAuditChain(db, audit);
    console.log(JSON.stringify({
      ok: true,
      action,
      ...result.proof,
      auditHeadId: verified.headId,
      auditRecordCount: verified.recordCount,
    }));
  }
} catch (error) {
  if (error instanceof NoopRekeyRepairError) {
    console.error(JSON.stringify({ ok: false, code: error.code }));
    process.exitCode = 1;
  } else {
    throw error;
  }
} finally {
  await pool.end();
}
