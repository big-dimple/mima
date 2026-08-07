import { AuditAnchorStore, loadAuditKey } from '@mima/crypto';
import { and, eq, sql } from 'drizzle-orm';
import { env } from '../env.ts';
import { createDb, createPool } from '../db/client.ts';
import { enterpriseRecoveryKeys, systemRoleAssignments, users } from '../db/schema.ts';
import { appendAudit, recordAnchor } from '../services/audit.ts';

const argumentsList = process.argv.slice(2);
if (argumentsList[0] === '--') argumentsList.shift();
const [action, username] = argumentsList;
if (
  (action === 'list' && argumentsList.length !== 1)
  || ((action === 'grant' || action === 'revoke') && argumentsList.length !== 2)
  || (action !== 'list' && action !== 'grant' && action !== 'revoke')
) {
  throw new Error('usage: system-role list | system-role <grant|revoke> <username>');
}

const pool = createPool();
try {
  const db = createDb(pool);
  if (action === 'list') {
    const assignments = await db
      .select({
        username: users.username,
        displayName: users.displayName,
        source: users.source,
        active: users.active,
        assignedAt: systemRoleAssignments.createdAt,
      })
      .from(systemRoleAssignments)
      .innerJoin(users, eq(users.id, systemRoleAssignments.userId))
      .where(eq(systemRoleAssignments.role, 'platform-admin'))
      .orderBy(sql`lower(${users.username})`);
    if (assignments.length === 0) {
      console.log('no local platform-admin assignments');
    } else {
      console.log('USERNAME\tDISPLAY_NAME\tSOURCE\tSTATUS\tASSIGNED_AT');
      for (const assignment of assignments) {
        console.log([
          assignment.username,
          assignment.displayName,
          assignment.source,
          assignment.active ? 'active' : 'inactive',
          assignment.assignedAt.toISOString(),
        ].join('\t'));
      }
    }
  } else {
    if (!username) throw new Error('usage: system-role <grant|revoke> <username>');
    const user = (
      await db
        .select()
        .from(users)
        .where(and(sql`lower(${users.username}) = lower(${username})`, eq(users.active, true)))
        .limit(1)
    )[0];
    if (!user) throw new Error('active user not found');
    const dbName = new URL(env.databaseUrl).pathname.replace(/^\//, '') || 'default';
    const audit = {
      hmacKey: loadAuditKey(env.auditKeyDir),
      anchors: new AuditAnchorStore(env.auditKeyDir, dbName),
    };
    const head = await db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('mima:platform-admin'))`);
      const currentAssignments = await tx.select({ userId: systemRoleAssignments.userId })
        .from(systemRoleAssignments)
        .where(eq(systemRoleAssignments.role, 'platform-admin'))
        .for('update');
      const alreadyAssigned = currentAssignments.some((entry) => entry.userId === user.id);
      if (action === 'grant' && !alreadyAssigned && currentAssignments.length >= 6) {
        throw new Error('企业恢复管理员最多只能设置 6 位；请先撤销一位不再参与的管理员');
      }
      if (action === 'revoke' && alreadyAssigned && currentAssignments.length <= 2) {
        const activeRecovery = (await tx.select({ id: enterpriseRecoveryKeys.id })
          .from(enterpriseRecoveryKeys)
          .where(eq(enterpriseRecoveryKeys.status, 'active'))
          .limit(1))[0];
        if (activeRecovery) {
          throw new Error('企业恢复启用后必须至少保留 2 位管理员；请先添加替代管理员');
        }
      }
      let changed: Array<{ userId: string }>;
      if (action === 'grant') {
        changed = await tx
          .insert(systemRoleAssignments)
          .values({ userId: user.id, role: 'platform-admin', assignedBy: 'cli' })
          .onConflictDoNothing()
          .returning({ userId: systemRoleAssignments.userId });
      } else {
        changed = await tx
          .delete(systemRoleAssignments)
          .where(and(
            eq(systemRoleAssignments.userId, user.id),
            eq(systemRoleAssignments.role, 'platform-admin'),
          ))
          .returning({ userId: systemRoleAssignments.userId });
      }
      if (!changed[0]) return null;
      return appendAudit(tx, audit, {
        actorUserId: null,
        action: `system_role.${action}`,
        success: true,
        details: { username: user.username, role: 'platform-admin', source: 'cli' },
      });
    });
    if (head) recordAnchor(audit, head);
    console.log(`${head ? action === 'grant' ? 'granted' : 'revoked' : 'unchanged'} platform-admin: ${user.username}`);
  }
} finally {
  await pool.end();
}
