import { and, eq } from 'drizzle-orm';
import { systemRoleAssignments } from '../db/schema.ts';
import type { DbOrTx } from './audit.ts';

export async function hasLocalPlatformAdminRole(db: DbOrTx, userId: string): Promise<boolean> {
  const row = (
    await db
      .select({ userId: systemRoleAssignments.userId })
      .from(systemRoleAssignments)
      .where(and(
        eq(systemRoleAssignments.userId, userId),
        eq(systemRoleAssignments.role, 'platform-admin'),
      ))
      .limit(1)
  )[0];
  return Boolean(row);
}
