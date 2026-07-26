import { sql } from 'drizzle-orm';
import type { DbOrTx } from './audit.ts';

export async function lockEnterpriseRecoveryCoverage(db: DbOrTx): Promise<void> {
  await db.execute(sql`
    SELECT pg_advisory_xact_lock(
      hashtextextended(current_database() || ':mima:enterprise-recovery-coverage', 0)
    )
  `);
}

export async function lockRecipientSets(db: DbOrTx, userIds: Iterable<string>): Promise<void> {
  const orderedUserIds = [...new Set(userIds)].sort((left, right) => left.localeCompare(right));
  for (const userId of orderedUserIds) {
    await db.execute(sql`
      SELECT pg_advisory_xact_lock(
        hashtextextended(
          current_database() || ':mima:recipient-set:' || ${userId},
          0
        )
      )
    `);
  }
}
