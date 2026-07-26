import { createHash } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { authAttempts } from '../db/schema.ts';

interface AttemptPolicy {
  suffix: string;
  durationMs: number;
  limit: number;
}

const POLICIES: AttemptPolicy[] = [
  { suffix: 'minute', durationMs: 60_000, limit: 5 },
  { suffix: 'hour', durationMs: 60 * 60_000, limit: 20 },
];

export class CredentialAttemptLimiter {
  constructor(private readonly db: Db) {}

  async retryAfterSeconds(key: string, now = new Date()): Promise<number> {
    const keyHash = hashKey(key);
    const rows = await this.db
      .select()
      .from(authAttempts)
      .where(eq(authAttempts.keyHash, keyHash));
    let retryAfter = 0;
    for (const row of rows) {
      if (!row.blockedUntil || row.blockedUntil <= now) continue;
      retryAfter = Math.max(retryAfter, Math.ceil((row.blockedUntil.getTime() - now.getTime()) / 1000));
    }
    return retryAfter;
  }

  async recordFailure(key: string, now = new Date()): Promise<void> {
    const keyHash = hashKey(key);
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`auth-attempt:${keyHash}`}))`);
      for (const policy of POLICIES) {
        const scope = `credential:${policy.suffix}`;
        const current = (
          await tx
            .select()
            .from(authAttempts)
            .where(and(eq(authAttempts.scope, scope), eq(authAttempts.keyHash, keyHash)))
            .for('update')
            .limit(1)
        )[0];
        const expired = !current || current.windowExpiresAt <= now;
        const failureCount = expired ? 1 : current.failureCount + 1;
        const windowStartedAt = expired ? now : current.windowStartedAt;
        const windowExpiresAt = expired
          ? new Date(now.getTime() + policy.durationMs)
          : current.windowExpiresAt;
        const blockedUntil = failureCount >= policy.limit ? windowExpiresAt : null;
        await tx.insert(authAttempts).values({
          scope,
          keyHash,
          windowStartedAt,
          windowExpiresAt,
          failureCount,
          blockedUntil,
          lastAttemptAt: now,
          updatedAt: now,
        }).onConflictDoUpdate({
          target: [authAttempts.scope, authAttempts.keyHash],
          set: {
            windowStartedAt,
            windowExpiresAt,
            failureCount,
            blockedUntil,
            lastAttemptAt: now,
            updatedAt: now,
          },
        });
      }
    });
  }

  async clear(key: string): Promise<void> {
    await this.db.delete(authAttempts).where(eq(authAttempts.keyHash, hashKey(key)));
  }
}

function hashKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}
