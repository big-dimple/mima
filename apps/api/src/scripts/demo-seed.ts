import { DEV_USERS } from '../auth/provider.ts';
import { createDb, createPool } from '../db/client.ts';
import { runMigrations } from '../db/migrate.ts';
import { users } from '../db/schema.ts';

if (!process.env.MIMA_DEMO_MODE || process.env.MIMA_DEMO_MODE !== 'true') {
  throw new Error('demo seed requires MIMA_DEMO_MODE=true');
}

await runMigrations();
const pool = createPool();
try {
  const db = createDb(pool);
  for (const user of DEV_USERS) {
    await db.insert(users).values(user).onConflictDoUpdate({
      target: users.id,
      set: {
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        groups: user.groups,
        source: user.source,
        active: user.active,
        updatedAt: new Date(),
      },
    });
  }
  console.log(`demo users ready: ${DEV_USERS.map((user) => user.username).join(', ')}`);
} finally {
  await pool.end();
}
