import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pg from 'pg';
import { env } from '../env.ts';

export async function runMigrations(databaseUrl = env.databaseUrl): Promise<void> {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const directory = [moduleDirectory, join(moduleDirectory, 'db')]
    .find((candidate) => existsSync(join(candidate, 'schema.sql')));
  if (!directory) throw new Error('database migration files are missing');
  const migrations = [
    { id: '0001_base_schema', path: join(directory, 'schema.sql') },
    ...readdirSync(join(directory, 'migrations'))
      .filter((name) => /^\d+_[a-z0-9_]+\.sql$/.test(name))
      .sort()
      .map((name) => ({ id: name.replace(/\.sql$/, ''), path: join(directory, 'migrations', name) })),
  ];
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await client.query("SELECT pg_advisory_lock(hashtext('mima:migrations'))");
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    for (const migration of migrations) {
      const sql = readFileSync(migration.path, 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const existing = await client.query<{ checksum: string }>(
        'SELECT checksum FROM schema_migrations WHERE id = $1',
        [migration.id],
      );
      if (existing.rows[0]) {
        if (existing.rows[0].checksum !== checksum) {
          throw new Error(`migration checksum mismatch: ${migration.id}`);
        }
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query(
          'INSERT INTO schema_migrations (id, checksum) VALUES ($1, $2)',
          [migration.id, checksum],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock(hashtext('mima:migrations'))").catch(() => undefined);
    await client.end();
  }
}

if (process.argv[1] && /migrate\.(?:ts|js)$/.test(process.argv[1])) {
  runMigrations()
    .then(() => {
      console.log('migrations applied');
      process.exit(0);
    })
    .catch((error) => {
      const errorName = error instanceof Error ? error.name : 'Error';
      const errorCode = typeof error === 'object' && error !== null && 'code' in error
        && typeof error.code === 'string' && /^[0-9A-Z]{5}$/.test(error.code)
        ? ` code=${error.code}`
        : '';
      console.error(`database migration failed (${errorName}${errorCode})`);
      process.exit(1);
    });
}
