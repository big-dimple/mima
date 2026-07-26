import { createDb, createPool } from '../db/client.ts';
import { runMigrations } from '../db/migrate.ts';
import { LdapConnector, LdapDirectoryService } from '../auth/ldap.ts';
import { ldapOptionsFromEnv } from '../auth/ldap-config.ts';

const apply = process.argv.includes('--apply');

await runMigrations();
const pool = createPool();
try {
  const service = new LdapDirectoryService(
    createDb(pool),
    new LdapConnector(ldapOptionsFromEnv()),
  );
  const report = await service.sync(true, !apply);
  console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', ...report }, null, 2));
} finally {
  await pool.end();
}
