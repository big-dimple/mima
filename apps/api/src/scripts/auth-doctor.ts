import { accessSync, constants } from 'node:fs';
import { sql } from 'drizzle-orm';
import { env } from '../env.ts';
import { createDb, createPool } from '../db/client.ts';
import { LdapConnector } from '../auth/ldap.ts';
import { ldapOptionsFromEnv } from '../auth/ldap-config.ts';
import { readPrivateFile } from '../auth/secrets.ts';

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

const checks: Check[] = [];

async function main(): Promise<void> {
  check('provider configuration', () => {
    if (env.loginProvider === 'feishu') {
      required(env.feishu.appId, 'Feishu app id');
      required(env.feishu.tenantKey, 'Feishu tenant key');
      readPrivateFile(required(env.feishu.appSecretFile, 'Feishu app secret file'), 'Feishu app secret file');
      const redirect = new URL(required(env.feishu.redirectUri, 'Feishu redirect URI'));
      if (redirect.origin !== new URL(env.publicBaseUrl).origin) throw new Error('Feishu callback origin mismatch');
    }
    if (env.loginProvider === 'oidc' || env.reauthProvider === 'oidc') {
      required(env.oidc.issuer, 'OIDC issuer');
      required(env.oidc.clientId, 'OIDC client id');
      readPrivateFile(required(env.oidc.clientSecretFile, 'OIDC client secret file'), 'OIDC client secret file');
    }
  });

  const pool = createPool();
  try {
    const db = createDb(pool);
    await db.execute(sql`SELECT 1`);
    const migrations = await db.execute(sql`SELECT count(*)::text AS count FROM schema_migrations`);
    checks.push({
      name: 'database',
      ok: true,
      detail: `${String(migrations.rows[0]?.count ?? '0')} migration(s) recorded`,
    });
  } catch (error) {
    checks.push({ name: 'database', ok: false, detail: message(error) });
  } finally {
    await pool.end();
  }

  if (
    env.loginProvider === 'ldap' ||
    env.reauthProvider === 'ldap' ||
    env.directoryProvider === 'ldap'
  ) {
    try {
      const connector = new LdapConnector(ldapOptionsFromEnv());
      const result = await connector.probe();
      checks.push({
        name: 'ldap',
        ok: true,
        detail: `${new URL(result.url).hostname}: TLS verified; directory search succeeded`,
      });
    } catch (error) {
      checks.push({ name: 'ldap', ok: false, detail: message(error) });
    }
  }

  check('callback security', () => {
    if (env.loginProvider !== 'dev' && new URL(env.publicBaseUrl).protocol !== 'https:') {
      throw new Error('public base URL must use HTTPS');
    }
    if (env.ldap.caFile) accessSync(env.ldap.caFile, constants.R_OK);
  });

  console.log(JSON.stringify({
    ok: checks.every((item) => item.ok),
    providers: {
      login: env.loginProvider,
      reauth: env.reauthProvider,
      directory: env.directoryProvider,
    },
    checks,
  }, null, 2));
  if (checks.some((item) => !item.ok)) process.exitCode = 1;
}

function check(name: string, run: () => void): void {
  try {
    run();
    checks.push({ name, ok: true, detail: 'ok' });
  } catch (error) {
    checks.push({ name, ok: false, detail: message(error) });
  }
}

function required(value: string | undefined, label: string): string {
  if (!value) throw new Error(`${label} is missing`);
  return value;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : 'check failed';
}

await main();
