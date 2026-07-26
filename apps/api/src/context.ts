import type pg from 'pg';
import type { MasterKeyProvider } from '@mima/crypto';
import type { Db } from './db/client.ts';
import type { SyncBus } from './services/bus.ts';
import type { AuthRuntime } from './auth/runtime.ts';
import type { AuditContext } from './services/audit.ts';

export interface AppContext {
  db: Db;
  pool: pg.Pool;
  runtimeKeys: MasterKeyProvider;
  legacyContentKeys?: MasterKeyProvider | null;
  audit: AuditContext;
  bus: SyncBus;
  auth: AuthRuntime;
  webOrigins: string[];
  /** 允许的扩展 Origin（chrome-extension://<id>），默认拒绝其余扩展。 */
  extensionOrigins: string[];
  e2eeRequired: boolean;
}
