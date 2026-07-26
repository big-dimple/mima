import { env } from '../env.ts';
import { createPoolForUrl } from './factory.ts';
export { createDb, schema, type Db } from './factory.ts';

export function createPool(databaseUrl = env.databaseUrl) {
  return createPoolForUrl(databaseUrl);
}
