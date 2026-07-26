import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dbDirectory = join(root, 'apps', 'api', 'src', 'db');
const lock = JSON.parse(readFileSync(join(dbDirectory, 'migration-lock.json'), 'utf8'));
if (lock.version !== 1 || !Array.isArray(lock.migrations)) throw new Error('invalid migration lock format');

const actualFiles = [
  'schema.sql',
  ...readdirSync(join(dbDirectory, 'migrations'))
    .filter((name) => /^\d+_[a-z0-9_]+\.sql$/.test(name))
    .sort()
    .map((name) => `migrations/${name}`),
];
const lockedFiles = lock.migrations.map((entry) => entry.file);
if (JSON.stringify(actualFiles) !== JSON.stringify(lockedFiles)) {
  throw new Error('migration file set or order differs from migration-lock.json');
}

for (const entry of lock.migrations) {
  const expectedId = entry.file === 'schema.sql'
    ? '0001_base_schema'
    : entry.file.split('/').at(-1).replace(/\.sql$/, '');
  if (entry.id !== expectedId) throw new Error(`migration id mismatch: ${entry.file}`);
  const digest = createHash('sha256').update(readFileSync(join(dbDirectory, entry.file))).digest('hex');
  if (digest !== entry.sha256) throw new Error(`migration checksum mismatch: ${entry.id}`);
}

console.log(`migration lock verified: ${lock.migrations.length} files, head ${lock.migrations.at(-1).id}`);
