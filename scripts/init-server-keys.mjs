import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const runtimeDir = process.env.MIMA_RUNTIME_KEY_DIR;
const auditDir = process.env.MIMA_AUDIT_KEY_DIR;
const existingAuditKeyFile = process.env.MIMA_EXISTING_AUDIT_KEY_FILE;

if (!runtimeDir || !auditDir) {
  throw new Error('MIMA_RUNTIME_KEY_DIR and MIMA_AUDIT_KEY_DIR are required');
}
if (runtimeDir === auditDir) {
  throw new Error('runtime and audit key directories must be different');
}

for (const directory of [runtimeDir, auditDir]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
}

const runtimeVersions = readdirSync(runtimeDir)
  .map((name) => /^kek-v(\d+)\.key$/.exec(name))
  .filter(Boolean)
  .map((match) => Number(match[1]))
  .sort((left, right) => left - right);
if (runtimeVersions.length === 0) {
  const runtimeKey = join(runtimeDir, 'kek-v1.key');
  writeFileSync(runtimeKey, `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
  chmodSync(runtimeKey, 0o600);
  console.log(`created ${runtimeKey} (server runtime state key)`);
}

const auditKey = join(auditDir, 'audit-hmac.key');
if (existsSync(auditKey)) {
  const currentKey = readAuditKey(auditKey);
  if (existingAuditKeyFile && currentKey !== readAuditKey(existingAuditKeyFile)) {
    throw new Error('existing audit HMAC key does not match the configured audit key directory');
  }
} else if (existingAuditKeyFile) {
  const existingKey = readAuditKey(existingAuditKeyFile);
  writeFileSync(auditKey, `${existingKey}\n`, { mode: 0o600 });
  chmodSync(auditKey, 0o600);
  console.log(`created ${auditKey} from the explicitly supplied existing audit chain key`);
} else {
  writeFileSync(auditKey, randomBytes(32).toString('hex'), { mode: 0o600 });
  chmodSync(auditKey, 0o600);
  console.log(`created ${auditKey} (audit chain key)`);
}

function readAuditKey(path) {
  if (!existsSync(path) || !lstatSync(path).isFile()) {
    throw new Error('existing audit HMAC key must be a regular file');
  }
  const key = readFileSync(path, 'utf8').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error('existing audit HMAC key must contain exactly 64 hex characters');
  }
  return key.toLowerCase();
}
