// Create a development KEK (key-encryption key) file if none exists.
// Location: $MIMA_MASTER_KEY_DIR or $HOME/.local/share/mima/master-keys/
// Files are named kek-v<N>.key, contain 64 hex chars (32 bytes), mode 0600.
import { randomBytes } from 'node:crypto';
import { mkdirSync, readdirSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';

const dir =
  process.env.MIMA_MASTER_KEY_DIR ??
  join(os.homedir(), '.local', 'share', 'mima', 'master-keys');

mkdirSync(dir, { recursive: true, mode: 0o700 });

// 审计 HMAC 密钥（独立于 KEK；只创建一次，轮换 KEK 不影响审计链）
const auditKeyFile = join(dir, 'audit-hmac.key');
if (!existsSync(auditKeyFile)) {
  writeFileSync(auditKeyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
  chmodSync(auditKeyFile, 0o600);
  console.log(`created ${auditKeyFile} (audit HMAC key)`);
}

const rotate = process.argv.includes('--rotate');
const existing = existsSync(dir)
  ? readdirSync(dir)
      .map((f) => /^kek-v(\d+)\.key$/.exec(f))
      .filter(Boolean)
      .map((m) => Number(m[1]))
      .sort((a, b) => a - b)
  : [];

if (existing.length > 0 && !rotate) {
  console.log(`master key already present: kek-v${existing.at(-1)}.key in ${dir}`);
  console.log('use --rotate to add a new key version');
  process.exit(0);
}

const version = (existing.at(-1) ?? 0) + 1;
const file = join(dir, `kek-v${version}.key`);
writeFileSync(file, randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
chmodSync(file, 0o600);
console.log(`created ${file} (AES-256 KEK, version ${version})`);
