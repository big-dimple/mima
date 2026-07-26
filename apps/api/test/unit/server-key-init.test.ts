import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const roots: string[] = [];
const initializer = join(process.cwd(), 'scripts/init-server-keys.mjs');

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('server key initializer', () => {
  it('copies an explicitly supplied audit key without changing its bytes', () => {
    const paths = keyPaths();
    const existingKey = randomBytes(32).toString('hex');
    writeFileSync(paths.existing, `${existingKey}\n`, { mode: 0o600 });

    const result = runInitializer(paths);

    expect(result.status).toBe(0);
    expect(readFileSync(paths.auditKey, 'utf8').trim()).toBe(existingKey);
    expect(statSync(paths.auditKey).mode & 0o777).toBe(0o600);
    expect(readFileSync(paths.runtimeKey, 'utf8').trim()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a different existing key instead of overwriting the audit directory', () => {
    const paths = keyPaths();
    const configuredKey = randomBytes(32).toString('hex');
    const differentKey = randomBytes(32).toString('hex');
    writeFileSync(paths.auditKey, `${configuredKey}\n`, { mode: 0o600 });
    writeFileSync(paths.existing, `${differentKey}\n`, { mode: 0o600 });

    const result = runInitializer(paths);

    expect(result.status).not.toBe(0);
    expect(readFileSync(paths.auditKey, 'utf8').trim()).toBe(configuredKey);
  });
});

function keyPaths() {
  const root = mkdtempSync(join(tmpdir(), 'mima-server-key-init-'));
  roots.push(root);
  const runtimeDir = join(root, 'runtime');
  const auditDir = join(root, 'audit');
  mkdirSync(runtimeDir);
  mkdirSync(auditDir);
  return {
    runtimeDir,
    auditDir,
    existing: join(root, 'existing-audit-hmac.key'),
    runtimeKey: join(runtimeDir, 'kek-v1.key'),
    auditKey: join(auditDir, 'audit-hmac.key'),
  };
}

function runInitializer(paths: ReturnType<typeof keyPaths>) {
  return spawnSync(process.execPath, [initializer], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MIMA_RUNTIME_KEY_DIR: paths.runtimeDir,
      MIMA_AUDIT_KEY_DIR: paths.auditDir,
      MIMA_EXISTING_AUDIT_KEY_FILE: paths.existing,
    },
    encoding: 'utf8',
  });
}
