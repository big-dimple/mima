import os from 'node:os';
import { join } from 'node:path';

function optional(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value || undefined;
}

const masterKeyDir = optional('MIMA_MASTER_KEY_DIR')
  ?? join(os.homedir(), '.local', 'share', 'mima', 'master-keys');

export const legacyEnv = {
  masterKeyDir,
  legacyContentKeyDir: optional('MIMA_LEGACY_CONTENT_KEY_DIR'),
};
