// DEK rewrap：把所有内容版本的 wrapped DEK 迁移到当前活跃 KEK 版本。
// 密文本体不动（内容版本不可覆盖）；仅更新 wrapped_dek / key_version。
// 用法：pnpm keys:rewrap [--dry-run]
import { eq, ne } from 'drizzle-orm';
import { FileMasterKeyProvider, rewrapDek } from '@mima/crypto';
import { createDb, createPool } from '../db/client.ts';
import { itemSecretVersions } from '../db/schema.ts';
import { legacyEnv } from '../legacy-env.ts';

const dryRun = process.argv.includes('--dry-run');
if (!legacyEnv.legacyContentKeyDir) throw new Error('MIMA_LEGACY_CONTENT_KEY_DIR is required');
const keys = new FileMasterKeyProvider(legacyEnv.legacyContentKeyDir);
const active = keys.activeVersion();
const pool = createPool();
const db = createDb(pool);

try {
  const stale = await db
    .select()
    .from(itemSecretVersions)
    .where(ne(itemSecretVersions.keyVersion, active));
  console.log(`active KEK: ${active}; available: ${keys.listVersions().join(', ')}`);
  console.log(`${stale.length} secret version(s) wrapped with non-active KEK`);
  let done = 0;
  for (const row of stale) {
    const aad = {
      vaultId: row.vaultId,
      itemId: row.itemId,
      secretVersion: row.secretVersion,
      itemKind: row.itemKind,
    };
    if (dryRun) {
      console.log(`[dry-run] would rewrap item=${row.itemId} v${row.secretVersion} ${row.keyVersion} -> ${active}`);
      continue;
    }
    const wrapped = rewrapDek(keys, aad, row.wrappedDek, row.keyVersion, active);
    await db
      .update(itemSecretVersions)
      .set({ wrappedDek: wrapped, keyVersion: active })
      .where(eq(itemSecretVersions.id, row.id));
    done++;
  }
  console.log(dryRun ? 'dry-run complete, no changes written' : `rewrapped ${done} secret version(s)`);
} finally {
  await pool.end();
}
