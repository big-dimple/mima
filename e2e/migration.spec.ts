import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { expect, test } from '@playwright/test';
import pg from 'pg';
import {
  provisionMigrationDatabaseRole,
  revokeMigrationDatabaseRole,
} from '../apps/api/src/scripts/provision-migration-role.ts';
import { loginAndUnlock } from './helpers.ts';

const execFileAsync = promisify(execFile);
const DATABASE_URL = process.env.MIMA_E2E_DATABASE_URL
  ?? 'postgres://mima:mima_dev_pw@127.0.0.1:55432/mima_test_e2e';
const FIXTURE_ROOT = '/tmp/mima-e2e-strict';
const LEGACY_TITLE = 'E2E 旧数据迁移样本';
const LEGACY_USERNAME = 'legacy-e2e-user';
const LEGACY_ORIGIN = 'https://legacy-e2e.example.test';
const LEGACY_PASSWORD = 'e2e-legacy-secret-canary-001';

test.describe.serial('旧格式密码库零知识迁移', () => {
  test('冻结、回滚演练、隔离导出、本地重加密和切换全链路', async ({ page, browser }) => {
    const recipientContext = await browser.newContext();
    try {
      await loginAndUnlock(await recipientContext.newPage(), 'carol');
    } finally {
      await recipientContext.close();
    }
    await loginAndUnlock(page, 'erin', { expectWorkspace: false });
    await expect(page.getByRole('heading', { name: '正在准备工作台' })).toBeVisible({ timeout: 30_000 });
    const vaultIds = await loadErinVaultIds();

    const migration = migrationRow(page, vaultIds.legacy);
    await expect(migration.getByText('尚未开始')).toBeVisible();

    await migration.getByRole('button', { name: '冻结并开始迁移' }).click();
    await expect(migration.getByText('等待隔离迁移程序')).toBeVisible({ timeout: 15_000 });
    const rolledBackJobId = await migration.locator('code').innerText();
    await migration.getByRole('button', { name: '回滚本次迁移' }).click();
    await expect(migration.getByText('尚未开始')).toBeVisible({ timeout: 15_000 });
    await expectRollbackEvidence(rolledBackJobId);

    await migration.getByRole('button', { name: '冻结并开始迁移' }).click();
    await expect(migration.getByText('等待隔离迁移程序')).toBeVisible({ timeout: 15_000 });
    const jobId = await migration.locator('code').innerText();
    expect(jobId).not.toBe(rolledBackJobId);

    const roleBase = 'mima_e2e_migration';
    const password = randomBytes(32).toString('hex');
    const provisioned = await provisionMigrationDatabaseRole({
      databaseUrl: DATABASE_URL,
      role: roleBase,
      password,
      jobId,
    });
    const workerUrl = new URL(DATABASE_URL);
    workerUrl.username = provisioned.role;
    workerUrl.password = password;
    writeFileSync(`${FIXTURE_ROOT}/migration-database-url`, `${workerUrl.toString()}\n`, { mode: 0o600 });
    let worker;
    try {
      worker = await execFileAsync(
        'pnpm',
        ['--filter', '@mima/api', 'exec', 'tsx', 'src/scripts/legacy-migration-worker.ts', '--job', jobId],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            MIMA_MIGRATION_DATABASE_URL_FILE: `${FIXTURE_ROOT}/migration-database-url`,
            MIMA_MIGRATION_DATABASE_ROLE: provisioned.role,
            MIMA_LEGACY_CONTENT_KEY_DIR: `${FIXTURE_ROOT}/legacy-content-keys`,
          },
          timeout: 30_000,
        },
      );
    } finally {
      await revokeMigrationDatabaseRole({ databaseUrl: DATABASE_URL, role: roleBase, jobId });
      rmSync(`${FIXTURE_ROOT}/migration-database-url`, { force: true });
    }
    const workerResult = JSON.parse(worker.stdout.trim()) as {
      jobId: string;
      sourceDigest: string;
      sealedExportDigest: string;
    };
    expect(workerResult.jobId).toBe(jobId);
    expect(workerResult.sourceDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(workerResult.sealedExportDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);

    await migration.getByRole('button', { name: '刷新状态' }).click();
    await expect(migration.getByText('等待浏览器加密')).toBeVisible({ timeout: 15_000 });
    await migration.getByRole('button', { name: '领取并本地转换' }).click();
    const verifyButton = migration.getByRole('button', { name: '核对记录与接收人' });
    const conversionError = page.getByRole('alert').last();
    await expect(verifyButton.or(conversionError)).toBeVisible({ timeout: 30_000 });
    if (await conversionError.isVisible()) {
      throw new Error(`浏览器本地转换失败：${await conversionError.innerText()}`);
    }
    await verifyButton.click();
    await expect(migration.getByText('核对完成，等待切换')).toBeVisible({ timeout: 15_000 });

    await setConcurrentMember(vaultIds.legacy, true);
    let rejectedCutoverStatus = 0;
    let cutoverRequest: { url: string; body: string; csrf: string } | null = null;
    const cutoverPath = `**/api/v2/vaults/${vaultIds.legacy}/migration/cutover`;
    const rollbackPath = `**/api/v2/vaults/${vaultIds.legacy}/migration/rollback`;
    await page.route(cutoverPath, async (route) => {
      const request = route.request();
      const response = await route.fetch();
      rejectedCutoverStatus = response.status();
      cutoverRequest = {
        url: request.url(),
        body: request.postData() ?? '',
        csrf: (await request.headerValue('x-mima-csrf')) ?? '',
      };
      await route.fulfill({ response });
    });
    await page.route(rollbackPath, (route) => route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ statusCode: 503, error: 'Service Unavailable', message: 'E2E 保留 verifying 状态' }),
    }));
    await migration.getByRole('button', { name: '切换到零知识密文' }).click();
    await expect(page.getByRole('alert').last()).toContainText(/迁移覆盖不完整|服务器可能仍处于冻结状态/);
    expect(rejectedCutoverStatus).toBe(409);
    expect(cutoverRequest).not.toBeNull();
    await expectVerifyingDatabaseState(jobId);

    await page.unroute(cutoverPath);
    await page.unroute(rollbackPath);
    await setConcurrentMember(vaultIds.legacy, false);
    const replay = cutoverRequest!;
    const cutoverResponse = await page.evaluate(async (request) => {
      const response = await fetch(request.url, {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json', 'x-mima-csrf': request.csrf },
        body: request.body,
      });
      return { status: response.status, body: await response.text() };
    }, replay);
    expect(cutoverResponse.status, cutoverResponse.body).toBe(200);

    await page.reload();
    await expect(page.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await page.locator('#main-password').fill('Erin-e2e-main-password-2026');
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await expect(page.getByRole('navigation', { name: '库导航' })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole('button', { name: 'E2E 旧格式密码库', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'E2E 旧格式密码库', exact: true }).click();
    await page.getByRole('option', { name: new RegExp(LEGACY_TITLE) }).click();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText(LEGACY_PASSWORD, { exact: true })).toBeVisible();

    await expectCompletedDatabaseState(jobId);
  });
});

function migrationRow(page: import('@playwright/test').Page, vaultId: string) {
  return page.locator('section[aria-busy]').filter({
    has: page.getByText(`密码库 ${vaultId.slice(0, 8)}`, { exact: true }),
  });
}

async function loadErinVaultIds(): Promise<{ personal: string; legacy: string }> {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const result = await client.query<{ id: string; kind: 'personal' | 'team' }>(
      `SELECT vault.id, vault.kind
       FROM vaults vault
       LEFT JOIN vault_memberships membership
         ON membership.vault_id = vault.id
        AND membership.subject_kind = 'user'
        AND membership.subject_id = 'u-erin'
       WHERE vault.owner_user_id = 'u-erin' OR membership.role = 'owner'
       ORDER BY vault.kind`,
    );
    const personal = result.rows.find((vault) => vault.kind === 'personal')?.id;
    const legacy = result.rows.find((vault) => vault.kind === 'team')?.id;
    expect(personal).toBeTruthy();
    expect(legacy).toBeTruthy();
    return { personal: personal!, legacy: legacy! };
  } finally {
    await client.end();
  }
}

async function setConcurrentMember(vaultId: string, present: boolean): Promise<void> {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    if (present) {
      await client.query(
        `INSERT INTO vault_memberships (vault_id, subject_kind, subject_id, role)
         VALUES ($1, 'user', 'u-carol', 'viewer')
         ON CONFLICT (vault_id, subject_kind, subject_id) DO UPDATE SET role = EXCLUDED.role`,
        [vaultId],
      );
    } else {
      await client.query(
        `DELETE FROM vault_memberships
         WHERE vault_id = $1 AND subject_kind = 'user' AND subject_id = 'u-carol'`,
        [vaultId],
      );
    }
  } finally {
    await client.end();
  }
}

async function expectVerifyingDatabaseState(jobId: string): Promise<void> {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const result = await client.query<{ state: string; storage_mode: string; write_state: string }>(
      `SELECT job.state, crypto.storage_mode, crypto.write_state
       FROM legacy_migration_jobs job
       JOIN vault_crypto_states crypto ON crypto.vault_id = job.vault_id
       WHERE job.id = $1`,
      [jobId],
    );
    expect(result.rows).toEqual([{ state: 'verifying', storage_mode: 'legacy', write_state: 'frozen' }]);
  } finally {
    await client.end();
  }
}

async function expectRollbackEvidence(jobId: string): Promise<void> {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const job = await client.query<{
      state: string;
      rolled_back_at: Date | null;
      last_error_code: string | null;
    }>(
      'SELECT state, rolled_back_at, last_error_code FROM legacy_migration_jobs WHERE id = $1',
      [jobId],
    );
    expect(job.rows[0]).toMatchObject({ state: 'legacy', last_error_code: 'user_rollback' });
    expect(job.rows[0]?.rolled_back_at).toBeInstanceOf(Date);

    const evidence = await client.query<{ evidence_type: string; stage: string }>(
      'SELECT evidence_type, stage FROM legacy_migration_evidence WHERE job_id = $1 AND evidence_type = $2',
      [jobId, 'rollback'],
    );
    expect(evidence.rows).toEqual([{ evidence_type: 'rollback', stage: 'legacy' }]);
  } finally {
    await client.end();
  }
}

async function expectCompletedDatabaseState(jobId: string): Promise<void> {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const result = await client.query<{
      vault_id: string;
      job_state: string;
      storage_mode: string;
      write_state: string;
      legacy_read_disabled_at: Date | null;
      vault_name: string;
      item_kind: string;
      item_title: string;
      item_username: string | null;
      item_origin: string | null;
      item_tags: string[];
    }>(
      `SELECT
         job.vault_id,
         job.state AS job_state,
         crypto.storage_mode,
         crypto.write_state,
         crypto.legacy_read_disabled_at,
         vault.name AS vault_name,
         item.kind AS item_kind,
         item.title AS item_title,
         item.username AS item_username,
         item.origin AS item_origin,
         item.tags AS item_tags
       FROM legacy_migration_jobs job
       JOIN vault_crypto_states crypto ON crypto.vault_id = job.vault_id
       JOIN vaults vault ON vault.id = job.vault_id
       JOIN items item ON item.vault_id = job.vault_id
       WHERE job.id = $1`,
      [jobId],
    );
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({
      job_state: 'e2ee',
      storage_mode: 'e2ee',
      write_state: 'open',
      vault_name: '',
      item_kind: 'secure_note',
      item_title: '',
      item_username: null,
      item_origin: null,
      item_tags: [],
    });
    expect(result.rows[0]?.legacy_read_disabled_at).toBeInstanceOf(Date);

    const vaultId = result.rows[0]!.vault_id;
    const encryptedCoverage = await client.query<{
      metadata_count: number;
      secret_count: number;
      wrap_count: number;
      evidence_count: number;
    }>(
      `SELECT
         (SELECT count(*)::int FROM encrypted_item_metadata_versions WHERE migration_job_id = $1) AS metadata_count,
         (SELECT count(*)::int FROM encrypted_item_secret_versions WHERE migration_job_id = $1) AS secret_count,
         (SELECT count(*)::int FROM encrypted_item_key_wraps WHERE migration_job_id = $1) AS wrap_count,
         (SELECT count(*)::int FROM legacy_migration_evidence WHERE job_id = $1 AND stage = 'e2ee') AS evidence_count`,
      [jobId],
    );
    expect(encryptedCoverage.rows[0]).toMatchObject({
      metadata_count: 1,
      secret_count: 1,
      wrap_count: 1,
      evidence_count: 1,
    });

    const plaintextScan = await client.query<{ row_text: string }>(
      `SELECT concat_ws(' ',
         vault.name,
         item.title,
         item.username,
         item.origin,
         item.tags::text,
         metadata.ciphertext::text,
         secret.ciphertext::text,
         key_wrap.wrapped_dek_ciphertext::text
       ) AS row_text
       FROM vaults vault
       JOIN items item ON item.vault_id = vault.id
       JOIN encrypted_item_metadata_versions metadata ON metadata.vault_id = vault.id
       JOIN encrypted_item_secret_versions secret ON secret.vault_id = vault.id AND secret.item_id = item.id
       JOIN encrypted_item_key_wraps key_wrap ON key_wrap.vault_id = vault.id AND key_wrap.item_id = item.id
       WHERE vault.id = $1`,
      [vaultId],
    );
    const persisted = plaintextScan.rows.map((row) => row.row_text).join('\n');
    for (const canary of [LEGACY_TITLE, LEGACY_USERNAME, LEGACY_ORIGIN, LEGACY_PASSWORD]) {
      expect(persisted).not.toContain(canary);
    }
  } finally {
    await client.end();
  }
}
