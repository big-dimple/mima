import pg from 'pg';
import { expect, test } from '@playwright/test';
import { ensureLoginItem, lockWorkspaceForTest, loginAndUnlock, MAIN_PASSWORDS } from './helpers.ts';

const ITEM = {
  title: 'E2E 离线缓存条目',
  username: 'offline-e2e-user',
  origin: 'https://offline-e2e.example.test',
  password: 'e2e-offline-secret-canary-003',
};
const DATABASE_URL = process.env.MIMA_E2E_DATABASE_URL
  ?? 'postgres://mima:mima_dev_pw@127.0.0.1:55432/mima_test_e2e';

test.describe.serial('零知识安全边界', () => {
  test('多标签页锁定同步，解锁必须各自输入主密码', async ({ context }) => {
    const pageA = await context.newPage();
    await loginAndUnlock(pageA, 'bob');
    await ensureLoginItem(pageA, ITEM);

    const pageB = await context.newPage();
    await pageB.goto('/');
    await expect(pageB.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await pageB.locator('#main-password').fill(MAIN_PASSWORDS.bob);
    await pageB.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await pageB.getByRole('option', { name: new RegExp(ITEM.title) }).click();
    await pageB.getByRole('button', { name: '查看密码' }).click();
    await expect(pageB.getByText(ITEM.password, { exact: true })).toBeVisible();

    await lockWorkspaceForTest(pageA);
    await expect(pageA.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await expect(pageB.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible({ timeout: 5_000 });
    await expect(pageB.getByText(ITEM.password, { exact: true })).toHaveCount(0);

    await pageA.locator('#main-password').fill(MAIN_PASSWORDS.bob);
    await pageA.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await expect(pageA.getByRole('navigation', { name: '库导航' })).toBeVisible();
    await expect(pageB.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
  });

  test('断网后只用本地密文缓存解锁和查看', async ({ page, context }) => {
    await loginAndUnlock(page, 'bob');
    await ensureLoginItem(page, ITEM);
    await page.getByRole('option', { name: new RegExp(ITEM.title) }).click();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText(ITEM.password, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '立即遮罩' }).click();

    await context.setOffline(true);
    await expect(page.getByText(/网络暂时不可用/)).toBeVisible({ timeout: 10_000 });
    await lockWorkspaceForTest(page, false);
    await page.locator('#main-password').fill(MAIN_PASSWORDS.bob);
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
    const navigation = page.getByRole('navigation', { name: '库导航' });
    const unlockError = page.getByRole('region', { name: '通知' }).getByRole('alert').last();
    await expect(navigation.or(unlockError)).toBeVisible({ timeout: 15_000 });
    if (await unlockError.isVisible()) throw new Error(await unlockError.innerText());
    await expect(page.getByText(/网络暂时不可用/)).toBeVisible();
    await page.getByRole('option', { name: new RegExp(ITEM.title) }).click();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText(ITEM.password, { exact: true })).toBeVisible();
    await context.setOffline(false);
  });

  test('浏览器持久化与锁定 DOM 不包含已知明文', async ({ page }) => {
    await loginAndUnlock(page, 'bob');
    await ensureLoginItem(page, ITEM);
    await page.getByRole('option', { name: new RegExp(ITEM.title) }).click();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText(ITEM.password, { exact: true })).toBeVisible();

    const persistedBeforeLock = await readBrowserPersistence(page);
    expect(persistedBeforeLock).not.toContain(ITEM.password);
    expect(persistedBeforeLock).not.toContain(ITEM.title);
    expect(persistedBeforeLock).not.toContain(ITEM.username);
    expect(persistedBeforeLock).not.toContain(ITEM.origin);

    await lockWorkspaceForTest(page);
    const lockedDocument = await page.locator('html').innerText();
    expect(lockedDocument).not.toContain(ITEM.password);
    expect(lockedDocument).not.toContain(ITEM.title);
    expect(await readBrowserPersistence(page)).not.toContain(ITEM.password);
  });

  test('PostgreSQL 全表扫描找不到浏览器生成的明文 canary', async () => {
    const client = new pg.Client({ connectionString: DATABASE_URL });
    await client.connect();
    try {
      const tables = await client.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
      );
      for (const table of tables.rows) {
        const rows = await client.query<{ row_text: string }>(
          `SELECT record::text AS row_text FROM ${quoteIdentifier(table.table_name)} record`,
        );
        for (const row of rows.rows) {
          expect(row.row_text).not.toContain(ITEM.password);
          expect(row.row_text).not.toContain(ITEM.title);
          expect(row.row_text).not.toContain(ITEM.username);
          expect(row.row_text).not.toContain(ITEM.origin);
        }
      }
    } finally {
      await client.end();
    }
  });
});

async function readBrowserPersistence(page: import('@playwright/test').Page): Promise<string> {
  return page.evaluate(async () => {
    const databases = await indexedDB.databases();
    const records: unknown[] = [];
    for (const info of databases) {
      if (!info.name) continue;
      const database = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open(info.name!);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      try {
        for (const storeName of Array.from(database.objectStoreNames)) {
          records.push(await new Promise((resolve, reject) => {
            const request = database.transaction(storeName, 'readonly').objectStore(storeName).getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
          }));
        }
      } finally {
        database.close();
      }
    }
    return JSON.stringify({
      localStorage: { ...localStorage },
      sessionStorage: { ...sessionStorage },
      indexedDb: records,
    });
  });
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}
