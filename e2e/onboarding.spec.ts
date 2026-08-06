import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { loginAndUnlock, MAIN_PASSWORDS } from './helpers.ts';

const SCREENSHOT_DIR = process.env.MIMA_E2E_SCREENSHOT_DIR
  ?? join(tmpdir(), 'mima-e2e-screenshots');

test.describe.serial('新手导览', () => {
  test('登录首屏说明真实价值、保护范围和恢复边界', async ({ page }) => {
    await page.goto('/');
    const entry = page.getByRole('button', { name: /为什么使用Mima/ });
    await expect(entry).toBeVisible();
    await entry.click();
    const dialog = page.getByRole('dialog', { name: '为什么使用Mima？' });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('安全底线：放心存')).toBeVisible();
    await expect(dialog.getByText('效率体验：用得快')).toBeVisible();
    await expect(dialog.getByText('团队协作：管得清')).toBeVisible();
    await expect(dialog.getByText(/服务器只保存加密后的数据/)).toBeHidden();
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'guide-desktop-1440x900.png'),
      animations: 'disabled',
      fullPage: true,
    });
    await dialog.getByText('安全底线：放心存').click();
    await expect(dialog.getByText(/服务器只保存加密后的数据/)).toBeVisible();
    await dialog.getByText('团队协作：管得清').click();
    await expect(dialog.getByText(/任何一人都不能单独恢复/)).toBeVisible();
    await expect(dialog.getByText(/AAD/)).toBeHidden();
    await dialog.getByText('安全原理（给好奇的同学）').click();
    await expect(dialog.getByText(/每个内容版本单独加密/)).toBeVisible();
    await expect(dialog.getByRole('button', { name: /开始 3 分钟入门/ })).toHaveCount(0);
    await dialog.getByText('安全底线：放心存').click();
    await dialog.getByText('团队协作：管得清').click();
    await dialog.getByText('安全原理（给好奇的同学）').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'guide-mobile-390x844.png'),
      animations: 'disabled',
      fullPage: true,
    });
    await dialog.getByRole('button', { name: '知道了' }).click();
  });

  test('首次进入直接开始，完整导览后只持久化非敏感完成状态', async ({ page }) => {
    await loginAndUnlock(page, 'bob', { skipGuide: false });
    await expect(page.getByRole('complementary', { name: '新手引导邀请' })).toHaveCount(0);
    await expect(page.getByRole('dialog', { name: '引导：选择密码库' })).toBeVisible();
    expect(JSON.parse(await page.evaluate(() => localStorage.getItem('mima.guide.v1') ?? '{}')))
      .toEqual({ promptShown: true, tourCompleted: false });

    const stepTitles = [
      '选择密码库',
      '调宽左栏',
      '修改库名',
      '新建条目',
      '搜索',
      '查看与复制',
      '创建团队库',
      '团队授权',
      '配对浏览器扩展',
    ];
    for (let index = 0; index < stepTitles.length; index += 1) {
      const card = page.getByRole('dialog', { name: `引导：${stepTitles[index]}` });
      await expect(card).toBeVisible({ timeout: 10_000 });
      await expect(card.getByText(`${index + 1} / ${stepTitles.length}`)).toBeVisible();
      if (stepTitles[index] === '调宽左栏') {
        await page.screenshot({
          path: join(SCREENSHOT_DIR, 'tour-resize-sidebar-1440x900.png'),
          animations: 'disabled',
          fullPage: true,
        });
      }
      await card.getByRole('button', { name: index === stepTitles.length - 1 ? '完成' : '下一步' }).click();
    }

    const stored = await page.evaluate(() => localStorage.getItem('mima.guide.v1'));
    expect(JSON.parse(stored ?? '{}')).toEqual({ promptShown: true, tourCompleted: true });

    await page.reload();
    await unlockAfterReload(page, 'bob');
    await expect(page.getByRole('complementary', { name: '新手引导邀请' })).toHaveCount(0);
    await page.getByRole('button', { name: '新手指南' }).click();
    const dialog = page.getByRole('dialog', { name: '为什么使用Mima？' });
    await dialog.getByRole('button', { name: /开始 3 分钟入门/ }).click();
    await expect(page.getByRole('dialog', { name: '引导：选择密码库' })).toBeVisible();
    await page.getByRole('button', { name: '跳过引导' }).click();
  });

  test('跳过后不再自动启动，也不伪装成已完成', async ({ page }) => {
    await loginAndUnlock(page, 'carol', { skipGuide: false });
    const firstStep = page.getByRole('dialog', { name: '引导：选择密码库' });
    await expect(firstStep).toBeVisible();
    await firstStep.getByRole('button', { name: '跳过引导' }).click();
    const stored = await page.evaluate(() => localStorage.getItem('mima.guide.v1'));
    expect(JSON.parse(stored ?? '{}')).toEqual({ promptShown: true, tourCompleted: false });
    await page.reload();
    await unlockAfterReload(page, 'carol');
    await expect(page.getByRole('dialog', { name: '引导：选择密码库' })).toHaveCount(0);
  });
});

async function unlockAfterReload(page: Page, username: keyof typeof MAIN_PASSWORDS): Promise<void> {
  await expect(page.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
  await page.locator('#main-password').fill(MAIN_PASSWORDS[username]);
  await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
  await expect(page.getByRole('navigation', { name: '库导航' })).toBeVisible();
}
