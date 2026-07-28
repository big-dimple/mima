import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';
import { expectNoHorizontalOverflow, loginAndUnlock } from './helpers.ts';

const SCREENSHOT_DIR = process.env.MIMA_E2E_SCREENSHOT_DIR
  ?? join(tmpdir(), 'mima-e2e-screenshots');

test('企业恢复中心在桌面、平板和手机视口保持可用', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await loginAndUnlock(page, 'alice');
  await page.getByRole('button', { name: '企业恢复', exact: true }).click();

  const dialog = page.locator('[data-recovery-dialog]');
  const pane = dialog.getByRole('main');
  await expect(dialog).toBeVisible();

  for (const viewport of [
    { name: 'desktop', width: 1440, height: 900 },
    { name: 'tablet', width: 900, height: 800 },
    { name: 'compact-desktop', width: 830, height: 781 },
    { name: 'mobile', width: 390, height: 844 },
  ]) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await expect(dialog).toBeVisible();
    await expectNoHorizontalOverflow(page);
    const bounds = await dialog.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.y).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width + 1);
    expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(viewport.height + 1);
    expect(await dialog.evaluate((element) => element.scrollWidth - element.clientWidth))
      .toBeLessThanOrEqual(0);

    const overview = dialog.getByRole('button', { name: '总览', exact: true });
    await overview.click();
    await expect(overview).toHaveAttribute('aria-current', 'page');
    await expect(dialog.getByText('企业恢复保障状态')).toBeVisible();

    const setup = dialog.getByRole('button', { name: '准备恢复能力', exact: true });
    await setup.click();
    await expect(setup).toHaveAttribute('aria-current', 'page');
    await expect(dialog.getByRole('heading', { name: '企业恢复设置' })).toBeVisible();
    for (const heading of [
      '准备三位管理员',
      '分发三份离线材料',
      '两位管理员确认启用',
      '纳入密码库保护',
      '正式启用',
    ]) {
      await expect(dialog.getByRole('heading', { name: heading })).toBeVisible();
    }
    await page.screenshot({
      path: join(SCREENSHOT_DIR, `enterprise-recovery-setup-${viewport.name}-${viewport.width}x${viewport.height}.png`),
      animations: 'disabled',
    });

    await pane.evaluate((element) => {
      element.scrollTop = element.scrollHeight;
    });
    await expect(dialog.getByRole('heading', { name: '正式启用' })).toBeInViewport();
    await page.screenshot({
      path: join(SCREENSHOT_DIR, `enterprise-recovery-setup-bottom-${viewport.name}-${viewport.width}x${viewport.height}.png`),
      animations: 'disabled',
    });

    for (const section of [
      { navigation: '待办审批', heading: '待办审批' },
      { navigation: '密码库保护', heading: '密码库保护' },
      { navigation: '高级维护', heading: '高级维护' },
      { navigation: '我的恢复', heading: '我的恢复' },
    ]) {
      const button = dialog.getByRole('button', { name: section.navigation, exact: true });
      await button.click();
      await expect(button).toHaveAttribute('aria-current', 'page');
      await expect(dialog.getByRole('heading', { name: section.heading, exact: true })).toBeVisible();
    }
    await pane.evaluate((element) => {
      element.scrollTop = 0;
    });
    expect(await pane.evaluate((element) => element.scrollWidth - element.clientWidth))
      .toBeLessThanOrEqual(0);
    await expectNoHorizontalOverflow(page);
  }
});
