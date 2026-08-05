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
    await expect(dialog.getByRole('heading', {
      name: '忘记主密码时，管理员可以帮你恢复原有访问',
    })).toBeVisible();
    await expect(dialog.getByText('管理员不能代替你')).toBeVisible();
    await expect(dialog.getByText('只恢复原有权限')).toBeVisible();

    const setup = dialog.getByRole('button', { name: '准备恢复', exact: true });
    await setup.click();
    await expect(setup).toHaveAttribute('aria-current', 'page');
    await expect(dialog.getByRole('heading', { name: '准备企业恢复' })).toBeVisible();
    for (const heading of [
      '1. 下载离线向导',
      '2. 登记公开清单',
      '3. 由另一位管理员确认',
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
    await expect(dialog.getByText(/企业恢复已经准备完成|系统正在后台保护现有密码库|两人确认后/)).toBeInViewport();
    await page.screenshot({
      path: join(SCREENSHOT_DIR, `enterprise-recovery-setup-bottom-${viewport.name}-${viewport.width}x${viewport.height}.png`),
      animations: 'disabled',
    });

    for (const section of [
      { navigation: '恢复案件', heading: '恢复案件' },
      { navigation: '历史记录', heading: '历史记录' },
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
