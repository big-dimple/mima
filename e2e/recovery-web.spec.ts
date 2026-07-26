import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';
import { expectNoHorizontalOverflow, loginAndUnlock } from './helpers.ts';

const SCREENSHOT_DIR = process.env.MIMA_E2E_SCREENSHOT_DIR
  ?? join(tmpdir(), 'mima-e2e-screenshots');

test('企业恢复五步流程在桌面、平板和手机视口保持可用', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await loginAndUnlock(page, 'alice');
  await page.getByRole('button', { name: '企业恢复', exact: true }).click();

  const dialog = page.locator('[data-recovery-dialog]');
  await expect(dialog).toBeVisible();
  for (const heading of [
    '准备三位管理员',
    '分发三份离线材料',
    '两位管理员确认启用',
    '纳入密码库保护',
    '正式启用',
  ]) {
    await expect(dialog.getByRole('heading', { name: heading })).toBeVisible();
  }

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
    await dialog.getByRole('button', { name: '管理者入门' }).click();
    const tour = page.getByRole('dialog', { name: /企业恢复管理者入门/ });
    await expect(tour).toBeVisible();
    const playbackControl = tour.getByRole('button', { name: /暂停|继续播放/ });
    await expect(playbackControl).toBeVisible();
    await playbackControl.click();
    await expect(tour.getByRole('button', { name: /暂停|继续播放/ })).toBeVisible();
    expect(await tour.evaluate((element) => element.parentElement === document.body)).toBe(true);
    const tourBounds = await tour.boundingBox();
    expect(tourBounds).not.toBeNull();
    expect(tourBounds!.x).toBe(0);
    expect(tourBounds!.y).toBe(0);
    expect(tourBounds!.width).toBe(viewport.width);
    expect(tourBounds!.height).toBe(viewport.height);
    const cardBounds = await tour.locator('[data-recovery-tour-card]').boundingBox();
    expect(cardBounds).not.toBeNull();
    expect(cardBounds!.x).toBeGreaterThanOrEqual(0);
    expect(cardBounds!.y).toBeGreaterThanOrEqual(0);
    expect(cardBounds!.x + cardBounds!.width).toBeLessThanOrEqual(viewport.width + 1);
    expect(cardBounds!.y + cardBounds!.height).toBeLessThanOrEqual(viewport.height + 1);
    await tour.getByRole('button', { name: '跳过' }).focus();
    await expect(tour.getByRole('button', { name: '跳过' })).toBeFocused();
    expect(await dialog.evaluate((element) => element.scrollWidth - element.clientWidth))
      .toBeLessThanOrEqual(0);
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      path: join(SCREENSHOT_DIR, `enterprise-recovery-tour-${viewport.name}-${viewport.width}x${viewport.height}.png`),
      animations: 'disabled',
    });
    await tour.getByRole('button', { name: '跳过' }).click();
    await page.screenshot({
      path: join(SCREENSHOT_DIR, `enterprise-recovery-${viewport.name}-top-${viewport.width}x${viewport.height}.png`),
      animations: 'disabled',
    });
    await dialog.evaluate((element) => {
      element.scrollTop = element.scrollHeight;
    });
    await expect(dialog.getByRole('heading', { name: '我的恢复请求' })).toBeInViewport();
    await page.screenshot({
      path: join(SCREENSHOT_DIR, `enterprise-recovery-${viewport.name}-bottom-${viewport.width}x${viewport.height}.png`),
      animations: 'disabled',
    });
    await dialog.evaluate((element) => {
      element.scrollTop = 0;
    });
  }
});
