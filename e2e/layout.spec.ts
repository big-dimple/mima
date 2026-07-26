import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';
import {
  ensureLoginItem,
  enterIntentionalText,
  expectNoHorizontalOverflow,
  loginAndUnlock,
  MAIN_PASSWORDS,
} from './helpers.ts';

const LAYOUT_ITEM = {
  title: 'E2E 响应式条目',
  username: 'responsive-e2e-user',
  origin: 'https://responsive-e2e.example.test',
  password: 'e2e-responsive-secret-004',
};
const SCREENSHOT_DIR = process.env.MIMA_E2E_SCREENSHOT_DIR
  ?? join(tmpdir(), 'mima-e2e-screenshots');

test.describe.serial('桌面、平板和手机布局', () => {
  test('1440x900 三栏可调整且刷新后保持', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.addInitScript(() => {
      localStorage.setItem('mima.layout.v1', JSON.stringify({ navWidth: 200, listWidth: 520 }));
    });
    await loginAndUnlock(page, 'bob');
    await ensureLoginItem(page, LAYOUT_ITEM);
    await page.getByRole('option', { name: new RegExp(LAYOUT_ITEM.title) }).click();
    await expectNoHorizontalOverflow(page);

    const navigationBox = await page.getByRole('navigation', { name: '库导航' }).boundingBox();
    const listBox = await page.getByRole('region', { name: '凭证列表' }).boundingBox();
    expect(navigationBox?.width ?? 0).toBeGreaterThan(300);
    expect(listBox?.width ?? 0).toBeGreaterThan(280);

    const separator = page.getByRole('separator', { name: '调整密码库导航宽度' });
    await expect(separator).toHaveAttribute('aria-valuenow', '384');
    expect(JSON.parse(await page.evaluate(() => localStorage.getItem('mima.layout.v3') ?? '{}')))
      .toEqual({ navWidth: 384, listWidth: 520 });
    await separator.focus();
    const before = Number(await separator.getAttribute('aria-valuenow'));
    await separator.press('ArrowRight');
    await expect(separator).toHaveAttribute('aria-valuenow', String(before + 16));
    await page.reload();
    await expect(page.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await page.locator('#main-password').fill(MAIN_PASSWORDS.bob);
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await expect(page.getByRole('region', { name: '凭证列表' })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole('separator', { name: '调整密码库导航宽度' }))
      .toHaveAttribute('aria-valuenow', String(before + 16));
    await page.setViewportSize({ width: 1920, height: 900 });
    await separator.focus();
    await separator.press('End');
    await expect(separator).toHaveAttribute('aria-valuenow', '640');
    const wideNavigationBox = await page.getByRole('navigation', { name: '库导航' }).boundingBox();
    expect(wideNavigationBox?.width ?? 0).toBeGreaterThan(630);
    await expectNoHorizontalOverflow(page);
    await page.getByRole('option', { name: new RegExp(LAYOUT_ITEM.title) }).click();
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'web-desktop-wide-1920x900.png'),
      animations: 'disabled',
      fullPage: true,
    });
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'web-desktop-1440x900.png'),
      animations: 'disabled',
      fullPage: true,
    });
  });

  test('平板视口无横向溢出且详情并排可用', async ({ page }) => {
    await page.setViewportSize({ width: 900, height: 800 });
    await loginAndUnlock(page, 'bob');
    await page.getByRole('option', { name: new RegExp(LAYOUT_ITEM.title) }).click();
    await expect(page.getByText('凭证详情', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('region', { name: '凭证列表' })).toBeVisible();
    await expect(page.getByRole('main', { name: new RegExp(`条目详情.*${LAYOUT_ITEM.title}`) })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'web-tablet-900x800.png'),
      animations: 'disabled',
      fullPage: true,
    });
  });

  test('390x844 手机导航抽屉、列表和详情不重叠', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await loginAndUnlock(page, 'bob');
    const moreTools = page.getByRole('button', { name: '更多工具' });
    await expect(moreTools).toBeVisible();
    await moreTools.click();
    const toolsMenu = page.getByRole('group', { name: '更多工具' });
    await expect(toolsMenu).toBeVisible();
    await expect(toolsMenu.getByRole('button')).toHaveCount(5);
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'web-mobile-tools-390x844.png'),
      animations: 'disabled',
      fullPage: true,
    });
    await page.keyboard.press('Escape');
    await expect(toolsMenu).toHaveCount(0);
    await expect(page.getByRole('button', { name: '打开密码库导航' })).toBeVisible();
    await page.getByRole('button', { name: '打开密码库导航' }).click();
    await expect(page.getByRole('dialog', { name: '密码库导航' })).toBeVisible();
    await page.getByRole('button', { name: '关闭密码库导航' }).last().click();

    await page.getByRole('option', { name: new RegExp(LAYOUT_ITEM.title) }).click();
    await expect(page.getByText('凭证详情', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '返回凭证列表' })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'web-mobile-390x844.png'),
      animations: 'disabled',
      fullPage: true,
    });
    await page.getByRole('button', { name: '返回凭证列表' }).click();
    await expect(page.getByRole('region', { name: '凭证列表' })).toBeVisible();
  });

  test('条目编辑入口和取消保存区在三种视口均可用', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');
    await ensureLoginItem(page, LAYOUT_ITEM);
    await page.getByRole('option', { name: new RegExp(LAYOUT_ITEM.title) }).click();

    for (const viewport of [
      { name: 'desktop', width: 1440, height: 900 },
      { name: 'tablet', width: 900, height: 800 },
      { name: 'mobile', width: 390, height: 844 },
    ]) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      const edit = page.getByRole('button', { name: '编辑', exact: true });
      await expect(edit).toBeVisible();
      await expect(edit).toContainText('编辑');
      await edit.click();

      const cancel = page.getByRole('button', { name: '取消' });
      const save = page.getByRole('button', { name: '保存', exact: true });
      await cancel.scrollIntoViewIfNeeded();
      await expect(cancel).toBeVisible();
      await expect(save).toBeVisible();
      await page.getByRole('checkbox', { name: '同时更换密码' }).click();
      const password = page.getByLabel('密码', { exact: true });
      await enterIntentionalText(password, 'selection-contrast-test');
      await password.evaluate((element) => (element as HTMLInputElement).select());
      const selectionStyle = await password.evaluate((element) => {
        const style = getComputedStyle(element, '::selection');
        return { background: style.backgroundColor, color: style.color };
      });
      expect(selectionStyle.background).not.toBe('rgba(0, 0, 0, 0)');
      expect(selectionStyle.color).toBe('rgb(255, 255, 255)');
      await expectNoHorizontalOverflow(page);

      const form = page.getByRole('main', { name: '编辑条目' });
      expect(await form.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(0);
      await page.screenshot({
        path: join(SCREENSHOT_DIR, `item-edit-${viewport.name}-${viewport.width}x${viewport.height}.png`),
        animations: 'disabled',
        fullPage: true,
      });
      await cancel.click();
      await expect(page.getByRole('button', { name: '编辑', exact: true })).toBeVisible();
    }
  });

  test('新建团队密码库弹窗在桌面、平板和手机均无溢出', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');

    for (const viewport of [
      { name: 'desktop', width: 1440, height: 900 },
      { name: 'tablet', width: 900, height: 800 },
      { name: 'mobile', width: 390, height: 844 },
    ]) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      let drawer = page.getByRole('dialog', { name: '密码库导航' });
      if (viewport.width < 1120) {
        await page.getByRole('button', { name: '打开密码库导航' }).click();
        drawer = page.getByRole('dialog', { name: '密码库导航' });
        await expect(drawer).toBeVisible();
        await drawer.getByRole('button', { name: '新建团队库' }).click();
      } else {
        await page.getByRole('button', { name: '新建团队库' }).click();
      }

      const dialog = page.getByRole('dialog', { name: '新建团队密码库' });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByLabel('团队密码库名称')).toBeVisible();
      await expect(dialog.getByRole('combobox', { name: '初始拥有者' })).toHaveCount(0);
      await expectNoHorizontalOverflow(page);
      const box = await dialog.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
      expect(box!.y + box!.height).toBeLessThanOrEqual(viewport.height);
      expect(await dialog.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(0);
      await page.screenshot({
        path: join(SCREENSHOT_DIR, `team-vault-dialog-${viewport.name}-${viewport.width}x${viewport.height}.png`),
        animations: 'disabled',
        fullPage: true,
      });
      await dialog.getByRole('button', { name: '关闭' }).click();
      if (viewport.width < 1120) {
        await drawer.getByRole('button', { name: '关闭密码库导航' }).click();
      }
    }
  });

  test('目录管理弹窗在桌面、平板和手机均完整可操作', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');

    for (const viewport of [
      { name: 'desktop', width: 1440, height: 900 },
      { name: 'tablet', width: 900, height: 800 },
      { name: 'mobile', width: 390, height: 844 },
    ]) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      let navigation = page.getByRole('navigation', { name: '库导航' });
      if (viewport.width < 1120) {
        await page.getByRole('button', { name: '打开密码库导航' }).click();
        navigation = page.getByRole('dialog', { name: '密码库导航' });
        await expect(navigation).toBeVisible();
      }
      const personalVault = navigation.locator('button[title$="个人密码库"]').first();
      if (await personalVault.getAttribute('aria-current') !== 'page') await personalVault.click();
      await expect(personalVault).toHaveAttribute('aria-current', 'page');
      const collapsedDisclosure = navigation.getByRole('button', { name: /展开.*个人密码库/ });
      if (await collapsedDisclosure.count()) await collapsedDisclosure.first().click();
      await expect(navigation.getByRole('button', { name: /折叠.*个人密码库/ }).first()).toBeVisible();
      await navigation.getByRole('button', { name: '新建目录' }).click();

      const dialog = page.getByRole('dialog', { name: '新建目录' });
      await expect(dialog.getByLabel('上级目录')).toBeVisible();
      await expect(dialog.getByRole('textbox', { name: '目录名称' })).toBeVisible();
      await expect(dialog.getByRole('button', { name: '取消' })).toBeVisible();
      await expect(dialog.getByRole('button', { name: '创建目录' })).toBeVisible();
      await expectNoHorizontalOverflow(page);
      const box = await dialog.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
      expect(box!.y + box!.height).toBeLessThanOrEqual(viewport.height);
      expect(await dialog.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(0);
      await page.screenshot({
        path: join(SCREENSHOT_DIR, `directory-dialog-${viewport.name}-${viewport.width}x${viewport.height}.png`),
        animations: 'disabled',
        fullPage: true,
      });
      await dialog.getByRole('button', { name: '取消' }).click();
      if (viewport.width < 1120) {
        await navigation.getByRole('button', { name: '关闭密码库导航' }).click();
      }
    }
  });

  test('用户组快速切换不跳位且始终显示最新选择', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');
    await page.getByRole('button', { name: '管理用户组' }).click();

    const dialog = page.getByRole('dialog', { name: '管理用户组' });
    const list = dialog.getByTestId('groups-dialog-list');
    const main = dialog.getByTestId('groups-dialog-main');
    const statusHelp = dialog.getByTestId('group-status-help');
    await expect(statusHelp).toContainText('人数是组内同事数');
    await expect(statusHelp).toContainText('同一人有两个库没开通，就会显示 2 项');
    await expect(statusHelp).toContainText('由对应密码库的拥有者在“管理成员”中开通');
    const suffix = `${testInfo.retry}-${Date.now().toString(36)}`;
    const groupNames = Array.from(
      { length: 12 },
      (_, index) => `布局回归组-${suffix}-${String(index + 1).padStart(2, '0')}`,
    );

    for (const groupName of groupNames) {
      await dialog.getByRole('button', { name: '新建用户组' }).click();
      await dialog.getByLabel('名称').fill(groupName);
      await dialog.getByRole('button', { name: '保存', exact: true }).click();
      await expect(list.getByText(groupName, { exact: true })).toHaveCount(1);
    }

    await list.evaluate((element) => { element.scrollTop = element.scrollHeight; });
    await expect.poll(() => list.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);

    let detailRequest = 0;
    await page.route(/\/api\/groups\/[^/?]+$/, async (route) => {
      if (route.request().method() === 'GET') {
        detailRequest += 1;
        if (detailRequest === 1) await new Promise((resolve) => setTimeout(resolve, 400));
      }
      await route.continue();
    });

    const firstName = groupNames[0]!;
    const secondName = groupNames[1]!;
    await list.getByRole('button').filter({ hasText: firstName }).click();
    await list.getByRole('button').filter({ hasText: secondName }).click();
    await expect(dialog.getByLabel('名称')).toHaveValue(secondName);
    await page.waitForTimeout(500);
    await expect(dialog.getByLabel('名称')).toHaveValue(secondName);
    await expect(page.getByText('用户组已创建', { exact: true })).toHaveCount(0, { timeout: 10_000 });

    const headerBox = await dialog.getByTestId('groups-dialog-header').boundingBox();
    const layoutBox = await dialog.getByTestId('groups-dialog-layout').boundingBox();
    const mainBox = await main.boundingBox();
    const nameBox = await dialog.getByLabel('名称').boundingBox();
    const statusHelpBox = await statusHelp.boundingBox();
    const listBox = await list.boundingBox();
    expect(headerBox).not.toBeNull();
    expect(layoutBox).not.toBeNull();
    expect(mainBox).not.toBeNull();
    expect(nameBox).not.toBeNull();
    expect(statusHelpBox).not.toBeNull();
    expect(listBox).not.toBeNull();
    expect(Math.abs(layoutBox!.y - (headerBox!.y + headerBox!.height))).toBeLessThanOrEqual(2);
    expect(nameBox!.y - mainBox!.y).toBeGreaterThanOrEqual(40);
    expect(nameBox!.y - mainBox!.y).toBeLessThanOrEqual(100);
    expect(statusHelpBox!.y + statusHelpBox!.height).toBeLessThanOrEqual(listBox!.y);
    expect(listBox!.height).toBeGreaterThanOrEqual(180);
    expect(await main.evaluate((element) => element.scrollTop)).toBe(0);
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      path: join(SCREENSHOT_DIR, 'groups-dialog-desktop-1440x900.png'),
      animations: 'disabled',
      fullPage: true,
    });
  });
});
