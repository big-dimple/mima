import { expect, test, type Locator, type Page } from '@playwright/test';
import {
  E2E_API_ORIGIN,
  ensureLoginItem,
  enterIntentionalText,
  expectNoHorizontalOverflow,
  loginAndUnlock,
  MAIN_PASSWORDS,
} from './helpers.ts';
const PERSONAL_ITEM = {
  title: 'E2E 本地登录',
  username: 'e2e-user',
  origin: 'https://login-e2e.example.test',
  password: 'e2e-browser-generated-secret-001',
};
const FULL_LOGIN_URL_ITEM = {
  title: 'E2E 示例云子账号',
  username: 'e2e-sub-account-user',
  origin: 'https://accounts.example.test/login/tenant/example-a',
  password: 'e2e-sub-account-secret-008',
};
const DAVE_UPDATED_MAIN_PASSWORD = 'Dave-e2e-updated-main-password-2026';

test.describe.serial('严格零知识工作台', () => {
  test('浏览器建钥、加密条目、错误主密码和真实锁定', async ({ page }) => {
    await loginAndUnlock(page, 'bob');
    await ensureLoginItem(page, PERSONAL_ITEM);

    await page.getByRole('option', { name: new RegExp(PERSONAL_ITEM.title) }).click();
    await expect(page.getByLabel('密码已遮罩')).toBeVisible();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText(PERSONAL_ITEM.password, { exact: true })).toBeVisible();

    await page.getByRole('button', { name: '锁定工作台' }).click();
    await expect(page.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await expect(page.getByText(PERSONAL_ITEM.password, { exact: true })).toHaveCount(0);

    await page.locator('#main-password').fill('wrong-e2e-main-password');
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await expect(page.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await expect(page.getByText(/主密码不正确/)).toBeVisible();

    await page.locator('#main-password').fill(MAIN_PASSWORDS.bob);
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await expect(page.getByRole('navigation', { name: '库导航' })).toBeVisible();
    await page.getByRole('option', { name: new RegExp(PERSONAL_ITEM.title) }).click();
    await expect(page.getByLabel('密码已遮罩')).toBeVisible();
  });

  test('完整登录地址可保存搜索，取消编辑不生效并可修改密码', async ({ page }, testInfo) => {
    const loginItem = {
      ...FULL_LOGIN_URL_ITEM,
      title: `${FULL_LOGIN_URL_ITEM.title}-${testInfo.retry}`,
    };
    const directoryPath = `工作/云服务-${testInfo.retry}/示例云`;
    const renamedParentPath = `工作/云平台-${testInfo.retry}`;
    const renamedDirectoryPath = `${renamedParentPath}/示例云`;
    const backupUrl = `https://backup-${testInfo.retry}.example.test/console`;
    await loginAndUnlock(page, 'bob');
    await ensureLoginItem(page, loginItem);
    await ensureDirectoryPath(page, directoryPath);
    await page.getByRole('button', { name: '目录：全部', exact: true }).click();

    const row = page.getByRole('option', { name: new RegExp(loginItem.title) });
    await row.click();
    await expect(page.getByText(loginItem.origin, { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '复制网址' })).toBeVisible();
    const openWebsite = page.getByRole('link', { name: '打开网址' });
    await expect(openWebsite).toHaveAttribute('href', loginItem.origin);
    await expect(openWebsite).toHaveAttribute('target', '_blank');
    await expect(openWebsite).toHaveAttribute('rel', 'noopener noreferrer');
    const itemDetail = page.getByRole('main', { name: `条目详情：${loginItem.title}` });
    const websiteTextBox = await itemDetail.getByTestId('website-url-value').boundingBox();
    const copyWebsiteBox = await itemDetail.getByRole('button', { name: '复制网址' }).boundingBox();
    expect(websiteTextBox).not.toBeNull();
    expect(copyWebsiteBox).not.toBeNull();
    expect(websiteTextBox!.height).toBeLessThanOrEqual(20);
    expect(copyWebsiteBox!.x - (websiteTextBox!.x + websiteTextBox!.width)).toBeGreaterThanOrEqual(0);
    expect(copyWebsiteBox!.x - (websiteTextBox!.x + websiteTextBox!.width)).toBeLessThanOrEqual(12);
    expect(Math.abs(
      copyWebsiteBox!.y + copyWebsiteBox!.height / 2 - (websiteTextBox!.y + websiteTextBox!.height / 2),
    )).toBeLessThanOrEqual(4);
    await expectNoHorizontalOverflow(page);
    await page.screenshot({ path: testInfo.outputPath('account-password-url-actions-desktop.png') });

    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole('button', { name: '复制网址' })).toBeVisible();
    await expect(openWebsite).toBeVisible();
    await expectNoHorizontalOverflow(page);
    const openWebsiteBox = await openWebsite.boundingBox();
    expect(openWebsiteBox).not.toBeNull();
    expect(openWebsiteBox!.x + openWebsiteBox!.width).toBeLessThanOrEqual(390);
    await page.screenshot({ path: testInfo.outputPath('account-password-url-actions-mobile.png') });
    await page.setViewportSize({ width: 1440, height: 900 });

    await expect(page.getByText('敏感标记', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '编辑', exact: true })).toBeVisible();

    const search = page.getByRole('textbox', { name: '搜索条目' });
    await expect(search).toHaveAttribute('placeholder', '搜索标题/说明/凭证标识/关联信息');
    await search.fill('example-a');
    await expect(row).toBeVisible();
    await search.fill('');

    await page.getByRole('button', { name: '编辑', exact: true }).click();
    await expect(page.getByLabel('网址（主网址，可选）')).toHaveValue(loginItem.origin);
    const title = page.getByLabel('标题 *');
    await enterIntentionalText(title, '不应保存的标题', true);
    await page.getByRole('button', { name: '取消' }).click();
    const discardDialog = page.getByRole('dialog', { name: '放弃未保存的修改？' });
    await expect(discardDialog).toBeVisible();
    await discardDialog.getByRole('button', { name: '继续编辑' }).click();
    await expect(title).toHaveValue('不应保存的标题');
    await page.getByRole('button', { name: '取消' }).click();
    await discardDialog.getByRole('button', { name: '放弃修改' }).click();
    await expect(page.getByRole('heading', { name: loginItem.title })).toBeVisible();

    await page.getByRole('button', { name: '编辑', exact: true }).click();
    await page.getByLabel('目录（可选）').selectOption(directoryPath);
    const protectedUsername = page.getByLabel('账号');
    await injectBrowserReplacement(protectedUsername, 'simulated-browser-account');
    await expect(protectedUsername).toHaveValue(loginItem.username);
    await expect(page.getByLabel('密码', { exact: true })).toHaveCount(0);
    await page.getByRole('checkbox', { name: '同时更换密码' }).click();
    const protectedPassword = page.getByLabel('密码', { exact: true });
    await injectBrowserReplacement(protectedPassword, 'simulated-browser-main-password');
    await expect(protectedPassword).toHaveValue('');
    await page.getByRole('button', { name: '保存', exact: true }).click();
    await expect(itemDetail.getByText(loginItem.username, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText(loginItem.password, { exact: true })).toBeVisible();

    await page.getByRole('button', { name: '编辑', exact: true }).click();
    await page.getByRole('button', { name: '添加网址' }).click();
    await enterIntentionalText(page.getByLabel('备用网址 2'), backupUrl);
    await page.getByRole('checkbox', { name: '同时更换密码' }).click();
    await enterIntentionalText(page.getByLabel('密码', { exact: true }), 'e2e-sub-account-secret-updated-009');
    await page.getByRole('button', { name: '保存', exact: true }).click();
    await expect(page.getByText(backupUrl, { exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: '打开备用网址 2' })).toHaveAttribute('href', backupUrl);
    await search.fill(`backup-${testInfo.retry}.example.test`);
    await expect(row).toBeVisible();
    await search.fill('');
    await expect(page.getByRole('button', { name: `目录：${directoryPath}`, exact: true })).toBeVisible();
    await page.getByRole('button', { name: '目录：工作', exact: true }).click();
    await expect(row).toBeVisible();
    const sourceDirectory = page.getByRole('button', {
      name: `目录：工作/云服务-${testInfo.retry}`,
      exact: true,
    });
    await sourceDirectory.click();
    await expect(sourceDirectory).toHaveAttribute('aria-current', 'page');
    await page.getByRole('button', { name: '修改当前目录' }).click();
    const renameDialog = page.getByRole('dialog', { name: '修改目录名称', exact: true });
    const directoryName = renameDialog.getByRole('textbox', { name: '目录名称', exact: true });
    await expect(directoryName).toHaveValue(`云服务-${testInfo.retry}`);
    await directoryName.fill(`云平台-${testInfo.retry}`);
    await renameDialog.getByRole('button', { name: '保存修改' }).click();
    await expect(page.getByRole('button', { name: `目录：${renamedDirectoryPath}`, exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: `目录：${directoryPath}`, exact: true })).toHaveCount(0);
    await expect(row).toBeVisible();
    await row.click();
    await page.getByRole('button', { name: '编辑', exact: true }).click();
    await expect(page.getByLabel('目录（可选）')).toHaveValue(renamedDirectoryPath);
    await page.getByRole('button', { name: '取消' }).click();
    await page.getByRole('button', { name: '查看密码' }).click();
    await expect(page.getByText('e2e-sub-account-secret-updated-009', { exact: true })).toBeVisible();
    await expect(page.getByText(loginItem.origin, { exact: true })).toBeVisible();

    const credentialTitle = `E2E 示例云 API 凭证-${testInfo.retry}`;
    await page.getByRole('button', { name: '新增关联凭证' }).click();
    await expect(
      page.getByLabel('条目类型').getByRole('button', { name: 'API 凭证' }),
    ).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByLabel('关联账号密码（可选）')).toHaveValue(/.+/);
    await enterIntentionalText(page.getByLabel('标题 *'), credentialTitle);
    await enterIntentionalText(page.getByLabel('凭证标识'), 'AKID-e2e-sub-account');
    await page.getByRole('button', { name: '添加字段' }).click();
    await page.getByRole('button', { name: '说明' }).click();
    await enterIntentionalText(page.getByLabel('说明（可选）'), 'E2E 自动化发布凭证说明');
    await enterIntentionalText(page.getByLabel('密钥 / Token *'), 'e2e-api-secret-010');
    await page.getByRole('button', { name: '保存', exact: true }).click();

    await expect(page.getByRole('heading', { name: credentialTitle })).toBeVisible();
    await expect(page.getByText('E2E 自动化发布凭证说明', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: loginItem.title, exact: true })).toBeVisible();
    await search.fill('E2E 自动化发布凭证说明');
    await expect(page.getByRole('option', { name: new RegExp(credentialTitle) })).toBeVisible();
    await search.fill(loginItem.title);
    await expect(page.getByRole('option', { name: new RegExp(credentialTitle) })).toBeVisible();
    await page.getByRole('button', { name: loginItem.title, exact: true }).click();
    await expect(page.getByRole('button', { name: new RegExp(credentialTitle) })).toBeVisible();
  });

  test('删除空目录并拒绝删除非空目录，不误删条目', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');
    await selectPersonalVault(page);
    const suffix = `${testInfo.retry}-${Date.now().toString(36)}`;
    const parentPath = `删除测试-${suffix}`;
    const childPath = `${parentPath}/空子目录`;
    const itemTitle = `删除测试条目-${suffix}`;
    await ensureDirectoryPath(page, childPath);
    // 在父目录下放一个条目，使父目录非空
    await ensureLoginItem(page, { title: itemTitle, password: 'e2e-delete-secret-010', useCurrentVault: true });
    await page.getByRole('button', { name: '目录：全部', exact: true }).click();
    await page.getByRole('option', { name: new RegExp(escapeRegExp(itemTitle)) }).first().click();
    await page.getByRole('button', { name: '编辑', exact: true }).click();
    await page.getByLabel('目录（可选）').selectOption(parentPath);
    await page.getByRole('button', { name: '保存', exact: true }).click();
    await expect(page.getByRole('main', { name: new RegExp(`条目详情.*${escapeRegExp(itemTitle)}`) })).toBeVisible();
    // 确认条目已归入父目录（父目录计数为 1）
    await expect(page.getByRole('button', { name: `目录：${parentPath}`, exact: true })).toContainText('1');

    // 非空父目录：删除被拒绝并提示，不发起请求、不删条目
    await page.getByRole('button', { name: `目录：${parentPath}`, exact: true }).click();
    await page.getByRole('button', { name: '删除当前目录' }).click();
    await expect(page.getByText(/还有 1 个条目/)).toBeVisible();
    await expect(page.getByRole('button', { name: `目录：${parentPath}`, exact: true })).toBeVisible();

    // 空子目录：二次确认后删除，选中父目录
    await page.getByRole('button', { name: `目录：${childPath}`, exact: true }).click();
    await page.getByRole('button', { name: '删除当前目录' }).click();
    await expect(page.getByText(/确定删除/)).toBeVisible();
    await page.getByRole('button', { name: '删除' }).click();
    await expect(page.getByRole('button', { name: `目录：${childPath}`, exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: `目录：${parentPath}`, exact: true })).toHaveAttribute('aria-current', 'page');
    await expectNoHorizontalOverflow(page);
  });

  test('桌面端拖拽把条目归类到目录，且不自动切换目录', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');
    await selectPersonalVault(page);
    const suffix = `${testInfo.retry}-${Date.now().toString(36)}`;
    const targetFolder = `拖拽目标-${suffix}`;
    const itemTitle = `拖拽条目-${suffix}`;
    await ensureDirectoryPath(page, targetFolder);
    await ensureLoginItem(page, { title: itemTitle, password: 'e2e-drag-secret-011', useCurrentVault: true });
    await expectNoHorizontalOverflow(page);

    const target = page.getByRole('button', { name: `目录：${targetFolder}`, exact: true });
    const row = page.getByRole('option', { name: new RegExp(escapeRegExp(itemTitle)) }).first();
    // 原生 HTML5 DnD：用真实 DataTransfer 分发 dragstart→dragenter→dragover→drop→dragend。
    // 事件内部 MIME 与生产一致（application/x-mima-item），不携带条目 ID 或解密元数据。
    await dragAndDrop(page, row, target);
    // 拖放完成后，条目归入目标目录；选中该条目，详情“目录”字段即目标目录，
    // 证明拖放完成了一次真实加密写入（复用 updateItemMeta，而非改 DOM 伪装成功）。
    await row.click();
    await expect(page.getByRole('main', { name: new RegExp(`条目详情.*${escapeRegExp(itemTitle)}`) })).toBeVisible();
    await expect(page.getByRole('button', { name: targetFolder, exact: true })).toBeVisible();
    await expect(row).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });

  test('平板和手机用“移动到目录”弹窗完成相同行为', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await loginAndUnlock(page, 'bob');
    await selectPersonalVault(page);
    const suffix = `${testInfo.retry}-${Date.now().toString(36)}`;
    const tabletFolder = `弹窗目标-平板-${suffix}`;
    const tabletItem = `弹窗条目-平板-${suffix}`;
    await ensureDirectoryPath(page, tabletFolder);
    // ensureDirectoryPath 会把当前目录过滤设到新建目录上；先回到“全部”，确保条目建在未分类。
    await page.getByRole('button', { name: '目录：全部', exact: true }).click();
    await ensureLoginItem(page, { title: tabletItem, password: 'e2e-move-secret-012', useCurrentVault: true });

    // 平板（900×800）：真实完成一次移动并校验弹窗不越界。
    await page.setViewportSize({ width: 900, height: 800 });
    await moveToFolderViaDialog(page, tabletItem, tabletFolder);

    // 手机（390×844）：导航为抽屉，验证“移动到目录”弹窗可打开、不越界、无横向溢出。
    // （完整移动链路由平板路径与 Web 单测覆盖。）
    const mobileItem = `弹窗条目-手机-${suffix}`;
    const mobileFolder = `弹窗目标-手机-${suffix}`;
    await page.setViewportSize({ width: 1440, height: 900 });
    await ensureDirectoryPath(page, mobileFolder);
    await page.getByRole('button', { name: '目录：全部', exact: true }).click();
    await ensureLoginItem(page, { title: mobileItem, password: 'e2e-move-secret-012b', useCurrentVault: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole('main', { name: new RegExp(`条目详情.*${escapeRegExp(mobileItem)}`) })).toBeVisible();
    await page.getByRole('button', { name: '移动到目录' }).click();
    const mobileDialog = page.getByRole('dialog', { name: '移动到目录' });
    await expect(mobileDialog.getByRole('combobox', { name: '目标目录' })).toBeVisible();
    const mobileBox = await mobileDialog.boundingBox();
    expect(mobileBox).not.toBeNull();
    expect(mobileBox!.x).toBeGreaterThanOrEqual(0);
    expect(mobileBox!.y).toBeGreaterThanOrEqual(0);
    expect(mobileBox!.x + mobileBox!.width).toBeLessThanOrEqual(390);
    expect(mobileBox!.y + mobileBox!.height).toBeLessThanOrEqual(844);
    await expectNoHorizontalOverflow(page);
    await mobileDialog.getByRole('button', { name: '取消' }).click();
  });

  test('团队共享原子分发密钥，撤权后冻结并轮换', async ({ browser }) => {
    const bobContext = await browser.newContext();
    const carolContext = await browser.newContext();
    const bob = await bobContext.newPage();
    const carol = await carolContext.newPage();
    try {
      await loginAndUnlock(carol, 'carol');
      await loginAndUnlock(bob, 'bob');

      const vaultName = `E2E 共享库 ${Date.now().toString(36)}`;
      const itemTitle = `E2E 共享条目 ${Date.now().toString(36)}`;
      await createTeamVault(bob, vaultName);
      await bob.getByRole('button', { name: vaultName, exact: true }).click();
      await ensureLoginItem(bob, {
        title: itemTitle,
        username: 'shared-e2e-user',
        origin: 'https://shared-e2e.example.test',
        password: 'e2e-shared-secret-002',
        useCurrentVault: true,
      });

      await openMembers(bob, vaultName);
      const dialog = bob.getByRole('dialog', { name: new RegExp(`成员管理.*${escapeRegExp(vaultName)}`) });
      await dialog.getByLabel('授权用户').fill('carol');
      await dialog.getByRole('option', { name: /Carol Wu/ }).click();
      await dialog.getByLabel('权限').selectOption('viewer');
      await dialog.getByRole('button', { name: '授权', exact: true }).click();
      await expect(dialog.getByRole('row', { name: /Carol Wu.*已开通/ })).toBeVisible({ timeout: 15_000 });
      await expect(dialog.getByRole('button', { name: '开通', exact: true })).toHaveCount(0);
      await dialog.getByRole('button', { name: '关闭' }).click();

      await expect(carol.getByRole('button', { name: vaultName, exact: true })).toBeVisible({ timeout: 15_000 });
      await carol.getByRole('button', { name: vaultName, exact: true }).click();
      await carol.getByRole('option', { name: new RegExp(itemTitle) }).click();
      await carol.getByRole('button', { name: '查看密码' }).click();
      await expect(carol.getByText('e2e-shared-secret-002', { exact: true })).toBeVisible();

      await openMembers(bob, vaultName);
      const memberRow = bob.getByRole('dialog').getByRole('row', { name: /Carol Wu/ });
      await memberRow.getByRole('button', { name: '移除授权' }).click();
      await bob.getByRole('dialog', { name: '移除密码库授权？' })
        .getByRole('button', { name: '确认移除' })
        .click();
      await expect(bob.getByRole('heading', { name: '密码库正在安全更新' })).toBeVisible();
      await bob.getByRole('button', { name: '完成安全更新' }).click();
      await expect(dialog.getByRole('row', { name: /Carol Wu/ })).toHaveCount(0, { timeout: 20_000 });
      await dialog.getByRole('button', { name: '关闭' }).click();
      await expect(bob.getByRole('navigation', { name: '库导航' })).toBeVisible({ timeout: 20_000 });

      await expect(carol.getByRole('button', { name: vaultName, exact: true })).toHaveCount(0, { timeout: 15_000 });
      await expect(carol.getByText('e2e-shared-secret-002', { exact: true })).toHaveCount(0);
    } finally {
      await Promise.all([bobContext.close(), carolContext.close()]);
    }
  });

  test('拥有者创建后可永久删除团队密码库', async ({ page }) => {
    await loginAndUnlock(page, 'bob');
    const vaultName = `顺丰到付的说法 ${Date.now().toString(36)}`;
    await createTeamVault(page, vaultName);
    const vaultRow = page.getByRole('button', { name: vaultName, exact: true }).locator('..');
    await vaultRow.getByRole('button', { name: vaultName, exact: true }).click();
    await vaultRow.getByRole('button', { name: '删除团队密码库' }).click();

    const dialog = page.getByRole('dialog', { name: '删除团队密码库' });
    const confirmation = dialog.getByLabel('输入完整密码库名称以确认');
    const submit = dialog.getByRole('button', { name: '永久删除' });
    await expect(submit).toBeDisabled();
    await confirmation.fill('顺丰到付');
    await expect(submit).toBeDisabled();
    await confirmation.fill(vaultName);
    await submit.click();

    await expect(page.getByText('团队密码库已删除', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: vaultName, exact: true })).toHaveCount(0);
  });

  test('可选项目从更多设置创建并保持一层独立导航', async ({ page }, testInfo) => {
    await loginAndUnlock(page, 'bob');
    const suffix = `${Date.now().toString(36)}-${testInfo.retry}`;
    const parentName = `E2E 扁平运维库 ${suffix}`;
    const projectName = `E2E 独立项目 ${suffix}`;
    const parentId = await createTeamVault(page, parentName);
    const navigation = page.getByRole('navigation', { name: '库导航' });
    const parentRow = navigation.getByRole('button', { name: parentName, exact: true }).locator('..');

    await parentRow.getByRole('button', { name: '编辑团队密码库' }).click();
    const editParent = page.getByRole('dialog', { name: '编辑团队密码库' });
    await expect(editParent.getByText('更多设置', { exact: true })).toBeVisible();
    await editParent.getByText('更多设置', { exact: true }).click();
    await expect(editParent.getByText(/默认保持扁平密码库最容易使用/)).toBeVisible();
    await editParent.getByRole('button', { name: '新建独立权限项目' }).click();

    const createProject = page.getByRole('dialog', { name: `在「${parentName}」下新建项目` });
    await expect(createProject.getByText('项目拥有独立成员和权限，不会继承上级密码库权限')).toBeVisible();
    await createProject.getByLabel('项目名称').fill(projectName);
    const createResponse = page.waitForResponse((response) =>
      response.request().method() === 'POST' && response.url().endsWith(`/api/v2/vaults/${parentId}/projects`)
    );
    await createProject.getByRole('button', { name: '创建项目', exact: true }).click();
    expect((await createResponse).status()).toBe(201);

    const projectTree = navigation.getByRole('group', { name: `${parentName}的项目`, exact: true });
    await expect(projectTree).toBeVisible();
    await expect(projectTree.getByRole('button', { name: projectName, exact: true })).toBeVisible();
    await expect(projectTree.getByRole('button', { name: `在${parentName}下新建项目` })).toBeVisible();

    await parentRow.getByRole('button', { name: '管理成员' }).click();
    const members = page.getByRole('dialog', { name: new RegExp(`成员管理.*${escapeRegExp(parentName)}`) });
    await expect(members.getByText('批量授权下属项目', { exact: true })).toBeVisible();
    await expect(members.getByText(/不会批量降权、撤权或授予拥有者/)).toBeVisible();
    await members.getByRole('button', { name: '关闭' }).click();

    const projectRow = projectTree.getByRole('button', { name: projectName, exact: true }).locator('..');
    await projectRow.getByRole('button', { name: '编辑团队密码库' }).click();
    const editProject = page.getByRole('dialog', { name: '编辑团队密码库' });
    await expect(editProject.getByText('更多设置', { exact: true })).toHaveCount(0);
    await editProject.getByRole('button', { name: '关闭' }).click();

    await expectNoHorizontalOverflow(page);
    await page.screenshot({ path: testInfo.outputPath('team-vault-project-desktop.png'), fullPage: true });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole('button', { name: '打开密码库导航' }).click();
    const drawer = page.getByRole('dialog', { name: '密码库导航' });
    await expect(drawer.getByRole('group', { name: `${parentName}的项目`, exact: true })).toBeVisible();
    await expect(drawer.getByRole('button', { name: projectName, exact: true })).toBeVisible();
    expect(await drawer.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(0);
    await expectNoHorizontalOverflow(page);
    await page.screenshot({ path: testInfo.outputPath('team-vault-project-mobile.png'), fullPage: true });

    await drawer.getByRole('button', { name: '关闭密码库导航' }).click();
    await page.setViewportSize({ width: 1440, height: 900 });
    const desktopNavigation = page.getByRole('navigation', { name: '库导航' });
    const projectRowForDelete = desktopNavigation
      .getByRole('button', { name: projectName, exact: true })
      .locator('..');
    await projectRowForDelete.getByRole('button', { name: '删除团队密码库' }).click();
    let deleteDialog = page.getByRole('dialog', { name: '删除团队密码库' });
    await deleteDialog.getByLabel('输入完整密码库名称以确认').fill(projectName);
    await deleteDialog.getByRole('button', { name: '永久删除' }).click();
    await expect(desktopNavigation.getByRole('button', { name: projectName, exact: true })).toHaveCount(0);

    const parentRowForDelete = desktopNavigation
      .getByRole('button', { name: parentName, exact: true })
      .locator('..');
    await parentRowForDelete.getByRole('button', { name: '删除团队密码库' }).click();
    deleteDialog = page.getByRole('dialog', { name: '删除团队密码库' });
    await deleteDialog.getByLabel('输入完整密码库名称以确认').fill(parentName);
    await deleteDialog.getByRole('button', { name: '永久删除' }).click();
    await expect(desktopNavigation.getByRole('button', { name: parentName, exact: true })).toHaveCount(0);
  });

  test('平台管理员作为 owner 可给包含自己的用户组授权，未授权管理员仍不可见', async ({ browser }) => {
    const aliceContext = await browser.newContext();
    const bobContext = await browser.newContext();
    const daveContext = await browser.newContext();
    const alice = await aliceContext.newPage();
    const bob = await bobContext.newPage();
    const dave = await daveContext.newPage();
    try {
      await loginAndUnlock(bob, 'bob');
      await loginWithoutUnlock(dave, 'dave');
      await loginAndUnlock(alice, 'alice');

      const suffix = Date.now().toString(36);
      const groupName = `E2E 运维部 ${suffix}`;
      const vaultName = `E2E 管理员团队库 ${suffix}`;

      await alice.getByRole('button', { name: '管理用户组' }).click();
      const groupsDialog = alice.getByRole('dialog', { name: '管理用户组' });
      await groupsDialog.getByRole('button', { name: '新建用户组' }).click();
      await groupsDialog.getByLabel('名称').fill(groupName);
      const memberPicker = groupsDialog.getByLabel('添加用户组成员');
      await memberPicker.fill('alice');
      await groupsDialog.getByRole('option', { name: /Alice Zhang/ }).click();
      await memberPicker.fill('bob');
      await groupsDialog.getByRole('option', { name: /Bob Li/ }).click();
      await groupsDialog.getByRole('button', { name: '保存', exact: true }).click();
      await expect(alice.getByText('用户组已创建', { exact: true })).toBeVisible();
      await groupsDialog.getByRole('button', { name: '关闭' }).click();

      const vaultId = await createTeamVault(alice, vaultName);
      const vaultRow = alice.getByRole('navigation', { name: '库导航' })
        .getByRole('button', { name: vaultName, exact: true })
        .locator('..');
      await expect(vaultRow).toContainText('拥有者');

      await openMembers(alice, vaultName);
      const membersDialog = alice.getByRole('dialog', {
        name: new RegExp(`成员管理.*${escapeRegExp(vaultName)}`),
      });
      await membersDialog.getByRole('button', { name: '平台用户组', exact: true }).click();
      await membersDialog.getByLabel('平台用户组').selectOption({ label: groupName });
      await membersDialog.getByLabel('权限').selectOption('viewer');
      await membersDialog.getByRole('button', { name: '授权', exact: true }).click();
      await expect(membersDialog.getByRole('row', { name: new RegExp(`${escapeRegExp(groupName)}.*查看`) }))
        .toBeVisible();

      const pendingRow = membersDialog.locator('div', { hasText: /Bob Li.*完整访问/ }).last();
      await pendingRow.getByRole('button', { name: '开通', exact: true }).click();
      await expect(membersDialog.getByRole('row', { name: new RegExp(`${escapeRegExp(groupName)}.*已开通`) }))
        .toBeVisible();
      await membersDialog.getByRole('button', { name: '关闭' }).click();

      await expect(bob.getByRole('button', { name: vaultName, exact: true })).toBeVisible({ timeout: 15_000 });
      await expect(dave.getByRole('button', { name: vaultName, exact: true })).toHaveCount(0);
      const unauthorizedProjection = await dave.evaluate(async ({ apiOrigin, targetVaultId }) => {
        const response = await fetch(`${apiOrigin}/api/v2/bootstrap`, { credentials: 'include' });
        const body = await response.json() as {
          vaults: Array<{ id: string }>;
          envelopes: Array<{ vaultId: string }>;
        };
        return {
          hasVault: body.vaults.some((vault) => vault.id === targetVaultId),
          hasEnvelope: body.envelopes.some((envelope) => envelope.vaultId === targetVaultId),
        };
      }, { apiOrigin: E2E_API_ORIGIN, targetVaultId: vaultId });
      expect(unauthorizedProjection).toEqual({ hasVault: false, hasEnvelope: false });

      await openMembers(alice, vaultName);
      const cleanupDialog = alice.getByRole('dialog', {
        name: new RegExp(`成员管理.*${escapeRegExp(vaultName)}`),
      });
      const groupRow = cleanupDialog.getByRole('row', {
        name: new RegExp(`${escapeRegExp(groupName)}.*查看`),
      });
      await groupRow.getByRole('button', { name: '移除授权' }).click();
      await alice.getByRole('dialog', { name: '移除密码库授权？' })
        .getByRole('button', { name: '确认移除' })
        .click();
      await expect(alice.getByRole('heading', { name: '密码库正在安全更新' })).toBeVisible();
      await alice.getByRole('button', { name: '完成安全更新' }).click();
      await expect(cleanupDialog.getByRole('row', { name: new RegExp(escapeRegExp(groupName)) }))
        .toHaveCount(0, { timeout: 20_000 });
      await cleanupDialog.getByRole('button', { name: '关闭' }).click();
      await expect(alice.getByRole('navigation', { name: '库导航' })).toBeVisible({ timeout: 20_000 });
      await expect(bob.getByRole('button', { name: vaultName, exact: true })).toHaveCount(0, { timeout: 15_000 });
    } finally {
      await Promise.all([aliceContext.close(), bobContext.close(), daveContext.close()]);
    }
  });

  test('旧明文接口在严格运行时不可用', async ({ page }) => {
    await loginAndUnlock(page, 'bob');
    const results = await page.evaluate(async (apiOrigin) => {
      const paths = ['/api/bootstrap', '/api/items/00000000-0000-0000-0000-000000000000/reveal'];
      return Promise.all(paths.map(async (path) => {
        const response = await fetch(`${apiOrigin}${path}`, {
          method: path.endsWith('/reveal') ? 'POST' : 'GET',
          credentials: 'include',
          headers: path.endsWith('/reveal') ? { 'content-type': 'application/json' } : undefined,
          body: path.endsWith('/reveal') ? JSON.stringify({ purpose: 'view' }) : undefined,
        });
        return { path, status: response.status, body: await response.text() };
      }));
    }, E2E_API_ORIGIN);
    expect(results.every((result) => result.status === 404 || result.status === 410)).toBe(true);
    expect(JSON.stringify(results)).not.toContain(PERSONAL_ITEM.password);
  });

  test('修改主密码锁定其他在线设备，并可撤销普通 Web 设备', async ({ browser }) => {
    const deviceAContext = await browser.newContext();
    const deviceBContext = await browser.newContext();
    const deviceA = await deviceAContext.newPage();
    const deviceB = await deviceBContext.newPage();
    try {
      await loginAndUnlock(deviceA, 'dave');
      await loginAndUnlock(deviceB, 'dave');

      await deviceB.getByRole('button', { name: '已授权设备' }).click();
      const deviceBDialog = deviceB.getByRole('dialog', { name: '已授权设备' });
      const deviceBFingerprint = await deviceBDialog
        .getByText('当前工作台', { exact: true })
        .locator('..')
        .locator('..')
        .locator('code')
        .textContent();
      expect(deviceBFingerprint).toBeTruthy();
      await deviceBDialog.getByRole('button', { name: '关闭' }).click();

      await deviceA.getByRole('button', { name: '已授权设备' }).click();
      const dialog = deviceA.getByRole('dialog', { name: '已授权设备' });
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: '修改主密码', exact: true }).click();
      await dialog.getByLabel('当前主密码').fill(MAIN_PASSWORDS.dave);
      await dialog.getByLabel('新主密码', { exact: true }).fill(DAVE_UPDATED_MAIN_PASSWORD);
      await dialog.getByLabel('再次输入新主密码', { exact: true }).fill(DAVE_UPDATED_MAIN_PASSWORD);
      await dialog.getByRole('button', { name: '验证并更新' }).click();

      await expect(deviceA.getByText(/主密码已更新/)).toBeVisible({ timeout: 15_000 });
      await dialog.getByRole('button', { name: '关闭' }).click();
      await expect(deviceA.getByRole('navigation', { name: '库导航' })).toBeVisible();
      await expect(deviceB.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible({ timeout: 15_000 });

      await deviceB.locator('#main-password').fill(MAIN_PASSWORDS.dave);
      await deviceB.getByRole('button', { name: '解锁密码库', exact: true }).click();
      await expect(deviceB.getByText('主密码不正确', { exact: true })).toBeVisible();

      await deviceB.locator('#main-password').fill(DAVE_UPDATED_MAIN_PASSWORD);
      await deviceB.getByRole('button', { name: '解锁密码库', exact: true }).click();
      await expect(deviceB.getByRole('navigation', { name: '库导航' })).toBeVisible({ timeout: 20_000 });

      await deviceA.getByRole('button', { name: '已授权设备' }).click();
      const devices = deviceA.getByRole('dialog', { name: '已授权设备' });
      const otherDeviceRevoke = devices
        .getByText(deviceBFingerprint!, { exact: true })
        .locator('..')
        .locator('..')
        .getByRole('button', { name: '撤销设备' });
      await expect(otherDeviceRevoke).toBeVisible();
      const revokeResponse = deviceA.waitForResponse((response) =>
        response.request().method() === 'POST' && response.url().endsWith('/revoke')
      );
      await otherDeviceRevoke.click();
      const confirm = deviceA.getByRole('dialog', { name: '撤销设备' });
      await confirm.getByRole('button', { name: '撤销设备', exact: true }).click();
      const response = await revokeResponse;
      expect(response.status(), await response.text()).toBe(200);

      await expect.poll(() => deviceB.evaluate(
        async (apiOrigin) => (await fetch(`${apiOrigin}/api/v2/bootstrap`, { credentials: 'include' })).status,
        E2E_API_ORIGIN,
      ))
        .toBe(423);
      await expect(deviceA.getByRole('heading', { name: '密码库正在安全更新' })).toBeVisible({ timeout: 15_000 });
      await deviceA.getByRole('button', { name: '完成安全更新' }).click();
      await expect(deviceA.getByRole('navigation', { name: '库导航' })).toBeVisible({ timeout: 20_000 });
      await ensureLoginItem(deviceA, {
        title: 'E2E Web 撤权后写入',
        password: 'e2e-web-device-revoked-secret-007',
      });

      await deviceA.getByRole('button', { name: '已授权设备' }).click();
      const restoreDialog = deviceA.getByRole('dialog', { name: '已授权设备' });
      await restoreDialog.getByRole('button', { name: '修改主密码', exact: true }).click();
      await restoreDialog.getByLabel('当前主密码').fill(DAVE_UPDATED_MAIN_PASSWORD);
      await restoreDialog.getByLabel('新主密码', { exact: true }).fill(MAIN_PASSWORDS.dave);
      await restoreDialog.getByLabel('再次输入新主密码', { exact: true }).fill(MAIN_PASSWORDS.dave);
      await restoreDialog.getByRole('button', { name: '验证并更新' }).click();
      await expect(deviceA.getByText(/主密码已更新/)).toBeVisible({ timeout: 15_000 });
    } finally {
      await Promise.all([deviceAContext.close(), deviceBContext.close()]);
    }
  });
});

/** 通过“移动到目录”弹窗把指定条目移动到目标目录，并校验弹窗不越界、移动成功。
 *  移动成功以条目详情“目录”字段变为目标目录为准（不依赖瞬时 toast）。 */
async function moveToFolderViaDialog(page: Page, itemTitle: string, targetFolder: string): Promise<void> {
  await page.getByRole('option', { name: new RegExp(escapeRegExp(itemTitle)) }).first().click();
  await expect(page.getByRole('main', { name: new RegExp(`条目详情.*${escapeRegExp(itemTitle)}`) })).toBeVisible();
  await page.getByRole('button', { name: '移动到目录' }).click();
  const dialog = page.getByRole('dialog', { name: '移动到目录' });
  const folderSelect = dialog.getByRole('combobox', { name: '目标目录' });
  await expect(folderSelect).toBeVisible();
  await folderSelect.selectOption(targetFolder);
  await expect(folderSelect).toHaveValue(targetFolder);
  const moveAction = dialog.getByRole('button', { name: '移动' });
  await expect(moveAction).toBeEnabled();
  // 弹窗不越界：移动前检查几何（成功后弹窗会关闭）。
  const box = await dialog.boundingBox();
  if (box) {
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    expect(box.y + box.height).toBeLessThanOrEqual(page.viewportSize()!.height);
  }
  await expectNoHorizontalOverflow(page);
  await moveAction.click();
  // 移动成功：弹窗关闭，详情“目录”字段变为目标目录（手机端导航抽屉关闭，故用详情字段而非目录按钮断言）。
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('main', { name: new RegExp(`条目详情.*${escapeRegExp(itemTitle)}`) })).toBeVisible();
  await expect(page.getByRole('button', { name: targetFolder, exact: true }).first()).toBeVisible();
}

async function selectPersonalVault(page: Page): Promise<void> {
  const personalVault = page.getByRole('navigation', { name: '库导航' })
    .locator('button[title$="个人密码库"]').first();
  await expect(personalVault).toBeVisible();
  if (
    await personalVault.getAttribute('aria-current') !== 'page'
    || await personalVault.getAttribute('data-tree-expanded') !== 'true'
  ) await personalVault.click();
  await expect(personalVault).toHaveAttribute('aria-current', 'page');
  await expect(personalVault).toHaveAttribute('data-tree-expanded', 'true');
}

/**
 * 真实 HTML5 拖放：Playwright 的 mouse.down/up 不会自动合成可携带自定义 MIME 的
 * DataTransfer，因此这里直接在源/目标元素上按真实顺序分发 dragstart→dragenter→
 * dragover→drop→dragend。事件只携带固定的内部 MIME，与生产安全约束一致；
 * 不在 DataTransfer 中放入条目 ID 或任何解密元数据。
 */
async function dragAndDrop(page: Page, source: Locator, target: Locator): Promise<void> {
  await source.scrollIntoViewIfNeeded();
  await target.scrollIntoViewIfNeeded();
  await page.evaluate(async ({ srcSel, tgtSel }) => {
    const mime = 'application/x-mima-item';
    const transfer = new DataTransfer();
    transfer.setData(mime, 'move');
    const fire = (type: string, el: Element) => {
      el.dispatchEvent(new DragEvent(type, { bubbles: true, cancelable: true, composed: true, dataTransfer: transfer }));
    };
    const src = document.querySelector(srcSel) as Element | null;
    const tgt = document.querySelector(tgtSel) as Element | null;
    if (!src || !tgt) throw new Error('drag source or target not found');
    fire('dragstart', src);
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    const readyTargets = [...document.querySelectorAll('[data-drop-state="ready"]')];
    if (readyTargets.length < 2) throw new Error('compatible folder targets were not highlighted');
    if (readyTargets.some((element) => element.getBoundingClientRect().height < 44)) {
      throw new Error('compatible folder target is smaller than the 44px interaction baseline');
    }
    if (document.querySelector('[aria-label="目录：全部"]')?.hasAttribute('data-drop-state')) {
      throw new Error('non-drop target was highlighted');
    }
    fire('dragenter', tgt);
    fire('dragover', tgt);
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    if (tgt.getAttribute('data-drop-state') !== 'over') {
      throw new Error('hovered folder target was not emphasized');
    }
    fire('drop', tgt);
    fire('dragend', src);
  }, {
    srcSel: await source.evaluate((el) => {
      if (!el.id) el.id = `__drag-src-${Math.random().toString(36).slice(2)}`;
      return `#${el.id}`;
    }),
    tgtSel: await target.evaluate((el) => {
      if (!el.id) el.id = `__drag-tgt-${Math.random().toString(36).slice(2)}`;
      return `#${el.id}`;
    }),
  });
}

async function ensureDirectoryPath(page: Page, directoryPath: string): Promise<void> {
  let parentPath = '';
  for (const segment of directoryPath.split('/')) {
    const currentPath = parentPath ? `${parentPath}/${segment}` : segment;
    const current = page.getByRole('button', { name: `目录：${currentPath}`, exact: true });
    if (!await current.count()) {
      await page.getByRole('button', {
        name: parentPath ? `目录：${parentPath}` : '目录：全部',
        exact: true,
      }).click();
      await page.getByRole('button', { name: '新建目录' }).click();
      const dialog = page.getByRole('dialog', { name: '新建目录' });
      await expect(dialog.getByLabel('上级目录')).toHaveValue(parentPath);
      await dialog.getByLabel('目录名称').fill(segment);
      await dialog.getByRole('button', { name: '创建目录' }).click();
      await expect(current).toBeVisible();
    }
    parentPath = currentPath;
  }
}

async function createTeamVault(page: Page, name: string): Promise<string> {
  await page.getByRole('button', { name: '新建团队库' }).click();
  const dialog = page.getByRole('dialog', { name: '新建团队密码库' });
  await expect(dialog.getByRole('combobox', { name: '初始拥有者' })).toHaveCount(0);
  await dialog.getByLabel('团队密码库名称').fill(name);
  const createResponse = page.waitForResponse((response) =>
    response.request().method() === 'POST' && response.url().endsWith('/api/v2/vaults')
  );
  await dialog.getByRole('button', { name: '创建并进入', exact: true }).click();
  const response = await createResponse;
  const responseBody = (await response.json()) as { id: string };
  expect(response.status(), JSON.stringify(responseBody)).toBe(201);
  const vaultId = responseBody.id;
  await expect(page.getByRole('button', { name, exact: true })).toBeVisible({ timeout: 15_000 });
  return vaultId;
}

async function openMembers(page: Page, vaultName: string): Promise<void> {
  const vaultRow = page.getByRole('navigation', { name: '库导航' })
    .getByRole('button', { name: vaultName, exact: true })
    .locator('..');
  await vaultRow.getByRole('button', { name: '管理成员' }).click();
  await expect(page.getByRole('dialog', { name: new RegExp(`成员管理.*${escapeRegExp(vaultName)}`) })).toBeVisible();
}

async function loginWithoutUnlock(page: Page, username: string): Promise<void> {
  await page.addInitScript(() => {
    localStorage.setItem(
      'mima.guide.v1',
      JSON.stringify({ promptShown: true, tourCompleted: true }),
    );
  });
  await page.goto('/');
  await page.getByLabel('用户名').fill(username);
  await page.getByLabel('开发密码').fill('dev');
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: '创建主密码' })
      .or(page.getByRole('heading', { name: '解锁你的密码库' })),
  ).toBeVisible({ timeout: 30_000 });
}

async function injectBrowserReplacement(locator: Locator, value: string): Promise<void> {
  await locator.evaluate((element, injectedValue) => {
    const input = element as HTMLInputElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    valueSetter?.call(input, injectedValue);
    input.dispatchEvent(new InputEvent('input', {
      bubbles: true,
      inputType: 'insertReplacementText',
      data: injectedValue,
    }));
  }, value);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
