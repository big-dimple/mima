import { execSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, type Locator, type Page } from '@playwright/test';

const CDP = process.env.MIMA_GUI_CDP ?? 'http://127.0.0.1:9333';
const WEB_ORIGIN = process.env.MIMA_GUI_WEB_ORIGIN ?? 'http://localhost:4183';
const DISPLAY = process.env.DISPLAY ?? ':0';
const USERNAME = process.env.MIMA_GUI_USERNAME ?? 'bob';
const MAIN_PASSWORD = process.env.MIMA_GUI_MAIN_PASSWORD ?? 'Bob-e2e-main-password-2026';
const EXTENSION_ID = 'gkhbkfdgghiaoohpldbjkpmopaojjhhp';
const EVIDENCE_DIR = process.env.MIMA_GUI_EVIDENCE_DIR ?? join(tmpdir(), 'mima-gui-evidence');
const runId = Date.now().toString(36);
const item = {
  title: `GUI 严格扩展登录 ${runId}`,
  username: `gui-user-${runId}`,
  origin: new URL(WEB_ORIGIN).origin,
  loginUrl: `${new URL(WEB_ORIGIN).origin}/demo-login.html?account=${runId}#sign-in`,
  password: `Gui-fill-${runId}-A9!secure`,
};

if (!/^:\d+(?:\.\d+)?$/.test(DISPLAY)) throw new Error(`不支持的 DISPLAY: ${DISPLAY}`);

function xdo(command: string): void {
  execSync(`DISPLAY=${DISPLAY} xdotool ${command}`, { stdio: 'pipe' });
}

function focusBrowserWindow(): void {
  const geometry = execSync(
    `DISPLAY=${DISPLAY} sh -c 'WIN=$(xdotool search --onlyvisible --class "chromium|google-chrome|chrome" | head -1); test -n "$WIN"; xdotool getwindowgeometry --shell "$WIN"'`,
    { encoding: 'utf8' },
  );
  const values = Object.fromEntries(
    geometry.trim().split('\n').map((line) => line.split('=')),
  ) as Record<string, string>;
  xdo(`mousemove ${Number(values.X) + Number(values.WIDTH) / 2} ${Number(values.Y) + Number(values.HEIGHT) / 2} click 1`);
}

async function isVisible(locator: Locator, timeout = 1_000): Promise<boolean> {
  return locator.isVisible({ timeout }).catch(() => false);
}

async function loginAndUnlock(page: Page): Promise<void> {
  await page.addInitScript(() => {
    localStorage.setItem(
      'mima.guide.v1',
      JSON.stringify({ promptShown: true, tourCompleted: true }),
    );
  });
  await page.goto(`${WEB_ORIGIN}/`);

  const loginInput = page.getByLabel('用户名');
  const setupHeading = page.getByRole('heading', { name: '创建主密码' });
  const lockedHeading = page.getByRole('heading', { name: '解锁你的密码库' });
  const migrationHeading = page.getByRole('heading', { name: '正在准备工作台' });
  const rekeyHeading = page.getByRole('heading', { name: '密码库正在安全更新' });
  const workspace = page.getByRole('region', { name: '凭证列表' });
  const errorAlert = page.getByRole('region', { name: '通知' }).getByRole('alert').last();
  await loginInput.or(setupHeading).or(lockedHeading).or(migrationHeading).or(rekeyHeading).or(workspace)
    .first()
    .waitFor({ state: 'visible', timeout: 20_000 });

  if (await isVisible(loginInput)) {
    await loginInput.fill(USERNAME);
    await page.getByLabel('开发密码').fill('dev');
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await setupHeading.or(lockedHeading).or(migrationHeading).or(rekeyHeading).or(workspace)
      .first()
      .waitFor({ state: 'visible', timeout: 30_000 });
  }

  if (await isVisible(setupHeading)) {
    await page.locator('#new-main-password').fill(MAIN_PASSWORD);
    await page.locator('#confirm-main-password').fill(MAIN_PASSWORD);
    await page.getByRole('button', { name: '创建主密码并继续' }).click();
  } else if (await isVisible(lockedHeading)) {
    await page.locator('#main-password').fill(MAIN_PASSWORD);
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
  }

  await migrationHeading.or(rekeyHeading).or(workspace).or(errorAlert)
    .first()
    .waitFor({ state: 'visible', timeout: 30_000 });
  if (await isVisible(errorAlert) && !await isVisible(workspace)) {
    throw new Error(`严格 Web 解锁失败: ${await errorAlert.innerText()}`);
  }

  if (await isVisible(migrationHeading, 10_000)) {
    const initialize = page.getByRole('button', { name: '创建并进入工作台' }).first();
    if (await isVisible(initialize, 10_000)) {
      await page.getByLabel('密码库名称').first().fill(`${USERNAME} 个人密码库`);
      await initialize.click();
    }
  }

  if (await isVisible(rekeyHeading, 5_000)) {
    const complete = page.getByRole('button', { name: '完成安全更新' });
    for (let attempt = 0; attempt < 20 && await complete.count() > 0; attempt += 1) {
      await complete.first().click();
      await page.waitForTimeout(250);
    }
  }

  await workspace.waitFor({ state: 'visible', timeout: 30_000 });
  await page.getByText('在线', { exact: true }).waitFor({ state: 'visible', timeout: 15_000 });
}

async function createLoginItem(page: Page): Promise<void> {
  const navigation = page.getByRole('navigation', { name: '库导航' });
  const personalVault = navigation.locator('#personal-vaults button[data-tree-row="true"]').first();
  await personalVault.waitFor({ state: 'visible', timeout: 15_000 });
  if (
    await personalVault.getAttribute('aria-current') !== 'page'
    || await personalVault.getAttribute('data-tree-expanded') !== 'true'
  ) await personalVault.click();
  await page.getByRole('button', { name: '新建', exact: true }).click();
  await enterIntentionalText(page.getByLabel('标题 *'), item.title);
  await enterIntentionalText(page.getByLabel('账号'), item.username);
  await enterIntentionalText(page.getByLabel('网址（主网址，可选）'), item.loginUrl);
  await enterIntentionalText(page.getByLabel('密码（可选）'), item.password);
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await page.getByRole('option', { name: new RegExp(item.title) })
    .waitFor({ state: 'visible', timeout: 15_000 });
}

async function enterIntentionalText(locator: Locator, value: string): Promise<void> {
  await locator.click();
  if ([...value].some((character) => (character.codePointAt(0) ?? 0) > 0x7f)) {
    const page = locator.page();
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], {
      origin: new URL(page.url()).origin,
    });
    await page.evaluate((text) => navigator.clipboard.writeText(text), value);
    await locator.press('Control+V');
    return;
  }
  await locator.pressSequentially(value);
}

async function openRealSidePanel(): Promise<Page> {
  focusBrowserWindow();
  xdo('key --clearmodifiers ctrl+shift+space');
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const targets = await fetch(`${CDP}/json/list`).then((response) => response.json()) as Array<{ url: string }>;
    if (targets.some((target) => target.url.includes(`${EXTENSION_ID}/sidepanel.html`))) {
      const browser = await chromium.connectOverCDP(CDP);
      const panel = browser.contexts()[0]?.pages()
        .find((page) => page.url().includes(`${EXTENSION_ID}/sidepanel.html`));
      if (panel) return panel;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error('Ctrl+Shift+Space 未打开Mima侧边栏');
}

async function pairExtension(web: Page, panel: Page): Promise<void> {
  await panel.getByRole('heading', { name: 'Mima · 扩展配对' })
    .waitFor({ state: 'visible', timeout: 10_000 });
  await web.getByRole('button', { name: '配对浏览器扩展' }).click();
  const dialog = web.getByRole('dialog', { name: '配对浏览器扩展' });
  const code = await dialog.getByText(/^[A-Z2-9]{8}$/).innerText();

  await panel.getByLabel('一次性配对码').fill(code);
  await panel.getByLabel('设备名称').fill(`GUI 扩展 ${runId}`);
  const compatibilityPassword = panel.locator('input[type="password"]');
  const passwordFieldCount = await compatibilityPassword.count();
  if (passwordFieldCount > 1) throw new Error('扩展兼容配对不应重复确认当前主密码');
  if (passwordFieldCount === 1) await compatibilityPassword.fill(MAIN_PASSWORD);
  await panel.getByRole('button', { name: '开始配对' }).click();

  const panelFingerprint = await panel.locator('code.fingerprint').innerText();
  await dialog.getByText('待批准设备指纹').waitFor({ state: 'visible', timeout: 15_000 });
  const webFingerprint = await dialog.locator('code').filter({ hasText: panelFingerprint }).innerText();
  if (webFingerprint !== panelFingerprint) throw new Error('Web 与扩展设备指纹不一致');
  await dialog.getByRole('button', { name: '指纹一致，批准此设备' }).click();
  await dialog.getByText(/扩展已获准连接/)
    .waitFor({ state: 'visible', timeout: 15_000 });

  await panel.getByRole('button', { name: '已确认，检查授权' }).click();
  await dialog.getByRole('button', { name: '关闭' }).click();
  await panel.getByLabel('搜索已解锁条目')
    .waitFor({ state: 'visible', timeout: 20_000 });
}

async function fillThroughExtension(panel: Page, demo: Page): Promise<void> {
  await demo.goto(item.loginUrl);
  await demo.bringToFront();
  focusBrowserWindow();
  await panel.getByRole('button', { name: '刷新' }).click();
  await panel.getByText('当前页面：').waitFor({ state: 'visible', timeout: 10_000 });
  const currentOrigin = await panel.locator('.originBar code').innerText();
  if (currentOrigin !== item.origin) throw new Error(`扩展读取到错误的网站地址: ${currentOrigin}`);

  const row = panel.locator('.item', { hasText: item.title });
  await row.getByRole('button', { name: '填充' }).waitFor({ state: 'visible', timeout: 15_000 });
  await row.getByRole('button', { name: '填充' }).click();
  await demo.waitForTimeout(1_000);
  const username = await demo.locator('#user').inputValue();
  const password = await demo.locator('#pass').inputValue();
  if (username !== item.username || password !== item.password) throw new Error('扩展未把目标登录条目准确填入页面');

  const persisted = await panel.evaluate(async () => JSON.stringify({
    local: await chrome.storage.local.get(null),
    session: await chrome.storage.session.get(null),
  }));
  for (const plaintext of [item.title, item.username, item.origin, item.loginUrl, item.password, MAIN_PASSWORD]) {
    if (persisted.includes(plaintext)) throw new Error('扩展持久化中发现测试明文');
  }
}

async function main(): Promise<void> {
  mkdirSync(EVIDENCE_DIR, { recursive: true, mode: 0o700 });
  const browser = await chromium.connectOverCDP(CDP);
  const context = browser.contexts()[0];
  if (!context) throw new Error('CDP 中没有可用浏览器上下文');
  const web = context.pages().find((page) => page.url().startsWith(WEB_ORIGIN)) ?? await context.newPage();
  await loginAndUnlock(web);
  console.log('[1] 严格 Web 登录并在本地解锁完成');
  await createLoginItem(web);
  console.log('[2] 测试登录条目已通过 Web 界面客户端加密保存');
  const panel = await openRealSidePanel();
  console.log('[3] Ctrl+Shift+Space 已用真实键盘事件打开侧边栏');
  await pairExtension(web, panel);
  await panel.screenshot({ path: join(EVIDENCE_DIR, 'strict-extension-unlocked.png'), animations: 'disabled' });
  console.log('[4] 指纹核对、设备批准和扩展本地解锁完成');
  const demo = await context.newPage();
  await fillThroughExtension(panel, demo);
  await demo.screenshot({ path: join(EVIDENCE_DIR, 'strict-extension-fill.png'), animations: 'disabled' });
  console.log('[5] activeTab 精确匹配和真实表单填充通过，持久化未发现测试明文');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : 'GUI 验收失败');
  process.exit(1);
});
