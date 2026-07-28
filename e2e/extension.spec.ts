import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, expect, test, type BrowserContext, type Page } from '@playwright/test';
import { fillLoginForm } from '../apps/extension/src/fill.ts';
import {
  E2E_API_ORIGIN,
  ensureLoginItem,
  expectNoHorizontalOverflow,
  loginAndUnlock,
  MAIN_PASSWORDS,
} from './helpers.ts';

const extensionPath = resolve(dirname(fileURLToPath(import.meta.url)), '../apps/extension/dist-e2e');
const E2E_API_HOST = process.env.MIMA_E2E_API_HOST ?? '127.0.0.1';
const E2E_API_URL_HOST = E2E_API_HOST.includes(':') ? `[${E2E_API_HOST}]` : E2E_API_HOST;
const E2E_WEB_ORIGIN = `http://${E2E_API_URL_HOST}:14273`;
const screenshotDir = process.env.MIMA_E2E_SCREENSHOT_DIR
  ?? join(tmpdir(), 'mima-e2e-screenshots');
const EXPECTED_EXTENSION_ID = 'gkhbkfdgghiaoohpldbjkpmopaojjhhp';
const EXTENSION_ITEM = {
  title: 'E2E 扩展登录',
  username: 'extension-e2e-user',
  origin: 'https://extension-e2e.example.test',
  password: 'e2e-extension-secret-canary-005',
};
const EXTENSION_RUN_SUFFIX = Date.now().toString(36);
const EXTENSION_PARENT_VAULT = `E2E 扩展多库换钥 ${EXTENSION_RUN_SUFFIX}`;
const EXTENSION_PROJECT = `E2E 扩展项目换钥 ${EXTENSION_RUN_SUFFIX}`;

let context: BrowserContext;
let extensionId: string;
let userDataDir: string;
let panel: Page;
let web: Page;
let standbyWeb: Page;
let staleWeb: Page;
let extensionSigningKeyPrefix: string;

test.beforeAll(async () => {
  userDataDir = mkdtempSync(join(tmpdir(), 'mima-extension-e2e-'));
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });
  let [serviceWorker] = context.serviceWorkers();
  if (!serviceWorker) serviceWorker = await context.waitForEvent('serviceworker');
  extensionId = new URL(serviceWorker.url()).host;
  expect(extensionId).toBe(EXPECTED_EXTENSION_ID);
});

test.afterAll(async () => {
  await context.close();
  rmSync(userDataDir, { recursive: true, force: true });
});

test.describe.serial('浏览器扩展零知识链路', () => {
  test('清单只持续读取标签元数据且网站注入必须按需授权', async () => {
    const manifest = JSON.parse(readFileSync(join(extensionPath, 'manifest.json'), 'utf8')) as {
      permissions: string[];
      host_permissions?: string[];
      optional_host_permissions?: string[];
      commands: Record<string, { suggested_key: { default: string } }>;
    };
    expect(manifest.permissions.sort()).toEqual(['activeTab', 'scripting', 'sidePanel', 'storage', 'tabs']);
    expect(manifest.permissions).not.toContain('history');
    expect((manifest.host_permissions ?? []).sort()).toEqual([...new Set([
      'http://127.0.0.1/*',
      'http://localhost/*',
      `http://${E2E_API_URL_HOST}/*`,
    ])].sort());
    expect(manifest.optional_host_permissions ?? []).toEqual(['http://*/*', 'https://*/*']);
    expect(manifest.host_permissions).not.toContain('<all_urls>');
    expect(manifest.host_permissions?.some((permission) => permission.startsWith('https://'))).toBe(false);
    expect(manifest.commands['open-panel']?.suggested_key.default).toBe('Ctrl+Shift+Space');

    const currentPage = await context.newPage();
    await currentPage.goto(`${E2E_WEB_ORIGIN}/demo-login.html?tenant=example-a&type=subAccount`);
    await currentPage.bringToFront();
    const [serviceWorker] = context.serviceWorkers();
    const activeTab = await serviceWorker!.evaluate(async () => {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      return { id: tab?.id, url: tab?.url };
    });
    expect(activeTab.id).toBeTruthy();
    expect(activeTab.url).toBe(`${E2E_WEB_ORIGIN}/demo-login.html?tenant=example-a&type=subAccount`);
    await currentPage.close();
  });

  test('一次性码只创建待审批设备，工作台批准后无密码完成本机解锁', async () => {
    web = await context.newPage();
    await loginAndUnlock(web, 'bob');
    await createTeamProjectFixture(web);
    await ensureLoginItem(web, EXTENSION_ITEM);
    await web.getByRole('button', { name: '配对浏览器扩展' }).click();
    const webDialog = web.getByRole('dialog', { name: '配对浏览器扩展' });
    const code = await webDialog.getByText(/^[A-Z2-9]{8}$/).innerText();

    panel = await context.newPage();
    await panel.setViewportSize({ width: 400, height: 600 });
    await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
    await expect(panel.getByRole('heading', { name: 'Mima · 扩展配对' })).toBeVisible();
    await panel.getByLabel('一次性配对码').fill(code);
    await panel.getByLabel('设备名称').fill('E2E 浏览器扩展');
    await expect(panel.getByText('无需在扩展重复输入主密码')).toBeVisible();
    await expect(panel.locator('input[type="password"]')).toHaveCount(0);
    await panel.getByRole('button', { name: '开始配对' }).click();

    const panelFingerprint = await panel.locator('code.fingerprint').innerText();
    await expect(webDialog.getByText('待批准设备指纹')).toBeVisible({ timeout: 10_000 });
    await expect(webDialog.locator('code').filter({ hasText: panelFingerprint })).toBeVisible();
    const approvalResponse = web.waitForResponse((response) =>
      response.request().method() === 'POST'
      && /\/api\/v2\/extension\/enrollments\/[^/]+\/approve$/.test(new URL(response.url()).pathname)
    );
    await webDialog.getByRole('button', { name: '指纹一致，批准此设备' }).click();
    const approval = await approvalResponse;
    expect(approval.status(), await approval.text()).toBe(200);
    const approvedEnrollmentId = new URL(approval.url()).pathname.split('/').at(-2);
    await expect(webDialog.getByText(/扩展已获准连接/))
      .toBeVisible({ timeout: 15_000 });
    await webDialog.getByRole('button', { name: '关闭' }).click();

    const panelNetwork: string[] = [];
    panel.on('response', (response) => {
      if (response.url().includes('/api/v2/extension/')) {
        panelNetwork.push(`${response.status()} ${new URL(response.url()).pathname}`);
      }
    });
    const pairingStatusResponse = panel.waitForResponse((response) =>
      response.request().method() === 'GET'
      && /\/api\/v2\/extension\/pairing\/[^/]+$/.test(new URL(response.url()).pathname)
    );
    await panel.getByRole('button', { name: '已确认，检查授权' }).click();
    const pairingStatus = await (await pairingStatusResponse).json() as {
      enrollmentId: string;
      status: string;
    };
    expect(pairingStatus.enrollmentId).toBe(approvedEnrollmentId);
    expect(pairingStatus.status).toBe('approved');
    const readySearch = panel.getByLabel('搜索已解锁条目');
    await expect.poll(async () => {
      if (await readySearch.isVisible()) return 'ready';
      const errors = await panel.getByRole('alert').allInnerTexts();
      if (errors.length > 0) return `error: ${errors.join(' | ')}`;
      const body = (await panel.locator('body').innerText()).replace(/\s+/g, ' ').trim();
      return `waiting: ${body} | network: ${panelNetwork.join(', ') || 'none'}`;
    }, {
      message: '扩展应由已解锁工作台完成本机解锁；收到 error 时会在断言中保留页面原因',
      timeout: 20_000,
    }).toBe('ready');
    extensionSigningKeyPrefix = await panel.evaluate(async () => {
      const stored = await chrome.storage.local.get('lmE2eeDevice') as {
        lmE2eeDevice?: { signingPublicKey?: string };
      };
      return stored.lmE2eeDevice?.signingPublicKey?.slice(0, 12) ?? '';
    });
    expect(extensionSigningKeyPrefix).toHaveLength(12);
    await panel.getByLabel('搜索已解锁条目').fill(EXTENSION_ITEM.title);
    await expect(panel.getByText(EXTENSION_ITEM.title, { exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(panel);
    await panel.screenshot({
      path: join(screenshotDir, 'extension-panel-400x600.png'),
      animations: 'disabled',
      fullPage: true,
    });

    const persisted = await panel.evaluate(async () => JSON.stringify({
      local: await chrome.storage.local.get(null),
      session: await chrome.storage.session.get(null),
    }));
    expect(persisted).not.toContain(EXTENSION_ITEM.title);
    expect(persisted).not.toContain(EXTENSION_ITEM.username);
    expect(persisted).not.toContain(EXTENSION_ITEM.origin);
    expect(persisted).not.toContain(EXTENSION_ITEM.password);
    expect(persisted).not.toContain(MAIN_PASSWORDS.bob);
  });

  test('三个工作台标签只由一个主端点恢复，失去响应后才切换', async () => {
    standbyWeb = await context.newPage();
    await loginAndUnlock(standbyWeb, 'bob');
    staleWeb = await context.newPage();
    await loginAndUnlock(staleWeb, 'bob');
    await staleWeb.bringToFront();
    await expect(staleWeb.getByRole('region', { name: '凭证列表' })).toBeVisible();

    const staleCdp = await context.newCDPSession(staleWeb);
    await staleCdp.send('Page.setWebLifecycleState', { state: 'frozen' });
    const resumeResponses: Array<{ status: number; url: string }> = [];
    const captureResume = (response: import('@playwright/test').Response) => {
      if (
        response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/v2/extension/session/resume'
      ) {
        resumeResponses.push({ status: response.status(), url: response.url() });
      }
    };
    context.on('response', captureResume);

    await panel.bringToFront();
    await panel.evaluate(async () => chrome.storage.session.clear());
    await panel.reload();

    await expect(panel.getByLabel('搜索已解锁条目')).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => resumeResponses.length, { timeout: 5_000 }).toBeGreaterThan(0);
    await panel.waitForTimeout(2_000);
    expect(resumeResponses).toHaveLength(1);
    expect(resumeResponses[0]?.status).toBe(200);
    await expect(panel.getByText('暂时无法连接服务，当前显示此浏览器保存的数据')).toHaveCount(0);
    await staleCdp.send('Page.setWebLifecycleState', { state: 'active' });
    context.off('response', captureResume);
  });

  test('两个侧栏共享一笔原子恢复，首个 bootstrap 完成前不放行第二笔', async () => {
    const secondPanel = await context.newPage();
    await secondPanel.setViewportSize({ width: 400, height: 600 });
    const resumeResponses: number[] = [];
    const challengeResponses: number[] = [];
    const captureRecovery = (response: import('@playwright/test').Response) => {
      const pathname = new URL(response.url()).pathname;
      if (response.request().method() === 'POST' && pathname === '/api/v2/extension/session/resume') {
        resumeResponses.push(response.status());
      }
      if (response.request().method() === 'POST' && pathname === '/api/v2/extension/unlock-challenges') {
        challengeResponses.push(response.status());
      }
    };
    let releaseBootstrap!: () => void;
    const bootstrapGate = new Promise<void>((resolve) => { releaseBootstrap = resolve; });
    let markBootstrapBlocked!: () => void;
    const bootstrapBlocked = new Promise<void>((resolve) => { markBootstrapBlocked = resolve; });
    let blocked = false;
    await context.route('**/api/v2/extension/bootstrap', async (route) => {
      if (!blocked && route.request().frame().page().url().startsWith(`chrome-extension://${extensionId}/`)) {
        blocked = true;
        markBootstrapBlocked();
        await bootstrapGate;
      }
      await route.continue();
    });
    context.on('response', captureRecovery);
    await panel.evaluate(async () => chrome.storage.session.clear());

    await Promise.all([
      panel.reload(),
      secondPanel.goto(`chrome-extension://${extensionId}/sidepanel.html`),
    ]);
    await bootstrapBlocked;
    await expect.poll(() => resumeResponses.length, { timeout: 5_000 }).toBe(1);
    await panel.waitForTimeout(500);
    expect(resumeResponses).toEqual([200]);
    expect(challengeResponses).toEqual([200]);

    releaseBootstrap();
    await expect(panel.getByLabel('搜索已解锁条目')).toBeVisible({ timeout: 15_000 });
    await expect(secondPanel.getByLabel('搜索已解锁条目')).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => challengeResponses.length, { timeout: 5_000 }).toBe(2);
    expect(resumeResponses).toEqual([200]);
    expect(challengeResponses).toEqual([200, 200]);
    await expect(panel.getByRole('button', { name: '重试工作台联动' })).toHaveCount(0);
    await expect(secondPanel.getByRole('button', { name: '重试工作台联动' })).toHaveCount(0);

    context.off('response', captureRecovery);
    await context.unroute('**/api/v2/extension/bootstrap');
    await secondPanel.close();
  });

  test('旧版工作台标签仍打开时不会扰动新版恢复', async () => {
    const accountId = await web.evaluate(async (apiOrigin) => {
      const response = await fetch(`${apiOrigin}/api/session`, { credentials: 'include' });
      const session = await response.json() as { user: { id: string } };
      return session.user.id;
    }, E2E_API_ORIGIN);
    await standbyWeb.evaluate(({ targetExtensionId, userId }) => {
      const wakeEvent = 'mima-extension-wake-v1';
      let legacyPort: chrome.runtime.Port | null = null;
      let stateGeneration = 0;
      let reconnectTimer: number | null = null;
      const connectLegacy = () => {
        if (legacyPort) return;
        const port = chrome.runtime.connect(targetExtensionId, { name: 'mima-workbench-v1' });
        legacyPort = port;
        port.onDisconnect.addListener(() => {
          if (legacyPort !== port) return;
          legacyPort = null;
          reconnectTimer = window.setTimeout(connectLegacy, 1_500);
        });
        port.postMessage({
          kind: 'workbench_state',
          accountId: userId,
          unlocked: true,
          stateGeneration: ++stateGeneration,
          visibility: 'visible',
          focused: true,
        });
      };
      const reconnectLegacy = () => {
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
        const previous = legacyPort;
        legacyPort = null;
        previous?.disconnect();
        connectLegacy();
      };
      window.addEventListener(wakeEvent, reconnectLegacy);
      (window as typeof window & { stopLegacyWorkbench?: () => void }).stopLegacyWorkbench = () => {
        window.removeEventListener(wakeEvent, reconnectLegacy);
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        legacyPort?.disconnect();
        legacyPort = null;
      };
      connectLegacy();
    }, { targetExtensionId: extensionId, userId: accountId });

    const resumeResponses: number[] = [];
    const captureResume = (response: import('@playwright/test').Response) => {
      if (
        response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/v2/extension/session/resume'
      ) resumeResponses.push(response.status());
    };
    context.on('response', captureResume);
    await panel.evaluate(async () => chrome.storage.session.clear());
    const cdp = await context.newCDPSession(panel);
    const { targetInfos } = await cdp.send('Target.getTargets') as {
      targetInfos: Array<{ targetId: string; type: string; url: string }>;
    };
    const workerTarget = targetInfos.find((target) => (
      target.type === 'service_worker'
      && target.url === `chrome-extension://${extensionId}/background.js`
    ));
    expect(workerTarget).toBeTruthy();
    await cdp.send('Target.closeTarget', { targetId: workerTarget!.targetId });

    await panel.reload();

    await expect(panel.getByLabel('搜索已解锁条目')).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => resumeResponses.length, { timeout: 5_000 }).toBeGreaterThan(0);
    await panel.waitForTimeout(2_000);
    expect(resumeResponses).toEqual([200]);
    await expect(panel.getByText('暂时无法连接服务，当前显示此浏览器保存的数据')).toHaveCount(0);
    await expect(panel.getByRole('button', { name: '重试工作台联动' })).toHaveCount(0);

    context.off('response', captureResume);
    await standbyWeb.evaluate(() => {
      (window as typeof window & { stopLegacyWorkbench?: () => void }).stopLegacyWorkbench?.();
    });
  });

  test('MV3 后台终止且三个工作台隐藏时自动恢复，不误报离线', async () => {
    const resumeResponses: Array<{ status: number; url: string }> = [];
    const captureResume = (response: import('@playwright/test').Response) => {
      if (
        response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/v2/extension/session/resume'
      ) {
        resumeResponses.push({ status: response.status(), url: response.url() });
      }
    };
    context.on('response', captureResume);
    await panel.bringToFront();
    await panel.evaluate(async () => chrome.storage.session.clear());
    const previousWorker = context.serviceWorkers()[0];
    expect(previousWorker).toBeTruthy();
    const cdp = await context.newCDPSession(panel);
    const { targetInfos } = await cdp.send('Target.getTargets') as {
      targetInfos: Array<{ targetId: string; type: string; url: string }>;
    };
    const workerTarget = targetInfos.find((target) => (
      target.type === 'service_worker'
      && target.url === `chrome-extension://${extensionId}/background.js`
    ));
    expect(workerTarget).toBeTruthy();
    await cdp.send('Target.closeTarget', { targetId: workerTarget!.targetId });

    await panel.reload();

    await expect(panel.getByLabel('搜索已解锁条目')).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => resumeResponses.length, { timeout: 5_000 }).toBeGreaterThan(0);
    await panel.waitForTimeout(2_000);
    expect(resumeResponses).toHaveLength(1);
    expect(resumeResponses[0]?.status).toBe(200);
    await expect(panel.getByText('暂时无法连接服务，当前显示此浏览器保存的数据')).toHaveCount(0);
    await expect(panel.getByRole('button', { name: '重试工作台联动' })).toHaveCount(0);
    context.off('response', captureResume);
  });

  test('工作台锁定撤销旧会话后扩展自动完成二次恢复', async () => {
    const resumeResponses: number[] = [];
    const challengeResponses: number[] = [];
    const captureRecovery = (response: import('@playwright/test').Response) => {
      const pathname = new URL(response.url()).pathname;
      if (response.request().method() === 'POST' && pathname === '/api/v2/extension/session/resume') {
        resumeResponses.push(response.status());
      }
      if (response.request().method() === 'POST' && pathname === '/api/v2/extension/unlock-challenges') {
        challengeResponses.push(response.status());
      }
    };
    context.on('response', captureRecovery);

    await web.bringToFront();
    await web.getByRole('button', { name: '锁定工作台' }).click();
    await expect(web.getByRole('heading', { name: '解锁你的密码库' })).toBeVisible();
    await expect(panel.getByRole('heading', { name: /恢复扩展连接|扩展已锁定/ })).toBeVisible();

    await web.getByLabel('主密码（本机解密）').fill(MAIN_PASSWORDS.bob);
    const webUnlockResponse = web.waitForResponse((response) => (
      response.request().method() === 'POST'
      && new URL(response.url()).pathname === '/api/v2/session/crypto-unlock'
    ));
    await web.getByRole('button', { name: '解锁密码库' }).click();
    const completedWebUnlock = await webUnlockResponse;
    expect(completedWebUnlock.status(), await completedWebUnlock.text()).toBe(200);

    await expect(web.getByRole('region', { name: '凭证列表' })).toBeVisible({ timeout: 15_000 });
    await expect(panel.getByLabel('搜索已解锁条目')).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => resumeResponses, { timeout: 5_000 }).toEqual([200]);
    expect(challengeResponses).toEqual([401, 200]);
    await expect(panel.getByRole('button', { name: '从已解锁工作台恢复' })).toHaveCount(0);
    await expect(panel.getByRole('button', { name: '重试工作台联动' })).toHaveCount(0);

    context.off('response', captureRecovery);
  });

  test('未知页面默认拒绝填充，锁定后清除解密投影', async () => {
    const demo = await context.newPage();
    await demo.goto(`${E2E_WEB_ORIGIN}/demo-login.html`);
    await demo.bringToFront();
    await panel.bringToFront();
    await panel.getByRole('button', { name: '刷新' }).click();
    await panel.getByLabel('搜索已解锁条目').fill(EXTENSION_ITEM.title);
    const row = panel.locator('.item', { hasText: EXTENSION_ITEM.title });
    await expect(row.getByRole('button', { name: '填充' })).toHaveCount(0);
    await expect(row.getByRole('button', { name: '复制密码' })).toBeVisible();

    await panel.getByRole('button', { name: '锁定' }).click();
    await expect(panel.getByRole('heading', { name: '扩展已锁定' })).toBeVisible();
    await expect(panel.getByText(EXTENSION_ITEM.title, { exact: true })).toHaveCount(0);

    const injected = await demo.evaluate(
      `(${fillLoginForm.toString()})('demo-user', 'e2e-fill-function-only')`,
    ) as { ok: boolean };
    expect(injected.ok).toBe(true);
    await expect(demo.locator('#user')).toHaveValue('demo-user');
    await expect(demo.locator('#pass')).toHaveValue('e2e-fill-function-only');
    await demo.close();
  });

  test('浏览器会话副本清除后由已解锁工作台自动恢复，不重新配对', async () => {
    const resumeResponses: number[] = [];
    const captureResume = (response: import('@playwright/test').Response) => {
      if (
        response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/api/v2/extension/session/resume'
      ) {
        resumeResponses.push(response.status());
      }
    };
    context.on('response', captureResume);
    await panel.evaluate(async () => chrome.storage.session.clear());

    await panel.reload();

    await expect(panel.getByText('Bob Li（Ops）', { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => resumeResponses.length, { timeout: 5_000 }).toBeGreaterThan(0);
    await panel.waitForTimeout(2_000);
    expect(resumeResponses).toEqual([200]);
    await expect(panel.getByRole('heading', { name: 'Mima · 扩展配对' })).toHaveCount(0);
    const persisted = await panel.evaluate(async () => chrome.storage.session.get(null));
    expect(persisted).toHaveProperty('lmE2eeSession');
    context.off('response', captureResume);
  });

  test('Web 撤销扩展设备后，扩展清除本机密钥和密文缓存', async () => {
    const retryLink = panel.getByRole('button', { name: '重试工作台联动' });
    if (await retryLink.count()) await retryLink.click();
    await expect(panel.getByText('Bob Li（Ops）', { exact: true })).toBeVisible({ timeout: 15_000 });
    await web.getByRole('button', { name: '已授权设备' }).click();
    const deviceDialog = web.getByRole('dialog', { name: '已授权设备' });
    const extensionDevice = deviceDialog.getByText(`${extensionSigningKeyPrefix}…`, { exact: true })
      .locator('..')
      .locator('..');
    await extensionDevice.getByRole('button', { name: '撤销浏览器扩展' }).click();
    const confirm = web.getByRole('dialog', { name: '撤销浏览器扩展' });
    const revokeResponse = web.waitForResponse((response) =>
      response.request().method() === 'POST' && response.url().endsWith('/revoke')
    );
    await confirm.getByRole('button', { name: '撤销扩展', exact: true }).click();
    const response = await revokeResponse;
    expect(response.status(), await response.text()).toBe(200);

    await expect(panel.getByRole('heading', { name: '此设备已被撤销' })).toBeVisible({ timeout: 10_000 });
    await expectNoHorizontalOverflow(panel);
    await panel.screenshot({
      path: join(screenshotDir, 'extension-revoked-400x600.png'),
      animations: 'disabled',
      fullPage: true,
    });
    const persisted = await panel.evaluate(async () => ({
      local: await chrome.storage.local.get(null),
      session: await chrome.storage.session.get(null),
    }));
    expect(persisted.local).toEqual({});
    expect(persisted.session).not.toHaveProperty('lmE2eeSession');
    expect(persisted.session).toEqual({ lmE2eeSessionGeneration: expect.any(Number) });

    await expect(web.getByRole('heading', { name: '密码库正在安全更新' })).toBeVisible({ timeout: 15_000 });
    const completeRekey = web.getByRole('button', { name: '完成安全更新' });
    await expect.poll(() => completeRekey.count()).toBeGreaterThanOrEqual(3);
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const remaining = await completeRekey.count();
      if (remaining === 0) break;
      await completeRekey.first().click();
      await expect.poll(() => completeRekey.count(), { timeout: 15_000 }).toBeLessThan(remaining);
    }
    await expect(completeRekey).toHaveCount(0);
    await expect(web.getByRole('navigation', { name: '库导航' })).toBeVisible({ timeout: 20_000 });
    await ensureLoginItem(web, {
      title: 'E2E 撤权后写入',
      username: 'post-revoke-user',
      origin: 'https://post-revoke.example.test',
      password: 'e2e-post-revoke-secret-canary-006',
    });
  });
});

async function createTeamProjectFixture(page: Page): Promise<void> {
  await page.getByRole('button', { name: '新建团队库' }).click();
  const createVault = page.getByRole('dialog', { name: '新建团队密码库' });
  await createVault.getByLabel('团队密码库名称').fill(EXTENSION_PARENT_VAULT);
  await createVault.getByRole('button', { name: '创建并进入', exact: true }).click();
  await expect(page.getByRole('button', { name: EXTENSION_PARENT_VAULT, exact: true })).toBeVisible();

  const parentRow = page.getByRole('navigation', { name: '库导航' })
    .getByRole('button', { name: EXTENSION_PARENT_VAULT, exact: true })
    .locator('..');
  await parentRow.getByRole('button', { name: '编辑团队密码库' }).click();
  const editVault = page.getByRole('dialog', { name: '编辑团队密码库' });
  await editVault.getByText('更多设置', { exact: true }).click();
  await editVault.getByRole('button', { name: '新建独立权限项目' }).click();

  const createProject = page.getByRole('dialog', { name: `在「${EXTENSION_PARENT_VAULT}」下新建项目` });
  await createProject.getByLabel('项目名称').fill(EXTENSION_PROJECT);
  await createProject.getByRole('button', { name: '创建项目', exact: true }).click();
  await expect(page.getByRole('button', { name: EXTENSION_PROJECT, exact: true })).toBeVisible();
}
