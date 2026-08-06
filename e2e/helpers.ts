import { expect, type Locator, type Page } from '@playwright/test';

const E2E_API_HOST = process.env.MIMA_E2E_API_HOST ?? '127.0.0.1';
const E2E_API_URL_HOST = E2E_API_HOST.includes(':') ? `[${E2E_API_HOST}]` : E2E_API_HOST;

export const E2E_API_ORIGIN = `http://${E2E_API_URL_HOST}:14274`;

export const MAIN_PASSWORDS = {
  alice: 'Alice-e2e-main-password-2026',
  bob: 'Bob-e2e-main-password-2026',
  carol: 'Carol-e2e-main-password-2026',
  dave: 'Dave-e2e-main-password-2026',
  erin: 'Erin-e2e-main-password-2026',
} as const satisfies Record<string, string>;

export async function lockWorkspaceForTest(page: Page, notifyServer = true): Promise<void> {
  if (notifyServer) {
    await page.evaluate(async () => {
      const sessionResponse = await fetch('/api/session', { credentials: 'same-origin' });
      if (!sessionResponse.ok) throw new Error(`session status failed: ${sessionResponse.status}`);
      const session = await sessionResponse.json() as { csrfToken?: unknown };
      if (typeof session.csrfToken !== 'string') throw new Error('session csrf token missing');
      const lockResponse = await fetch('/api/session/lock', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'x-mima-csrf': session.csrfToken },
      });
      if (!lockResponse.ok) throw new Error(`session lock failed: ${lockResponse.status}`);
    });
  }
  await page.evaluate(async () => {
    const channel = new BroadcastChannel('mima-session');
    channel.postMessage('lock');
    await new Promise((resolve) => setTimeout(resolve, 0));
    channel.close();
  });
}

export async function loginAndUnlock(
  page: Page,
  username: keyof typeof MAIN_PASSWORDS,
  options: { skipGuide?: boolean; expectWorkspace?: boolean } = {},
): Promise<void> {
  const apiEvidence: string[] = [];
  const recordResponse = (response: import('@playwright/test').Response) => {
    const url = new URL(response.url());
    if (!url.pathname.startsWith('/api/')) return;
    const retryAfter = response.headers()['retry-after'];
    apiEvidence.push(
      `${response.request().method()} ${url.pathname} -> ${response.status()}${retryAfter ? ` retry-after=${retryAfter}` : ''}`,
    );
  };
  const recordFailure = (request: import('@playwright/test').Request) => {
    const url = new URL(request.url());
    if (!url.pathname.startsWith('/api/')) return;
    apiEvidence.push(`${request.method()} ${url.pathname} -> ${request.failure()?.errorText ?? 'request failed'}`);
  };
  const recordPageError = (error: Error) => {
    apiEvidence.push(`PAGEERROR ${error.name}: ${error.message}`);
  };
  const recordConsoleError = (message: import('@playwright/test').ConsoleMessage) => {
    if (message.type() === 'error') apiEvidence.push(`CONSOLE ${message.text()}`);
  };
  page.on('response', recordResponse);
  page.on('requestfailed', recordFailure);
  page.on('pageerror', recordPageError);
  page.on('console', recordConsoleError);
  if (options.skipGuide !== false) {
    await page.addInitScript(() => {
      localStorage.setItem(
        'mima.guide.v1',
        JSON.stringify({ promptShown: true, tourCompleted: true }),
      );
    });
  }
  await gotoWithTransientRetry(page, '/');

  const loginInput = page.getByLabel('用户名');
  const workspace = page.getByRole('region', { name: '凭证列表' });
  const setupHeading = page.getByRole('heading', { name: '创建主密码' });
  const lockedHeading = page.getByRole('heading', { name: '解锁你的密码库' });
  const prepareHeading = page.getByRole('heading', { name: '正在准备工作台' });
  const rekeyHeading = page.getByRole('heading', { name: '密码库正在安全更新' });
  const errorAlert = page.getByRole('region', { name: '通知' }).getByRole('alert').last();
  await waitForAnyVisible([
    loginInput,
    workspace,
    setupHeading,
    lockedHeading,
    prepareHeading,
    rekeyHeading,
  ], 15_000);

  if (await loginInput.isVisible()) {
    await loginInput.fill(username);
    await page.getByLabel('开发密码').fill('dev');
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await waitForVisibleState([workspace, setupHeading, lockedHeading], errorAlert, 30_000, apiEvidence);
  }

  if (await setupHeading.isVisible()) {
    await page.locator('#new-main-password').fill(MAIN_PASSWORDS[username]);
    await page.locator('#confirm-main-password').fill(MAIN_PASSWORDS[username]);
    await page.getByRole('button', { name: '创建主密码并继续' }).click();
    await waitForVisibleState([workspace, prepareHeading, rekeyHeading], errorAlert, 30_000, apiEvidence);
  } else if (await lockedHeading.isVisible()) {
    await page.locator('#main-password').fill(MAIN_PASSWORDS[username]);
    await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
    await waitForVisibleState([workspace, prepareHeading, rekeyHeading], errorAlert, 30_000, apiEvidence);
  }

  if (options.expectWorkspace !== false) {
    await initializeEmptyVaultIfNeeded(page, `${username} 个人密码库`);
    await expect(workspace).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText('在线', { exact: true })).toBeVisible({ timeout: 15_000 });
  }
  page.off('response', recordResponse);
  page.off('requestfailed', recordFailure);
  page.off('pageerror', recordPageError);
  page.off('console', recordConsoleError);
}

async function gotoWithTransientRetry(page: Page, url: string): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await page.goto(url);
      return;
    } catch (error) {
      lastError = error;
      const message = error instanceof Error ? error.message : String(error);
      if (!/net::ERR_CONNECTION_(?:RESET|REFUSED)/.test(message)) throw error;
      await page.waitForTimeout(250 * (attempt + 1));
    }
  }
  throw lastError;
}

async function waitForAnyVisible(locators: Locator[], timeout: number): Promise<void> {
  await expect.poll(async () => {
    for (const locator of locators) {
      if (await locator.isVisible()) return true;
    }
    return false;
  }, { timeout }).toBe(true);
}

async function waitForVisibleState(
  success: Locator[],
  errorAlert: Locator,
  timeout: number,
  apiEvidence: string[],
): Promise<void> {
  try {
    await waitForAnyVisible(success, timeout);
  } catch (error) {
    try {
      await throwVisibleError(errorAlert, success);
    } catch (visibleError) {
      throw withApiEvidence(visibleError, apiEvidence);
    }
    throw withApiEvidence(error, apiEvidence);
  }
}

function withApiEvidence(error: unknown, apiEvidence: string[]): Error {
  const message = error instanceof Error ? error.message : String(error);
  const recent = apiEvidence.slice(-30).join('\n') || '没有捕获到 API 请求';
  return new Error(`${message}\n最近 API 证据：\n${recent}`, { cause: error });
}

async function throwVisibleError(errorAlert: Locator, success: Locator[]): Promise<void> {
  for (const locator of success) {
    if (await locator.isVisible()) return;
  }
  if (await errorAlert.isVisible()) {
    const bootstrapStatus = await errorAlert.page().evaluate(async (apiOrigin) => {
      const response = await fetch(`${apiOrigin}/api/v2/bootstrap`, { credentials: 'include' });
      return response.status;
    }, E2E_API_ORIGIN).catch(() => 0);
    throw new Error(`${await errorAlert.innerText()}\n严格 bootstrap 状态：${bootstrapStatus}`);
  }
}

export async function initializeEmptyVaultIfNeeded(page: Page, name: string): Promise<void> {
  const prepareHeading = page.getByRole('heading', { name: '正在准备工作台' });
  const workspace = page.getByRole('region', { name: '凭证列表' });
  await expect(prepareHeading.or(workspace)).toBeVisible({ timeout: 30_000 });
  if (await workspace.isVisible()) return;

  const initialize = page.getByRole('button', { name: '创建并进入工作台' });
  await expect(initialize).toBeVisible({ timeout: 15_000 });
  await page.getByLabel('密码库名称').fill(name);
  await expect(initialize).toBeEnabled({ timeout: 30_000 });
  await initialize.click();
}

export async function ensureLoginItem(
  page: Page,
  input: {
    title: string;
    username?: string;
    origin?: string;
    password: string;
    useCurrentVault?: boolean;
  },
): Promise<void> {
  if (!input.useCurrentVault) {
    const navigation = page.getByRole('navigation', { name: '库导航' });
    const personalVault = navigation.locator('#personal-vaults button[data-tree-row="true"]').first();
    const availableLabels = await navigation.locator('button[aria-label]').evaluateAll((buttons) =>
      buttons.map((button) => button.getAttribute('aria-label')),
    );
    await expect(personalVault, `没有找到个人密码库，可用导航项：${availableLabels.join('、')}`).toBeVisible();
    if (
      await personalVault.getAttribute('aria-current') !== 'page'
      || await personalVault.getAttribute('data-tree-expanded') !== 'true'
    ) await personalVault.click();
    await expect(personalVault).toHaveAttribute('aria-current', 'page');
    await expect(personalVault).toHaveAttribute('data-tree-expanded', 'true');
  }
  const existing = page.getByRole('option', { name: new RegExp(escapeRegExp(input.title)) });
  if (await existing.count()) return;
  const createButton = page.getByRole('button', { name: '新建', exact: true });
  await expect(createButton).toBeEnabled();
  await createButton.click();
  await enterIntentionalText(page.getByLabel('标题 *'), input.title);
  if (input.username) await enterIntentionalText(page.getByLabel('账号'), input.username);
  if (input.origin) await enterIntentionalText(page.getByLabel('网址（主网址，可选）'), input.origin);
  await enterIntentionalText(page.getByLabel('密码（可选）'), input.password);
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(existing).toBeVisible();
}

export async function enterIntentionalText(locator: Locator, value: string, replace = false): Promise<void> {
  await locator.click();
  if (replace) await locator.press('Control+A');
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

export async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => {
    const element = document.scrollingElement;
    return element ? element.scrollWidth - element.clientWidth : 0;
  });
  expect(overflow).toBeLessThanOrEqual(0);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
