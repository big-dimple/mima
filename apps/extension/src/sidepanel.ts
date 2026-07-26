/// <reference types="chrome" />
import '@mima/ui-tokens/tokens.css';
import './panel.css';
import { readLastFocusedActiveTab } from './active-tab.ts';
import { ensureOriginPermission } from './api-permission.ts';
import { createChromeExtensionStorage } from './extension-storage.ts';
import { fillLoginForm } from './fill.ts';
import { PanelActions, type PanelBrowserAdapter } from './panel-actions.ts';
import { PanelApi } from './panel-api.ts';
import { PanelModel } from './panel-model.ts';
import { PanelView } from './panel-view.ts';
import { sitePermissionPattern } from './site-permission.ts';
import { WorkerCryptoKeyring } from './worker-crypto-keyring.ts';
import { ExtensionTrustedUnlockBridge } from './trusted-unlock-bridge.ts';

const API_BASE: string = import.meta.env.VITE_MIMA_API_BASE ?? 'http://127.0.0.1:4184';
const WORKBENCH_ORIGIN = new URL(API_BASE).origin;

const model = new PanelModel();
const storage = createChromeExtensionStorage();
const api = new PanelApi(API_BASE, model);
const keyring = new WorkerCryptoKeyring();
const trustedUnlockBridge = new ExtensionTrustedUnlockBridge();
const browser: PanelBrowserAdapter = {
  async ensureApiAccess() {
    const url = new URL(API_BASE);
    if (url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]') {
      return true;
    }
    const originPattern = `${url.origin}/*`;
    return ensureOriginPermission(chrome.permissions, originPattern);
  },
  async ensureSiteAccess(origin) {
    const originPattern = sitePermissionPattern(origin);
    if (!originPattern) return false;
    return chrome.permissions.request({ origins: [originPattern] });
  },
  isProtectedWorkbenchOrigin(origin) {
    return origin === WORKBENCH_ORIGIN;
  },
  async readActiveTab() {
    return readLastFocusedActiveTab(chrome.tabs);
  },
  async executeFill(tabId, username, value) {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: fillLoginForm,
      args: [username, value],
    });
    return (results[0]?.result as { ok: boolean; reason?: string } | undefined) ?? {
      ok: false,
      reason: '页面未返回填充结果',
    };
  },
  async openUrl(url) {
    await chrome.tabs.create({ url, active: true });
  },
  async writeClipboard(value) {
    await navigator.clipboard.writeText(value);
  },
  schedule(callback, delayMs) {
    setTimeout(callback, delayMs);
  },
  requestTrustedUnlock(request) {
    return trustedUnlockBridge.request(request);
  },
  loadSession() {
    return trustedUnlockBridge.loadSession();
  },
  adoptSession(session, deviceId) {
    return trustedUnlockBridge.adoptSession(session, deviceId);
  },
  invalidateSession(expectedGeneration) {
    return trustedUnlockBridge.invalidateSession(expectedGeneration);
  },
  clearSession() {
    return trustedUnlockBridge.clearSession();
  },
  completeTrustedUnlock(requestId) {
    return trustedUnlockBridge.completeTrustedUnlock(requestId);
  },
  isWorkbenchUnlocked(accountId) {
    return trustedUnlockBridge.isWorkbenchUnlocked(accountId);
  },
};
const actions = new PanelActions(model, api, browser, storage, keyring);
const root = document.getElementById('app');
if (!root) throw new Error('Panel root missing');
const view = new PanelView(root, model, actions, start);
let offlineRetryTimer: ReturnType<typeof setTimeout> | null = null;
let offlineRetryDelay = 2_000;
const render = () => {
  view.render();
  scheduleOfflineRefresh();
};
const refreshActiveTab = () => {
  if (model.state.phase !== 'ready') return;
  void actions.refreshActiveTab().then(render).catch(() => undefined);
};
chrome.tabs.onActivated.addListener(refreshActiveTab);
chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (tab.active && (changeInfo.url !== undefined || changeInfo.status === 'complete')) {
    refreshActiveTab();
  }
});
keyring.onFatal((error) => {
  model.handleCryptoWorkerFailure(error.message);
  render();
});
trustedUnlockBridge.onWorkbenchLocked((accountId) => {
  if (accountId && model.state.device?.userId && accountId !== model.state.device.userId) return;
  actions.allowAutomaticTrustedUnlock();
  if (model.state.phase === 'ready' || model.state.phase === 'unlocking') {
    void actions.lock().then(render);
  }
});
trustedUnlockBridge.onWorkbenchUnlocked((accountId) => {
  if (accountId && model.state.device?.userId && accountId !== model.state.device.userId) return;
  if (model.state.phase === 'locked' && model.state.device?.webUnlock) {
    void actions.tryTrustedUnlock().then(render).catch(render);
  }
});
trustedUnlockBridge.onDeviceRevoked((deviceId) => {
  void actions.confirmWorkbenchDeviceRevocation(deviceId).then((revoked) => {
    if (revoked) render();
  }).catch(() => undefined);
});
trustedUnlockBridge.onSessionChanged((session) => {
  void actions.syncSession(session).then(async () => {
    const accountId = model.state.device?.userId;
    if (
      !session
      && model.state.phase === 'locked'
      && model.state.device?.webUnlock
      && trustedUnlockBridge.isWorkbenchUnlocked(accountId)
    ) {
      await actions.tryTrustedUnlock().catch(() => undefined);
    }
    render();
  });
});
trustedUnlockBridge.start();

document.addEventListener('visibilitychange', () => {
  const accountId = model.state.device?.userId;
  if (
    document.visibilityState === 'visible'
    && model.state.phase === 'locked'
    && model.state.device?.webUnlock
    && trustedUnlockBridge.isWorkbenchUnlocked(accountId)
  ) {
    void actions.tryTrustedUnlock().then(render).catch(render);
  }
});

function scheduleOfflineRefresh(): void {
  if (model.state.phase !== 'ready' || !model.state.offline) {
    if (offlineRetryTimer) clearTimeout(offlineRetryTimer);
    offlineRetryTimer = null;
    offlineRetryDelay = 2_000;
    return;
  }
  if (offlineRetryTimer) return;
  offlineRetryTimer = setTimeout(() => {
    offlineRetryTimer = null;
    if (model.state.phase !== 'ready' || !model.state.offline) return;
    void actions.refreshData().then(() => {
      offlineRetryDelay = 2_000;
      render();
    }).catch(() => {
      offlineRetryDelay = Math.min(offlineRetryDelay * 2, 30_000);
      render();
    });
  }, offlineRetryDelay);
}

async function start(): Promise<void> {
  model.setLoading();
  render();
  try {
    await actions.startup();
    render();
  } catch (error) {
    model.setError(error instanceof Error ? error.message : '扩展初始化失败');
    render();
  }
}

void start();
