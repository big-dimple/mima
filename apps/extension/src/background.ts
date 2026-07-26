/// <reference types="chrome" />
import {
  BackgroundCoordinator,
  type CoordinatorSessionStore,
} from './background-coordinator.ts';
import {
  SESSION_GENERATION_KEY,
  SESSION_KEY,
} from './extension-storage.ts';
import type { ExtSession } from './protocol.ts';
import {
  createWorkbenchWakeScheduler,
  type WorkbenchWakeAdapter,
} from './workbench-wake.ts';

chrome.runtime.onInstalled.addListener(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  void restrictStorageAccess();
});

chrome.runtime.onStartup.addListener(() => {
  void restrictStorageAccess();
});

chrome.commands.onCommand.addListener((command, tab) => {
  if (command !== 'open-panel' || tab?.windowId === undefined) return;
  void chrome.sidePanel.open({ windowId: tab.windowId });
});

const API_BASE: string = import.meta.env.VITE_MIMA_API_BASE ?? 'http://127.0.0.1:4184';
const WEB_ORIGIN: string | undefined = import.meta.env.VITE_MIMA_WEB_ORIGIN;
const allowedWorkbenchOrigins = new Set([
  new URL(API_BASE).origin,
  ...(WEB_ORIGIN ? [new URL(WEB_ORIGIN).origin] : []),
  'http://127.0.0.1:4173',
  'http://localhost:4173',
  'http://[::1]:14273',
]);

const sessionStore: CoordinatorSessionStore = {
  async loadSession() {
    const data = await chrome.storage.session.get(SESSION_KEY);
    return (data[SESSION_KEY] as ExtSession | undefined) ?? null;
  },
  async saveSession(session) {
    await chrome.storage.session.set({ [SESSION_KEY]: session });
  },
  async removeSession() {
    await chrome.storage.session.remove(SESSION_KEY);
  },
  async loadGeneration() {
    const data = await chrome.storage.session.get(SESSION_GENERATION_KEY);
    const generation = data[SESSION_GENERATION_KEY];
    return Number.isSafeInteger(generation) && (generation as number) >= 0
      ? generation as number
      : 0;
  },
  async saveGeneration(generation) {
    await chrome.storage.session.set({ [SESSION_GENERATION_KEY]: generation });
  },
};
const coordinator = new BackgroundCoordinator(sessionStore);
const workbenchWakeAdapter: WorkbenchWakeAdapter = {
  listTabs: () => chrome.tabs.query({}),
  async wake(tabId, eventName) {
    await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      world: 'MAIN',
      func: (name) => window.dispatchEvent(new CustomEvent(name)),
      args: [eventName],
    });
  },
};
const wakeWorkbenches = createWorkbenchWakeScheduler(
  workbenchWakeAdapter,
  allowedWorkbenchOrigins,
);

chrome.runtime.onConnectExternal.addListener((port) => {
  if (port.name !== 'mima-workbench-v1' || !isAllowedWorkbench(port.sender)) {
    port.disconnect();
    return;
  }
  coordinator.registerWorkbench(port, workbenchEndpoint(port.sender!));
  port.onMessage.addListener((message: unknown) => {
    coordinator.handleWorkbenchMessage(port, message);
  });
  port.onDisconnect.addListener(() => coordinator.unregisterWorkbench(port));
});

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'mima-sidepanel-v1') return;
  coordinator.registerSidePanel(port);
  void wakeWorkbenches();
  port.onMessage.addListener((message: unknown) => {
    const accountId = trustedUnlockAccountId(message);
    const shouldWake = accountId !== null && !coordinator.hasUnlockedWorkbench(accountId);
    coordinator.handleSidePanelMessage(port, message);
    if (shouldWake) void wakeWorkbenches();
  });
  port.onDisconnect.addListener(() => coordinator.unregisterSidePanel(port));
});

async function restrictStorageAccess(): Promise<void> {
  await Promise.all([
    chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
    chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
  ]);
}

function isAllowedWorkbench(sender: chrome.runtime.MessageSender | undefined): boolean {
  if (!sender?.url || sender.frameId !== 0) return false;
  try {
    return allowedWorkbenchOrigins.has(new URL(sender.url).origin);
  } catch {
    return false;
  }
}

function workbenchEndpoint(
  sender: chrome.runtime.MessageSender,
): { tabId: number | null; documentId: string | null; origin: string } {
  const tabId = sender.tab?.id;
  return {
    tabId: Number.isSafeInteger(tabId) ? tabId as number : null,
    documentId: typeof sender.documentId === 'string' ? sender.documentId : null,
    origin: new URL(sender.url ?? '').origin,
  };
}

function trustedUnlockAccountId(message: unknown): string | null {
  if (
    !message
    || typeof message !== 'object'
    || !('kind' in message)
    || message.kind !== 'trusted_unlock_request'
    || !('request' in message)
    || !message.request
    || typeof message.request !== 'object'
    || !('accountId' in message.request)
    || typeof message.request.accountId !== 'string'
  ) return null;
  return message.request.accountId;
}
