import { createContext, useContext } from 'react';
import { useStore } from 'zustand';
import {
  EncryptedCommandOutbox,
  EncryptedSyncClient,
  IndexedDbEncryptedStorage,
  SecretLeaseStore,
  ZeroKnowledgeActions,
  ZeroKnowledgeApiClient,
  ZeroKnowledgeClient,
  createMetaStore,
  encryptedCommandItemId,
  type MetaStore,
  type MetaState,
  type MetaActions,
} from '@mima/client-core';
import { clearSecretClipboard } from '../utils/clipboard.ts';
import { useUi } from './ui-store.ts';
import { WorkerKeyring } from '../crypto/worker-keyring.ts';
import { WorkbenchExtensionBridge } from '../extension-trusted-bridge.ts';

export interface AppServices {
  api: ZeroKnowledgeApiClient;
  store: MetaStore;
  leases: SecretLeaseStore;
  outbox: EncryptedCommandOutbox;
  actions: ZeroKnowledgeActions;
  zeroKnowledge: ZeroKnowledgeClient;
  sync: EncryptedSyncClient;
  extensionBridge: WorkbenchExtensionBridge;
}

const BROADCAST_CHANNEL = 'mima-session';

/**
 * 组装全部客户端服务。leases 只保存展示到期时间；敏感内容正文不进入状态对象。
 *
 * 敏感内容明文清除矩阵（H3）：
 * - 锁定 / 退出 / SSE 401 / 任意请求 401（会话过期）→ revokeAll + 清剪贴板；
 * - 网络切换为离线 → revokeAll；密钥仍在 Worker，可按需从本地密文缓存重新查看；
 * - 权限撤销（vault.revoked）→ 该库全部租约 + 清剪贴板；
 * - 角色降为 auditor / 条目版本变化 → onItemStale 逐条销毁；
 * - 条目切换 → App 层订阅 UI store 销毁上一条目的全部租约（含历史版本）。
 * 多标签页：BroadcastChannel 同步锁定/退出；每个标签页必须单独使用主密码解锁。
 */
export function createAppServices(): AppServices {
  const apiBaseUrl = import.meta.env.VITE_MIMA_API_BASE?.trim() ?? '';
  const api = new ZeroKnowledgeApiClient(apiBaseUrl);
  const leases = new SecretLeaseStore();
  const store = createMetaStore({
    onItemStale: (itemId) => leases.revoke(itemId),
    onVaultRevoked: (itemIds) => {
      itemIds.forEach((id) => leases.revoke(id));
      void clearSecretClipboard();
    },
  });
  const storage = new IndexedDbEncryptedStorage();
  const outbox = new EncryptedCommandOutbox(api, storage);
  let notifyExtensionDeviceRevoked: (deviceId: string) => void = () => undefined;
  const zeroKnowledge = new ZeroKnowledgeClient({
    api,
    store,
    leases,
    keyring: new WorkerKeyring(),
    storage,
    outbox,
    onKeyringFatal: () => {
      void clearSecretClipboard();
    },
    onDeviceRevoked: (deviceId) => notifyExtensionDeviceRevoked(deviceId),
  });
  const extensionBridge = new WorkbenchExtensionBridge(
    (request, needsSession) => zeroKnowledge.prepareExtensionTrustedUnlock(request, needsSession),
  );
  notifyExtensionDeviceRevoked = (deviceId) => extensionBridge.notifyDeviceRevoked(deviceId);
  extensionBridge.start();
  const publishExtensionState = (state: MetaState) => {
    extensionBridge.setState(
      state.user?.id ?? null,
      state.securityPhase === 'unlocked-online' || state.securityPhase === 'unlocked-offline',
    );
  };
  publishExtensionState(store.getState());
  outbox.onConflict((command) => {
    const itemId = encryptedCommandItemId(command);
    if (!itemId || !command.conflict) return;
    store.getState().setConflict({
      itemId,
      reason: command.conflict.reason,
      currentVersion: command.conflict.currentVersion,
      commandId: command.id,
      candidateKind: command.kind,
      candidateCreatedAt: command.createdAt,
    }, itemId);
  });
  let conflictRefresh: Promise<void> | null = null;
  outbox.onError((error) => {
    if ((error as { status?: number }).status === 409) {
      const outdated = (error as { body?: { code?: string } }).body?.code === 'metadata_format_outdated';
      useUi.getState().toast('warn', outdated
        ? '应用版本已更新。系统已暂停旧版保存并保留本地草稿；请刷新页面后重新编辑'
        : '这条记录刚有了新修改。系统已暂停保存并保留本地草稿；请查看最新内容后再决定如何处理');
      conflictRefresh ??= zeroKnowledge.refresh()
        .catch((caught) => {
          useUi.getState().toast(
            'error',
            caught instanceof Error ? `服务器版本刷新失败：${caught.message}` : '服务器版本刷新失败',
          );
        })
        .finally(() => { conflictRefresh = null; });
      return;
    }
    useUi.getState().toast(
      'error',
      error instanceof Error
        ? `离线修改同步失败：${error.message}`
        : '离线修改同步失败，请重新打开条目确认当前版本',
    );
  });
  const sync = new EncryptedSyncClient({
    baseUrl: apiBaseUrl,
    getCursor: () => store.getState().cursor,
    onEvent: (event) => zeroKnowledge.applyEncryptedSyncEvent(event),
  });
  zeroKnowledge.attachSync(sync);
  sync.onUnauthorized(() => {
    void clearSecretClipboard();
    void zeroKnowledge.handleSessionGone();
  });
  const actions = new ZeroKnowledgeActions(
    zeroKnowledge,
    store,
    leases,
    (message) => useUi.getState().toast('error', message),
  );

  // --- 多标签页锁定/退出同步 ---
  const bc = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(BROADCAST_CHANNEL) : null;
  let applyingRemote = false;
  if (bc) {
    bc.onmessage = (ev: MessageEvent<unknown>) => {
      void applyRemoteMessage(ev.data);
    };
    const applyRemoteMessage = async (message: unknown) => {
      applyingRemote = true;
      try {
        if (message === 'lock') {
          await zeroKnowledge.lock(false);
        } else if (message === 'logout') {
          await zeroKnowledge.lock(false);
          await outbox.clear(false);
          void clearSecretClipboard();
          api.setCsrfToken(null);
          store.getState().reset();
        }
      } finally {
        applyingRemote = false;
      }
    };
  }

  // --- 状态转变驱动的敏感内容清除与广播 ---
  let prev = store.getState();
  store.subscribe((s) => {
    const before = prev;
    prev = s;
    // 网络边界变化时先清当前展示；用户可从本地密文缓存重新查看。
    if (s.connection === 'offline' && before.connection !== 'offline') {
      leases.revokeAll();
    }
    // 锁定/解锁：清租约+剪贴板，并广播到其他标签页
    if (s.locked && !before.locked) {
      leases.revokeAll();
      void clearSecretClipboard();
      useUi.getState().resetWorkspaceUi();
      if (!applyingRemote) bc?.postMessage('lock');
    }
    // 退出（user 置空）：广播 + 清剪贴板
    if (before.user && !s.user) {
      void clearSecretClipboard();
      useUi.getState().resetWorkspaceUi();
      api.setCsrfToken(null);
      if (!applyingRemote) bc?.postMessage('logout');
    }
    if (s.user?.id !== before.user?.id || s.securityPhase !== before.securityPhase) {
      publishExtensionState(s);
    }
  });

  // --- 会话过期 / 401：清空全部敏感内容并回登录（store.reset 触发上面的广播） ---
  const onSessionGone = () => {
    void zeroKnowledge.handleSessionGone();
    void clearSecretClipboard();
    api.setCsrfToken(null);
  };
  api.setUnauthorizedHandler(onSessionGone);

  return { api, store, leases, outbox, actions, zeroKnowledge, sync, extensionBridge };
}

export const AppContext = createContext<AppServices | null>(null);

export function useApp(): AppServices {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('AppContext missing');
  return ctx;
}

export function useMeta<T>(selector: (s: MetaState & MetaActions) => T): T {
  const { store } = useApp();
  return useStore(store, selector);
}
