import { createStore } from 'zustand/vanilla';
import type {
  BootstrapResponse,
  ItemMeta,
  Membership,
  SessionUser,
  SyncEvent,
  Vault,
} from '@mima/contracts';
import { canReveal, resolveEffectiveRole } from '@mima/domain';
import type { VaultDirectoryEntry } from '@mima/domain';
import type { DecryptedBootstrapProjection, DecryptedItemMeta, SecurityPhase } from './e2ee-model.ts';
import type { EncryptedCommandKind } from './encrypted-storage.ts';

export type ConnectionState = 'connecting' | 'online' | 'offline';

export interface ConflictInfo {
  itemId: string;
  reason?: 'version_conflict' | 'metadata_format_outdated';
  currentVersion: number;
  currentItem?: ItemMeta;
  commandId?: string;
  candidateKind?: EncryptedCommandKind;
  candidateCreatedAt?: string;
}

export interface MetaState {
  user: SessionUser | null;
  securityPhase: SecurityPhase;
  locked: boolean;
  connection: ConnectionState;
  cursor: number;
  /** 登录代际：reset()（退出/401/会话失效）时 +1。
   * 在途命令与回滚闭包捕获发起时的代际，代际不符的晚到响应一律丢弃。 */
  epoch: number;
  vaults: Record<string, Vault>;
  items: Record<string, DecryptedItemMeta>;
  /** vaultId → 成员表（仅团队库）。 */
  memberships: Record<string, Membership[]>;
  /** 乐观更新中、尚未收到服务端确认的条目。 */
  pendingItemIds: Record<string, true>;
  conflicts: Record<string, ConflictInfo>;
  /** 权限被撤销的库（用于 UI 提示后清理）。 */
  lastRevokedVaultId: string | null;
  vaultCrypto: DecryptedBootstrapProjection['vaultCrypto'];
  pendingVaultAccessIds: Record<string, true>;
  vaultDirectories: Record<string, VaultDirectoryEntry[]>;
}

export interface MetaActions {
  applyBootstrap(data: BootstrapResponse): void;
  applyDecryptedBootstrap(data: DecryptedBootstrapProjection): void;
  applyEvent(event: SyncEvent): void;
  setConnection(state: ConnectionState): void;
  setLocked(locked: boolean): void;
  setSecurityPhase(phase: SecurityPhase): void;
  advanceCursor(cursor: number): void;
  setVaultCryptoState(state: import('@mima/contracts').VaultCryptoState): void;
  lockProjection(): void;
  setUser(user: SessionUser | null): void;
  upsertItemOptimistic(item: DecryptedItemMeta | ItemMeta): void;
  /** 非 409 写失败时回滚乐观状态。回滚前校验：条目仍存在、所在库仍可访问、
   * 且没有更新的权威版本——绝不用旧快照覆盖已撤权/已更新的数据。 */
  rollbackItem(item: DecryptedItemMeta | ItemMeta): void;
  markPending(itemId: string, pending: boolean): void;
  setConflict(conflict: ConflictInfo | null, itemId: string): void;
  reset(): void;
}

export type MetaStore = ReturnType<typeof createMetaStore>;

const initialState: MetaState = {
  user: null,
  securityPhase: 'unauthenticated',
  locked: false,
  connection: 'connecting',
  cursor: 0,
  epoch: 0,
  vaults: {},
  items: {},
  memberships: {},
  pendingItemIds: {},
  conflicts: {},
  lastRevokedVaultId: null,
  vaultCrypto: {},
  pendingVaultAccessIds: {},
  vaultDirectories: {},
};

/**
 * 规范化内存元数据 Store（Zustand Vanilla）。
 * 不做任何持久化（LocalStorage/IndexedDB）；密码、Token 等敏感内容永远不进入这里。
 */
export function createMetaStore(hooks?: {
  /** 条目版本变化或删除时回调（销毁旧 Secret Lease）。 */
  onItemStale?: (itemId: string) => void;
  /** 库权限被撤销时回调。 */
  onVaultRevoked?: (itemIds: string[]) => void;
}) {
  return createStore<MetaState & MetaActions>()((set, get) => ({
    ...initialState,

    applyBootstrap: (data) =>
      set({
        user: data.user,
        cursor: data.cursor,
        vaults: Object.fromEntries(data.vaults.map((v) => [v.id, v])),
        items: Object.fromEntries(data.items.map((item) => [item.id, {
          ...item,
          secretState: 'present' as const,
        }])),
        memberships: groupMemberships(data.memberships),
        pendingItemIds: {},
        pendingVaultAccessIds: {},
        vaultDirectories: {},
      }),

    applyDecryptedBootstrap: (data) =>
      set((state) => {
        const items = Object.fromEntries(data.items.map((item) => [item.id, item]));
        const conflicts = Object.fromEntries(
          Object.entries(state.conflicts).filter(([itemId]) => items[itemId] !== undefined),
        );
        return {
          user: data.user,
          locked: false,
          cursor: data.cursor,
          vaults: Object.fromEntries(data.vaults.map((vault) => [vault.id, vault])),
          items,
          memberships: groupMemberships(data.memberships),
          pendingItemIds: {},
          conflicts,
          vaultCrypto: data.vaultCrypto,
          pendingVaultAccessIds: data.pendingVaultAccessIds ?? {},
          vaultDirectories: data.vaultDirectories,
        };
      }),

    applyEvent: (event) => {
      const state = get();
      const cursor = Math.max(state.cursor, event.cursor);
      switch (event.type) {
        case 'item.upserted': {
          const incoming = withSecretState(event.item);
          // 拒收所属库不在本地缓存的条目：库已被撤权/删除后，晚到的命令确认
          // 或事件不得让旧条目"复活"为无主数据
          if (!state.vaults[incoming.vaultId]) {
            set({ cursor });
            return;
          }
          const existing = state.items[incoming.id];
          if (existing && existing.version > incoming.version) {
            set({ cursor });
            return;
          }
          if (existing && incoming.version > existing.version) {
            hooks?.onItemStale?.(incoming.id);
          }
          const pending = { ...state.pendingItemIds };
          delete pending[incoming.id];
          set({
            cursor,
            items: { ...state.items, [incoming.id]: incoming },
            pendingItemIds: pending,
          });
          return;
        }
        case 'item.deleted': {
          const items = { ...state.items };
          delete items[event.itemId];
          hooks?.onItemStale?.(event.itemId);
          set({ cursor, items });
          return;
        }
        case 'vault.upserted': {
          const vaults = { ...state.vaults, [event.vault.id]: event.vault };
          const memberships = { ...state.memberships, [event.vault.id]: event.memberships };
          let items = state.items;
          if (event.items) {
            items = { ...state.items };
            // 全量替换该库的条目快照
            for (const [id, item] of Object.entries(items)) {
              if (item.vaultId === event.vault.id) delete items[id];
            }
            for (const item of event.items) items[item.id] = withSecretState(item);
          }
          // 角色可能被降为 auditor（仍可见元数据但不可读取内容）：立即销毁该库全部租约
          const user = state.user;
          if (user && event.vault.kind === 'team') {
            const role = resolveEffectiveRole(event.memberships, {
              userId: user.id,
              groups: user.groups,
            });
            if (!canReveal(role)) {
              for (const item of Object.values(items)) {
                if (item.vaultId === event.vault.id) hooks?.onItemStale?.(item.id);
              }
            }
          }
          set({ cursor, vaults, memberships, items });
          return;
        }
        case 'vault.revoked': {
          if (!state.vaults[event.vaultId]) {
            set({ cursor });
            return;
          }
          const vaults = { ...state.vaults };
          delete vaults[event.vaultId];
          const memberships = { ...state.memberships };
          delete memberships[event.vaultId];
          const vaultCrypto = { ...state.vaultCrypto };
          delete vaultCrypto[event.vaultId];
          const pendingVaultAccessIds = { ...state.pendingVaultAccessIds };
          delete pendingVaultAccessIds[event.vaultId];
          const vaultDirectories = { ...state.vaultDirectories };
          delete vaultDirectories[event.vaultId];
          const items = { ...state.items };
          const dropped: string[] = [];
          for (const [id, item] of Object.entries(items)) {
            if (item.vaultId === event.vaultId) {
              dropped.push(id);
              delete items[id];
            }
          }
          hooks?.onVaultRevoked?.(dropped);
          set({
            cursor,
            vaults,
            memberships,
            items,
            vaultCrypto,
            pendingVaultAccessIds,
            vaultDirectories,
            lastRevokedVaultId: event.vaultId,
          });
          return;
        }
        case 'sync.cursor': {
          // 被过滤：只推进游标
          set({ cursor });
          return;
        }
        case 'sync.ready': {
          // 回放完毕：vaultIds 是服务端此刻的权威可访问库列表。
          // 删除离线期间被撤权/删除、且没有对应 vault.revoked 事件送达的本地缓存。
          const allowed = new Set(event.vaultIds);
          const staleVaultIds = Object.keys(state.vaults).filter((id) => !allowed.has(id));
          if (staleVaultIds.length === 0) {
            set({ cursor });
            return;
          }
          const vaults = { ...state.vaults };
          const memberships = { ...state.memberships };
          const vaultCrypto = { ...state.vaultCrypto };
          const pendingVaultAccessIds = { ...state.pendingVaultAccessIds };
          const vaultDirectories = { ...state.vaultDirectories };
          const items = { ...state.items };
          const dropped: string[] = [];
          for (const vaultId of staleVaultIds) {
            delete vaults[vaultId];
            delete memberships[vaultId];
            delete vaultCrypto[vaultId];
            delete pendingVaultAccessIds[vaultId];
            delete vaultDirectories[vaultId];
          }
          for (const [id, item] of Object.entries(items)) {
            if (!allowed.has(item.vaultId)) {
              dropped.push(id);
              delete items[id];
            }
          }
          hooks?.onVaultRevoked?.(dropped);
          set({
            cursor,
            vaults,
            memberships,
            items,
            vaultCrypto,
            pendingVaultAccessIds,
            vaultDirectories,
            lastRevokedVaultId: staleVaultIds[staleVaultIds.length - 1] ?? state.lastRevokedVaultId,
          });
          return;
        }
      }
    },

    setConnection: (connection) => set({ connection }),
    setLocked: (locked) => set({ locked }),
    setSecurityPhase: (securityPhase) => set({ securityPhase }),
    advanceCursor: (incoming) => set((state) => ({ cursor: Math.max(state.cursor, incoming) })),
    setVaultCryptoState: (crypto) =>
      set((state) => ({ vaultCrypto: { ...state.vaultCrypto, [crypto.vaultId]: crypto } })),
    lockProjection: () =>
      set((state) => ({
        locked: true,
        securityPhase: 'authenticated-locked',
        cursor: 0,
        vaults: {},
        items: {},
        memberships: {},
        pendingItemIds: {},
        conflicts: {},
        vaultCrypto: {},
        pendingVaultAccessIds: {},
        vaultDirectories: {},
        epoch: state.epoch + 1,
      })),
    setUser: (user) => set({ user }),

    upsertItemOptimistic: (item) =>
      set((s) => ({
        items: { ...s.items, [item.id]: withSecretState(item) },
        pendingItemIds: { ...s.pendingItemIds, [item.id]: true },
      })),

    rollbackItem: (item) =>
      set((s) => {
        const restored = withSecretState(item);
        const pendingItemIds = { ...s.pendingItemIds };
        delete pendingItemIds[restored.id];
        const current = s.items[restored.id];
        // 校验后再回滚：条目已被删除/所在库已撤权（current 不存在或库不存在），
        // 或服务端已有更新的权威版本——都不得用旧快照覆盖，仅清除 pending。
        if (!current || !s.vaults[restored.vaultId] || current.version > restored.version) {
          return { pendingItemIds };
        }
        return { items: { ...s.items, [restored.id]: restored }, pendingItemIds };
      }),

    markPending: (itemId, pending) =>
      set((s) => {
        const pendingItemIds = { ...s.pendingItemIds };
        if (pending) pendingItemIds[itemId] = true;
        else delete pendingItemIds[itemId];
        return { pendingItemIds };
      }),

    setConflict: (conflict, itemId) =>
      set((s) => {
        const conflicts = { ...s.conflicts };
        if (conflict) conflicts[itemId] = conflict;
        else delete conflicts[itemId];
        return { conflicts };
      }),

    // 退出/401：清空全部状态并推进登录代际——在途命令的晚到响应不得写回
    reset: () => set((s) => ({ ...initialState, epoch: s.epoch + 1 })),
  }));
}

function withSecretState(item: ItemMeta | DecryptedItemMeta): DecryptedItemMeta {
  return 'secretState' in item ? item : { ...item, secretState: 'present' };
}

function groupMemberships(list: Membership[]): Record<string, Membership[]> {
  const map: Record<string, Membership[]> = {};
  for (const m of list) {
    (map[m.vaultId] ??= []).push(m);
  }
  return map;
}
