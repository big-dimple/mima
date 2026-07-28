import { create } from 'zustand';
import type { ItemKind } from '@mima/contracts';

export type VaultFilter = 'all' | 'favorites' | string;

export const folderTreeNodeId = (vaultId: string, path: string) => `folder:${vaultId}:${path}`;

export interface NewItemPreset {
  kind: ItemKind;
  vaultId?: string;
  linkedLoginItemId?: string;
}

interface Toast {
  id: number;
  kind: 'info' | 'error' | 'warn';
  text: string;
}

interface ConfirmState {
  title: string;
  body: string;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  resolve: (confirmed: boolean) => void;
}

interface UiState {
  selectedVaultId: VaultFilter;
  selectedItemId: string | null;
  search: string;
  kindFilter: ItemKind | 'all';
  tagFilter: string | null;
  /** null=当前库全部；空字符串=未分类；其他值=目录及其子目录。 */
  selectedFolderPath: string | null;
  /** null=浏览; 'new'=新建; itemId=编辑 */
  editing: string | null;
  newItemPreset: NewItemPreset | null;
  /** 只记录草稿状态；条目内容和敏感字段绝不进入全局状态。 */
  itemDraftDirty: boolean;
  itemSavePending: boolean;
  toasts: Toast[];
  membersDialogVaultId: string | null;
  auditDialogVaultId: string | null;
  pairingOpen: boolean;
  groupsOpen: boolean;
  recoveryOpen: boolean;
  devicesOpen: boolean;
  retirementOpen: boolean;
  /** 新手指南对话框（登录前后皆可打开）。 */
  guideOpen: boolean;
  /** 互动引导：null=未进行，数字=当前步骤下标。 */
  tourStep: number | null;
  /** 当前解锁会话内的导航树展开节点；目录路径不得写入持久化存储。 */
  expandedTreeNodeIds: Set<string>;
  confirm: ConfirmState | null;
  selectVault(id: VaultFilter): void;
  selectItem(id: string | null): void;
  setSearch(v: string): void;
  setKindFilter(v: ItemKind | 'all'): void;
  setTagFilter(v: string | null): void;
  selectFolder(path: string | null): void;
  setEditing(v: string | null): void;
  startNewItem(preset?: NewItemPreset): void;
  setItemDraftState(dirty: boolean, saving?: boolean): void;
  discardItemDraft(): void;
  toast(kind: Toast['kind'], text: string): void;
  dismissToast(id: number): void;
  openMembers(vaultId: string | null): void;
  openAudit(vaultId: string | null): void;
  setPairingOpen(open: boolean): void;
  setGroupsOpen(open: boolean): void;
  setRecoveryOpen(open: boolean): void;
  setDevicesOpen(open: boolean): void;
  setRetirementOpen(open: boolean): void;
  setGuideOpen(open: boolean): void;
  startTour(): void;
  setTourStep(step: number | null): void;
  toggleTreeNode(id: string): void;
  expandTreeNodes(ids: Iterable<string>): void;
  collapseAllTreeNodes(): void;
  pruneTreeNodes(validIds: ReadonlySet<string>): void;
  resetWorkspaceUi(): void;
  requestConfirm(options: Omit<ConfirmState, 'resolve'>): Promise<boolean>;
  closeConfirm(confirmed: boolean): void;
}

let toastSeq = 1;

export const useUi = create<UiState>((set, get) => {
  const guardedItemTransition = (transition: () => void) => {
    const state = get();
    if (state.itemSavePending) {
      state.toast('warn', '正在保存这条记录，请稍候');
      return;
    }
    if (!state.editing || !state.itemDraftDirty) {
      transition();
      return;
    }
    if (state.confirm) return;
    void state.requestConfirm({
      title: '放弃未保存的修改？',
      body: '当前条目还有未保存的内容。继续离开会丢弃这些修改。',
      confirmText: '放弃修改',
      cancelText: '继续编辑',
      danger: true,
    }).then((confirmed) => {
      if (!confirmed) return;
      set({ itemDraftDirty: false, itemSavePending: false });
      transition();
    });
  };

  return ({
  selectedVaultId: 'all',
  selectedItemId: null,
  search: '',
  kindFilter: 'all',
  tagFilter: null,
  selectedFolderPath: null,
  editing: null,
  newItemPreset: null,
  itemDraftDirty: false,
  itemSavePending: false,
  toasts: [],
  membersDialogVaultId: null,
  auditDialogVaultId: null,
  pairingOpen: false,
  groupsOpen: false,
  recoveryOpen: false,
  devicesOpen: false,
  retirementOpen: false,
  guideOpen: false,
  tourStep: null,
  expandedTreeNodeIds: new Set(),
  confirm: null,
  selectVault: (id) => guardedItemTransition(() => set({
    selectedVaultId: id,
    selectedItemId: null,
    editing: null,
    newItemPreset: null,
    tagFilter: null,
    selectedFolderPath: null,
    itemDraftDirty: false,
  })),
  selectItem: (id) => guardedItemTransition(() => set({
    selectedItemId: id,
    editing: null,
    newItemPreset: null,
    itemDraftDirty: false,
  })),
  setSearch: (search) => set({ search }),
  setKindFilter: (kindFilter) => set({ kindFilter }),
  setTagFilter: (tagFilter) => set({ tagFilter }),
  selectFolder: (selectedFolderPath) => guardedItemTransition(() => set({
    selectedFolderPath,
    selectedItemId: null,
    editing: null,
    newItemPreset: null,
    itemDraftDirty: false,
  })),
  setEditing: (editing) => {
    if (get().editing === editing) return;
    guardedItemTransition(() => set({
      editing,
      newItemPreset: null,
      itemDraftDirty: false,
      itemSavePending: false,
    }));
  },
  startNewItem: (newItemPreset) => guardedItemTransition(() => set({
    editing: 'new',
    newItemPreset: newItemPreset ?? null,
    itemDraftDirty: false,
    itemSavePending: false,
  })),
  setItemDraftState: (itemDraftDirty, itemSavePending = get().itemSavePending) => set({
    itemDraftDirty,
    itemSavePending,
  }),
  discardItemDraft: () => set({ itemDraftDirty: false, itemSavePending: false }),
  toast: (kind, text) => {
    const id = toastSeq++;
    set({ toasts: [...get().toasts, { id, kind, text }] });
    setTimeout(() => get().dismissToast(id), 4200);
  },
  dismissToast: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
  openMembers: (membersDialogVaultId) => set({ membersDialogVaultId }),
  openAudit: (auditDialogVaultId) => set({ auditDialogVaultId }),
  setPairingOpen: (pairingOpen) => set({ pairingOpen }),
  setGroupsOpen: (groupsOpen) => set({ groupsOpen }),
  setRecoveryOpen: (recoveryOpen) => set({ recoveryOpen }),
  setDevicesOpen: (devicesOpen) => set({ devicesOpen }),
  setRetirementOpen: (retirementOpen) => set({ retirementOpen }),
  setGuideOpen: (guideOpen) => set({ guideOpen }),
  startTour: () => guardedItemTransition(() => set({
    guideOpen: false,
    tourStep: 0,
    editing: null,
    newItemPreset: null,
    itemDraftDirty: false,
  })),
  setTourStep: (tourStep) => set({ tourStep }),
  toggleTreeNode: (id) => set((state) => {
    const expandedTreeNodeIds = new Set(state.expandedTreeNodeIds);
    if (expandedTreeNodeIds.has(id)) expandedTreeNodeIds.delete(id);
    else expandedTreeNodeIds.add(id);
    return { expandedTreeNodeIds };
  }),
  expandTreeNodes: (ids) => set((state) => {
    const expandedTreeNodeIds = new Set(state.expandedTreeNodeIds);
    let changed = false;
    for (const id of ids) {
      if (expandedTreeNodeIds.has(id)) continue;
      expandedTreeNodeIds.add(id);
      changed = true;
    }
    return changed ? { expandedTreeNodeIds } : state;
  }),
  collapseAllTreeNodes: () => set({ expandedTreeNodeIds: new Set() }),
  pruneTreeNodes: (validIds) => set((state) => {
    const expandedTreeNodeIds = new Set(
      [...state.expandedTreeNodeIds].filter((id) => validIds.has(id)),
    );
    return expandedTreeNodeIds.size === state.expandedTreeNodeIds.size
      ? state
      : { expandedTreeNodeIds };
  }),
  resetWorkspaceUi: () => {
    const pending = get().confirm;
    pending?.resolve(false);
    set({
      selectedVaultId: 'all',
      selectedItemId: null,
      search: '',
      kindFilter: 'all',
      tagFilter: null,
      selectedFolderPath: null,
      editing: null,
      newItemPreset: null,
      itemDraftDirty: false,
      itemSavePending: false,
      membersDialogVaultId: null,
      auditDialogVaultId: null,
      pairingOpen: false,
      groupsOpen: false,
      recoveryOpen: false,
      devicesOpen: false,
      retirementOpen: false,
      guideOpen: false,
      tourStep: null,
      expandedTreeNodeIds: new Set(),
      confirm: null,
    });
  },
  requestConfirm: (options) =>
    new Promise((resolve) => {
      set({ confirm: { ...options, resolve } });
    }),
  closeConfirm: (confirmed) => {
    const { confirm } = get();
    if (confirm) {
      confirm.resolve(confirmed);
      set({ confirm: null });
    }
  },
  });
});
