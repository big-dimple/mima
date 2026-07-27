import { useEffect, useMemo, useRef } from 'react';
import { Plus, Search, Star, AlertTriangle, Clock, GripVertical } from 'lucide-react';
import type { DecryptedItemMeta } from '@mima/client-core';
import type { ItemKind } from '@mima/contracts';
import {
  getItemPresentation,
  getVisibleItemAuxiliary,
  folderContainsPath,
  resolveEffectiveRole,
  canEditItems,
} from '@mima/domain';
import { useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { useDrag, ITEM_DRAG_MIME, ITEM_DRAG_TOKEN } from '../state/drag-store.ts';
import { useDragEnvironment } from '../hooks/useDragEnvironment.ts';
import { ActionButton } from './ActionButton.tsx';
import { SegmentedControl } from './SegmentedControl.tsx';
import { ItemKindMark } from './ItemKindMark.tsx';
import styles from './ItemList.module.css';

const KIND_LABEL: Record<ItemKind | 'all', string> = {
  all: '全部',
  login: getItemPresentation('login').kindLabel,
  api_token: getItemPresentation('api_token').kindLabel,
  secure_note: getItemPresentation('secure_note').kindLabel,
};

const FILTER_OPTIONS = (['all', 'login', 'api_token', 'secure_note'] as const).map((value) => ({
  value,
  label: KIND_LABEL[value],
  icon: <ItemKindMark kind={value} compact />,
}));

export function ItemList() {
  const items = useMeta((s) => s.items);
  const vaults = useMeta((s) => s.vaults);
  const memberships = useMeta((s) => s.memberships);
  const pendingIds = useMeta((s) => s.pendingItemIds);
  const conflicts = useMeta((s) => s.conflicts);
  const user = useMeta((s) => s.user)!;
  const ui = useUi();
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // 全部过滤/搜索在客户端内存完成，不请求服务端
  const filtered = useMemo(() => {
    const q = ui.search.trim().toLowerCase();
    return Object.values(items)
      .filter((item) => {
        if (ui.selectedVaultId === 'favorites') return item.favorite;
        if (ui.selectedVaultId !== 'all' && item.vaultId !== ui.selectedVaultId) return false;
        return true;
      })
      .filter((item) => {
        if (ui.selectedVaultId === 'all' || ui.selectedVaultId === 'favorites') return true;
        if (ui.selectedFolderPath === null) return true;
        if (ui.selectedFolderPath === '') return !item.folderPath;
        return folderContainsPath(ui.selectedFolderPath, item.folderPath);
      })
      .filter((item) => (ui.kindFilter === 'all' ? true : item.kind === ui.kindFilter))
      .filter((item) => (ui.tagFilter ? item.tags.includes(ui.tagFilter) : true))
      .filter((item) => {
        if (!q) return true;
        const linkedLogin = item.kind === 'api_token' && item.linkedLoginItemId
          ? items[item.linkedLoginItemId]
          : undefined;
        const validLinkedLogin = linkedLogin?.kind === 'login' && linkedLogin.vaultId === item.vaultId
          ? linkedLogin
          : undefined;
        return [
          item.title,
          getVisibleItemAuxiliary(item.kind, item.username) ?? '',
          item.kind === 'login' ? (item.loginUrls ?? [item.loginUrl ?? item.origin ?? '']).join(' ') : '',
          item.description ?? '',
          validLinkedLogin?.title ?? '',
          item.folderPath ?? '',
          item.tags.join(' '),
        ]
          .join(' ')
          .toLowerCase()
          .includes(q);
      })
      .sort((a, b) =>
        Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title, 'zh-CN'),
      );
  }, [items, ui.selectedVaultId, ui.selectedFolderPath, ui.kindFilter, ui.tagFilter, ui.search]);

  // 键盘：/ 聚焦搜索，↑↓ 选择，Enter 打开
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // 拖拽状态只存瞬时内存：Escape、组件卸载或工作台锁定都要清空。
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') useDrag.getState().endDrag();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      useDrag.getState().endDrag();
    };
  }, []);
  const locked = useMeta((s) => s.locked);
  useEffect(() => {
    if (locked) useDrag.getState().endDrag();
  }, [locked]);

  const moveSelection = (delta: number) => {
    if (filtered.length === 0) return;
    const idx = filtered.findIndex((i) => i.id === ui.selectedItemId);
    const next = idx < 0 ? (delta > 0 ? 0 : filtered.length - 1) : Math.min(filtered.length - 1, Math.max(0, idx + delta));
    ui.selectItem(filtered[next]!.id);
  };

  const canCreateHere = useMemo(() => {
    if (ui.selectedVaultId === 'all' || ui.selectedVaultId === 'favorites') return false;
    const vault = vaults[ui.selectedVaultId];
    if (!vault) return false;
    const role = vault.kind === 'personal'
      ? 'owner'
      : resolveEffectiveRole(memberships[vault.id] ?? [], { userId: user.id, groups: user.groups });
    return canEditItems(role);
  }, [ui.selectedVaultId, vaults, memberships, user]);

  // 仅在选中具体密码库、用户可编辑、视口同时显示左右栏且为细指针时启用原生拖拽。
  const canDragItems = useMemo(() => {
    if (ui.selectedVaultId === 'all' || ui.selectedVaultId === 'favorites') return false;
    const vault = vaults[ui.selectedVaultId];
    if (!vault) return false;
    const role = vault.kind === 'personal'
      ? 'owner'
      : resolveEffectiveRole(memberships[vault.id] ?? [], { userId: user.id, groups: user.groups });
    return canEditItems(role);
  }, [ui.selectedVaultId, vaults, memberships, user]);
  const finePointer = useDragEnvironment();
  const dragEnabled = canDragItems && finePointer;

  return (
    <section className={styles.pane} aria-label="凭证列表">
      <div className={styles.toolbar}>
        <div className={styles.searchBox} data-tour="search">
          <Search size={14} className={styles.searchIcon} aria-hidden />
          <input
            ref={searchRef}
            className={styles.search}
            aria-label="搜索条目"
            placeholder="搜索标题/说明/凭证标识/关联信息"
            value={ui.search}
            onChange={(e) => ui.setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                moveSelection(1);
                listRef.current?.focus();
              }
            }}
          />
        </div>
        <ActionButton
          label="新建"
          icon={<Plus size={16} />}
          onClick={() => ui.startNewItem()}
          disabled={!canCreateHere}
          title={canCreateHere ? '新建条目' : '请先在左侧选择一个你可编辑的库'}
          tour="new-item"
        />
      </div>

      <div className={styles.filters}>
        <SegmentedControl
          label="类型过滤"
          value={ui.kindFilter}
          options={FILTER_OPTIONS}
          onChange={ui.setKindFilter}
          layout="filter"
        />
      </div>
      {ui.tagFilter && (
        <div className={styles.tagFilterRow}>
          标签过滤：<span className={styles.tagChip}>{ui.tagFilter}</span>
          <button className={styles.clearTag} onClick={() => ui.setTagFilter(null)}>清除</button>
        </div>
      )}

      <div
        ref={listRef}
        className={styles.list}
        tabIndex={0}
        role="listbox"
        aria-label="凭证"
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            moveSelection(1);
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            moveSelection(-1);
          }
        }}
      >
        {filtered.length === 0 && (
          <div className={styles.empty}>
            {Object.keys(items).length === 0 ? '这里还没有条目' : '没有匹配的条目'}
          </div>
        )}
        {filtered.map((item) => (
          <ItemRow
            key={item.id}
            item={item}
            vaultName={vaults[item.vaultId]?.name ?? ''}
            selected={ui.selectedItemId === item.id}
            pending={!!pendingIds[item.id]}
            conflicted={!!conflicts[item.id]}
            showVaultName={ui.selectedVaultId === 'all' || ui.selectedVaultId === 'favorites'}
            onSelect={() => ui.selectItem(item.id)}
            draggable={dragEnabled}
          />
        ))}
      </div>
      <div className={styles.count}>
        {ui.selectedFolderPath === '' ? '未分类 · ' : ui.selectedFolderPath ? `${ui.selectedFolderPath} · ` : ''}
        {filtered.length} 个条目
      </div>
    </section>
  );
}

function ItemRow({
  item,
  vaultName,
  selected,
  pending,
  conflicted,
  showVaultName,
  onSelect,
  draggable,
}: {
  item: DecryptedItemMeta;
  vaultName: string;
  selected: boolean;
  pending: boolean;
  conflicted: boolean;
  showVaultName: boolean;
  onSelect: () => void;
  draggable: boolean;
}) {
  const auxiliary = getVisibleItemAuxiliary(item.kind, item.username);
  // pending / conflicted 条目当前不可拖动，避免重复写入或覆盖冲突候选。
  const canDragThis = draggable && !pending && !conflicted;

  const handleDragStart = (event: React.DragEvent<HTMLButtonElement>) => {
    if (!canDragThis) {
      event.preventDefault();
      return;
    }
    // DataTransfer 只放固定内部 MIME 与常量值，绝不写入 item ID、标题、用户名、
    // 网址、目录、标签或任何解密元数据。条目 ID 只驻留瞬时内存。
    event.dataTransfer.setData(ITEM_DRAG_MIME, ITEM_DRAG_TOKEN);
    event.dataTransfer.effectAllowed = 'move';
    useDrag.getState().beginDrag({ id: item.id, vaultId: item.vaultId });
  };

  return (
    <button
      role="option"
      aria-selected={selected}
      className={[styles.row, selected ? styles.rowSelected : '', canDragThis ? styles.rowDraggable : ''].join(' ')}
      onClick={onSelect}
      draggable={canDragThis}
      onDragStart={handleDragStart}
      onDragEnd={() => useDrag.getState().endDrag()}
    >
      {draggable && (
        <span className={styles.grip} aria-hidden>
          <GripVertical size={14} />
        </span>
      )}
      <span className={styles.rowIcon}><ItemKindMark kind={item.kind} /></span>
      <span className={styles.rowBody}>
        <span className={styles.rowTitle}>
          <span className={styles.rowTitleText}>{item.title}</span>
          {item.favorite && <Star size={12} className={styles.fav} aria-label="收藏" />}
          {item.sensitivity === 'high' && <span className={styles.sensHigh}>高敏</span>}
        </span>
        <span className={styles.rowSub}>
          {auxiliary && <span className={styles.rowSubText}>{auxiliary}</span>}
          {item.kind === 'login' && item.origin && <span className={styles.origin}>{safeHost(item.origin)}</span>}
          {showVaultName && <span className={styles.vaultTag}>{vaultName}</span>}
        </span>
      </span>
      {pending && <Clock size={13} className={styles.pendingIcon} aria-label="待同步" />}
      {conflicted && <AlertTriangle size={13} className={styles.conflictIcon} aria-label="有新的修改需要处理" />}
    </button>
  );
}

function safeHost(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}
