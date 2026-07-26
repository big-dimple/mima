import { useCallback } from 'react';
import { folderContainsPath } from '@mima/domain';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';

export interface MoveItemTarget {
  id: string;
  vaultId: string;
  folderPath?: string | null;
}

/**
 * 把条目移动到目标目录的统一入口，供原生拖拽和“移动到目录”弹窗共用。
 *
 * - 相同目标不发请求，仅提示“条目已在该目录中”。
 * - pending / conflicted 条目不可移动，避免重复写入或覆盖冲突候选。
 * - 复用 actions.updateItemMeta（本地加密 + 离线 Outbox + 版本冲突链路），不直接改 DOM/Zustand。
 * - 在线 409 会被 client 记录为冲突并保留原位置：调用返回后若发现冲突，绝不显示成功提示。
 * - 成功后不自动切换目录；若条目已离开当前过滤结果，清除详情选择并用 toast 指明目标目录。
 *
 * 返回 true 表示确实发起了一次移动写入（成功或进入离线队列），false 表示 no-op / 拒绝 / 冲突 / 失败。
 */
export function useMoveItemToFolder(): (item: MoveItemTarget, targetFolderPath: string | null) => Promise<boolean> {
  const { actions, store } = useApp();
  const pendingItemIds = useMeta((s) => s.pendingItemIds);
  const conflicts = useMeta((s) => s.conflicts);
  const toast = useUi((s) => s.toast);

  return useCallback(async (item, targetFolderPath) => {
    const current = item.folderPath ?? null;
    const target = targetFolderPath ?? null;
    if (current === target) {
      toast('info', '条目已在该目录中');
      return false;
    }
    if (pendingItemIds[item.id]) {
      toast('warn', '该条目还在同步中，请稍后再移动');
      return false;
    }
    if (conflicts[item.id]) {
      toast('warn', '这条记录已有新修改，请先在详情中确认最新内容');
      return false;
    }

    const label = target === null ? '未分类' : target;
    try {
      await actions.updateItemMeta(item.id, { folderPath: target });
      // 在线 409 被 client 吞并记录为冲突：保留原位置，不显示成功提示。
      if (store.getState().conflicts[item.id]) return false;

      const filterPath = useUi.getState().selectedFolderPath;
      const stillVisible = filterPath === null
        || (filterPath === '' ? target === null : folderContainsPath(filterPath, target));
      if (!stillVisible && useUi.getState().selectedItemId === item.id) {
        useUi.getState().selectItem(null);
      }
      // 不自动切换目录，便于连续整理；仅用 toast 明确目标目录。
      toast('info', `已移动到「${label}」`);
      return true;
    } catch (error) {
      // 非 409 失败：actions 已弹出错误提示，这里只保证不误报成功。
      if (!(error instanceof Error)) toast('error', '移动失败');
      return false;
    }
  }, [actions, store, pendingItemIds, conflicts, toast]);
}
