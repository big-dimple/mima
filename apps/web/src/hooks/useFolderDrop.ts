import { useCallback, useEffect, useState } from 'react';
import { useDrag, ITEM_DRAG_MIME } from '../state/drag-store.ts';
import { useApp } from '../state/app-context.ts';
import { useMoveItemToFolder } from './useMoveItemToFolder.ts';

/**
 * 目录行的原生放置目标。合法目标仅限“同一密码库的真实目录或未分类”：
 * “全部”、收藏、其他库或无权限目录都不是目标（由拖拽源只标记内部 MIME、
 * 且 beginDrag 记录 sourceVaultId 后，drop 时校验是否同库实现）。
 *
 * dragover 高亮只随瞬时状态变化，不改变布局（用轮廓而非尺寸）。
 */
export function useFolderDrop(
  vaultId: string | null,
  folderPath: string,
): {
  isOver: boolean;
  canDrop: boolean;
  dropProps: {
    onDragOver(event: React.DragEvent<HTMLElement>): void;
    onDragEnter(event: React.DragEvent<HTMLElement>): void;
    onDragLeave(event: React.DragEvent<HTMLElement>): void;
    onDrop(event: React.DragEvent<HTMLElement>): void;
  };
} {
  const [isOver, setIsOver] = useState(false);
  const move = useMoveItemToFolder();
  const canDrop = useDrag((state) => Boolean(
    vaultId &&
    state.draggingItemId &&
    state.sourceVaultId === vaultId
  ));

  useEffect(() => {
    if (!canDrop) setIsOver(false);
  }, [canDrop]);

  const canAcceptDrag = useCallback((): boolean => {
    const state = useDrag.getState();
    return Boolean(vaultId && state.draggingItemId && state.sourceVaultId === vaultId);
  }, [vaultId]);

  const isInternalDrag = useCallback((event: React.DragEvent<HTMLElement>): boolean => {
    // 只接受固定的内部 MIME；其他来源（文件、文本、图片等）一律忽略。
    return Array.from(event.dataTransfer.types).includes(ITEM_DRAG_MIME);
  }, []);

  const onDragEnter = useCallback((event: React.DragEvent<HTMLElement>) => {
    if (!canAcceptDrag() || !isInternalDrag(event)) return;
    event.preventDefault();
    setIsOver(true);
  }, [canAcceptDrag, isInternalDrag]);

  const onDragOver = useCallback((event: React.DragEvent<HTMLElement>) => {
    if (!canAcceptDrag() || !isInternalDrag(event)) return;
    // 必须 preventDefault 才允许后续 drop。
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    setIsOver(true);
  }, [canAcceptDrag, isInternalDrag]);

  const onDragLeave = useCallback((event: React.DragEvent<HTMLElement>) => {
    if (!canAcceptDrag() || !isInternalDrag(event)) return;
    // 仅当离开整个目标元素时清除高亮，避免子元素边界抖动。
    if (event.currentTarget.contains(event.relatedTarget as Node | null)) return;
    setIsOver(false);
  }, [canAcceptDrag, isInternalDrag]);

  const { store } = useApp();
  const onDrop = useCallback((event: React.DragEvent<HTMLElement>) => {
    if (!canAcceptDrag() || !isInternalDrag(event)) return;
    event.preventDefault();
    setIsOver(false);
    const { draggingItemId, sourceVaultId } = useDrag.getState();
    useDrag.getState().endDrag();
    if (!draggingItemId || !vaultId || sourceVaultId !== vaultId) return;
    // 条目 ID 只来自瞬时内存 store（不在 DataTransfer 中）；从这里取出当前 folderPath。
    const item = store.getState().items[draggingItemId];
    if (!item) return;
    const target = folderPath === '' ? null : folderPath;
    void move(item, target);
  }, [canAcceptDrag, folderPath, isInternalDrag, move, vaultId, store]);

  return { isOver, canDrop, dropProps: { onDragOver, onDragEnter, onDragLeave, onDrop } };
}
