import { create } from 'zustand';

/**
 * 拖拽归类的固定内部标记。DataTransfer 只放这一个 MIME 与常量值，
 * 绝不写入 item ID、标题、用户名、网址、目录、标签或任何解密元数据。
 * 被拖条目的 ID 只存在于下方的瞬时内存 store，随 dragend/drop/Escape/卸载/锁定清空。
 */
export const ITEM_DRAG_MIME = 'application/x-mima-item';
export const ITEM_DRAG_TOKEN = 'move';

interface DragState {
  /** 正在拖拽的条目 ID；null 表示当前没有拖拽。只存内存，不持久化。 */
  draggingItemId: string | null;
  /** 拖拽起点所在库，用于把放置目标限定在同一密码库。 */
  sourceVaultId: string | null;
  beginDrag(item: { id: string; vaultId: string }): void;
  endDrag(): void;
}

export const useDrag = create<DragState>((set) => ({
  draggingItemId: null,
  sourceVaultId: null,
  beginDrag: (item) => set({ draggingItemId: item.id, sourceVaultId: item.vaultId }),
  endDrag: () => set({ draggingItemId: null, sourceVaultId: null }),
}));
