import { useEffect, useMemo, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { FolderInput, X } from 'lucide-react';
import type { DecryptedItemMeta } from '@mima/client-core';
import { materializeVaultDirectories, normalizeFolderPath } from '@mima/domain';
import { useMeta } from '../state/app-context.ts';
import { useMoveItemToFolder } from '../hooks/useMoveItemToFolder.ts';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './DirectoryDialog.module.css';

/**
 * 移动到目录：触摸、键盘和无拖拽环境下的同一行为入口。
 * 复用统一 dialog 样式与真实目录下拉；移动逻辑与原生拖拽共用 useMoveItemToFolder。
 */
export function MoveToFolderDialog({
  open,
  item,
  onOpenChange,
}: {
  open: boolean;
  item: DecryptedItemMeta;
  onOpenChange: (open: boolean) => void;
}) {
  const items = useMeta((state) => state.items);
  const storedDirectories = useMeta((state) => state.vaultDirectories);
  const move = useMoveItemToFolder();
  const [folderPath, setFolderPath] = useState(item.folderPath ?? '');
  const [moving, setMoving] = useState(false);

  const directories = useMemo(() => materializeVaultDirectories(
    storedDirectories[item.vaultId] ?? [],
    Object.values(items)
      .filter((candidate) => candidate.vaultId === item.vaultId)
      .map((candidate) => candidate.folderPath),
  ), [items, storedDirectories, item.vaultId]);

  useEffect(() => {
    if (open) {
      setFolderPath(item.folderPath ?? '');
      setMoving(false);
    }
  }, [open, item.folderPath]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const normalized = normalizeFolderPath(folderPath);
    setMoving(true);
    try {
      const moved = await move(item, normalized);
      // move() 内部已处理 no-op 提示、冲突保留原位与成功提示。
      if (moved || normalized === (item.folderPath ?? null)) {
        onOpenChange(false);
      }
    } finally {
      setMoving(false);
    }
  };

  const unchanged = normalizeFolderPath(folderPath) === (item.folderPath ?? null);
  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (!moving) onOpenChange(next); }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={dialogStyles.content}>
          <Dialog.Title className={dialogStyles.title}>移动到目录</Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            选择目标目录，或“未分类”移出目录。这只改变条目分类，不改变成员权限。
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={moving}><X size={16} /></button>
          </Dialog.Close>
          <form className={styles.form} aria-busy={moving} onSubmit={submit}>
            <label>
              目标目录
              <select value={folderPath} onChange={(event) => setFolderPath(event.target.value)} autoFocus>
                <option value="">未分类</option>
                {directories.map((entry) => <option key={entry.path} value={entry.path}>{entry.path}</option>)}
              </select>
            </label>
            <div className={styles.actions}>
              <ActionButton label="取消" variant="secondary" onClick={() => onOpenChange(false)} disabled={moving} />
              <ActionButton
                label={moving ? '移动中…' : '移动'}
                type="submit"
                icon={<FolderInput size={16} />}
                disabled={moving || unchanged}
              />
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
