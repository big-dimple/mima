import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { AlertTriangle, Trash2, X } from 'lucide-react';
import type { Vault } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './DeleteVaultDialog.module.css';

export function DeleteVaultDialog({
  vault,
  onOpenChange,
}: {
  vault: Vault | null;
  onOpenChange: (open: boolean) => void;
}) {
  const { zeroKnowledge } = useApp();
  const itemCount = useMeta((state) => vault
    ? Object.values(state.items).filter((item) => item.vaultId === vault.id).length
    : 0);
  const directoryCount = useMeta((state) => vault ? (state.vaultDirectories[vault.id]?.length ?? 0) : 0);
  const blocked = itemCount > 0 || directoryCount > 0;
  const toast = useUi((state) => state.toast);
  const [confirmation, setConfirmation] = useState('');
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    setConfirmation('');
  }, [vault]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!vault || blocked || confirmation !== vault.name) return;
    setDeleting(true);
    try {
      await zeroKnowledge.deleteVault(vault.id);
      useUi.getState().selectVault('all');
      onOpenChange(false);
      toast('info', '团队密码库已删除');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '删除失败');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Dialog.Root open={vault !== null} onOpenChange={(open) => {
      if (!deleting) onOpenChange(open);
    }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={dialogStyles.content}>
          <Dialog.Title className={dialogStyles.title}>删除团队密码库</Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            这是不可撤销的危险操作。
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={deleting}><X size={16} /></button>
          </Dialog.Close>
          <div className={styles.warning} role="alert">
            <AlertTriangle size={20} aria-hidden />
            <div>
              <strong>{vault?.name}</strong>
              <span>
                {blocked
                  ? `删除前必须先清空密码库。当前还有 ${itemCount} 个条目、${directoryCount} 个目录，请返回密码库逐项清理。成员和权限不需要手动移除。`
                  : '密码库内容已经清空。删除后，成员授权和访问能力将永久移除；需要保留的审计记录不会被破坏。'}
              </span>
            </div>
          </div>
          {blocked ? (
            <div className={styles.actions}>
              <ActionButton
                label="返回清理"
                onClick={() => {
                  if (vault) useUi.getState().selectVault(vault.id);
                  onOpenChange(false);
                }}
              />
            </div>
          ) : <form className={styles.form} aria-busy={deleting} onSubmit={submit}>
            <label>
              输入完整密码库名称以确认
              <input
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                placeholder={vault?.name ?? ''}
                autoComplete="off"
                spellCheck={false}
                autoFocus
              />
            </label>
            <div className={styles.actions}>
              <ActionButton
                label="取消"
                variant="secondary"
                onClick={() => onOpenChange(false)}
                disabled={deleting}
              />
              <ActionButton
                label={deleting ? '正在删除…' : '永久删除'}
                icon={<Trash2 size={15} />}
                variant="danger"
                type="submit"
                disabled={deleting || !vault || confirmation !== vault.name}
              />
            </div>
          </form>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
