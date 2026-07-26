import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import type { Vault } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './CreateVaultDialog.module.css';

export function CreateVaultDialog({
  open,
  onOpenChange,
  parentVault = null,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  parentVault?: Vault | null;
}) {
  const { zeroKnowledge } = useApp();
  const { toast, selectVault } = useUi();
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName('');
  }, [open]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    try {
      const vaultId = parentVault
        ? await zeroKnowledge.createProject(parentVault.id, name.trim())
        : await zeroKnowledge.createVault(name.trim());
      selectVault(vaultId);
      setName('');
      onOpenChange(false);
      toast('info', parentVault ? '项目已创建' : '团队密码库已创建');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '创建失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={(nextOpen) => {
      if (!saving) onOpenChange(nextOpen);
    }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={`${dialogStyles.content} ${styles.dialog}`}>
          <Dialog.Title className={dialogStyles.title}>
            {parentVault ? `在「${parentVault.name}」下新建项目` : '新建团队密码库'}
          </Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            {parentVault
              ? '项目拥有独立成员和权限，不会继承上级密码库权限'
              : '你将成为拥有者，可以稍后添加成员或转移所有权'}
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={saving}><X size={16} /></button>
          </Dialog.Close>
          <form className={styles.form} aria-busy={saving} onSubmit={submit}>
            <label>
              {parentVault ? '项目名称' : '团队密码库名称'}
              <input value={name} onChange={(event) => setName(event.target.value)} maxLength={120} autoFocus />
            </label>
            <div className={styles.actions}>
              <ActionButton
                label="取消"
                variant="secondary"
                onClick={() => onOpenChange(false)}
                disabled={saving}
              />
              <ActionButton
                label={saving ? '创建中…' : parentVault ? '创建项目' : '创建并进入'}
                type="submit"
                disabled={saving || !name.trim()}
              />
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
