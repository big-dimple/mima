import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Plus, X } from 'lucide-react';
import type { Vault } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './RenameVaultDialog.module.css';

export function RenameVaultDialog({
  vault,
  onOpenChange,
  onCreateProject,
}: {
  vault: Vault | null;
  onOpenChange: (open: boolean) => void;
  onCreateProject: (vault: Vault) => void;
}) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const [name, setName] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (vault) {
      setName(vault.name);
      setAdvancedOpen(false);
    }
  }, [vault]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const normalizedName = name.trim();
    if (!vault || !normalizedName || normalizedName === vault.name) return;
    setSaving(true);
    try {
      await zeroKnowledge.renameVault(vault.id, normalizedName);
      onOpenChange(false);
      toast('info', '密码库名称已修改');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '修改失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open={vault !== null} onOpenChange={(open) => {
      if (!saving) onOpenChange(open);
    }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={dialogStyles.content}>
          <Dialog.Title className={dialogStyles.title}>
            {vault?.kind === 'team' ? '编辑团队密码库' : '修改密码库名称'}
          </Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            名称会在当前设备加密后保存，服务器无法读取。
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={saving}><X size={16} /></button>
          </Dialog.Close>
          <form className={styles.form} aria-busy={saving} onSubmit={submit}>
            <label>
              名称
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                maxLength={120}
                autoFocus
                onFocus={(event) => event.currentTarget.select()}
              />
            </label>
            {vault?.kind === 'team' && vault.projectContext?.kind !== 'project' && (
              <details
                className={styles.advanced}
                open={advancedOpen}
                onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}
              >
                <summary>更多设置</summary>
                <div className={styles.advancedBody}>
                  <p>
                    默认保持扁平密码库最容易使用。只有确需在一个上级库下分别管理多套独立权限时，才创建项目。
                  </p>
                  <ActionButton
                    label="新建独立权限项目"
                    icon={<Plus size={15} />}
                    variant="secondary"
                    disabled={saving}
                    onClick={() => {
                      if (!vault) return;
                      onOpenChange(false);
                      onCreateProject(vault);
                    }}
                  />
                </div>
              </details>
            )}
            <div className={styles.actions}>
              <ActionButton
                label="取消"
                variant="secondary"
                onClick={() => onOpenChange(false)}
                disabled={saving}
              />
              <ActionButton
                label={saving ? '保存中…' : '保存'}
                type="submit"
                disabled={
                  saving ||
                  !name.trim() ||
                  name.trim() === vault?.name
                }
              />
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
