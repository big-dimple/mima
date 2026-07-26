import * as Dialog from '@radix-ui/react-dialog';
import { useUi } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './ConfirmDialog.module.css';

export function ConfirmDialog() {
  const confirm = useUi((s) => s.confirm);
  const closeConfirm = useUi((s) => s.closeConfirm);
  if (!confirm) return null;

  const { title, body, confirmText = '确定', cancelText = '取消', danger } = confirm;

  return (
    <Dialog.Root open onOpenChange={(open) => !open && closeConfirm(false)}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={dialogStyles.content}>
          <Dialog.Title className={dialogStyles.title}>{title}</Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>{body}</Dialog.Description>
          <div className={styles.actions}>
            <ActionButton label={cancelText} variant="secondary" onClick={() => closeConfirm(false)} />
            <ActionButton label={confirmText} variant={danger ? 'danger' : 'primary'} onClick={() => closeConfirm(true)} />
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
