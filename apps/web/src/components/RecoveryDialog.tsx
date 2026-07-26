import * as Dialog from '@radix-ui/react-dialog';
import { PlayCircle, ShieldAlert, X } from 'lucide-react';
import { useState } from 'react';
import { useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import dialogStyles from './dialog.module.css';
import styles from './RecoveryDialog.module.css';
import { AdminAccountResetApprovals } from './SecurityGate.tsx';
import { EnterpriseRecoveryRequestPanel } from './EnterpriseRecoveryRequestPanel.tsx';
import { RecoveryCoverageTasks } from './RecoveryCoverageTasks.tsx';
import { RecoveryKeyManager } from './RecoveryKeyManager.tsx';
import { RecoveryAdminTour } from './RecoveryAdminTour.tsx';
import { RecoveryExecutiveSummary } from './RecoveryExecutiveSummary.tsx';
import { readRecoveryGuideState, writeRecoveryGuideState } from '../utils/recovery-guide-storage.ts';

export { RecoveryKeyManager, parseEnterpriseRecoveryManifest } from './RecoveryKeyManager.tsx';

export function RecoveryDialog() {
  const open = useUi((state) => state.recoveryOpen);
  const setOpen = useUi((state) => state.setRecoveryOpen);
  const isLocalPlatformAdmin = useMeta((state) => state.user?.isLocalPlatformAdmin ?? false);
  const [tourOpen, setTourOpen] = useState(false);
  const [promptVisible, setPromptVisible] = useState(
    () => isLocalPlatformAdmin && !readRecoveryGuideState().promptShown,
  );

  if (!open) return null;
  return (
    <Dialog.Root open onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content
          className={[dialogStyles.content, styles.content].join(' ')}
          aria-describedby={undefined}
          data-recovery-dialog
        >
          <div className={styles.titleBar}>
            <Dialog.Title className={dialogStyles.title}>企业恢复</Dialog.Title>
            {isLocalPlatformAdmin && (
              <button type="button" className={styles.tourButton} onClick={() => {
                writeRecoveryGuideState({ promptShown: true });
                setPromptVisible(false);
                setTourOpen(true);
              }}>
                <PlayCircle size={15} aria-hidden />管理者入门
              </button>
            )}
          </div>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭"><X size={16} /></button>
          </Dialog.Close>
          {promptVisible && (
            <div className={styles.tourPrompt} role="status">
              <div>
                <strong>第一次管理企业恢复？</strong>
                <span>用 3 分钟看懂为什么安全、需要哪些人，以及真正恢复时怎么做。</span>
              </div>
              <div className={styles.tourPromptActions}>
                <button type="button" className={styles.secondaryButton} onClick={() => {
                  writeRecoveryGuideState({ promptShown: true });
                  setPromptVisible(false);
                }}>稍后</button>
                <button type="button" onClick={() => {
                  writeRecoveryGuideState({ promptShown: true });
                  setPromptVisible(false);
                  setTourOpen(true);
                }}><PlayCircle size={15} aria-hidden />开始导览</button>
              </div>
            </div>
          )}
          {isLocalPlatformAdmin && <RecoveryExecutiveSummary />}
          <div className={styles.warning} data-recovery-tour="recovery-boundary">
            <ShieldAlert size={17} aria-hidden />
            <span>恢复不会找回员工旧主密码，也不会新增访问权限。仍有人能打开团队库时，优先由所有者直接重新授权；个人库只能恢复给仍具合法归属的原所有者本人。</span>
          </div>
          {isLocalPlatformAdmin && <RecoveryKeyManager />}
          <RecoveryCoverageTasks />
          {isLocalPlatformAdmin && <AdminAccountResetApprovals />}
          <EnterpriseRecoveryRequestPanel />
          {tourOpen && <RecoveryAdminTour onFinish={(completed) => {
            writeRecoveryGuideState({ promptShown: true, completed });
            setTourOpen(false);
          }} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
