import * as Dialog from '@radix-ui/react-dialog';
import {
  Clock3,
  LayoutDashboard,
  LifeBuoy,
  RefreshCw,
  Settings2,
  ShieldAlert,
  X,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import { useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import dialogStyles from './dialog.module.css';
import styles from './RecoveryDialog.module.css';
import { AdminAccountResetApprovals } from './SecurityGate.tsx';
import { RecoveryKeyManager } from './RecoveryKeyManager.tsx';
import {
  RecoveryWorkspaceProvider,
  useRecoveryWorkspace,
} from './RecoveryWorkspaceContext.tsx';

export { RecoveryKeyManager, parseEnterpriseRecoveryManifest } from './RecoveryKeyManager.tsx';

type RecoverySection = 'overview' | 'setup' | 'cases' | 'history';

const ADMIN_NAVIGATION: Array<{
  id: RecoverySection;
  label: string;
  icon: typeof LayoutDashboard;
}> = [
  { id: 'overview', label: '总览', icon: LayoutDashboard },
  { id: 'setup', label: '准备恢复', icon: Settings2 },
  { id: 'cases', label: '恢复案件', icon: LifeBuoy },
  { id: 'history', label: '历史记录', icon: Clock3 },
];

const MEMBER_NAVIGATION = ADMIN_NAVIGATION.filter(({ id }) => (
  id === 'overview' || id === 'cases' || id === 'history'
));

export function RecoveryDialog() {
  const open = useUi((state) => state.recoveryOpen);
  const setOpen = useUi((state) => state.setRecoveryOpen);

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
          <RecoveryWorkspaceProvider>
            <RecoveryWorkspaceCenter />
          </RecoveryWorkspaceProvider>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function RecoveryWorkspaceCenter() {
  const isLocalPlatformAdmin = useMeta((state) => state.user?.isLocalPlatformAdmin ?? false);
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const { workspace, loading, refreshing, error, refreshedAt, refresh } = useRecoveryWorkspace();
  const [activeSection, setActiveSection] = useState<RecoverySection>('overview');
  const navigation = isLocalPlatformAdmin ? ADMIN_NAVIGATION : MEMBER_NAVIGATION;
  const activeCases = (workspace?.cases ?? []).filter((entry) => (
    ['waiting_for_target', 'pending_approval', 'approved', 'processing'].includes(entry.status)
  )) ?? [];
  const counts = useMemo<Partial<Record<RecoverySection, number>>>(() => ({
    cases: isLocalPlatformAdmin
      ? activeCases.filter((entry) => (
        entry.targetUserId !== currentUserId
        && entry.status === 'pending_approval'
        && !entry.approvalUserIds.includes(currentUserId)
      )).length
      : activeCases.filter((entry) => entry.targetUserId === currentUserId).length,
  }), [activeCases, currentUserId, isLocalPlatformAdmin]);

  return (
    <div className={styles.workspaceShell}>
      <header className={styles.workspaceHeader}>
        <div>
          <Dialog.Title className={dialogStyles.title}>企业恢复中心</Dialog.Title>
          <span>包括平台管理员也绝对无法查看受保护库；这里只帮助本人恢复原有访问。</span>
        </div>
        <div className={styles.headerActions}>
          <span className={styles.refreshStatus} data-error={Boolean(error)} role="status">
            {loading
              ? '正在核对状态'
              : refreshing
                ? '正在刷新状态'
              : error
                ? '状态更新失败'
                : refreshedAt
                  ? `更新于 ${formatTime(refreshedAt)}`
                  : '尚未更新'}
          </span>
          <button
            type="button"
            className={styles.iconButton}
            aria-label="刷新企业恢复状态"
            title="刷新企业恢复状态"
            disabled={loading || refreshing}
            onClick={() => void refresh()}
          >
            <RefreshCw className={refreshing ? styles.spin : undefined} size={17} aria-hidden />
          </button>
          <Dialog.Close asChild>
            <button className={styles.iconButton} aria-label="关闭" title="关闭">
              <X size={18} aria-hidden />
            </button>
          </Dialog.Close>
        </div>
      </header>

      <div className={styles.workspaceBody}>
        <nav className={styles.workspaceNav} aria-label="企业恢复功能">
          {navigation.map(({ id, label, icon: Icon }) => {
            const count = counts[id] ?? 0;
            return (
              <button
                key={id}
                type="button"
                className={styles.navItem}
                data-active={activeSection === id}
                aria-current={activeSection === id ? 'page' : undefined}
                onClick={() => setActiveSection(id)}
              >
                <Icon size={17} aria-hidden />
                <span>{label}</span>
                {count > 0 && <strong aria-label={`${count} 项待处理`}>{count}</strong>}
              </button>
            );
          })}
          <div className={styles.navBoundary}>
            <ShieldAlert size={16} aria-hidden />
            <span>只恢复既有访问，不找回旧主密码，也不会给任何人新增权限。</span>
          </div>
        </nav>

        <main className={styles.workspacePane} tabIndex={-1}>
          {error && workspace && (
            <div className={styles.inlineWarning} role="alert">
              <ShieldAlert size={16} aria-hidden />
              <span>{error}。当前展示上一次成功读取的状态，可点击右上角重试。</span>
            </div>
          )}
          {activeSection === 'overview' && (
            <MemberRecoveryOverview />
          )}
          {activeSection === 'setup' && isLocalPlatformAdmin && (
            <RecoveryKeyManager />
          )}
          {activeSection === 'cases' && (
            <section className={styles.paneSection} aria-labelledby="recovery-cases-heading">
              <div className={styles.paneHeading}>
                <span>{isLocalPlatformAdmin ? '管理员协助' : '我的协助'}</span>
                <h2 id="recovery-cases-heading">恢复案件</h2>
                <p>{isLocalPlatformAdmin
                  ? '同事在公司群里求助后，从这里发起；两位管理员分别确认即可。'
                  : '管理员发起后，你只需要设置新主密码，后续会自动完成。'}</p>
              </div>
              {isLocalPlatformAdmin ? (
                <AdminAccountResetApprovals
                  showEmpty
                  recoveryWorkspace={workspace}
                  onRecoveryChanged={refresh}
                />
              ) : <RecoveryCaseList active />}
            </section>
          )}
          {activeSection === 'history' && (
            <section className={styles.paneSection} aria-labelledby="recovery-history-heading">
              <div className={styles.paneHeading}>
                <span>处理记录</span>
                <h2 id="recovery-history-heading">历史记录</h2>
                <p>保留每次协助的结果和时间，不显示密码库名称或库内内容。</p>
              </div>
              <RecoveryCaseList active={false} />
            </section>
          )}
        </main>
      </div>
    </div>
  );
}

function MemberRecoveryOverview() {
  return (
    <section className={styles.paneSection} aria-labelledby="member-recovery-overview-heading">
      <div className={styles.paneHeading}>
        <span>恢复说明</span>
        <h2 id="member-recovery-overview-heading">忘记主密码时，管理员可以帮你恢复原有访问</h2>
        <p>你直接在公司群里联系管理员即可，不需要自己找申请入口、下载工具或理解技术步骤。</p>
      </div>
      <div className={styles.boundaryGrid}>
        <div><strong>旧主密码不会被找回</strong><span>你会设置一个新主密码。</span></div>
        <div><strong>只恢复原有权限</strong><span>系统不会借恢复流程给你新增任何密码库权限。</span></div>
        <div><strong>需要两位管理员确认</strong><span>任何一位管理员都不能单独完成恢复。</span></div>
        <div><strong>管理员不能代替你</strong><span>包括平台管理员也绝对无法查看受保护库，更不能登录你的账号。</span></div>
      </div>
    </section>
  );
}

function RecoveryCaseList({ active }: { active: boolean }) {
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const isLocalPlatformAdmin = useMeta((state) => state.user?.isLocalPlatformAdmin ?? false);
  const { workspace } = useRecoveryWorkspace();
  const rows = (workspace?.cases ?? []).filter((entry) => {
    if (!isLocalPlatformAdmin && entry.targetUserId !== currentUserId) return false;
    const ongoing = ['waiting_for_target', 'pending_approval', 'approved', 'processing'].includes(entry.status);
    return active ? ongoing : !ongoing;
  });
  if (rows.length === 0) return <div className={styles.empty}>{active ? '当前没有进行中的恢复协助。' : '还没有历史记录。'}</div>;
  return (
    <ul className={styles.maintenanceList}>
      {rows.map((entry) => (
        <li key={entry.id}>
          <div>
            <strong>{isLocalPlatformAdmin ? entry.targetDisplayName : (entry.kind === 'forgot_password' ? '忘记主密码' : '交接中断')}</strong>
            <span>{caseStatusLabel(entry)} · {new Date(entry.createdAt).toLocaleString()}</span>
            <span>原有密码库 {entry.items.length} 个，已恢复 {entry.resolvedItemCount} 个{entry.skippedItemCount ? `，已跳过 ${entry.skippedItemCount} 个失效权限` : ''}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}

function caseStatusLabel(entry: import('@mima/contracts').EnterpriseRecoveryCase) {
  if (entry.status === 'waiting_for_target') {
    return entry.kind === 'forgot_password' ? '等待用户设置新主密码' : '正在自动准备恢复';
  }
  if (entry.status === 'pending_approval') return '等待两位管理员确认';
  if (entry.status === 'approved' || entry.status === 'processing') return '正在自动恢复';
  if (entry.status === 'completed') return '已完成';
  if (entry.status === 'completed_with_skips') return '已完成，失效权限已跳过';
  if (entry.status === 'expired') return '已过期';
  return '已取消';
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '刚刚';
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}
