import * as Dialog from '@radix-ui/react-dialog';
import {
  ClipboardCheck,
  Clock3,
  LayoutDashboard,
  LifeBuoy,
  RefreshCw,
  Settings2,
  ShieldAlert,
  ShieldPlus,
  Wrench,
  X,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import type { EnterpriseRecoveryKey } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import dialogStyles from './dialog.module.css';
import styles from './RecoveryDialog.module.css';
import { AdminAccountResetApprovals } from './SecurityGate.tsx';
import { EnterpriseRecoveryRequestPanel } from './EnterpriseRecoveryRequestPanel.tsx';
import { RecoveryCoverageTasks } from './RecoveryCoverageTasks.tsx';
import { RecoveryKeyManager } from './RecoveryKeyManager.tsx';
import { RecoveryExecutiveSummary } from './RecoveryExecutiveSummary.tsx';
import {
  RecoveryWorkspaceProvider,
  useRecoveryWorkspace,
} from './RecoveryWorkspaceContext.tsx';

export { RecoveryKeyManager, parseEnterpriseRecoveryManifest } from './RecoveryKeyManager.tsx';

type RecoverySection = 'overview' | 'setup' | 'approvals' | 'coverage' | 'maintenance' | 'mine';

const ADMIN_NAVIGATION: Array<{
  id: RecoverySection;
  label: string;
  icon: typeof LayoutDashboard;
}> = [
  { id: 'overview', label: '总览', icon: LayoutDashboard },
  { id: 'setup', label: '准备恢复能力', icon: Settings2 },
  { id: 'approvals', label: '待办审批', icon: ClipboardCheck },
  { id: 'coverage', label: '密码库保护', icon: ShieldPlus },
  { id: 'maintenance', label: '高级维护', icon: Wrench },
  { id: 'mine', label: '我的恢复', icon: LifeBuoy },
];

const MEMBER_NAVIGATION = ADMIN_NAVIGATION.filter(({ id }) => (
  id === 'overview' || id === 'coverage' || id === 'mine'
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
  const activeRequests = workspace?.requests.filter((request) => (
    (request.status === 'pending' || request.status === 'approved')
    && Date.parse(request.expiresAt) > Date.now()
  )) ?? [];
  const counts = useMemo<Partial<Record<RecoverySection, number>>>(() => ({
    approvals: isLocalPlatformAdmin
      ? (workspace?.candidates.length ?? 0) + activeRequests.filter((request) => (
        request.targetUserId !== currentUserId && !request.approvalUserIds.includes(currentUserId)
      )).length
      : 0,
    coverage: workspace?.coverage?.vaults.filter((vault) => vault.canManage && !vault.covered).length ?? 0,
    maintenance: workspace?.keys.filter((key) => key.status === 'pending' || key.status === 'staged').length ?? 0,
    mine: activeRequests.filter((request) => request.targetUserId === currentUserId).length,
  }), [activeRequests, currentUserId, isLocalPlatformAdmin, workspace]);

  return (
    <div className={styles.workspaceShell}>
      <header className={styles.workspaceHeader}>
        <div>
          <Dialog.Title className={dialogStyles.title}>企业恢复中心</Dialog.Title>
          <span>管理员无法查看密码库内容；所有恢复都需要独立审批和离线材料。</span>
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
            isLocalPlatformAdmin
              ? <RecoveryExecutiveSummary />
              : <MemberRecoveryOverview />
          )}
          {activeSection === 'setup' && isLocalPlatformAdmin && <RecoveryKeyManager />}
          {activeSection === 'approvals' && isLocalPlatformAdmin && (
            <section className={styles.paneSection} aria-labelledby="recovery-approvals-heading">
              <div className={styles.paneHeading}>
                <span>管理员待办</span>
                <h2 id="recovery-approvals-heading">待办审批</h2>
                <p>先核对申请人、密码库和请求摘要。你的确认只推进流程，不能解密或查看内容。</p>
              </div>
              <AdminAccountResetApprovals
                showEmpty
                recoveryWorkspace={workspace}
                onRecoveryChanged={refresh}
              />
            </section>
          )}
          {activeSection === 'coverage' && (
            <section className={styles.paneSection} aria-labelledby="recovery-coverage-page-heading">
              <div className={styles.paneHeading}>
                <span>密码库所有者待办</span>
                <h2 id="recovery-coverage-page-heading">密码库保护</h2>
                <p>只有你能解锁并管理的密码库会出现在这里。平台不能代替所有者生成恢复保护。</p>
              </div>
              <RecoveryCoverageTasks showEmpty />
            </section>
          )}
          {activeSection === 'maintenance' && isLocalPlatformAdmin && <RecoveryMaintenance />}
          {activeSection === 'mine' && <EnterpriseRecoveryRequestPanel />}
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
        <h2 id="member-recovery-overview-heading">先判断是否真的需要企业恢复</h2>
        <p>仍有可信设备或密码库所有者可以打开内容时，应优先直接恢复访问。企业恢复只处理所有正常入口都不可用的情况。</p>
      </div>
      <div className={styles.boundaryGrid}>
        <div><strong>不会找回旧主密码</strong><span>恢复完成后仍需在目标设备建立新的本机解锁能力。</span></div>
        <div><strong>不会绕过原有权限</strong><span>只能恢复到已经拥有合法访问权的本人设备。</span></div>
        <div><strong>需要多人共同完成</strong><span>两位管理员确认，再由两名离线材料保管人联合处理。</span></div>
        <div><strong>每次请求单独核对</strong><span>恢复包、审批和结果都只属于本次请求，不能跨请求重复使用。</span></div>
      </div>
    </section>
  );
}

function RecoveryMaintenance() {
  const { api } = useApp();
  const toast = useUi((state) => state.toast);
  const { workspace, refresh } = useRecoveryWorkspace();
  const [busyId, setBusyId] = useState<string | null>(null);
  const keys = workspace?.keys ?? [];

  const cancelKey = async (key: EnterpriseRecoveryKey) => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '取消本次恢复能力准备？',
      body: '这会结束当前未启用的公开清单。已经分发到线下的对应恢复材料应按公司制度销毁；已正式启用的恢复能力不会受影响。',
      confirmText: '确认取消',
      cancelText: '返回',
      danger: true,
    });
    if (!confirmed) return;
    setBusyId(key.id);
    try {
      await api.cancelRecoveryKey(key.id, {
        idempotencyKey: crypto.randomUUID(),
        ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
      });
      toast('info', '本次恢复能力准备已取消');
      await refresh();
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '取消失败');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section className={styles.paneSection} aria-labelledby="recovery-maintenance-heading">
      <div className={styles.paneHeading}>
        <span>低频操作</span>
        <h2 id="recovery-maintenance-heading">高级维护</h2>
        <p>这里只处理未完成准备的取消和历史核对。正式启用的恢复能力不能在浏览器中直接删除。</p>
      </div>
      {keys.length === 0 ? (
        <div className={styles.empty}>还没有企业恢复公开清单。</div>
      ) : (
        <ul className={styles.maintenanceList}>
          {keys.map((key) => (
            <li key={key.id}>
              <div>
                <strong>{recoveryKeyStatusLabel(key.status)}</strong>
                <span><Clock3 size={14} aria-hidden />{new Date(key.createdAt).toLocaleString()}</span>
                <code>{key.keyFingerprint}</code>
              </div>
              {(key.status === 'pending' || key.status === 'staged') && (
                <button type="button" disabled={busyId !== null} onClick={() => void cancelKey(key)}>
                  {busyId === key.id ? '正在取消…' : '取消本次准备'}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function recoveryKeyStatusLabel(status: EnterpriseRecoveryKey['status']) {
  if (status === 'pending') return '等待第二位管理员确认';
  if (status === 'staged') return '等待密码库覆盖或正式启用';
  if (status === 'active') return '当前启用';
  if (status === 'retired') return '已退役';
  if (status === 'compromised') return '已标记为不可信';
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
