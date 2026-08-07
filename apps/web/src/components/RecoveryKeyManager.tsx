import {
  CheckCircle2,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  UsersRound,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  RegisterEnterpriseRecoveryKeyRequestSchema,
  type EnterpriseRecoveryCoverage,
  type EnterpriseRecoveryKey,
  type EnterpriseRecoveryReadiness,
  type EnterpriseRecoveryWorkspace,
  type RegisterEnterpriseRecoveryKeyRequest,
} from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { RecoveryAdministratorGuide } from './RecoveryAdministratorGuide.tsx';
import { useOptionalRecoveryWorkspace } from './RecoveryWorkspaceContext.tsx';
import styles from './RecoveryDialog.module.css';

interface ManagerState {
  keys: EnterpriseRecoveryKey[];
  readiness: EnterpriseRecoveryReadiness;
  workflowKey: EnterpriseRecoveryKey | null;
  coverage: EnterpriseRecoveryCoverage | null;
}

export function RecoveryKeyManager() {
  const { api, zeroKnowledge } = useApp();
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const recoveryWorkspace = useOptionalRecoveryWorkspace();
  const [fallbackState, setFallbackState] = useState<ManagerState | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const automaticActivation = useRef<string | null>(null);
  const workspaceState = managerStateFromWorkspace(recoveryWorkspace?.workspace ?? null);
  const state = workspaceState ?? fallbackState;

  const load = async () => {
    if (recoveryWorkspace) {
      await recoveryWorkspace.refresh();
      return;
    }
    const workspace = await api.recoveryWorkspace();
    setFallbackState(managerStateFromWorkspace(workspace));
  };

  useEffect(() => {
    if (!recoveryWorkspace) void load().catch((error) => {
      setActionError(error instanceof Error ? error.message : '企业恢复状态加载失败');
    });
  }, [recoveryWorkspace]);

  useEffect(() => {
    const key = state?.workflowKey;
    if (!key || key.status !== 'staged' || !state?.readiness.ready) return;
    const replacingActiveKey = state.keys.some((entry) => entry.id !== key.id && entry.status === 'active');
    if (replacingActiveKey && !state.coverage?.complete) return;
    if (automaticActivation.current === key.id) return;
    automaticActivation.current = key.id;
    setBusyAction(`activate:${key.id}`);
    void api.activateRecoveryKey(key.id, {
      idempotencyKey: `activate-${key.id}`,
      ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
    }).then(async () => {
      toast('info', '企业恢复已经准备完成');
      await load();
    }).catch((error) => {
      automaticActivation.current = null;
      setActionError(error instanceof Error ? error.message : '自动启用失败，请刷新重试');
    }).finally(() => setBusyAction(null));
  }, [api, state, toast]);

  const currentManagedKey = useMemo(() => state?.keys.find((key) => (
    key.custodyMode === 'administrator_accounts'
    && ['pending', 'staged', 'active'].includes(key.status)
  )) ?? null, [state]);
  const expectedAdministratorIds = useMemo(() => (
    state?.readiness.administrators.map((entry) => entry.userId).sort() ?? []
  ), [state]);
  const managedAdministratorIds = useMemo(() => (
    [...(currentManagedKey?.custodyUserIds ?? [])].sort()
  ), [currentManagedKey]);
  const administratorSetCurrent = expectedAdministratorIds.length === managedAdministratorIds.length
    && expectedAdministratorIds.every((entry, index) => entry === managedAdministratorIds[index]);

  const prepare = async () => {
    if (!state?.readiness.ready) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: currentManagedKey ? '更新企业恢复管理员？' : '启用企业恢复？',
      body: `系统会把参与恢复所需的加密能力分别放入当前 ${state.readiness.administratorCount} 位管理员账号中。今后任意两位管理员确认即可帮助同事恢复，任何一位管理员都不能单独完成。`,
      confirmText: currentManagedKey ? '确认更新' : '确认启用',
      cancelText: '暂不处理',
    });
    if (!confirmed) return;
    setBusyAction('prepare');
    setActionError(null);
    try {
      if (currentManagedKey
        && currentManagedKey.status !== 'active'
        && !administratorSetCurrent
      ) {
        await api.cancelRecoveryKey(currentManagedKey.id, {
          idempotencyKey: `replace-${currentManagedKey.id}`,
          ceremonyEvidenceDigest: currentManagedKey.ceremonyEvidenceDigest,
        });
      }
      const request = await zeroKnowledge.prepareManagedEnterpriseRecoveryKey(
        state.readiness.administrators,
      );
      await api.registerManagedRecoveryKey(request);
      await zeroKnowledge.refresh().catch(() => undefined);
      await load();
      toast('info', '你的确认已完成，请另一位管理员进入本页确认');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : '企业恢复准备失败');
    } finally {
      setBusyAction(null);
    }
  };

  const approve = async (key: EnterpriseRecoveryKey) => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '确认企业恢复设置？',
      body: '浏览器会在本机核对你的恢复权限。确认后即可与其他任意一位恢复管理员共同帮助同事，平台仍无法查看密码库内容。',
      confirmText: '核对并确认',
      cancelText: '暂不确认',
    });
    if (!confirmed) return;
    setBusyAction(`approve:${key.id}`);
    setActionError(null);
    try {
      const share = await api.recoveryCustodyShare(key.id);
      const request = await zeroKnowledge.prepareManagedEnterpriseRecoveryKeyApproval(key, share);
      const updated = await api.approveRecoveryKey(key.id, request);
      await zeroKnowledge.refresh().catch(() => undefined);
      await load();
      toast('info', updated.status === 'active'
        ? '第二位管理员已确认，企业恢复已经启用'
        : '第二位管理员已确认，历史密码库正在后台更新保护');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : '确认失败');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <section className={styles.keyManager} aria-labelledby="recovery-key-heading">
      <div className={styles.sectionHeading}>
        <div>
          <h2 id="recovery-key-heading"><KeyRound size={16} aria-hidden />准备企业恢复</h2>
          <p>设置两至六位恢复管理员。任何一次恢复只需要其中两位分别确认。</p>
        </div>
      </div>
      {actionError && <div className={styles.actionError} role="alert">{actionError}</div>}
      {!state && <div className={styles.emptyState}>正在查看准备状态…</div>}
      {state && (
        <div className={styles.workflowSteps}>
          <section className={styles.workflowStep} data-complete={state.readiness.ready}>
            <div className={styles.stepRail} aria-hidden>{state.readiness.ready ? <CheckCircle2 size={17} /> : <UsersRound size={17} />}</div>
            <div className={styles.stepBody}>
              <div className={styles.stepTitle}><h3><UsersRound size={17} aria-hidden />1. 核对恢复管理员</h3></div>
              <p>服务器管理员可用 <code>./deploy/mima.sh admin grant &lt;登录用户名&gt;</code> 设置管理员；最少两位，最多六位。</p>
              <RecoveryAdministratorGuide readiness={state.readiness} compact />
            </div>
          </section>

          <section className={styles.workflowStep} data-complete={Boolean(currentManagedKey)}>
            <div className={styles.stepRail} aria-hidden>{currentManagedKey ? <CheckCircle2 size={17} /> : <KeyRound size={17} />}</div>
            <div className={styles.stepBody}>
              <div className={styles.stepTitle}><h3><KeyRound size={17} aria-hidden />2. 自动准备恢复保护</h3></div>
              {!state.readiness.ready && <p>所有恢复管理员完成首次登录并设置主密码后，即可继续。</p>}
              {state.readiness.ready && (!currentManagedKey || !administratorSetCurrent) && (
                <button type="button" disabled={busyAction !== null} onClick={() => void prepare()}>
                  <ShieldCheck size={15} aria-hidden />
                  {busyAction === 'prepare' ? '正在准备…' : currentManagedKey ? '更新管理员保护' : '启用企业恢复'}
                </button>
              )}
              {currentManagedKey?.status === 'pending' && currentManagedKey.approvalUserIds.includes(currentUserId) && (
                <p>你的确认已经完成，等待另一位管理员进入本页确认。</p>
              )}
              {currentManagedKey?.status === 'pending' && !currentManagedKey.approvalUserIds.includes(currentUserId) && (
                <button type="button" disabled={busyAction !== null} onClick={() => void approve(currentManagedKey)}>
                  <CheckCircle2 size={15} aria-hidden />
                  {busyAction?.startsWith('approve:') ? '正在核对…' : '核对并完成第二次确认'}
                </button>
              )}
            </div>
          </section>

          <section className={styles.workflowStep} data-complete={currentManagedKey?.status === 'active' && administratorSetCurrent}>
            <div className={styles.stepRail} aria-hidden>{currentManagedKey?.status === 'active' ? <CheckCircle2 size={17} /> : <RefreshCw size={17} />}</div>
            <div className={styles.stepBody}>
              <div className={styles.stepTitle}><h3><ShieldCheck size={17} aria-hidden />3. 自动启用</h3></div>
              {currentManagedKey?.status === 'active' && administratorSetCurrent && state.coverage?.complete && (
                <p className={styles.completedLine}><CheckCircle2 size={15} aria-hidden />企业恢复已经启用，现有密码库均已保护。</p>
              )}
              {currentManagedKey?.status === 'pending' && (
                <p>还需要另一位管理员确认，确认后系统会自动继续。</p>
              )}
              {currentManagedKey?.status === 'staged' && (
                <p>两位管理员已经确认，历史密码库正在后台更新保护，无需额外保管或来回处理文件。</p>
              )}
              {currentManagedKey?.status === 'active' && !state.coverage?.complete && (
                <p>企业恢复已经启用。历史密码库会在各自拥有者下次解锁时自动补齐；已完成保护的密码库可立即恢复。</p>
              )}
              {!currentManagedKey && <p>两位管理员确认后，系统会自动完成后续设置。</p>}
            </div>
          </section>
        </div>
      )}
    </section>
  );
}

function managerStateFromWorkspace(workspace: EnterpriseRecoveryWorkspace | null): ManagerState | null {
  if (!workspace?.readiness) return null;
  const workflowKey = workspace.keys.find((key) => key.status === 'pending' || key.status === 'staged')
    ?? workspace.keys.find((key) => key.status === 'active')
    ?? null;
  return { keys: workspace.keys, readiness: workspace.readiness, workflowKey, coverage: workspace.coverage };
}

const PUBLIC_MANIFEST_FIELDS = new Set([
  'protocol',
  'kind',
  'ceremonyId',
  'ceremonyDigest',
  'publicEncryptionKey',
  'keyFingerprint',
  'threshold',
  'shareCount',
]);

export function parseEnterpriseRecoveryManifest(raw: string): RegisterEnterpriseRecoveryKeyRequest {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new Error('这不是有效的企业恢复公开清单');
  }
  if (!isRecord(value)
    || value.protocol !== 'lm-e2ee-v1'
    || value.kind !== 'enterprise-recovery-manifest'
    || Object.keys(value).length !== PUBLIC_MANIFEST_FIELDS.size
    || Object.keys(value).some((field) => !PUBLIC_MANIFEST_FIELDS.has(field))) {
    throw new Error('这不是有效的企业恢复公开清单');
  }
  const parsed = RegisterEnterpriseRecoveryKeyRequestSchema.safeParse({
    ceremonyId: value.ceremonyId,
    publicEncryptionKey: value.publicEncryptionKey,
    keyFingerprint: value.keyFingerprint,
    threshold: value.threshold,
    shareCount: value.shareCount,
    ceremonyEvidenceDigest: value.ceremonyDigest,
  });
  if (!parsed.success) throw new Error('企业恢复公开清单不完整');
  return parsed.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
