import { useCallback, useEffect, useRef, useState } from 'react';
import {
  CheckCircle2,
  Download,
  FileCheck2,
  KeyRound,
  PackageCheck,
  ShieldCheck,
  UsersRound,
} from 'lucide-react';
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
import { readTextFile } from '../utils/read-text-file.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import styles from './RecoveryDialog.module.css';
import { useOptionalRecoveryWorkspace } from './RecoveryWorkspaceContext.tsx';

interface ManagerState {
  keys: EnterpriseRecoveryKey[];
  readiness: EnterpriseRecoveryReadiness;
  workflowKey: EnterpriseRecoveryKey | null;
  coverage: EnterpriseRecoveryCoverage | null;
}

export function RecoveryKeyManager() {
  const { api } = useApp();
  const currentUserId = useMeta((store) => store.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const recoveryWorkspace = useOptionalRecoveryWorkspace();
  const refreshWorkspace = recoveryWorkspace?.refresh;
  const hasWorkspace = recoveryWorkspace !== null;
  const manifestInputRef = useRef<HTMLInputElement>(null);
  const [manifest, setManifest] = useState<{
    fileName: string;
    request: RegisterEnterpriseRecoveryKeyRequest;
  } | null>(null);
  const [manifestError, setManifestError] = useState<string | null>(null);
  const [standaloneState, setStandaloneState] = useState<ManagerState | null>(null);
  const [standaloneLoadError, setStandaloneLoadError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const state = recoveryWorkspace
    ? managerStateFromWorkspace(recoveryWorkspace.workspace)
    : standaloneState;
  const loadError = recoveryWorkspace?.error ?? standaloneLoadError;

  const load = useCallback(async () => {
    if (refreshWorkspace) {
      await refreshWorkspace({ showLoading: true });
      return;
    }
    setStandaloneState(null);
    setStandaloneLoadError(null);
    try {
      const [keys, readiness] = await Promise.all([
        api.recoveryKeys(),
        api.recoveryReadiness(),
      ]);
      const workflowKey = keys.find((key) => key.status === 'pending' || key.status === 'staged')
        ?? keys.find((key) => key.status === 'active')
        ?? null;
      const coverage = workflowKey && (workflowKey.status === 'staged' || workflowKey.status === 'active')
        ? await api.recoveryCoverage(workflowKey.id)
        : null;
      setStandaloneState({ keys, readiness, workflowKey, coverage });
    } catch (caught) {
      setStandaloneLoadError(caught instanceof Error ? caught.message : '企业恢复状态加载失败');
    }
  }, [api, refreshWorkspace]);

  useEffect(() => {
    if (hasWorkspace) return undefined;
    void load();
    const refresh = () => void load();
    window.addEventListener('mima:recovery-coverage-updated', refresh);
    return () => window.removeEventListener('mima:recovery-coverage-updated', refresh);
  }, [hasWorkspace, load]);

  const refreshWorkflow = async () => {
    if (refreshWorkspace) await refreshWorkspace();
    else await load();
    window.dispatchEvent(new Event('mima:recovery-key-updated'));
  };

  const selectManifest = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setManifest(null);
    setManifestError(null);
    setActionError(null);
    if (!file) return;
    try {
      const request = parseEnterpriseRecoveryManifest(await readTextFile(file));
      setManifest({ fileName: file.name, request });
    } catch (caught) {
      setManifestError(caught instanceof Error ? caught.message : '公开清单读取失败');
    }
  };

  const register = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!manifest) return;
    setBusyAction('register');
    setActionError(null);
    try {
      await api.registerRecoveryKey(manifest.request);
      if (manifestInputRef.current) manifestInputRef.current.value = '';
      setManifest(null);
      await refreshWorkflow();
      toast('info', '公开清单已登记，等待两名不同管理员核对并批准');
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : '公开清单登记失败');
    } finally {
      setBusyAction(null);
    }
  };

  const approve = async (key: EnterpriseRecoveryKey) => {
    setBusyAction(`approve:${key.id}`);
    setActionError(null);
    try {
      await api.approveRecoveryKey(key.id, {
        idempotencyKey: crypto.randomUUID(),
        ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
      });
      await refreshWorkflow();
      toast('info', '批准已绑定到同一公开清单和恢复材料摘要');
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : '恢复设置批准失败');
    } finally {
      setBusyAction(null);
    }
  };

  const activate = async (key: EnterpriseRecoveryKey) => {
    if (!state?.readiness.ready || !state.coverage?.complete) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: '正式启用企业恢复',
      body: '确认三份恢复材料已经交给三个独立保管人，任意两份才能共同使用；同时确认需要保护的密码库都已明确纳入恢复范围。',
      confirmText: '确认保管并启用',
      cancelText: '取消',
    });
    if (!confirmed) return;
    setBusyAction(`activate:${key.id}`);
    setActionError(null);
    try {
      await api.activateRecoveryKey(key.id, {
        idempotencyKey: crypto.randomUUID(),
        ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
      });
      await refreshWorkflow();
      toast('info', '企业恢复已正式启用');
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : '企业恢复启用失败');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <section className={styles.keyManager} aria-labelledby="recovery-key-heading">
      <div className={styles.sectionHeading}>
        <div>
          <h2 id="recovery-key-heading"><KeyRound size={16} aria-hidden />企业恢复设置</h2>
          <p>这是企业可选的兜底能力。未启用时不影响日常使用，启用后任何一个人仍然无法单独恢复。</p>
        </div>
      </div>
      {actionError && <div className={styles.actionError} role="alert">{actionError}</div>}
      {loadError && <ErrorState message={loadError} onRetry={() => void load()} />}
      {!loadError && !state && <LoadingState label="正在核对企业恢复状态…" />}
      {state && <RecoveryWorkflow
        state={state}
        currentUserId={currentUserId}
        manifest={manifest}
        manifestError={manifestError}
        manifestInputRef={manifestInputRef}
        busyAction={busyAction}
        onManifestSelected={selectManifest}
        onRegister={register}
        onApprove={approve}
        onActivate={activate}
      />}
    </section>
  );
}

function RecoveryWorkflow({
  state,
  currentUserId,
  manifest,
  manifestError,
  manifestInputRef,
  busyAction,
  onManifestSelected,
  onRegister,
  onApprove,
  onActivate,
}: {
  state: ManagerState;
  currentUserId: string;
  manifest: { fileName: string; request: RegisterEnterpriseRecoveryKeyRequest } | null;
  manifestError: string | null;
  manifestInputRef: React.RefObject<HTMLInputElement>;
  busyAction: string | null;
  onManifestSelected: (event: React.ChangeEvent<HTMLInputElement>) => Promise<void>;
  onRegister: (event: React.FormEvent) => Promise<void>;
  onApprove: (key: EnterpriseRecoveryKey) => Promise<void>;
  onActivate: (key: EnterpriseRecoveryKey) => Promise<void>;
}) {
  const { readiness, workflowKey, coverage } = state;
  const approvalCount = Math.min(workflowKey?.approvalUserIds.length ?? 0, 2);
  const approvedByCurrentUser = workflowKey?.approvalUserIds.includes(currentUserId) ?? false;
  const missingOwners = coverage
    ? [...new Set(coverage.vaults.filter((vault) => !vault.covered).flatMap((vault) => vault.ownerUserIds))]
    : [];
  const canActivate = workflowKey?.status === 'staged' && readiness.ready && coverage?.complete === true;

  return (
    <ol className={styles.workflowSteps}>
      <WorkflowStep
        number={1}
        title="准备三位管理员"
        icon={<UsersRound size={16} aria-hidden />}
        complete={readiness.ready}
        metric={`${readiness.readyAdministratorCount}/${readiness.requiredAdministratorCount}`}
      >
        <p>名单来自系统已直授的 platform-admin，不在这里临时指定。三人需分别完成实名登录、主密码和可信设备准备。</p>
        <ul className={styles.adminReadinessList}>
          {readiness.administrators.map((administrator) => (
            <li key={administrator.userId} data-ready={administrator.ready}>
              <div>
                <strong>{administrator.displayName}</strong>
                <span>{administrator.username} · {identitySourceLabel(administrator.identitySource)}</span>
              </div>
              <span>{administrator.ready
                ? '已准备'
                : !administrator.active
                  ? '账号已停用'
                  : !administrator.hasCryptoProfile
                    ? '待设置主密码'
                    : administrator.activeDeviceCount === 0
                      ? '待授权设备'
                      : '需实名 OIDC'}</span>
            </li>
          ))}
        </ul>
      </WorkflowStep>

      <WorkflowStep
        number={2}
        title="分发三份离线材料"
        icon={<Download size={16} aria-hidden />}
        complete={workflowKey !== null}
        metric={workflowKey ? '已登记' : '未登记'}
      >
        <p>在隔离设备生成一份可公开核对的清单和三份离线材料。保管人是公司线下指定的职责，不是系统账号，也不会在工作台收到材料；任意两份才能共同使用。</p>
        <div className={styles.downloadActions}>
          <a href="/downloads/mima-recovery-tool-0.2.0.zip" download>
            <Download size={15} aria-hidden />离线工具 ZIP
          </a>
          <a href="/downloads/mima-recovery-tool-0.2.0.zip.sha256" download>
            <ShieldCheck size={15} aria-hidden />SHA-256
          </a>
        </div>
        <div className={styles.keyBoundary}>
          浏览器这里只接收公开清单。三份恢复材料不得上传、截图或放在同一台设备、同一账号或同一保管位置。
        </div>
        <form className={styles.manifestForm} onSubmit={onRegister}>
          <label htmlFor="recovery-key-manifest">公开清单 manifest.json</label>
          <input
            ref={manifestInputRef}
            id="recovery-key-manifest"
            className={styles.fileInput}
            type="file"
            accept="application/json,.json"
            onChange={(event) => void onManifestSelected(event)}
          />
          {manifest && (
            <div className={styles.fileSummary}>
              <FileCheck2 size={16} aria-hidden />
              <span><strong>{manifest.fileName}</strong>公开清单已在本机校验，可以登记。</span>
            </div>
          )}
          {manifestError && <div className={styles.fieldError} role="alert">{manifestError}</div>}
          <button type="submit" disabled={busyAction !== null || !manifest}>
            <KeyRound size={15} aria-hidden />
            {busyAction === 'register'
              ? '正在登记…'
              : state.keys.some((key) => key.status === 'active') ? '登记轮换公开清单' : '登记公开清单'}
          </button>
        </form>
      </WorkflowStep>

      <WorkflowStep
        number={3}
        title="两位管理员确认启用"
        icon={<CheckCircle2 size={16} aria-hidden />}
        complete={workflowKey?.status === 'staged' || workflowKey?.status === 'active'}
        metric={`${approvalCount}/2`}
      >
        {!workflowKey && <p>登记公开清单后，两位不同管理员分别确认这是同一次准备流程。这里的确认只允许启用，不等于执行一次恢复。</p>}
        {workflowKey && (
          <>
            <dl className={styles.keyEvidence}>
              <div><dt>公钥指纹</dt><dd><code>{workflowKey.keyFingerprint}</code></dd></div>
              <div><dt>恢复材料摘要</dt><dd><code>{workflowKey.ceremonyEvidenceDigest}</code></dd></div>
            </dl>
            {workflowKey.status === 'pending' && approvedByCurrentUser && (
              <p className={styles.completedLine}>
                <CheckCircle2 size={15} aria-hidden />你已批准，等待另一名管理员核对同一份公开清单。
              </p>
            )}
            {workflowKey.status === 'pending' && !approvedByCurrentUser && (
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => void onApprove(workflowKey)}
              >
                <CheckCircle2 size={15} aria-hidden />
                {busyAction === `approve:${workflowKey.id}` ? '正在批准…' : '核对公开清单并批准'}
              </button>
            )}
            {(workflowKey.status === 'staged' || workflowKey.status === 'active') && (
              <p className={styles.completedLine}><CheckCircle2 size={15} aria-hidden />两名不同管理员已批准同一份公开清单。</p>
            )}
          </>
        )}
      </WorkflowStep>

      <WorkflowStep
        number={4}
        title="纳入密码库保护"
        icon={<PackageCheck size={16} aria-hidden />}
        complete={coverage?.complete === true}
        metric={coverage ? `${coverage.coveredVaultCount}/${coverage.totalVaultCount}` : '等待批准'}
      >
        {!coverage && <p>完成两位管理员确认后，各密码库所有者会收到添加恢复保护的任务。</p>}
        {coverage && coverage.complete && (
          <p className={styles.completedLine}><CheckCircle2 size={15} aria-hidden />全部需要保护的密码库都已纳入恢复范围。</p>
        )}
        {coverage && !coverage.complete && (
          <div className={styles.coverageGap}>
            <strong>还有 {coverage.totalVaultCount - coverage.coveredVaultCount} 个密码库待处理</strong>
            <span>{missingOwners.length > 0
              ? `需要 ${missingOwners.length} 名拥有者完成：${missingOwners.map((id) => id.slice(0, 12)).join('、')}`
              : '等待对应密码库拥有者解锁并添加保护。'}</span>
          </div>
        )}
      </WorkflowStep>

      <WorkflowStep
        number={5}
        title="正式启用"
        icon={<ShieldCheck size={16} aria-hidden />}
        complete={workflowKey?.status === 'active'}
        metric={workflowKey?.status === 'active' ? '已启用' : '未启用'}
      >
        {workflowKey?.status === 'active' ? (
          <p className={styles.completedLine}><CheckCircle2 size={15} aria-hidden />企业恢复当前已启用。</p>
        ) : (
          <>
            <p>{!readiness.ready
              ? '三名实名管理员尚未全部准备完成。'
              : coverage?.complete !== true
                ? '密码库覆盖尚未完成，启用操作不可用。'
                : '全部条件已满足，可以正式启用。'}</p>
            <button
              type="button"
              disabled={busyAction !== null || !canActivate}
              onClick={() => workflowKey && void onActivate(workflowKey)}
            >
              <ShieldCheck size={15} aria-hidden />
              {workflowKey && busyAction === `activate:${workflowKey.id}` ? '正在启用…' : '正式启用企业恢复'}
            </button>
          </>
        )}
      </WorkflowStep>
    </ol>
  );
}

function managerStateFromWorkspace(workspace: EnterpriseRecoveryWorkspace | null): ManagerState | null {
  if (!workspace?.readiness) return null;
  const workflowKey = workspace.keys.find((key) => key.status === 'pending' || key.status === 'staged')
    ?? workspace.keys.find((key) => key.status === 'active')
    ?? null;
  return {
    keys: workspace.keys,
    readiness: workspace.readiness,
    workflowKey,
    coverage: workspace.coverage,
  };
}

function WorkflowStep({
  number,
  title,
  icon,
  complete,
  metric,
  children,
}: {
  number: number;
  title: string;
  icon: React.ReactNode;
  complete: boolean;
  metric: string;
  children: React.ReactNode;
}) {
  return (
    <li className={styles.workflowStep} data-complete={complete}>
      <div className={styles.stepRail} aria-hidden>
        {complete ? <CheckCircle2 size={17} /> : <span>{number}</span>}
      </div>
      <div className={styles.stepBody}>
        <div className={styles.stepTitle}>
          <h3>{icon}{title}</h3>
          <span>{metric}</span>
        </div>
        {children}
      </div>
    </li>
  );
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
    throw new Error('公开清单不是有效 JSON。请选择 manifest.json，不要选择 .mimashare');
  }
  if (!isRecord(value)
    || value.protocol !== 'lm-e2ee-v1'
    || value.kind !== 'enterprise-recovery-manifest'
    || Object.keys(value).length !== PUBLIC_MANIFEST_FIELDS.size
    || Object.keys(value).some((field) => !PUBLIC_MANIFEST_FIELDS.has(field))) {
    throw new Error('内容不是Mima生成的公开恢复清单，已拒绝导入');
  }
  const parsed = RegisterEnterpriseRecoveryKeyRequestSchema.safeParse({
    ceremonyId: value.ceremonyId,
    publicEncryptionKey: value.publicEncryptionKey,
    keyFingerprint: value.keyFingerprint,
    threshold: value.threshold,
    shareCount: value.shareCount,
    ceremonyEvidenceDigest: value.ceremonyDigest,
  });
  if (!parsed.success) {
    throw new Error('公开恢复清单字段无效，请重新使用离线恢复工具生成');
  }
  return parsed.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function identitySourceLabel(source: EnterpriseRecoveryReadiness['administrators'][number]['identitySource']) {
  if (source === 'oidc') return '实名 OIDC';
  if (source === 'ldap') return '域账号';
  if (source === 'feishu') return '飞书账号';
  return '本地开发账号';
}
