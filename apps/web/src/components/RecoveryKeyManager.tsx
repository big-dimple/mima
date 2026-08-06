import { useCallback, useEffect, useRef, useState } from 'react';
import {
  CheckCircle2,
  Download,
  FileCheck2,
  KeyRound,
  RefreshCw,
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
import { RecoveryAdministratorGuide } from './RecoveryAdministratorGuide.tsx';
import styles from './RecoveryDialog.module.css';
import { useOptionalRecoveryWorkspace } from './RecoveryWorkspaceContext.tsx';

interface ManagerState {
  keys: EnterpriseRecoveryKey[];
  readiness: EnterpriseRecoveryReadiness;
  workflowKey: EnterpriseRecoveryKey | null;
  coverage: EnterpriseRecoveryCoverage | null;
}

export function RecoveryKeyManager() {
  const { api, zeroKnowledge } = useApp();
  const currentUserId = useMeta((store) => store.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const recoveryWorkspace = useOptionalRecoveryWorkspace();
  const manifestInputRef = useRef<HTMLInputElement>(null);
  const automaticActivation = useRef<string | null>(null);
  const [manifest, setManifest] = useState<{
    fileName: string;
    request: RegisterEnterpriseRecoveryKeyRequest;
  } | null>(null);
  const [sharesSeparated, setSharesSeparated] = useState(false);
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
    if (recoveryWorkspace) {
      await recoveryWorkspace.refresh({ showLoading: true });
      return;
    }
    setStandaloneLoadError(null);
    try {
      const [keys, readiness] = await Promise.all([api.recoveryKeys(), api.recoveryReadiness()]);
      const workflowKey = keys.find((key) => key.status === 'pending' || key.status === 'staged')
        ?? keys.find((key) => key.status === 'active')
        ?? null;
      const coverage = workflowKey && ['staged', 'active'].includes(workflowKey.status)
        ? await api.recoveryCoverage(workflowKey.id)
        : null;
      setStandaloneState({ keys, readiness, workflowKey, coverage });
    } catch (error) {
      setStandaloneLoadError(error instanceof Error ? error.message : '企业恢复状态加载失败');
    }
  }, [api, recoveryWorkspace]);

  useEffect(() => {
    if (recoveryWorkspace) return undefined;
    void load();
    const refresh = () => void load();
    window.addEventListener('mima:recovery-coverage-updated', refresh);
    return () => window.removeEventListener('mima:recovery-coverage-updated', refresh);
  }, [load, recoveryWorkspace]);

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
  }, [api, load, state, toast]);

  const selectManifest = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setManifest(null);
    setManifestError(null);
    setActionError(null);
    if (!file) return;
    try {
      setManifest({ fileName: file.name, request: parseEnterpriseRecoveryManifest(await readTextFile(file)) });
    } catch (error) {
      setManifestError(error instanceof Error ? error.message : '公开清单读取失败');
    }
  };

  const register = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!manifest || !sharesSeparated) return;
    setBusyAction('register');
    setActionError(null);
    try {
      const registered = await api.registerRecoveryKey(manifest.request);
      await api.approveRecoveryKey(registered.id, {
        idempotencyKey: crypto.randomUUID(),
        ceremonyEvidenceDigest: registered.ceremonyEvidenceDigest,
      });
      if (manifestInputRef.current) manifestInputRef.current.value = '';
      setManifest(null);
      setSharesSeparated(false);
      await load();
      toast('info', '公开清单已登记，你的确认也已记录；请另一位管理员确认');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : '公开清单登记失败');
    } finally {
      setBusyAction(null);
    }
  };

  const approve = async (key: EnterpriseRecoveryKey) => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '确认这套企业恢复设置？',
      body: '请确认公开清单来自公司刚刚生成的恢复材料，并且三份恢复材料已经分开保存。你的确认不会让你看到任何密码库内容。',
      confirmText: '已经核对，确认',
      cancelText: '暂不确认',
    });
    if (!confirmed) return;
    setBusyAction(`approve:${key.id}`);
    setActionError(null);
    try {
      const approved = await api.approveRecoveryKey(key.id, {
        idempotencyKey: crypto.randomUUID(),
        ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
      });
      void zeroKnowledge.refresh().catch(() => undefined);
      await load();
      toast('info', approved.status === 'active'
        ? '第二次确认已完成，企业恢复已经启用'
        : '第二次确认已完成，企业恢复正在自动启用');
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
          <p>只需准备一次。以后同事忘记主密码时，管理员不需要重新配置这些材料。</p>
        </div>
      </div>
      {actionError && <div className={styles.actionError} role="alert">{actionError}</div>}
      {loadError && <ErrorState message={loadError} onRetry={() => void load()} />}
      {!loadError && !state && <LoadingState label="正在查看准备状态…" />}
      {state && (
        <div className={styles.workflowSteps}>
          <SimpleStep icon={<Download size={17} aria-hidden />} title="1. 下载离线向导" complete={Boolean(state.workflowKey)}>
            <p>把 ZIP 带到一台断网电脑（这样生成和使用恢复材料时，它们始终不会接触服务器或网络），解压后双击“打开企业恢复向导.html”。无需安装软件，也不用填写编号、目录或文件名。</p>
            <button type="button" disabled={busyAction !== null} onClick={() => void downloadVerifiedRecoveryTool(setBusyAction, setActionError)}>
              <Download size={15} aria-hidden />下载并自动校验
            </button>
          </SimpleStep>

          <SimpleStep icon={<FileCheck2 size={17} aria-hidden />} title="2. 登记公开清单" complete={Boolean(state.workflowKey)}>
            {state.workflowKey ? (
              <p className={styles.completedLine}><CheckCircle2 size={15} aria-hidden />公开清单已登记，登记人的第一次确认已经记录。</p>
            ) : (
              <form className={styles.manifestForm} onSubmit={register}>
                <p>离线向导会生成一份“企业恢复公开清单.json”和三份恢复材料。这里只选择公开清单，恢复材料绝不能上传。</p>
                <input
                  ref={manifestInputRef}
                  className={styles.fileInput}
                  type="file"
                  aria-label="选择企业恢复公开清单"
                  accept="application/json,.json"
                  onChange={(event) => void selectManifest(event)}
                />
                {manifest && <div className={styles.fileSummary}><FileCheck2 size={16} aria-hidden /><span>{manifest.fileName} 文件检查通过。</span></div>}
                {manifestError && <div className={styles.fieldError} role="alert">{manifestError}</div>}
                <label className={styles.attestationLine}>
                  <input type="checkbox" checked={sharesSeparated} onChange={(event) => setSharesSeparated(event.target.checked)} />
                  三份恢复材料已经分别保存在三个独立位置
                </label>
                <button type="submit" disabled={!manifest || !sharesSeparated || busyAction !== null}>
                  <ShieldCheck size={15} aria-hidden />{busyAction === 'register' ? '正在登记…' : '登记并完成第一次确认'}
                </button>
              </form>
            )}
          </SimpleStep>

          <SimpleStep icon={<UsersRound size={17} aria-hidden />} title="3. 由另一位管理员确认" complete={state.workflowKey?.status === 'staged' || state.workflowKey?.status === 'active'}>
            {!state.workflowKey && <p>登记完成后，另一位管理员进入本页确认即可。</p>}
            {state.workflowKey?.status === 'pending' && state.workflowKey.approvalUserIds.includes(currentUserId) && (
              <p>你的确认已经完成，等待另一位管理员进入本页确认。</p>
            )}
            {state.workflowKey?.status === 'pending' && !state.workflowKey.approvalUserIds.includes(currentUserId) && (
              <button type="button" disabled={busyAction !== null} onClick={() => void approve(state.workflowKey!)}>
                <CheckCircle2 size={15} aria-hidden />{busyAction?.startsWith('approve:') ? '正在确认…' : '核对并确认'}
              </button>
            )}
            {(state.workflowKey?.status === 'staged' || state.workflowKey?.status === 'active') && (
              <p className={styles.completedLine}><CheckCircle2 size={15} aria-hidden />两位管理员已经确认。</p>
            )}
          </SimpleStep>

          {state.workflowKey && state.workflowKey.status !== 'active' && (
            <div className={styles.keyBoundary}>
              <RefreshCw className={busyAction?.startsWith('activate:') ? styles.spin : undefined} size={15} aria-hidden />
              两位管理员的设置已经完成，企业恢复正在自动启用。
            </div>
          )}
          {state.workflowKey?.status === 'active' && (
            <div className={styles.keyBoundary}>
              <ShieldCheck size={15} aria-hidden />
              {state.coverage?.complete
                ? '企业恢复已经启用，现有密码库均已纳入保护。'
                : `企业恢复已经启用；现有密码库已保护 ${state.coverage?.coveredVaultCount ?? 0}/${state.coverage?.totalVaultCount ?? 0}，其余会在对应拥有者下次解锁时自动补上。`}
            </div>
          )}
          <RecoveryAdministratorGuide readiness={state.readiness} compact />
        </div>
      )}
    </section>
  );
}

function SimpleStep({
  icon,
  title,
  complete,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  complete: boolean;
  children: React.ReactNode;
}) {
  return (
    <section className={styles.workflowStep} data-complete={complete}>
      <div className={styles.stepRail} aria-hidden>{complete ? <CheckCircle2 size={17} /> : icon}</div>
      <div className={styles.stepBody}>
        <div className={styles.stepTitle}><h3>{icon}{title}</h3>{complete && <CheckCircle2 size={17} aria-label="已完成" />}</div>
        {children}
      </div>
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

async function downloadVerifiedRecoveryTool(
  setBusy: (value: string | null) => void,
  setError: (value: string | null) => void,
): Promise<void> {
  const archiveUrl = '/downloads/mima-recovery-tool-0.2.0.zip';
  setBusy('download');
  setError(null);
  try {
    const [archiveResponse, digestResponse] = await Promise.all([
      fetch(archiveUrl, { cache: 'no-store' }),
      fetch(`${archiveUrl}.sha256`, { cache: 'no-store' }),
    ]);
    if (!archiveResponse.ok || !digestResponse.ok) throw new Error('离线向导下载失败，请稍后重试');
    const bytes = await archiveResponse.arrayBuffer();
    const expected = (await digestResponse.text()).trim().split(/\s+/)[0]?.toLowerCase();
    const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
      .map((value) => value.toString(16).padStart(2, '0')).join('');
    if (!expected || expected !== actual) throw new Error('离线向导校验失败，已停止下载');
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'mima-recovery-tool-0.2.0.zip';
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  } catch (error) {
    setError(error instanceof Error ? error.message : '离线向导下载失败');
  } finally {
    setBusy(null);
  }
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
    throw new Error('这不是有效的公开清单，请选择“企业恢复公开清单.json”');
  }
  if (!isRecord(value)
    || value.protocol !== 'lm-e2ee-v1'
    || value.kind !== 'enterprise-recovery-manifest'
    || Object.keys(value).length !== PUBLIC_MANIFEST_FIELDS.size
    || Object.keys(value).some((field) => !PUBLIC_MANIFEST_FIELDS.has(field))) {
    throw new Error('请选择离线向导生成的“企业恢复公开清单.json”，不要选择恢复材料');
  }
  const parsed = RegisterEnterpriseRecoveryKeyRequestSchema.safeParse({
    ceremonyId: value.ceremonyId,
    publicEncryptionKey: value.publicEncryptionKey,
    keyFingerprint: value.keyFingerprint,
    threshold: value.threshold,
    shareCount: value.shareCount,
    ceremonyEvidenceDigest: value.ceremonyDigest,
  });
  if (!parsed.success) throw new Error('公开清单不完整，请重新使用离线向导生成');
  return parsed.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
