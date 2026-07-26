import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { ArchiveX, CheckCircle2, RefreshCw, ShieldAlert, X } from 'lucide-react';
import type {
  LegacyKeyRetirementReason,
  LegacyKeyRetirementResponse,
} from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import dialogStyles from './dialog.module.css';
import styles from './LegacyKeyRetirementDialog.module.css';

const REASON_LABELS: Record<LegacyKeyRetirementReason, string> = {
  post_cutover: '迁移完成后的短期保留',
  rollback_window: '环境级回滚验证窗口',
  regulatory_hold: '合规要求的受控保留',
  fresh_install: '全新安装，没有旧托管密钥',
};

export function LegacyKeyRetirementDialog() {
  const { zeroKnowledge } = useApp();
  const open = useUi((state) => state.retirementOpen);
  const setOpen = useUi((state) => state.setRetirementOpen);
  const toast = useUi((state) => state.toast);
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const [status, setStatus] = useState<LegacyKeyRetirementResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [reasonCode, setReasonCode] = useState<LegacyKeyRetirementReason>('rollback_window');
  const [retireBy, setRetireBy] = useState(defaultDeadline);
  const [copyInventoryDigest, setCopyInventoryDigest] = useState('');
  const [copyManifestDigest, setCopyManifestDigest] = useState('');
  const [kekFingerprintDigest, setKekFingerprintDigest] = useState('');
  const [approvalEvidenceDigest, setApprovalEvidenceDigest] = useState('');

  const load = async () => {
    setStatus(null);
    setError(null);
    try {
      const value = await zeroKnowledge.legacyKeyRetirementStatus();
      setStatus(value);
      if (value.approvalEvidenceDigest) setApprovalEvidenceDigest(value.approvalEvidenceDigest);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '旧密钥退役状态加载失败');
    }
  };

  useEffect(() => {
    if (open) void load();
    else resetForm();
  }, [open]);

  const createPlan = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!validDigest(copyInventoryDigest) || !validDigest(copyManifestDigest)) {
      toast('error', '副本清点摘要和证据 manifest 摘要必须是 SHA-256 的 base64url 值');
      return;
    }
    if (reasonCode !== 'fresh_install' && !validDigest(kekFingerprintDigest)) {
      toast('error', '旧 KEK 指纹摘要必须是 SHA-256 的 base64url 值，不能输入 KEK 本身');
      return;
    }
    const deadline = reasonCode === 'fresh_install' ? null : localDateTimeToIso(retireBy);
    if (reasonCode !== 'fresh_install' && !deadline) {
      toast('error', '请选择有效的最晚退役时间');
      return;
    }
    setBusy(true);
    try {
      const value = await zeroKnowledge.createLegacyKeyRetirement({
        reasonCode,
        retireBy: deadline,
        copyInventoryDigest: copyInventoryDigest.trim(),
        copyManifestDigest: copyManifestDigest.trim(),
        kekFingerprintDigest: reasonCode === 'fresh_install' ? null : kekFingerprintDigest.trim(),
      });
      setStatus(value);
      notifyStatusChanged();
      toast('info', '旧密钥退役计划已登记，等待两名管理员审批同一份完成证据');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '旧密钥退役计划登记失败');
    } finally {
      setBusy(false);
    }
  };

  const approve = async () => {
    if (!status?.planDigest) return;
    const evidenceDigest = status.approvalEvidenceDigest ?? approvalEvidenceDigest.trim();
    if (!validDigest(evidenceDigest)) {
      toast('error', '销毁与副本清点证据摘要必须是 SHA-256 的 base64url 值');
      return;
    }
    setBusy(true);
    try {
      const value = await zeroKnowledge.approveLegacyKeyRetirement(status.planDigest, evidenceDigest);
      setStatus(value);
      setApprovalEvidenceDigest(value.approvalEvidenceDigest ?? evidenceDigest);
      notifyStatusChanged();
      toast('info', '审批已绑定到这份计划和共同证据摘要');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '旧密钥退役审批失败');
    } finally {
      setBusy(false);
    }
  };

  const complete = async () => {
    if (!status?.planDigest || !status.approvalEvidenceDigest) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: status.reasonCode === 'fresh_install' ? '确认全新安装不适用' : '确认旧托管密钥已退役',
      body: status.reasonCode === 'fresh_install'
        ? '系统将记录这次部署从未使用旧托管密钥。两名管理员必须已经核对同一份环境与副本清点证据。'
        : '系统不会自动删除外部备份或介质。只有清单内全部 KEK 副本都已按流程移除、销毁与复核证据已归档时才能确认。',
      confirmText: status.reasonCode === 'fresh_install' ? '确认不适用' : '确认已经退役',
      cancelText: '取消',
      danger: status.reasonCode !== 'fresh_install',
    });
    if (!confirmed) return;
    setBusy(true);
    try {
      const value = await zeroKnowledge.completeLegacyKeyRetirement(
        status.planDigest,
        status.approvalEvidenceDigest,
      );
      setStatus(value);
      notifyStatusChanged();
      toast('info', value.status === 'not_applicable' ? '已记录全新安装不适用' : '旧密钥退役证据已完成登记');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '旧密钥退役完成确认失败');
    } finally {
      setBusy(false);
    }
  };

  if (!open) return null;
  const approvedByCurrentUser = status?.approvalUserIds.includes(currentUserId) ?? false;
  return (
    <Dialog.Root open onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={[dialogStyles.content, styles.content].join(' ')} aria-describedby={undefined}>
          <Dialog.Title className={dialogStyles.title}>旧密钥退役</Dialog.Title>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭"><X size={16} /></button>
          </Dialog.Close>
          <div className={styles.boundary}>
            <ShieldAlert size={17} aria-hidden />
            <span>这里只登记非敏感摘要和审批。不要输入 KEK、文件路径、备份位置或任何密码内容。</span>
          </div>
          <div className={styles.toolbar}>
            <span>部署：{status?.deploymentId ?? '正在读取'}</span>
            <button type="button" aria-label="刷新旧密钥退役状态" onClick={() => void load()} disabled={busy}>
              <RefreshCw size={15} aria-hidden />
            </button>
          </div>
          {error && <ErrorState message={error} onRetry={() => void load()} />}
          {!error && status === null && <LoadingState label="正在加载旧密钥退役状态…" />}
          {status?.status === 'unplanned' && (
            <form className={styles.form} onSubmit={createPlan}>
              <h2>登记计划</h2>
              <label htmlFor="retirement-reason">保留原因</label>
              <select id="retirement-reason" value={reasonCode} onChange={(event) => setReasonCode(event.target.value as LegacyKeyRetirementReason)}>
                {Object.entries(REASON_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
              {reasonCode !== 'fresh_install' && (
                <>
                  <label htmlFor="retirement-deadline">最晚退役时间</label>
                  <input id="retirement-deadline" type="datetime-local" value={retireBy} onChange={(event) => setRetireBy(event.target.value)} />
                </>
              )}
              <DigestInput id="retirement-copy-inventory" label="副本清点 SHA-256（base64url）" value={copyInventoryDigest} onChange={setCopyInventoryDigest} />
              <DigestInput id="retirement-copy-manifest" label="清单 manifest SHA-256（base64url）" value={copyManifestDigest} onChange={setCopyManifestDigest} />
              {reasonCode !== 'fresh_install' && (
                <DigestInput id="retirement-kek-fingerprint" label="旧 KEK 指纹 SHA-256（base64url）" value={kekFingerprintDigest} onChange={setKekFingerprintDigest} />
              )}
              <button className={styles.primary} type="submit" disabled={busy}>
                <ArchiveX size={16} aria-hidden />{busy ? '正在签名并登记…' : '签名并登记计划'}
              </button>
            </form>
          )}
          {status && status.status !== 'unplanned' && (
            <>
              <StatusSummary status={status} />
              {(status.status === 'planned' || status.status === 'approved') && (
                <section className={styles.section}>
                  <h2>双人审批</h2>
                  <p>两名不同管理员必须核对并批准同一份销毁与副本清点证据摘要。</p>
                  <DigestInput
                    id="retirement-completion-evidence"
                    label="销毁与副本清点证据 SHA-256（base64url）"
                    value={status.approvalEvidenceDigest ?? approvalEvidenceDigest}
                    onChange={setApprovalEvidenceDigest}
                    readOnly={status.approvalEvidenceDigest !== null}
                  />
                  <button className={styles.primary} type="button" disabled={busy || approvedByCurrentUser} onClick={() => void approve()}>
                    <CheckCircle2 size={16} aria-hidden />
                    {approvedByCurrentUser ? '你已批准这份证据' : busy ? '正在签名审批…' : '核对后签名批准'}
                  </button>
                  {status.status === 'approved' && (
                    <button className={styles.dangerAction} type="button" disabled={busy} onClick={() => void complete()}>
                      <ArchiveX size={16} aria-hidden />
                      {status.reasonCode === 'fresh_install' ? '确认全新安装不适用' : '确认旧 KEK 已按清单退役'}
                    </button>
                  )}
                </section>
              )}
              {(status.status === 'completed' || status.status === 'not_applicable') && (
                <div className={styles.complete} role="status">
                  <CheckCircle2 size={17} aria-hidden />
                  <span>{status.status === 'not_applicable'
                    ? '该部署已由两名管理员确认是全新安装，旧托管密钥不适用。'
                    : `旧密钥退役证据已完成，覆盖 ${status.evidenceJobCount}/${status.migratedJobCount} 个已迁移密码库任务。`}</span>
                </div>
              )}
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );

  function resetForm() {
    setStatus(null);
    setError(null);
    setBusy(false);
    setReasonCode('rollback_window');
    setRetireBy(defaultDeadline());
    setCopyInventoryDigest('');
    setCopyManifestDigest('');
    setKekFingerprintDigest('');
    setApprovalEvidenceDigest('');
  }
}

function DigestInput({
  id,
  label,
  value,
  onChange,
  readOnly = false,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
}) {
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className={styles.digestInput}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        readOnly={readOnly}
        autoComplete="off"
        spellCheck={false}
        maxLength={43}
      />
    </>
  );
}

function StatusSummary({ status }: { status: LegacyKeyRetirementResponse }) {
  return (
    <dl className={styles.summary}>
      <div><dt>状态</dt><dd>{statusLabel(status)}</dd></div>
      <div><dt>原因</dt><dd>{status.reasonCode ? REASON_LABELS[status.reasonCode] : '未登记'}</dd></div>
      <div><dt>审批</dt><dd>{status.approvalCount}/2 人</dd></div>
      <div><dt>最晚退役</dt><dd>{status.retireBy ? new Date(status.retireBy).toLocaleString() : '不适用'}</dd></div>
      <div className={styles.digestRow}><dt>计划摘要</dt><dd>{status.planDigest}</dd></div>
    </dl>
  );
}

function statusLabel(status: LegacyKeyRetirementResponse): string {
  if (status.status === 'planned') return status.overdue ? '计划已逾期，等待审批' : '等待双人审批';
  if (status.status === 'approved') return status.overdue ? '已审批但逾期未完成' : '双人已审批，等待完成确认';
  if (status.status === 'completed') return '退役证据已完成';
  if (status.status === 'not_applicable') return '全新安装，不适用';
  return '尚未登记';
}

function validDigest(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value.trim());
}

function localDateTimeToIso(value: string): string | null {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.getTime() > Date.now() ? date.toISOString() : null;
}

function defaultDeadline(): string {
  const date = new Date(Date.now() + 7 * 86_400_000);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function notifyStatusChanged() {
  window.dispatchEvent(new Event('mima:legacy-retirement-updated'));
}
