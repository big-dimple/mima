import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, Download, FileCheck2, LifeBuoy, RefreshCw, XCircle } from 'lucide-react';
import {
  parseOfflineRecoveryResult,
  type OfflineRecoveryResult,
} from '@mima/client-core';
import type { EnterpriseRecoveryRequest } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { readTextFile } from '../utils/read-text-file.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import styles from './RecoveryDialog.module.css';
import { useOptionalRecoveryWorkspace } from './RecoveryWorkspaceContext.tsx';

export function EnterpriseRecoveryRequestPanel({
  recoveryRequired = false,
  onCompleted,
}: {
  recoveryRequired?: boolean;
  onCompleted?: () => void;
}) {
  const { api, zeroKnowledge } = useApp();
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const recoveryWorkspace = useOptionalRecoveryWorkspace();
  const refreshWorkspace = recoveryWorkspace?.refresh;
  const hasWorkspace = recoveryWorkspace !== null;
  const resultInputRef = useRef<HTMLInputElement>(null);
  const [standaloneRequests, setStandaloneRequests] = useState<EnterpriseRecoveryRequest[] | null>(null);
  const [selectedId, setSelectedId] = useState('');
  const [standaloneError, setStandaloneError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resultFile, setResultFile] = useState<{
    fileName: string;
    result: OfflineRecoveryResult;
  } | null>(null);
  const [resultError, setResultError] = useState<string | null>(null);
  const requests = recoveryWorkspace
    ? activeRequestsForUser(recoveryWorkspace.workspace?.requests ?? [], currentUserId)
    : standaloneRequests;
  const error = recoveryWorkspace?.error ?? standaloneError;
  const loading = recoveryWorkspace
    ? recoveryWorkspace.loading && !recoveryWorkspace.workspace
    : standaloneRequests === null;

  const updateSelection = useCallback((values: EnterpriseRecoveryRequest[]) => {
    setSelectedId((current) => values.some((entry) => entry.id === current)
      ? current
      : values[0]?.id ?? '');
  }, []);

  const load = useCallback(async () => {
    if (refreshWorkspace) {
      await refreshWorkspace();
      return;
    }
    setStandaloneError(null);
    try {
      const values = activeRequestsForUser(await api.recoveryRequests(), currentUserId);
      setStandaloneRequests(values);
      updateSelection(values);
    } catch (caught) {
      setStandaloneRequests([]);
      setStandaloneError(caught instanceof Error ? caught.message : '企业恢复请求加载失败');
    }
  }, [api, currentUserId, refreshWorkspace, updateSelection]);

  useEffect(() => {
    if (!hasWorkspace) void load();
    return () => {
      if (resultInputRef.current) resultInputRef.current.value = '';
    };
  }, [hasWorkspace, load]);

  useEffect(() => {
    if (requests) updateSelection(requests);
  }, [requests, updateSelection]);

  const selected = requests?.find((request) => request.id === selectedId) ?? null;

  const download = async () => {
    if (!selected || selected.status !== 'approved') return;
    setBusy(true);
    try {
      const recoveryPackage = await api.recoveryPackage(selected.id);
      const blob = new Blob([JSON.stringify(recoveryPackage, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `mima-recovery-${selected.id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '离线恢复包下载失败');
    } finally {
      setBusy(false);
    }
  };

  const selectResult = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setResultFile(null);
    setResultError(null);
    if (!file) return;
    try {
      const parsed = parseOfflineRecoveryResult(JSON.parse(await readTextFile(file)) as unknown);
      setResultFile({ fileName: file.name, result: parsed });
    } catch (caught) {
      setResultError(caught instanceof SyntaxError
        ? '离线恢复结果不是有效 JSON'
        : caught instanceof Error ? caught.message : '离线恢复结果读取失败');
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected || selected.status !== 'approved' || !resultFile) return;
    setBusy(true);
    try {
      await zeroKnowledge.completeRecovery(selected, resultFile.result);
      toast(selected.targetCapability === 'metadata' ? 'info' : 'warn', selected.targetCapability === 'metadata'
        ? '已恢复审计信息访问，不包含密码或敏感内容'
        : '完整恢复已验证，下一步需要由拥有者完成密码库安全更新');
      if (resultInputRef.current) resultInputRef.current.value = '';
      setResultFile(null);
      if (refreshWorkspace) await refreshWorkspace();
      else await load();
      window.dispatchEvent(new Event('mima:recovery-workspace-updated'));
      onCompleted?.();
    } catch (caught) {
      setResultError(caught instanceof Error ? caught.message : '离线恢复结果导入失败');
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!selected) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: '取消这次恢复请求？',
      body: '取消后，本次审批和离线恢复包都不能继续使用。需要恢复时必须重新发起并由两位管理员重新确认。',
      confirmText: '确认取消',
      cancelText: '返回',
      danger: true,
    });
    if (!confirmed) return;
    setBusy(true);
    try {
      await api.cancelRecoveryRequest(selected.id, {
        idempotencyKey: crypto.randomUUID(),
        requestDigest: selected.requestDigest,
      });
      toast('info', '这次恢复请求已取消');
      if (refreshWorkspace) await refreshWorkspace();
      else await load();
      window.dispatchEvent(new Event('mima:recovery-workspace-updated'));
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '恢复请求取消失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={styles.requestPanel} aria-labelledby="recovery-request-heading">
      <div className={styles.sectionHeading}>
        <div>
          <h2 id="recovery-request-heading"><LifeBuoy size={17} aria-hidden />我的恢复</h2>
          <p>这里仅显示恢复到你本人设备的进行中请求。两位管理员确认后，再下载恢复包交给两名材料保管人离线处理。</p>
        </div>
        {!hasWorkspace && (
          <button type="button" className={styles.secondaryButton} disabled={busy} onClick={() => void load()}>
            <RefreshCw size={15} aria-hidden />刷新状态
          </button>
        )}
      </div>
      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {!error && loading && <LoadingState label="正在加载恢复请求…" />}
      {!error && !loading && requests?.length === 0 && (
        <div className={styles.empty}>{recoveryRequired
          ? '管理员发起请求并完成两人审批后，这里会提供离线恢复包。'
          : '当前没有需要你处理的恢复请求。仍有拥有者能打开密码库时，系统会在其下次解锁后自动恢复你的访问。'}</div>
      )}
      {requests && requests.length > 0 && (
        <form className={styles.requestForm} onSubmit={submit}>
          <label htmlFor="enterprise-recovery-request">选择恢复请求</label>
          <select
            id="enterprise-recovery-request"
            value={selectedId}
            onChange={(event) => {
              setSelectedId(event.target.value);
              setResultFile(null);
              setResultError(null);
              if (resultInputRef.current) resultInputRef.current.value = '';
            }}
          >
            {requests.map((request) => (
              <option key={request.id} value={request.id}>
                密码库 {request.vaultId.slice(0, 8)} · {request.targetCapability === 'metadata' ? '仅审计信息' : '全部内容'} · {request.approvalUserIds.length}/2 人已审批
              </option>
            ))}
          </select>
          {selected && (
            <div className={styles.requestStatus} data-ready={selected.status === 'approved'}>
              {selected.status === 'approved'
                ? <CheckCircle2 size={16} aria-hidden />
                : <RefreshCw size={16} aria-hidden />}
              <span>{selected.status === 'approved'
                ? '两位管理员已经确认。下载本次恢复包，交给两位材料保管人在隔离设备共同处理。'
                : `等待第 ${selected.approvalUserIds.length + 1} 位管理员确认。确认完成前不会生成可用恢复包。`}</span>
            </div>
          )}
          {selected?.status === 'approved' && (
            <>
              <div className={styles.requestActions}>
                <a className={styles.toolLink} href="/downloads/mima-recovery-tool-0.2.0.zip" download>
                  <Download size={15} aria-hidden />下载离线工具
                </a>
                <button type="button" disabled={busy} onClick={() => void download()}>
                  <Download size={15} aria-hidden />下载本次恢复包
                </button>
              </div>
              <label htmlFor="enterprise-recovery-result">离线恢复结果 JSON</label>
              <input
                ref={resultInputRef}
                id="enterprise-recovery-result"
                className={styles.fileInput}
                type="file"
                accept="application/json,.json"
                onChange={(event) => void selectResult(event)}
              />
              {resultFile && (
                <div className={styles.fileSummary}>
                  <FileCheck2 size={16} aria-hidden />
                  <span><strong>{resultFile.fileName}</strong>恢复结果已在本机解析，导入时还会核对请求、设备和签名。</span>
                </div>
              )}
              {resultError && <div className={styles.fieldError} role="alert">{resultError}</div>}
              <p>{selected.targetCapability === 'metadata'
                ? '仅审计信息恢复不包含密码、Token 或备注正文，也不会冻结密码库。'
                : '完整恢复后会暂时停止修改，直到拥有者完成密码库安全更新。'}</p>
              <button type="submit" disabled={busy || !resultFile}>
                {busy ? <RefreshCw className={styles.spin} size={16} aria-hidden /> : <CheckCircle2 size={16} aria-hidden />}
                {busy ? '正在本地验证…' : '验证并导入恢复结果'}
              </button>
            </>
          )}
          <button type="button" className={styles.cancelAction} disabled={busy} onClick={() => void cancel()}>
            <XCircle size={15} aria-hidden />取消这次恢复
          </button>
        </form>
      )}
    </section>
  );
}

function activeRequestsForUser(requests: EnterpriseRecoveryRequest[], currentUserId: string) {
  return requests.filter((request) => (
    request.targetUserId === currentUserId
    && (request.status === 'pending' || request.status === 'approved')
    && Date.parse(request.expiresAt) > Date.now()
  ));
}
