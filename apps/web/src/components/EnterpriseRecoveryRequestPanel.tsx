import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, Download, RefreshCw, Upload } from 'lucide-react';
import { parseOfflineRecoveryResult } from '@mima/client-core';
import type { EnterpriseRecoveryRequest } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import styles from './RecoveryDialog.module.css';

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
  const [requests, setRequests] = useState<EnterpriseRecoveryRequest[] | null>(null);
  const [selectedId, setSelectedId] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const resultRef = useRef<HTMLTextAreaElement>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const values = (await api.recoveryRequests()).filter((request) =>
        request.targetUserId === currentUserId
        && (request.status === 'pending' || request.status === 'approved')
        && Date.parse(request.expiresAt) > Date.now(),
      );
      setRequests(values);
      setSelectedId((current) => values.some((entry) => entry.id === current)
        ? current
        : values[0]?.id ?? '');
    } catch (caught) {
      setRequests([]);
      setError(caught instanceof Error ? caught.message : '企业恢复请求加载失败');
    }
  }, [api, currentUserId]);

  useEffect(() => {
    void load();
    return () => {
      if (resultRef.current) resultRef.current.value = '';
    };
  }, [load]);

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

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const raw = resultRef.current?.value.trim();
    if (!selected || selected.status !== 'approved' || !raw) return;
    setBusy(true);
    try {
      const parsed = parseOfflineRecoveryResult(JSON.parse(raw) as unknown);
      await zeroKnowledge.completeRecovery(selected, parsed);
      toast(selected.targetCapability === 'metadata' ? 'info' : 'warn', selected.targetCapability === 'metadata'
        ? '已恢复审计信息访问，不包含密码或敏感内容'
        : '完整恢复已验证，下一步需要由拥有者完成密码库安全更新');
      if (resultRef.current) resultRef.current.value = '';
      await load();
      onCompleted?.();
    } catch (caught) {
      toast('error', caught instanceof SyntaxError
        ? '离线恢复结果不是有效 JSON'
        : caught instanceof Error ? caught.message : '离线恢复结果导入失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={styles.requestPanel} aria-labelledby="recovery-request-heading" data-recovery-tour="recovery-requests">
      <div className={styles.sectionHeading}>
        <div>
          <h2 id="recovery-request-heading"><Upload size={16} aria-hidden />我的恢复请求</h2>
          <p>每次恢复都要重新走完整流程：两位管理员确认、两位材料保管人离线操作，最后由请求绑定的目标设备验证。</p>
        </div>
        <button type="button" className={styles.secondaryButton} disabled={busy} onClick={() => void load()}>
          <RefreshCw size={15} aria-hidden />刷新
        </button>
      </div>
      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {!error && requests === null && <LoadingState label="正在加载恢复请求…" />}
      {!error && requests?.length === 0 && (
        <div className={styles.empty}>{recoveryRequired
          ? '管理员发起请求并完成两人审批后，这里会提供离线恢复包。'
          : '当前没有需要你下载或导入的企业恢复请求。仍有拥有者能打开密码库时，应优先由拥有者重新开通访问。'}</div>
      )}
      {requests && requests.length > 0 && (
        <form className={styles.requestForm} onSubmit={submit}>
          <label htmlFor="enterprise-recovery-request">请求状态</label>
          <select
            id="enterprise-recovery-request"
            value={selectedId}
            onChange={(event) => setSelectedId(event.target.value)}
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
                ? '两位管理员已经确认。下一步下载本次恢复包，交给两位材料保管人在隔离设备共同处理。'
                : `等待第 ${selected.approvalUserIds.length + 1} 位管理员确认。两人确认完成前不会生成可用恢复包。`}</span>
            </div>
          )}
          {selected?.status === 'approved' && (
            <>
              <a
                className={styles.toolLink}
                href="/downloads/mima-recovery-tool-0.2.0.zip"
                download
              >
                <Download size={15} aria-hidden />下载离线恢复工具 ZIP
              </a>
              <button type="button" disabled={busy} onClick={() => void download()}>
                <Download size={15} aria-hidden />下载本次恢复包
              </button>
              <label htmlFor="enterprise-recovery-result">离线恢复结果</label>
              <textarea
                id="enterprise-recovery-result"
                ref={resultRef}
                rows={7}
                spellCheck={false}
                autoComplete="off"
                placeholder="粘贴离线工具生成的恢复结果 JSON"
              />
              <p>{selected.targetCapability === 'metadata'
                ? '仅审计信息恢复不包含密码、Token 或备注正文，也不会冻结密码库。'
                : '完整恢复后会暂时停止修改，直到拥有者完成密码库安全更新。'}</p>
              <button type="submit" disabled={busy}>
                {busy ? <RefreshCw className={styles.spin} size={16} aria-hidden /> : <CheckCircle2 size={16} aria-hidden />}
                {busy ? '正在本地验证…' : '本地验证并导入'}
              </button>
            </>
          )}
        </form>
      )}
    </section>
  );
}
