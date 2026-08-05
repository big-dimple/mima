import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, LifeBuoy, RefreshCw } from 'lucide-react';
import type { EnterpriseRecoveryCase } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import styles from './RecoveryDialog.module.css';

const ACTIVE_STATUSES: EnterpriseRecoveryCase['status'][] = [
  'waiting_for_target',
  'pending_approval',
  'approved',
  'processing',
];

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
  const preparingCaseId = useRef<string | null>(null);
  const previousCaseId = useRef<string | null>(null);
  const [recoveryCase, setRecoveryCase] = useState<EnterpriseRecoveryCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const cases = await api.recoveryCases();
      const active = cases.find((entry) => (
        entry.targetUserId === currentUserId && ACTIVE_STATUSES.includes(entry.status)
      )) ?? null;
      if (previousCaseId.current && !active) onCompleted?.();
      previousCaseId.current = active?.id ?? null;
      setRecoveryCase(active);
      if (active?.kind === 'interrupted_handoff'
        && active.status === 'waiting_for_target'
        && preparingCaseId.current !== active.id
      ) {
        preparingCaseId.current = active.id;
        try {
          const prepared = await zeroKnowledge.continueInterruptedHandoffRecoveryCase(active);
          setRecoveryCase(prepared);
          toast('info', '恢复准备已完成，正在等待两位管理员确认');
        } catch (caught) {
          preparingCaseId.current = null;
          setError(caught instanceof Error ? caught.message : '自动恢复暂时没有完成');
        }
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '恢复进度加载失败');
    } finally {
      setLoading(false);
    }
  }, [api, currentUserId, onCompleted, toast, zeroKnowledge]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  return (
    <section className={styles.requestPanel} aria-labelledby="recovery-request-heading">
      <div className={styles.sectionHeading}>
        <div>
          <h2 id="recovery-request-heading"><LifeBuoy size={17} aria-hidden />恢复进度</h2>
          <p>管理员发起后，系统会自动恢复原有权限。</p>
        </div>
        <button type="button" className={styles.secondaryButton} onClick={() => void load()}>
          <RefreshCw size={15} aria-hidden />刷新
        </button>
      </div>
      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {!error && loading && <LoadingState label="正在查看恢复进度…" />}
      {!error && !loading && !recoveryCase && (
        <div className={styles.empty}>{recoveryRequired
          ? '请在公司群里联系管理员，直接说“我打不开原有密码库，请发起恢复协助”。管理员发起后，重新登录或刷新即可继续。'
          : '当前没有进行中的恢复协助。'}</div>
      )}
      {!error && recoveryCase && (
        <div className={styles.requestStatus} data-ready={recoveryCase.status === 'processing'}>
          {recoveryCase.status === 'processing'
            ? <CheckCircle2 size={16} aria-hidden />
            : <RefreshCw size={16} aria-hidden />}
          <span>{recoveryStatusText(recoveryCase)}</span>
        </div>
      )}
    </section>
  );
}

function recoveryStatusText(recoveryCase: EnterpriseRecoveryCase): string {
  if (recoveryCase.status === 'waiting_for_target') return '管理员已发起协助，系统正在自动准备恢复。';
  if (recoveryCase.status === 'pending_approval') {
    return `恢复准备已完成，管理员已确认 ${recoveryCase.approvalUserIds.length}/2 人。`;
  }
  if (recoveryCase.status === 'approved') return '两位管理员已经确认，系统正在自动准备恢复原有访问。';
  return '系统正在自动恢复原有访问，无需停留在这里。';
}
