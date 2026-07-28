import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, RefreshCw, ShieldPlus } from 'lucide-react';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryVaultCoverage,
  EnterpriseRecoveryWorkspace,
} from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import styles from './RecoveryDialog.module.css';
import { useOptionalRecoveryWorkspace } from './RecoveryWorkspaceContext.tsx';

interface CoverageState {
  key: EnterpriseRecoveryKey;
  coverage: EnterpriseRecoveryCoverage;
}

interface VaultResult {
  status: 'success' | 'error';
  message: string;
}

export function RecoveryCoverageTasks({ showEmpty = false }: { showEmpty?: boolean } = {}) {
  const { api, zeroKnowledge } = useApp();
  const vaults = useMeta((state) => state.vaults);
  const locked = useMeta((state) => state.locked);
  const selectedVaultId = useUi((state) => state.selectedVaultId);
  const recoveryWorkspace = useOptionalRecoveryWorkspace();
  const refreshWorkspace = recoveryWorkspace?.refresh;
  const hasWorkspace = recoveryWorkspace !== null;
  const [standaloneState, setStandaloneState] = useState<CoverageState | null | undefined>(undefined);
  const [standaloneError, setStandaloneError] = useState<string | null>(null);
  const [busyVaultIds, setBusyVaultIds] = useState<Set<string>>(new Set());
  const [batchBusy, setBatchBusy] = useState(false);
  const [results, setResults] = useState<Record<string, VaultResult>>({});
  const controllers = useRef(new Set<AbortController>());
  const mounted = useRef(true);
  const state = recoveryWorkspace
    ? coverageStateFromWorkspace(recoveryWorkspace.workspace)
    : standaloneState;
  const error = recoveryWorkspace?.error ?? standaloneError;
  const loading = recoveryWorkspace
    ? recoveryWorkspace.loading && !recoveryWorkspace.workspace
    : standaloneState === undefined;

  const abortTasks = useCallback(() => {
    controllers.current.forEach((controller) => controller.abort());
    controllers.current.clear();
  }, []);

  const load = useCallback(async (showLoading = true) => {
    if (refreshWorkspace) {
      await refreshWorkspace({ showLoading });
      return;
    }
    if (showLoading) setStandaloneState(undefined);
    setStandaloneError(null);
    try {
      const keys = await api.recoveryKeys();
      const key = keys.find((entry) => entry.status === 'staged');
      if (!key) {
        if (mounted.current) setStandaloneState(null);
        return;
      }
      const coverage = await api.recoveryCoverage(key.id);
      if (mounted.current) setStandaloneState({ key, coverage });
    } catch (caught) {
      if (mounted.current) {
        setStandaloneState(null);
        setStandaloneError(caught instanceof Error ? caught.message : '公司恢复保护任务加载失败');
      }
    }
  }, [api, refreshWorkspace]);

  useEffect(() => {
    mounted.current = true;
    if (!hasWorkspace) void load();
    return () => {
      mounted.current = false;
      abortTasks();
    };
  }, [abortTasks, hasWorkspace, load]);

  useEffect(() => () => abortTasks(), [abortTasks, locked, selectedVaultId]);

  const distribute = async (
    vault: EnterpriseRecoveryVaultCoverage,
    controller: AbortController,
  ) => {
    if (!state) return;
    setBusyVaultIds((current) => new Set(current).add(vault.vaultId));
    try {
      const result = await zeroKnowledge.distributeEnterpriseRecoveryEnvelope(
        state.key,
        vault,
        controller.signal,
      );
      if (!controller.signal.aborted && mounted.current) {
        setResults((current) => ({
          ...current,
          [vault.vaultId]: {
            status: 'success',
            message: result.alreadyCovered ? '已存在有效保护' : '恢复保护已添加',
          },
        }));
      }
    } catch (caught) {
      if (!controller.signal.aborted && mounted.current) {
        setResults((current) => ({
          ...current,
          [vault.vaultId]: {
            status: 'error',
            message: caught instanceof Error ? caught.message : '添加失败',
          },
        }));
      }
    } finally {
      controllers.current.delete(controller);
      if (mounted.current) {
        setBusyVaultIds((current) => {
          const next = new Set(current);
          next.delete(vault.vaultId);
          return next;
        });
      }
    }
  };

  const runOne = async (vault: EnterpriseRecoveryVaultCoverage) => {
    const controller = new AbortController();
    controllers.current.add(controller);
    await distribute(vault, controller);
    if (!controller.signal.aborted) {
      await load(false);
      window.dispatchEvent(new Event('mima:recovery-coverage-updated'));
    }
  };

  const runAll = async () => {
    if (!state) return;
    setBatchBusy(true);
    const pending = state.coverage.vaults.filter((vault) => vault.canManage && !vault.covered);
    for (const vault of pending) {
      if (!mounted.current) break;
      const controller = new AbortController();
      controllers.current.add(controller);
      await distribute(vault, controller);
      if (controller.signal.aborted) break;
    }
    if (mounted.current) {
      setBatchBusy(false);
      await load(false);
      window.dispatchEvent(new Event('mima:recovery-coverage-updated'));
    }
  };

  if (loading) return <LoadingState label="正在检查你负责的密码库…" />;
  if (error) return <ErrorState message={error} onRetry={() => void load()} />;
  if (!state) return showEmpty ? <div className={styles.empty}>当前没有需要添加恢复保护的密码库。</div> : null;
  const pending = state.coverage.vaults.filter((vault) => vault.canManage && !vault.covered);
  if (pending.length === 0) return showEmpty ? <div className={styles.empty}>你负责的密码库均已完成恢复保护，没有待办。</div> : null;

  return (
    <section className={styles.coverageTasks} aria-labelledby="owner-coverage-heading">
      <div className={styles.sectionHeading}>
        <div>
          <h2 id="owner-coverage-heading"><ShieldPlus size={16} aria-hidden />添加公司恢复保护</h2>
          <p>你是以下密码库的拥有者。恢复保护只在当前已解锁的浏览器中生成，服务器只收到加密后的结果。</p>
        </div>
        <button
          type="button"
          disabled={batchBusy || busyVaultIds.size > 0 || locked}
          onClick={() => void runAll()}
        >
          <ShieldPlus size={15} aria-hidden />
          {batchBusy ? '正在逐库处理…' : `处理全部 ${pending.length} 个`}
        </button>
      </div>
      <ul className={styles.coverageTaskList}>
        {pending.map((vault) => {
          const result = results[vault.vaultId];
          return (
            <li key={vault.vaultId}>
              <div>
                <strong>{vaults[vault.vaultId]?.name ?? `密码库 ${vault.vaultId.slice(0, 8)}`}</strong>
                <span>当前保护版本 {vault.epoch ?? '未初始化'}</span>
                {result && <span data-result={result.status}>{result.message}</span>}
              </div>
              <button
                type="button"
                disabled={batchBusy || busyVaultIds.size > 0 || locked}
                onClick={() => void runOne(vault)}
              >
                {busyVaultIds.has(vault.vaultId)
                  ? <RefreshCw className={styles.spin} size={15} aria-hidden />
                  : result?.status === 'success'
                    ? <CheckCircle2 size={15} aria-hidden />
                    : <ShieldPlus size={15} aria-hidden />}
                {busyVaultIds.has(vault.vaultId) ? '处理中…' : '添加保护'}
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function coverageStateFromWorkspace(
  workspace: EnterpriseRecoveryWorkspace | null,
): CoverageState | null {
  if (!workspace?.coverage) return null;
  const key = workspace.keys.find((entry) => entry.id === workspace.coverage?.keyId);
  return key ? { key, coverage: workspace.coverage } : null;
}
