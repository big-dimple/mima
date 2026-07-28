import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { EnterpriseRecoveryWorkspace } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';

interface RecoveryWorkspaceValue {
  workspace: EnterpriseRecoveryWorkspace | null;
  loading: boolean;
  refreshing: boolean;
  error: string | null;
  refreshedAt: string | null;
  refresh: (options?: { showLoading?: boolean }) => Promise<void>;
}

const RecoveryWorkspaceContext = createContext<RecoveryWorkspaceValue | null>(null);

export function RecoveryWorkspaceProvider({ children }: { children: React.ReactNode }) {
  const { api } = useApp();
  const [workspace, setWorkspace] = useState<EnterpriseRecoveryWorkspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  const inFlight = useRef<Promise<void> | null>(null);

  const refresh = useCallback(async (options?: { showLoading?: boolean }) => {
    if (inFlight.current) return inFlight.current;
    const request = (async () => {
      if (options?.showLoading) setLoading(true);
      else setRefreshing(true);
      setError(null);
      try {
        const value = await api.recoveryWorkspace();
        if (mounted.current) setWorkspace(value);
      } catch (caught) {
        if (mounted.current) {
          setError(caught instanceof Error ? caught.message : '企业恢复状态加载失败');
        }
      } finally {
        if (mounted.current) {
          setLoading(false);
          setRefreshing(false);
        }
        inFlight.current = null;
      }
    })();
    inFlight.current = request;
    return request;
  }, [api]);

  useEffect(() => {
    mounted.current = true;
    void refresh({ showLoading: true });
    const interval = window.setInterval(() => void refresh(), 15_000);
    const onFocus = () => void refresh();
    const onChanged = () => void refresh();
    window.addEventListener('focus', onFocus);
    window.addEventListener('mima:recovery-workspace-updated', onChanged);
    window.addEventListener('mima:recovery-key-updated', onChanged);
    window.addEventListener('mima:recovery-coverage-updated', onChanged);
    return () => {
      mounted.current = false;
      window.clearInterval(interval);
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('mima:recovery-workspace-updated', onChanged);
      window.removeEventListener('mima:recovery-key-updated', onChanged);
      window.removeEventListener('mima:recovery-coverage-updated', onChanged);
    };
  }, [refresh]);

  const value = useMemo<RecoveryWorkspaceValue>(() => ({
    workspace,
    loading,
    refreshing,
    error,
    refreshedAt: workspace?.refreshedAt ?? null,
    refresh,
  }), [error, loading, refresh, refreshing, workspace]);

  return (
    <RecoveryWorkspaceContext.Provider value={value}>
      {children}
    </RecoveryWorkspaceContext.Provider>
  );
}

export function useRecoveryWorkspace() {
  const value = useContext(RecoveryWorkspaceContext);
  if (!value) throw new Error('RecoveryWorkspaceProvider missing');
  return value;
}

export function useOptionalRecoveryWorkspace() {
  return useContext(RecoveryWorkspaceContext);
}
