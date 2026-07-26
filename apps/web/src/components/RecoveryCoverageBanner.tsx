import { useCallback, useEffect, useState } from 'react';
import { ShieldPlus } from 'lucide-react';
import type { EnterpriseRecoveryCoverage } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import styles from './RecoveryCoverageBanner.module.css';

export function RecoveryCoverageBanner() {
  const { api } = useApp();
  const setRecoveryOpen = useUi((state) => state.setRecoveryOpen);
  const [coverage, setCoverage] = useState<EnterpriseRecoveryCoverage | null>(null);

  const load = useCallback(() => {
    void api.recoveryKeys().then(async (keys) => {
      const staged = keys.find((key) => key.status === 'staged');
      return staged ? api.recoveryCoverage(staged.id) : null;
    }).then(setCoverage, () => setCoverage(null));
  }, [api]);

  useEffect(() => {
    load();
    const refreshWhenVisible = () => {
      if (document.visibilityState === 'visible') load();
    };
    const interval = window.setInterval(refreshWhenVisible, 30_000);
    window.addEventListener('mima:recovery-coverage-updated', load);
    window.addEventListener('mima:recovery-key-updated', load);
    window.addEventListener('focus', refreshWhenVisible);
    window.addEventListener('online', load);
    document.addEventListener('visibilitychange', refreshWhenVisible);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener('mima:recovery-coverage-updated', load);
      window.removeEventListener('mima:recovery-key-updated', load);
      window.removeEventListener('focus', refreshWhenVisible);
      window.removeEventListener('online', load);
      document.removeEventListener('visibilitychange', refreshWhenVisible);
    };
  }, [load]);

  const pendingCount = coverage?.vaults.filter((vault) => vault.canManage && !vault.covered).length ?? 0;
  if (pendingCount === 0) return null;
  return (
    <div className={styles.banner} role="status">
      <ShieldPlus size={16} aria-hidden />
      <span>为你拥有的 {pendingCount} 个密码库添加公司恢复保护</span>
      <button type="button" onClick={() => setRecoveryOpen(true)}>查看任务</button>
    </div>
  );
}
