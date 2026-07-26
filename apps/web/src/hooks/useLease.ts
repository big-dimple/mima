import { useEffect, useState } from 'react';
import type { SecretLease } from '@mima/client-core';
import { useApp } from '../state/app-context.ts';

/**
 * 订阅某条目某个内容版本的 Secret Lease（历史版本同样经由 LeaseStore，
 * 不进 React state）。返回值仅在组件本地使用，
 * 不得存入任何全局状态或作为可序列化 props 层层传递。
 */
export function useLease(
  itemId: string | null,
  secretVersion: number | null,
): { lease: SecretLease | null; remainingSec: number } {
  const { leases } = useApp();
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!itemId) return;
    const unsub = leases.subscribe((changed) => {
      if (changed === itemId) setTick((t) => t + 1);
    });
    const unsubClock = leases.subscribeToClock(() => setTick((t) => t + 1));
    return () => {
      unsub();
      unsubClock();
    };
  }, [itemId, leases]);

  void tick;
  const lease = itemId && secretVersion !== null ? leases.get(itemId, secretVersion) : null;
  const remainingSec = lease ? Math.max(0, Math.ceil((lease.expiresAt - Date.now()) / 1000)) : 0;
  return { lease, remainingSec };
}
