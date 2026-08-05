import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import type { EnterpriseRecoveryCase } from '@mima/contracts';
import { EnterpriseRecoveryRequestPanel } from '../src/components/EnterpriseRecoveryRequestPanel.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const user = {
  id: 'u-owner',
  username: 'owner',
  displayName: 'Owner',
  email: 'owner@example.test',
  groups: [],
  isPlatformAdmin: false,
};

beforeEach(() => {
  useUi.setState({ selectedVaultId: 'all', toasts: [] });
});

afterEach(() => vi.restoreAllMocks());

describe('enterprise recovery target experience', () => {
  it('automatically prepares an interrupted handoff without browser instructions', async () => {
    const waiting = recoveryCase('waiting_for_target');
    const pending = recoveryCase('pending_approval');
    const continueInterruptedHandoffRecoveryCase = vi.fn().mockResolvedValue(pending);
    renderPanel({
      api: { recoveryCases: vi.fn().mockResolvedValue([waiting]) },
      zeroKnowledge: { continueInterruptedHandoffRecoveryCase },
    });

    await waitFor(() => expect(continueInterruptedHandoffRecoveryCase).toHaveBeenCalledWith(waiting));
    expect(await screen.findByText(/管理员已确认 0\/2 人/)).toBeVisible();
    expect(screen.queryByText(/设备|浏览器|本机/)).not.toBeInTheDocument();
  });

  it('shows only human progress while the automatic recovery runs', async () => {
    renderPanel({
      api: { recoveryCases: vi.fn().mockResolvedValue([recoveryCase('processing')]) },
      zeroKnowledge: { continueInterruptedHandoffRecoveryCase: vi.fn() },
    });

    expect(await screen.findByText(/系统正在自动恢复原有访问，无需停留在这里/)).toBeVisible();
    expect(screen.queryByRole('link', { name: /下载/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/JSON|离线恢复结果/)).not.toBeInTheDocument();
  });

  it('tells the colleague exactly what to ask an administrator to do', async () => {
    renderPanel({
      api: { recoveryCases: vi.fn().mockResolvedValue([]) },
      zeroKnowledge: { continueInterruptedHandoffRecoveryCase: vi.fn() },
    }, true);

    expect(await screen.findByText(/请在公司群里联系管理员/)).toHaveTextContent('请发起恢复协助');
  });
});

function renderPanel(
  services: Pick<AppServices, 'api' | 'zeroKnowledge'>,
  recoveryRequired = false,
) {
  const store = createMetaStore();
  store.getState().setUser(user);
  return render(
    <AppContext.Provider value={{ ...services, store } as AppServices}>
      <EnterpriseRecoveryRequestPanel recoveryRequired={recoveryRequired} />
    </AppContext.Provider>,
  );
}

function recoveryCase(status: EnterpriseRecoveryCase['status']): EnterpriseRecoveryCase {
  const now = new Date().toISOString();
  return {
    id: '30000000-0000-4000-8000-000000000001',
    kind: 'interrupted_handoff',
    targetUserId: user.id,
    targetUsername: user.username,
    targetDisplayName: user.displayName,
    recoveryKeyId: '31000000-0000-4000-8000-000000000001',
    status,
    caseDigest: status === 'waiting_for_target' ? null : 'A'.repeat(43),
    targetDeviceId: status === 'waiting_for_target' ? null : '32000000-0000-4000-8000-000000000001',
    targetKeyVersion: status === 'waiting_for_target' ? null : 1,
    accountResetRequestId: null,
    approvalUserIds: [],
    items: [],
    resolvedItemCount: 0,
    skippedItemCount: 0,
    hasOfflineResult: status === 'processing',
    createdByUserId: 'u-admin',
    createdAt: now,
    expiresAt: '2099-08-05T00:00:00.000Z',
    finalizedAt: status === 'waiting_for_target' ? null : now,
    approvedAt: status === 'approved' || status === 'processing' ? now : null,
    processingAt: status === 'processing' ? now : null,
    completedAt: null,
    cancelledAt: null,
    expiredAt: null,
    lastErrorCode: null,
  };
}
