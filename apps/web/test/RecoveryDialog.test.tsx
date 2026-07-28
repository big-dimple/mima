import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import type { EnterpriseRecoveryWorkspace } from '@mima/contracts';
import { RecoveryDialog } from '../src/components/RecoveryDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

beforeEach(() => {
  useUi.setState({ recoveryOpen: true, toasts: [] });
});

describe('enterprise recovery center', () => {
  it('shows a focused member workspace without administrator controls', async () => {
    const store = createMetaStore();
    store.getState().setUser({
      id: 'group-admin',
      username: 'group-admin',
      displayName: 'Group Admin',
      email: 'group-admin@example.test',
      groups: ['group:default/platform'],
      isPlatformAdmin: false,
      isLocalPlatformAdmin: false,
    });
    const api = { recoveryWorkspace: vi.fn(async () => emptyWorkspace()) };

    render(
      <AppContext.Provider value={{ api, store, zeroKnowledge: {} } as unknown as AppServices}>
        <RecoveryDialog />
      </AppContext.Provider>,
    );

    expect(await screen.findByRole('heading', { name: '企业恢复中心' })).toBeVisible();
    expect(screen.getByRole('navigation', { name: '企业恢复功能' })).toBeVisible();
    expect(screen.getByRole('button', { name: '总览' })).toBeVisible();
    expect(screen.getByRole('button', { name: '密码库保护' })).toBeVisible();
    expect(screen.getByRole('button', { name: '我的恢复' })).toBeVisible();
    expect(screen.queryByRole('button', { name: '准备恢复能力' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '待办审批' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '管理者入门' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '我的恢复' }));
    expect(await screen.findByRole('heading', { name: '我的恢复' })).toBeVisible();
    expect(screen.getByText(/当前没有需要你处理的恢复请求/)).toBeVisible();
    expect(api.recoveryWorkspace).toHaveBeenCalledTimes(1);
  });

  it('uses one workspace snapshot and fixed sections for administrators', async () => {
    const store = createMetaStore();
    store.getState().setUser({
      id: 'admin-1',
      username: 'admin-1',
      displayName: 'Admin One',
      email: 'admin-1@example.test',
      groups: [],
      isPlatformAdmin: true,
      isLocalPlatformAdmin: true,
    });
    const api = { recoveryWorkspace: vi.fn(async () => ({
      ...emptyWorkspace(),
      readiness: {
        requiredAdministratorCount: 3,
        administratorCount: 0,
        readyAdministratorCount: 0,
        ready: false,
        administrators: [],
      },
    })) };

    render(
      <AppContext.Provider value={{ api, store, zeroKnowledge: {} } as unknown as AppServices}>
        <RecoveryDialog />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('未准备')).toBeVisible();
    for (const label of ['总览', '准备恢复能力', '待办审批', '密码库保护', '高级维护', '我的恢复']) {
      expect(screen.getByRole('button', { name: label })).toBeVisible();
    }
    await waitFor(() => expect(api.recoveryWorkspace).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('第一次管理企业恢复？')).not.toBeInTheDocument();
  });
});

function emptyWorkspace(): EnterpriseRecoveryWorkspace {
  return {
    refreshedAt: '2026-07-27T12:00:00.000Z',
    keys: [],
    readiness: null,
    coverage: null,
    requests: [],
    candidates: [],
  };
}
