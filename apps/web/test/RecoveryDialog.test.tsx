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
    expect(screen.getByRole('button', { name: '恢复案件' })).toBeVisible();
    expect(screen.getByRole('button', { name: '历史记录' })).toBeVisible();
    expect(screen.queryByRole('button', { name: '准备恢复' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '恢复案件' }));
    expect(await screen.findByRole('heading', { name: '恢复案件' })).toBeVisible();
    expect(screen.getByText(/当前没有进行中的恢复协助/)).toBeVisible();
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

    expect(await screen.findByRole('heading', { name: '企业恢复中心' })).toBeVisible();
    for (const label of ['总览', '准备恢复', '恢复案件', '历史记录']) {
      expect(screen.getByRole('button', { name: label })).toBeVisible();
    }
    await userEvent.click(screen.getByRole('button', { name: '准备恢复' }));
    expect(await screen.findByRole('heading', { name: '准备企业恢复' })).toBeVisible();
    expect(screen.getByText(/还需设置 3 名恢复管理员/)).toBeVisible();
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
    cases: [],
  };
}
