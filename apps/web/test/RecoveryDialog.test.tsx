import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { RecoveryDialog } from '../src/components/RecoveryDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

beforeEach(() => {
  useUi.setState({ recoveryOpen: true, toasts: [] });
});

describe('enterprise recovery administrator visibility', () => {
  it('does not show recovery management to a directory-group-only platform admin', async () => {
    const store = createMetaStore();
    store.getState().setUser({
      id: 'group-admin',
      username: 'group-admin',
      displayName: 'Group Admin',
      email: 'group-admin@example.test',
      groups: ['group:default/platform'],
      isPlatformAdmin: true,
      isLocalPlatformAdmin: false,
    });
    const api = {
      recoveryKeys: vi.fn(async () => []),
      recoveryRequests: vi.fn(async () => []),
    };

    render(
      <AppContext.Provider value={{ api, store, zeroKnowledge: {} } as unknown as AppServices}>
        <RecoveryDialog />
      </AppContext.Provider>,
    );

    expect(await screen.findByRole('heading', { name: '企业恢复' })).toBeVisible();
    expect(await screen.findByRole('heading', { name: '我的恢复请求' })).toBeVisible();
    expect(screen.queryByRole('button', { name: '管理者入门' })).not.toBeInTheDocument();
    expect(screen.queryByText('企业恢复保障状态')).not.toBeInTheDocument();
    expect(screen.queryByText('待处理的恢复协助')).not.toBeInTheDocument();
    expect(screen.queryByText('企业恢复设置')).not.toBeInTheDocument();
  });
});
