import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretLeaseStore, createMetaStore } from '@mima/client-core';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import { ItemDetail } from '../src/components/ItemDetail.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const itemId = '4e23c38e-d931-4b4b-88ee-b4f1716a86b0';

describe('ItemDetail encrypted conflict resolution', () => {
  beforeEach(() => useUi.setState({ selectedItemId: itemId, editing: null, toasts: [] }));
  afterEach(() => useUi.setState({ selectedItemId: null, editing: null, toasts: [] }));

  it('refreshes the server version without discarding the retained candidate', async () => {
    const { services, refresh, discardConflict } = conflictServices();
    renderDetail(services);

    expect(screen.getByRole('button', { name: '编辑' })).toBeVisible();
    expect(screen.queryByText('敏感标记')).not.toBeInTheDocument();
    expect(screen.queryByText('普通')).not.toBeInTheDocument();
    expect(screen.getByText(/当前设备仍保留加密草稿/)).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '查看最新内容' }));

    await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    expect(discardConflict).not.toHaveBeenCalled();
    expect(screen.getByText(/当前设备仍保留加密草稿/)).toBeVisible();
  });

  it('only removes the candidate after the user explicitly chooses to discard it', async () => {
    const { services, store, refresh, discardConflict } = conflictServices();
    renderDetail(services);

    await userEvent.click(screen.getByRole('button', { name: '放弃本地修改' }));
    expect(screen.getByText(/此操作不能撤销/)).toBeVisible();
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '放弃本地修改' }));

    await waitFor(() => expect(discardConflict).toHaveBeenCalledWith('conflicting-command'));
    expect(refresh).toHaveBeenCalledOnce();
    expect(store.getState().conflicts[itemId]).toBeUndefined();
    expect(screen.queryByText(/当前设备仍保留加密草稿/)).not.toBeInTheDocument();
  });
});

function conflictServices() {
  const store = createMetaStore();
  store.getState().applyBootstrap({
    user: {
      id: 'user-1',
      username: 'bob',
      displayName: 'Bob Li',
      email: 'bob@example.test',
      groups: [],
      isPlatformAdmin: false,
    },
    vaults: [{
      id: '10000000-0000-4000-8000-000000000001',
      kind: 'personal',
      name: '我的密码',
      ownerUserId: 'user-1',
      createdAt: '2026-07-19T00:00:00.000Z',
      updatedAt: '2026-07-19T00:00:00.000Z',
    }],
    memberships: [],
    items: [{
      id: itemId,
      vaultId: '10000000-0000-4000-8000-000000000001',
      kind: 'login',
      title: '服务器版本',
      username: 'bob',
      origin: 'https://example.test',
      tags: [],
      favorite: false,
      sensitivity: 'medium',
      version: 7,
      secretVersion: 4,
      createdAt: '2026-07-19T00:00:00.000Z',
      updatedAt: '2026-07-19T01:00:00.000Z',
      updatedBy: 'user-2',
    }],
    cursor: 10,
  });
  store.getState().setConnection('online');
  store.getState().setConflict({
    itemId,
    currentVersion: 7,
    commandId: 'conflicting-command',
    candidateKind: 'item.update',
    candidateCreatedAt: '2026-07-19T00:30:00.000Z',
  }, itemId);

  const refresh = vi.fn().mockResolvedValue(undefined);
  const discardConflict = vi.fn().mockResolvedValue(1);
  const actions = {
    updateItemMeta: vi.fn(),
    deleteItem: vi.fn(),
    reveal: vi.fn(),
    revealForCopy: vi.fn(),
    resolveConflict: (id: string) => store.getState().setConflict(null, id),
  };
  const services = {
    store,
    leases: new SecretLeaseStore(),
    actions,
    outbox: { discardConflict },
    zeroKnowledge: { refresh },
    api: { itemVersions: vi.fn().mockResolvedValue([]) },
  } as unknown as AppServices;
  return { services, store, refresh, discardConflict };
}

function renderDetail(services: AppServices): void {
  render(
    <AppContext.Provider value={services}>
      <Tooltip.Provider>
        <ItemDetail />
        <ConfirmDialog />
      </Tooltip.Provider>
    </AppContext.Provider>,
  );
}
