import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore, type DecryptedItemMeta } from '@mima/client-core';
import { MoveToFolderDialog } from '../src/components/MoveToFolderDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const vaultId = '10000000-0000-4000-8000-000000000001';

function makeStore(itemFolder: string | null) {
  const store = createMetaStore();
  store.getState().applyDecryptedBootstrap({
    user: {
      id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
    },
    vaults: [{
      id: vaultId, kind: 'personal', name: '个人密码库', ownerUserId: 'u-1',
      createdAt: '2026-07-20T00:00:00Z', updatedAt: '2026-07-20T00:00:00Z',
    }],
    memberships: [],
    items: [],
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: {
      [vaultId]: [
        { path: '工作', aliases: [] },
        { path: '工作/云服务', aliases: [] },
      ],
    },
    encryptedItems: {},
  });
  store.getState().setConnection('online');
  return { store, item: testItem(itemFolder) };
}

function testItem(folder: string | null): DecryptedItemMeta {
  return {
    id: '4e23c38e-d931-4b4b-88ee-b4f1716a86b0',
    vaultId,
    kind: 'login',
    title: '示例云子账号',
    username: 'user',
    origin: 'https://example.test',
    loginUrl: 'https://example.test/',
    folderPath: folder,
    tags: [],
    favorite: false,
    sensitivity: 'medium',
    version: 1,
    secretVersion: 1,
    createdAt: '2026-07-20T00:00:00Z',
    updatedAt: '2026-07-20T00:00:00Z',
    updatedBy: 'u-1',
  };
}

describe('MoveToFolderDialog', () => {
  beforeEach(() => useUi.setState({ selectedVaultId: vaultId, toasts: [] }));
  afterEach(() => useUi.setState({ toasts: [] }));

  it('shows only real directories plus 未分类 and moves via updateItemMeta', async () => {
    const { store, item } = makeStore(null);
    const updateItemMeta = vi.fn().mockResolvedValue(undefined);
    const services = { store, actions: { updateItemMeta } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <MoveToFolderDialog open item={item} onOpenChange={vi.fn()} />
      </AppContext.Provider>,
    );

    const select = screen.getByRole('combobox', { name: '目标目录' });
    expect(select).toHaveValue('');
    expect(screen.getByRole('option', { name: '工作' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: '工作/云服务' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: '未分类' })).toBeInTheDocument();

    await userEvent.selectOptions(select, '工作/云服务');
    await userEvent.click(screen.getByRole('button', { name: '移动' }));
    expect(updateItemMeta).toHaveBeenCalledWith(item.id, { folderPath: '工作/云服务' });
  });

  it('disables move when the target equals the current folder', async () => {
    const { store, item } = makeStore('工作');
    const services = { store, actions: { updateItemMeta: vi.fn() } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <MoveToFolderDialog open item={item} onOpenChange={vi.fn()} />
      </AppContext.Provider>,
    );
    expect(screen.getByRole('button', { name: '移动' })).toBeDisabled();
  });
});
