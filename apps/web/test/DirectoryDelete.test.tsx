import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { VaultNav } from '../src/components/VaultNav.tsx';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const vaultId = '10000000-0000-4000-8000-000000000001';

function personalStore({
  directories,
  items = [],
}: {
  directories: { path: string; aliases: string[] }[];
  items?: { id: string; title: string; folderPath: string | null }[];
}) {
  const store = createMetaStore();
  store.getState().applyDecryptedBootstrap({
    user: {
      id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
    },
    vaults: [{
      id: vaultId,
      kind: 'personal',
      name: '个人密码库',
      ownerUserId: 'u-1',
      createdAt: '2026-07-20T00:00:00Z',
      updatedAt: '2026-07-20T00:00:00Z',
    }],
    memberships: [],
    items: items.map((item) => ({
      id: item.id,
      vaultId,
      kind: 'login' as const,
      title: item.title,
      username: 'user',
      origin: 'https://example.test',
      loginUrl: 'https://example.test/',
      folderPath: item.folderPath,
      tags: [],
      favorite: false,
      sensitivity: 'medium' as const,
      version: 1,
      secretVersion: 1,
      createdAt: '2026-07-20T00:00:00Z',
      updatedAt: '2026-07-20T00:00:00Z',
      updatedBy: 'u-1',
    })),
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: { [vaultId]: directories },
    encryptedItems: {},
  });
  store.getState().setConnection('online');
  return store;
}

function renderVaultNav(store: ReturnType<typeof personalStore>, zeroKnowledge: unknown) {
  const services = { store, zeroKnowledge } as unknown as AppServices;
  return render(
    <AppContext.Provider value={services}>
      <Tooltip.Provider>
        <VaultNav />
        <ConfirmDialog />
      </Tooltip.Provider>
    </AppContext.Provider>,
  );
}

describe('directory delete', () => {
  beforeEach(() => useUi.setState({
    selectedVaultId: vaultId,
    selectedFolderPath: null,
    expandedTreeNodeIds: new Set(),
    toasts: [],
  }));

  it('only owners see the delete entry and it stays disabled until a real directory is selected', async () => {
    const store = personalStore({ directories: [{ path: '工作', aliases: [] }] });
    renderVaultNav(store, { updateVaultDirectories: vi.fn() });

    // owner: 操作条可见，包含“删除当前目录”
    expect(screen.getByRole('button', { name: '删除当前目录' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: '目录：工作' }));
    expect(screen.getByRole('button', { name: '删除当前目录' })).toBeEnabled();
    // “全部”和“未分类”不可删除：选中“全部”时删除被禁用
    await userEvent.click(screen.getByRole('button', { name: '目录：全部' }));
    expect(screen.getByRole('button', { name: '删除当前目录' })).toBeDisabled();
  });

  it('refuses a non-empty directory without deleting, moving items, or reporting success', async () => {
    const store = personalStore({
      directories: [
        { path: '工作', aliases: [] },
        { path: '工作/云服务', aliases: [] },
      ],
      items: [{ id: 'i-1', title: '示例云', folderPath: '工作/云服务' }],
    });
    const updateVaultDirectories = vi.fn().mockResolvedValue(undefined);
    renderVaultNav(store, { updateVaultDirectories });

    await userEvent.click(screen.getByRole('button', { name: '展开目录：工作' }));
    await userEvent.click(screen.getByRole('button', { name: '目录：工作/云服务' }));
    await userEvent.click(screen.getByRole('button', { name: '删除当前目录' }));

    expect(updateVaultDirectories).not.toHaveBeenCalled();
    expect(useUi.getState().toasts.at(-1)?.text).toMatch(/还有 1 个条目/);
  });

  it('deletes an empty subtree after confirmation and selects the surviving parent', async () => {
    const store = personalStore({
      directories: [
        { path: '工作', aliases: [] },
        { path: '工作/云服务', aliases: ['旧名'] },
        { path: '工作/云服务/示例云', aliases: [] },
      ],
    });
    const updateVaultDirectories = vi.fn().mockResolvedValue(undefined);
    renderVaultNav(store, { updateVaultDirectories });

    await userEvent.click(screen.getByRole('button', { name: '展开目录：工作' }));
    await userEvent.click(screen.getByRole('button', { name: '目录：工作/云服务' }));
    await userEvent.click(screen.getByRole('button', { name: '删除当前目录' }));

    expect(screen.getByText(/确定删除“工作\/云服务”及其 1 个空子目录/)).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '删除' }));

    // 子树（含别名）一并移除，父目录“工作”保留
    expect(updateVaultDirectories).toHaveBeenCalledWith(vaultId, [{ path: '工作', aliases: [] }]);
    expect(useUi.getState().selectedFolderPath).toBe('工作');
    expect(useUi.getState().toasts.at(-1)?.text).toBe('目录已删除，条目未受影响');
  });

  it('returns to “全部” after deleting a top-level directory', async () => {
    const store = personalStore({
      directories: [
        { path: '工作', aliases: [] },
        { path: '个人', aliases: [] },
      ],
    });
    const updateVaultDirectories = vi.fn().mockResolvedValue(undefined);
    renderVaultNav(store, { updateVaultDirectories });

    await userEvent.click(screen.getByRole('button', { name: '目录：工作' }));
    await userEvent.click(screen.getByRole('button', { name: '删除当前目录' }));
    await userEvent.click(screen.getByRole('button', { name: '删除' }));

    expect(updateVaultDirectories).toHaveBeenCalledWith(vaultId, [{ path: '个人', aliases: [] }]);
    expect(useUi.getState().selectedFolderPath).toBeNull();
  });
});
