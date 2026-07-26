import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { Vault } from '@mima/contracts';
import { createMetaStore } from '@mima/client-core';
import { RenameVaultDialog } from '../src/components/RenameVaultDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';

const vault: Vault = {
  id: '10000000-0000-4000-8000-000000000001',
  kind: 'team',
  name: '研发共享',
  ownerUserId: 'user-1',
  createdAt: '2026-07-20T00:00:00.000Z',
  updatedAt: '2026-07-20T00:00:00.000Z',
};

describe('RenameVaultDialog', () => {
  it('cancels beside save without renaming', async () => {
    const store = createMetaStore();
    const renameVault = vi.fn();
    const onOpenChange = vi.fn();
    const services = { store, zeroKnowledge: { renameVault } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <RenameVaultDialog vault={vault} onOpenChange={onOpenChange} onCreateProject={vi.fn()} />
      </AppContext.Provider>,
    );

    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(renameVault).not.toHaveBeenCalled();
  });

  it('renames the vault without exposing the optional project model', async () => {
    const store = createMetaStore();
    const renameVault = vi.fn().mockResolvedValue(undefined);
    const onOpenChange = vi.fn();
    const services = { store, zeroKnowledge: { renameVault } } as unknown as AppServices;
    const user = userEvent.setup();

    render(
      <AppContext.Provider value={services}>
        <RenameVaultDialog vault={vault} onOpenChange={onOpenChange} onCreateProject={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(screen.queryByLabelText('库分组（可选）')).not.toBeInTheDocument();
    const name = screen.getByLabelText('名称');
    await user.clear(name);
    await user.type(name, '云平台共享');
    await user.click(screen.getByRole('button', { name: '保存' }));

    await waitFor(() => expect(renameVault).toHaveBeenCalledWith(vault.id, '云平台共享'));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('offers project creation only inside more settings for a root team vault', async () => {
    const store = createMetaStore();
    const onOpenChange = vi.fn();
    const onCreateProject = vi.fn();

    render(
      <AppContext.Provider value={{ store, zeroKnowledge: {} } as unknown as AppServices}>
        <RenameVaultDialog
          vault={vault}
          onOpenChange={onOpenChange}
          onCreateProject={onCreateProject}
        />
      </AppContext.Provider>,
    );

    const details = screen.getByText('更多设置').closest('details');
    expect(details).not.toHaveAttribute('open');
    await userEvent.click(screen.getByText('更多设置'));
    expect(details).toHaveAttribute('open');
    await userEvent.click(screen.getByRole('button', { name: '新建独立权限项目' }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onCreateProject).toHaveBeenCalledWith(vault);
  });
});
