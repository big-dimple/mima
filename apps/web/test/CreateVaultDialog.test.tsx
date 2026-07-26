import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CreateVaultDialog } from '../src/components/CreateVaultDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

describe('CreateVaultDialog', () => {
  beforeEach(() => useUi.setState({ selectedVaultId: 'all', toasts: [] }));
  afterEach(() => useUi.setState({ selectedVaultId: 'all', toasts: [] }));

  it('asks only for a name, creates for the current user and enters the new vault', async () => {
    const createVault = vi.fn().mockResolvedValue('vault-team-1');
    const onOpenChange = vi.fn();
    const services = { zeroKnowledge: { createVault } } as unknown as AppServices;
    const user = userEvent.setup();

    render(
      <AppContext.Provider value={services}>
        <CreateVaultDialog open onOpenChange={onOpenChange} />
      </AppContext.Provider>,
    );

    const dialog = screen.getByRole('dialog', { name: '新建团队密码库' });
    expect(within(dialog).getByText('你将成为拥有者，可以稍后添加成员或转移所有权')).toBeVisible();
    expect(within(dialog).queryByRole('combobox', { name: '初始拥有者' })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: '发送给拥有者' })).not.toBeInTheDocument();

    await user.type(within(dialog).getByLabelText('团队密码库名称'), ' 研发共享 ');
    await user.click(within(dialog).getByRole('button', { name: '创建并进入' }));

    await waitFor(() => expect(createVault).toHaveBeenCalledWith('研发共享'));
    expect(useUi.getState().selectedVaultId).toBe('vault-team-1');
    expect(useUi.getState().toasts.at(-1)?.text).toBe('团队密码库已创建');
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('creates an independent project beneath the selected root vault', async () => {
    const createProject = vi.fn().mockResolvedValue('vault-project-1');
    const services = { zeroKnowledge: { createProject } } as unknown as AppServices;
    const user = userEvent.setup();
    const parentVault = {
      id: '10000000-0000-4000-8000-000000000001',
      kind: 'team' as const,
      name: '运维',
      ownerUserId: 'u-owner',
      projectContext: { kind: 'root' as const },
      createdAt: '2026-07-20T00:00:00.000Z',
      updatedAt: '2026-07-20T00:00:00.000Z',
    };

    render(
      <AppContext.Provider value={services}>
        <CreateVaultDialog open onOpenChange={vi.fn()} parentVault={parentVault} />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('dialog', { name: '在「运维」下新建项目' })).toBeVisible();
    expect(screen.getByText('项目拥有独立成员和权限，不会继承上级密码库权限')).toBeVisible();
    await user.type(screen.getByLabelText('项目名称'), ' 示例云项目 ');
    await user.click(screen.getByRole('button', { name: '创建项目' }));

    await waitFor(() => expect(createProject).toHaveBeenCalledWith(parentVault.id, '示例云项目'));
    expect(useUi.getState().selectedVaultId).toBe('vault-project-1');
    expect(useUi.getState().toasts.at(-1)?.text).toBe('项目已创建');
  });

  it('places cancel beside create without submitting', async () => {
    const createVault = vi.fn();
    const onOpenChange = vi.fn();
    const services = { zeroKnowledge: { createVault } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <CreateVaultDialog open onOpenChange={onOpenChange} />
      </AppContext.Provider>,
    );

    const dialog = screen.getByRole('dialog', { name: '新建团队密码库' });
    await userEvent.click(within(dialog).getByRole('button', { name: '取消' }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(createVault).not.toHaveBeenCalled();
  });
});
