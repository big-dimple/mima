import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { VaultNav } from '../src/components/VaultNav.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

describe('VaultNav', () => {
  beforeEach(() => {
    localStorage.removeItem('mima:vault-sections:v1');
    useUi.getState().resetWorkspaceUi();
  });

  it('keeps an accessible name when compact CSS hides the visible label', () => {
    const store = createMetaStore();
    store.getState().applyBootstrap({
      user: {
        id: 'u-1',
        username: 'bob',
        displayName: 'Bob Li',
        email: 'bob@example.test',
        groups: [],
        isPlatformAdmin: false,
      },
      vaults: [],
      memberships: [],
      items: [],
      cursor: 0,
    });
    const services = { store } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.getByRole('button', { name: '全部条目' })).toHaveAttribute('aria-label', '全部条目');
  });

  it('shows encrypted nested directories beneath the selected vault', async () => {
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '个人密码库',
        ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [],
      items: [{
        id: '00000000-0000-4000-8000-000000000001',
        vaultId,
        kind: 'login',
        title: '示例云子账号',
        username: 'user',
        origin: 'https://accounts.example.test',
        folderPath: '工作/云服务/示例云',
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        version: 1,
        secretVersion: 1,
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
        updatedBy: 'u-1',
      }],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: null });
    const services = { store } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.getByRole('button', { name: '目录：工作' })).toHaveTextContent('1');
    expect(screen.queryByRole('button', { name: '目录：工作/云服务' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '展开目录：工作' }));
    expect(screen.getByRole('button', { name: '目录：工作/云服务' })).toBeVisible();
    expect(screen.queryByRole('button', { name: '目录：工作/云服务/示例云' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '目录：工作/云服务' }));
    expect(useUi.getState().selectedFolderPath).toBe('工作/云服务');
    expect(screen.queryByRole('button', { name: '目录：工作/云服务/示例云' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '展开目录：工作/云服务' }));
    await userEvent.click(screen.getByRole('button', { name: '目录：工作/云服务/示例云' }));
    expect(useUi.getState().selectedFolderPath).toBe('工作/云服务/示例云');
  });

  it('uses standard tree arrow navigation between parents and visible children', async () => {
    const user = userEvent.setup();
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '个人密码库',
        ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
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
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: '工作/云服务' });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const vault = screen.getByRole('button', { name: '个人密码库' });
    const directorySection = screen.getByRole('button', { name: '折叠目录' });
    const allItems = screen.getByRole('button', { name: '目录：全部' });
    const parent = screen.getByRole('button', { name: '目录：工作' });
    const child = screen.getByRole('button', { name: '目录：工作/云服务' });

    vault.focus();
    await user.keyboard('{ArrowRight}');
    expect(directorySection).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(allItems).toHaveFocus();

    child.focus();
    await user.keyboard('{ArrowLeft}');
    expect(parent).toHaveFocus();
    await user.keyboard('{ArrowLeft}');
    expect(parent).toHaveFocus();
    expect(screen.queryByRole('button', { name: '目录：工作/云服务' })).not.toBeInTheDocument();
    await user.keyboard('{ArrowLeft}');
    expect(directorySection).toHaveFocus();
  });

  it('hides an empty unclassified filter and returns a stale selection to all items', async () => {
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '个人密码库',
        ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [],
      items: [{
        id: '00000000-0000-4000-8000-000000000001',
        vaultId,
        kind: 'login',
        title: '示例云子账号',
        username: 'user',
        origin: 'https://accounts.example.test',
        folderPath: '工作',
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        version: 1,
        secretVersion: 1,
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
        updatedBy: 'u-1',
      }],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: { [vaultId]: [{ path: '工作', aliases: [] }] },
      encryptedItems: {},
    });
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: '' });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.queryByRole('button', { name: '目录：未分类' })).not.toBeInTheDocument();
    await waitFor(() => expect(useUi.getState().selectedFolderPath).toBeNull());
  });

  it('collapses and restores the currently selected vault when its own row is clicked', async () => {
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '我的密码库',
        ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: { [vaultId]: [{ path: '工作', aliases: [] }] },
      encryptedItems: {},
    });
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: '工作' });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const vault = screen.getByRole('button', { name: '我的密码库' });
    expect(screen.getByRole('button', { name: '折叠我的密码库' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: '目录：工作' })).toBeVisible();

    await userEvent.click(vault);
    expect(screen.getByRole('button', { name: '展开我的密码库' })).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('button', { name: '目录：工作' })).not.toBeInTheDocument();
    expect(useUi.getState().selectedFolderPath).toBe('工作');

    await userEvent.click(vault);
    expect(screen.getByRole('button', { name: '折叠我的密码库' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: '目录：工作' })).toBeVisible();
    expect(useUi.getState().selectedFolderPath).toBe('工作');
  });

  it('collapses personal and team groups independently', async () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [
        {
          id: '10000000-0000-4000-8000-000000000001',
          kind: 'personal',
          name: '个人密码库',
          ownerUserId: 'u-1',
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        },
        {
          id: '20000000-0000-4000-8000-000000000001',
          kind: 'team',
          name: '研发团队库',
          ownerUserId: 'u-1',
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        },
      ],
      memberships: [{
        vaultId: '20000000-0000-4000-8000-000000000001',
        subjectKind: 'user',
        subjectId: 'u-1',
        role: 'owner',
      }],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.queryByRole('button', { name: '展开个人密码库' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '个人密码库' }));
    expect(useUi.getState().selectedVaultId).toBe('10000000-0000-4000-8000-000000000001');
    expect(screen.getByRole('button', { name: '折叠个人密码库' })).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: '折叠个人库' }));
    expect(screen.queryByRole('button', { name: '个人密码库' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '研发团队库' })).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: '折叠团队库' }));
    expect(screen.queryByRole('button', { name: '研发团队库' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '展开个人库' }));
    expect(screen.getByRole('button', { name: '个人密码库' })).toBeVisible();
    expect(screen.queryByRole('button', { name: '研发团队库' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '全部收起' }));
    expect(screen.queryByRole('button', { name: '个人密码库' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '研发团队库' })).not.toBeInTheDocument();
    expect(useUi.getState().expandedTreeNodeIds.size).toBe(0);
  });

  it('nests visible projects under their root vault and keeps unrelated vaults flat', async () => {
    const store = createMetaStore();
    const rootVaultId = '20000000-0000-4000-8000-000000000001';
    const projectVaultId = '20000000-0000-4000-8000-000000000003';
    const flatVaultId = '20000000-0000-4000-8000-000000000002';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [
        {
          id: rootVaultId,
          kind: 'team',
          name: '运维',
          ownerUserId: null,
          projectContext: { kind: 'root' },
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        },
        {
          id: flatVaultId,
          kind: 'team',
          name: '公共资料',
          ownerUserId: null,
          projectContext: { kind: 'root' },
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        },
        {
          id: projectVaultId,
          kind: 'team',
          name: '示例云项目',
          ownerUserId: null,
          projectContext: { kind: 'project', visibleParentVaultId: rootVaultId },
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        },
      ],
      memberships: [
        { vaultId: rootVaultId, subjectKind: 'user', subjectId: 'u-1', role: 'owner' },
        { vaultId: flatVaultId, subjectKind: 'user', subjectId: 'u-1', role: 'owner' },
        { vaultId: projectVaultId, subjectKind: 'user', subjectId: 'u-1', role: 'owner' },
      ],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.getByRole('button', { name: '运维' })).toBeVisible();
    expect(screen.queryByRole('button', { name: '示例云项目' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '运维' }));
    await userEvent.click(screen.getByRole('button', { name: '展开运维的项目' }));
    expect(screen.getByRole('button', { name: '示例云项目' })).toBeVisible();
    expect(screen.getByRole('button', { name: '公共资料' })).toBeVisible();
    expect(screen.getByLabelText('运维的项目')).toContainElement(screen.getByRole('button', { name: '示例云项目' }));
    expect(screen.getAllByText('项目', { selector: 'span' })).toHaveLength(2);
  });

  it('shows a child-only project as a flat team vault without leaking its parent', () => {
    const store = createMetaStore();
    const projectVaultId = '20000000-0000-4000-8000-000000000003';
    const hiddenParentVaultId = '20000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: projectVaultId,
        kind: 'team',
        name: '示例云项目',
        ownerUserId: null,
        projectContext: { kind: 'project', visibleParentVaultId: null },
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [
        { vaultId: projectVaultId, subjectKind: 'user', subjectId: 'u-1', role: 'viewer' },
      ],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.getByRole('button', { name: '示例云项目' })).toBeVisible();
    expect(screen.getByText('项目', { selector: 'span' })).toBeVisible();
    expect(screen.queryByLabelText(/的项目$/)).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(hiddenParentVaultId);
  });

  it('blocks deletion until every item and directory has been removed', async () => {
    const store = createMetaStore();
    const vaultId = '20000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'team',
        name: '顺丰到付的说法',
        ownerUserId: null,
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [{
        vaultId,
        subjectKind: 'user',
        subjectId: 'u-1',
        role: 'owner',
      }],
      items: [{
        id: '00000000-0000-4000-8000-000000000001',
        vaultId,
        kind: 'secure_note',
        title: '临时条目',
        username: null,
        origin: null,
        folderPath: '',
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        version: 1,
        secretVersion: 1,
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
        updatedBy: 'u-1',
      }],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    store.getState().setConnection('online');
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: null });
    const deleteVault = vi.fn().mockResolvedValue(undefined);

    render(
      <AppContext.Provider value={{ store, zeroKnowledge: { deleteVault } } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    await userEvent.click(screen.getByRole('button', { name: '删除团队密码库' }));
    expect(screen.getByRole('alert')).toHaveTextContent('当前还有 1 个条目、0 个目录');
    expect(screen.queryByLabelText('输入完整密码库名称以确认')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '永久删除' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '返回清理' }));

    expect(deleteVault).not.toHaveBeenCalled();
    expect(useUi.getState().selectedVaultId).toBe(vaultId);
  });

  it('requires the exact decrypted name after a team vault is empty', async () => {
    const store = createMetaStore();
    const vaultId = '20000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'team',
        name: '顺丰到付的说法',
        ownerUserId: null,
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [{ vaultId, subjectKind: 'user', subjectId: 'u-1', role: 'owner' }],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: { [vaultId]: [] },
      encryptedItems: {},
    });
    store.getState().setConnection('online');
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: null });
    const deleteVault = vi.fn().mockResolvedValue(undefined);

    render(
      <AppContext.Provider value={{ store, zeroKnowledge: { deleteVault } } as unknown as AppServices}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    await userEvent.click(screen.getByRole('button', { name: '删除团队密码库' }));
    const confirmation = screen.getByLabelText('输入完整密码库名称以确认');
    const submit = screen.getByRole('button', { name: '永久删除' });
    await userEvent.type(confirmation, '顺丰到付');
    expect(submit).toBeDisabled();
    await userEvent.clear(confirmation);
    await userEvent.type(confirmation, '顺丰到付的说法');
    await userEvent.click(submit);

    expect(deleteVault).toHaveBeenCalledWith(vaultId);
    expect(useUi.getState().selectedVaultId).toBe('all');
  });

  it('creates an encrypted empty directory from the sidebar and keeps it visible', async () => {
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '个人密码库',
        ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: { [vaultId]: [{ path: '工作', aliases: [] }] },
      encryptedItems: {},
    });
    store.getState().setConnection('online');
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: '工作' });
    const updateVaultDirectories = vi.fn().mockResolvedValue(undefined);
    const services = {
      store,
      zeroKnowledge: { updateVaultDirectories },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.getByRole('button', { name: '目录：工作' })).toHaveTextContent('0');
    await userEvent.click(screen.getByRole('button', { name: '新建目录' }));
    expect(screen.getByLabelText('上级目录')).toHaveValue('工作');
    await userEvent.type(screen.getByLabelText('目录名称'), '云服务');
    await userEvent.click(screen.getByRole('button', { name: '创建目录' }));

    expect(updateVaultDirectories).toHaveBeenCalledWith(vaultId, [
      { path: '工作', aliases: [] },
      { path: '工作/云服务', aliases: [] },
    ]);
    expect(useUi.getState().selectedFolderPath).toBe('工作/云服务');
  });

  it('renames a directory subtree with one encrypted header update', async () => {
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '个人密码库',
        ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {
        [vaultId]: [
          { path: '工作', aliases: [] },
          { path: '工作/云服务', aliases: [] },
          { path: '工作/云服务/示例云', aliases: [] },
        ],
      },
      encryptedItems: {},
    });
    store.getState().setConnection('online');
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: '工作/云服务' });
    const updateVaultDirectories = vi.fn().mockResolvedValue(undefined);
    const services = {
      store,
      zeroKnowledge: { updateVaultDirectories },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <VaultNav />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    await userEvent.click(screen.getByRole('button', { name: '修改当前目录' }));
    const name = screen.getByLabelText('目录名称');
    await userEvent.clear(name);
    await userEvent.type(name, '云平台');
    await userEvent.click(screen.getByRole('button', { name: '保存修改' }));

    expect(updateVaultDirectories).toHaveBeenCalledWith(vaultId, [
      { path: '工作', aliases: [] },
      { path: '工作/云平台', aliases: ['工作/云服务'] },
      { path: '工作/云平台/示例云', aliases: ['工作/云服务/示例云'] },
    ]);
    expect(useUi.getState().selectedFolderPath).toBe('工作/云平台');
  });
});
