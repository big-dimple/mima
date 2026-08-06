import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { ItemList } from '../src/components/ItemList.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

describe('ItemList encrypted metadata search', () => {
  afterEach(() => useUi.setState({
    search: '',
    selectedVaultId: 'all',
    selectedFolderPath: null,
    selectedItemId: null,
    editing: null,
    newItemPreset: null,
  }));

  it('searches the full login URL and only badges high sensitivity', () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
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
        name: '个人密码库',
        ownerUserId: 'user-1',
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [],
      items: [{
        id: '4e23c38e-d931-4b4b-88ee-b4f1716a86b0',
        vaultId: '10000000-0000-4000-8000-000000000001',
        kind: 'login',
        title: '示例云子账号',
        username: 'sub-account-user',
        origin: 'https://accounts.example.test',
        loginUrl: 'https://accounts.example.test/login/tenant/example-a',
        tags: [],
        favorite: false,
        sensitivity: 'high',
        version: 1,
        secretVersion: 1,
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
        updatedBy: 'user-1',
      }],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    useUi.setState({ search: 'example-a', selectedVaultId: 'all' });
    const services = { store } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <ItemList />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('option', { name: /示例云子账号/ })).toBeVisible();
    expect(screen.getByRole('button', { name: '账号密码' })).toBeVisible();
    expect(screen.getByRole('textbox', { name: '搜索条目' })).toHaveAttribute(
      'placeholder',
      '搜索标题/说明/凭证标识/关联信息',
    );
    const clearSearch = screen.getByRole('button', { name: '清空搜索' });
    fireEvent.click(clearSearch);
    expect(screen.getByRole('textbox', { name: '搜索条目' })).toHaveValue('');
    expect(screen.queryByRole('button', { name: '清空搜索' })).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: '搜索条目' })).toHaveFocus();
    expect(screen.getByText('高敏')).toBeVisible();
    expect(screen.queryByText('普通')).not.toBeInTheDocument();
  });

  it('finds an account password by server details without a web address', () => {
    const store = directoryStore();
    const itemId = '00000000-0000-4000-8000-000000000002';
    store.setState((state) => ({
      items: {
        ...state.items,
        [itemId]: {
          ...state.items[itemId]!,
          title: '生产 Redis',
          origin: null,
          loginUrl: null,
          description: '10.0.0.8:6379 · 生产缓存',
        },
      },
    }));
    useUi.setState({ search: '10.0.0.8', selectedVaultId: 'all' });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <ItemList />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('option', { name: /生产 Redis/ })).toBeVisible();
  });

  it('searches every saved login URL while keeping the primary URL compatible', () => {
    const store = directoryStore();
    const itemId = '00000000-0000-4000-8000-000000000001';
    store.setState((state) => ({
      items: {
        ...state.items,
        [itemId]: {
          ...state.items[itemId]!,
          loginUrls: [
            'https://primary.example.test/login',
            'https://secondary.example.test/console',
          ],
        },
      },
    }));
    useUi.setState({ search: 'secondary.example.test', selectedVaultId: 'all' });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <ItemList />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('option', { name: /示例云子账号/ })).toBeVisible();
  });

  it('searches encrypted descriptions and linked login titles', () => {
    const store = directoryStore();
    const loginId = '00000000-0000-4000-8000-000000000001';
    store.setState((state) => ({
      items: {
        ...state.items,
        [loginId]: { ...state.items[loginId]!, title: '示例云主账号登录' },
        '00000000-0000-4000-8000-000000000004': {
          ...state.items[loginId]!,
          id: '00000000-0000-4000-8000-000000000004',
          kind: 'api_token',
          title: '云平台发布凭证',
          username: 'AKID-example',
          origin: null,
          loginUrl: null,
          description: '采购审批后申请，用于自动化发布',
          linkedLoginItemId: loginId,
        },
      },
    }));
    useUi.setState({ search: '采购审批', selectedVaultId: 'all' });
    const services = { store } as unknown as AppServices;
    render(<AppContext.Provider value={services}><ItemList /></AppContext.Provider>);

    expect(screen.getByRole('option', { name: /云平台发布凭证/ })).toBeVisible();
    act(() => useUi.setState({ search: '示例云主账号登录' }));
    expect(screen.getByRole('option', { name: /云平台发布凭证/ })).toBeVisible();
  });

  it('filters a parent directory with all descendants and keeps unclassified separate', () => {
    const store = directoryStore();
    useUi.setState({
      selectedVaultId: '10000000-0000-4000-8000-000000000001',
      selectedFolderPath: '工作/云服务',
    });
    const services = { store } as unknown as AppServices;

    const { rerender } = render(
      <AppContext.Provider value={services}>
        <ItemList />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('option', { name: /示例云子账号/ })).toBeVisible();
    expect(screen.queryByRole('option', { name: /代码仓库/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /未分类条目/ })).not.toBeInTheDocument();

    useUi.setState({ selectedFolderPath: '' });
    rerender(
      <AppContext.Provider value={services}>
        <ItemList />
      </AppContext.Provider>,
    );
    expect(screen.getByRole('option', { name: /未分类条目/ })).toBeVisible();
    expect(screen.queryByRole('option', { name: /示例云子账号/ })).not.toBeInTheDocument();
  });

  it('uses one roving tab stop and moves selection with arrow keys', () => {
    const store = directoryStore();
    const firstId = '00000000-0000-4000-8000-000000000002';
    useUi.setState({ selectedVaultId: 'all', selectedItemId: firstId });
    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <ItemList />
      </AppContext.Provider>,
    );

    const options = screen.getAllByRole('option');
    expect(options.filter((option) => option.tabIndex === 0)).toHaveLength(1);
    const selected = screen.getByRole('option', { name: /代码仓库/ });
    expect(selected).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(selected, { key: 'ArrowDown' });

    const next = screen.getByRole('option', { name: /示例云子账号/ });
    expect(next).toHaveAttribute('aria-selected', 'true');
    expect(next.tabIndex).toBe(0);
    expect(selected.tabIndex).toBe(-1);
  });

  it('distinguishes an empty vault from an empty search result', () => {
    const store = directoryStore();
    store.setState({ items: {} });
    useUi.setState({
      selectedVaultId: '10000000-0000-4000-8000-000000000001',
      selectedFolderPath: null,
      search: '',
    });
    const services = { store } as unknown as AppServices;
    const { rerender } = render(
      <AppContext.Provider value={services}><ItemList /></AppContext.Provider>,
    );
    expect(screen.getByText('这个密码库还没有条目')).toBeVisible();

    act(() => useUi.setState({ search: '不存在' }));
    rerender(<AppContext.Provider value={services}><ItemList /></AppContext.Provider>);
    expect(screen.getByText('没有匹配的条目')).toBeVisible();
  });

  it('shows only the automatic preparation state for an authorized vault without keys', () => {
    const store = createMetaStore();
    const vaultId = '10000000-0000-4000-8000-000000000009';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'user-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: vaultId,
        kind: 'team',
        name: '正在自动准备团队访问',
        ownerUserId: null,
        projectContext: { kind: 'root' },
        createdAt: '2026-07-20T00:00:00.000Z',
        updatedAt: '2026-07-20T00:00:00.000Z',
      }],
      memberships: [{
        id: '20000000-0000-4000-8000-000000000009',
        vaultId,
        subjectKind: 'user',
        subjectId: 'user-1',
        role: 'viewer',
        createdAt: '2026-07-20T00:00:00.000Z',
      }],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      pendingVaultAccessIds: { [vaultId]: true },
      vaultDirectories: {},
      encryptedItems: {},
    });
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: null });

    render(
      <AppContext.Provider value={{ store } as unknown as AppServices}>
        <ItemList />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('status')).toHaveTextContent('正在自动准备团队访问');
    expect(screen.queryByRole('textbox', { name: '搜索条目' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '新建' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option')).not.toBeInTheDocument();
  });
});

function directoryStore() {
  const store = createMetaStore();
  const vaultId = '10000000-0000-4000-8000-000000000001';
  const baseItem = {
    vaultId,
    kind: 'login' as const,
    username: 'user',
    origin: 'https://example.test',
    loginUrl: 'https://example.test/',
    tags: [],
    favorite: false,
    sensitivity: 'medium' as const,
    version: 1,
    secretVersion: 1,
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T00:00:00.000Z',
    updatedBy: 'user-1',
  };
  store.getState().applyDecryptedBootstrap({
    user: {
      id: 'user-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
    },
    vaults: [{
      id: vaultId,
      kind: 'personal',
      name: '个人密码库',
      ownerUserId: 'user-1',
      createdAt: baseItem.createdAt,
      updatedAt: baseItem.updatedAt,
    }],
    memberships: [],
    items: [
      { ...baseItem, id: '00000000-0000-4000-8000-000000000001', title: '示例云子账号', folderPath: '工作/云服务/示例云' },
      { ...baseItem, id: '00000000-0000-4000-8000-000000000002', title: '代码仓库', folderPath: '工作/研发' },
      { ...baseItem, id: '00000000-0000-4000-8000-000000000003', title: '未分类条目', folderPath: null },
    ],
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: {},
    encryptedItems: {},
  });
  return store;
}
