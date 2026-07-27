import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretLeaseStore, createMetaStore, type DecryptedItemMeta } from '@mima/client-core';
import { ItemDetail } from '../src/components/ItemDetail.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';
import { clearSecretClipboard } from '../src/utils/clipboard.ts';

const vaultId = '10000000-0000-4000-8000-000000000001';
const loginId = '4e23c38e-d931-4b4b-88ee-b4f1716a86b0';
const credentialId = '5f34d49f-e042-4c5c-99ff-c502827b97c1';

describe('ItemDetail credential relations', () => {
  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    useUi.setState({
      selectedVaultId: 'all',
      selectedItemId: loginId,
      editing: null,
      newItemPreset: null,
      toasts: [],
    });
  });
  afterEach(async () => {
    await clearSecretClipboard();
    useUi.setState({
      selectedVaultId: 'all',
      selectedItemId: null,
      editing: null,
      newItemPreset: null,
      toasts: [],
    });
  });

  it('aggregates linked credentials and opens a prelinked create form', async () => {
    const services = relationServices();
    renderDetail(services);

    expect(screen.getByRole('heading', { name: '关联 API 凭证' })).toBeVisible();
    expect(screen.getByRole('button', { name: /示例云 API 凭证/ })).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '新增关联凭证' }));

    expect(screen.getByRole('heading', { name: '新建条目' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'API 凭证' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('关联账号密码（可选）')).toHaveValue(loginId);
  });

  it('navigates to the linked login and degrades safely when the target is gone', async () => {
    useUi.setState({ selectedItemId: credentialId });
    const services = relationServices();
    const view = renderDetail(services);

    expect(screen.getByText('用于示例云自动化发布')).toBeVisible();
    expect(screen.getByText('密钥 / Token')).toBeVisible();
    expect(screen.getByRole('button', { name: '查看密钥 / Token' })).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: /示例云子账号登录/ }));
    expect(useUi.getState().selectedItemId).toBe(loginId);

    useUi.setState({ selectedItemId: credentialId });
    services.store.setState((state) => {
      const items = { ...state.items };
      delete items[loginId];
      return { items };
    });
    view.rerender(detailElement(services));
    expect(screen.getByText('关联账号密码已不存在')).toBeVisible();
  });

  it('copies and opens the displayed website URL from the read-only detail', async () => {
    const services = relationServices();
    renderDetail(services);

    const openLink = screen.getByRole('link', { name: '打开网址' });
    expect(openLink).toHaveAttribute('href', 'https://accounts.example.test/login');
    expect(openLink).toHaveAttribute('target', '_blank');
    expect(openLink).toHaveAttribute('rel', 'noopener noreferrer');

    await userEvent.click(screen.getByRole('button', { name: '复制网址' }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('https://accounts.example.test/login');
    expect(useUi.getState().toasts.at(-1)?.text).toBe('网址已复制');
  });

  it('shows every saved URL in order with independent copy and open actions', async () => {
    const services = relationServices();
    services.store.setState((state) => ({
      items: {
        ...state.items,
        [loginId]: {
          ...state.items[loginId]!,
          loginUrls: [
            'https://accounts.example.test/login',
            'https://console.example.test/account',
          ],
        },
      },
    }));
    renderDetail(services);

    expect(screen.getAllByTestId('website-url-value').map((node) => node.textContent)).toEqual([
      'https://accounts.example.test/login',
      'https://console.example.test/account',
    ]);
    expect(screen.getByRole('link', { name: '打开备用网址 2' })).toHaveAttribute(
      'href',
      'https://console.example.test/account',
    );
    await userEvent.click(screen.getByRole('button', { name: '复制备用网址 2' }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('https://console.example.test/account');
  });

  it('never creates an external link for a non-HTTP legacy value', () => {
    const services = relationServices();
    services.store.setState((state) => ({
      items: {
        ...state.items,
        [loginId]: { ...state.items[loginId]!, loginUrl: 'javascript:alert(1)' },
      },
    }));
    renderDetail(services);

    expect(screen.getByText('javascript:alert(1)')).toBeVisible();
    expect(screen.getByRole('button', { name: '复制网址' })).toBeVisible();
    expect(screen.queryByRole('link', { name: '打开网址' })).not.toBeInTheDocument();
  });

  it('shows a URL-only entry without password controls or fake history', () => {
    const services = relationServices();
    services.store.setState((state) => ({
      items: {
        ...state.items,
        [loginId]: { ...state.items[loginId]!, secretState: 'absent' },
      },
    }));
    renderDetail(services);

    expect(screen.getByText('未保存密码')).toBeVisible();
    expect(screen.queryByRole('button', { name: '查看密码' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '复制密码' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '查看版本历史' })).not.toBeInTheDocument();
    expect(services.api.itemVersions).not.toHaveBeenCalled();
  });
});

function relationServices(): AppServices {
  const store = createMetaStore();
  store.getState().applyDecryptedBootstrap({
    user: {
      id: 'user-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
    },
    vaults: [{
      id: vaultId,
      kind: 'personal',
      name: '个人密码库',
      ownerUserId: 'user-1',
      createdAt: '2026-07-20T00:00:00.000Z',
      updatedAt: '2026-07-20T00:00:00.000Z',
    }],
    memberships: [],
    items: [
      item({ id: loginId, kind: 'login', title: '示例云子账号登录', username: 'alice' }),
      item({
        id: credentialId,
        kind: 'api_token',
        title: '示例云 API 凭证',
        username: 'AKID-example',
        origin: null,
        loginUrl: null,
        description: '用于示例云自动化发布',
        linkedLoginItemId: loginId,
      }),
    ],
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: {},
    encryptedItems: {},
  });
  store.getState().setConnection('online');
  return {
    store,
    leases: new SecretLeaseStore(),
    actions: {
      updateItemMeta: vi.fn(),
      deleteItem: vi.fn(),
      reveal: vi.fn(),
      revealForCopy: vi.fn(),
      createItem: vi.fn(),
    },
    api: { itemVersions: vi.fn().mockResolvedValue([]) },
  } as unknown as AppServices;
}

function item(overrides: Partial<DecryptedItemMeta>): DecryptedItemMeta {
  return {
    id: loginId,
    vaultId,
    kind: 'login',
    title: '条目',
    username: 'user',
    origin: 'https://accounts.example.test',
    loginUrl: 'https://accounts.example.test/login',
    folderPath: null,
    description: null,
    linkedLoginItemId: null,
    tags: [],
    favorite: false,
    sensitivity: 'medium',
    secretState: 'present',
    version: 1,
    secretVersion: 1,
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T00:00:00.000Z',
    updatedBy: 'user-1',
    ...overrides,
  };
}

function detailElement(services: AppServices): React.ReactElement {
  return (
    <AppContext.Provider value={services}>
      <Tooltip.Provider>
        <ItemDetail />
      </Tooltip.Provider>
    </AppContext.Provider>
  );
}

function renderDetail(services: AppServices) {
  return render(detailElement(services));
}
