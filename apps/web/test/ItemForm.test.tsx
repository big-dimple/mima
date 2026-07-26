import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore, type DecryptedItemMeta } from '@mima/client-core';
import { ItemForm } from '../src/components/ItemForm.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const vaultId = '10000000-0000-4000-8000-000000000001';
const loginUrl = 'https://accounts.example.test/login/tenant/example-a';

describe('ItemForm', () => {
  beforeEach(() => useUi.setState({
    selectedVaultId: vaultId,
    selectedFolderPath: null,
    selectedItemId: null,
    editing: null,
    newItemPreset: null,
    toasts: [],
  }));
  afterEach(() => useUi.setState({
    selectedVaultId: 'all',
    selectedFolderPath: null,
    selectedItemId: null,
    editing: null,
    newItemPreset: null,
    toasts: [],
  }));

  it('stores a full login URL while deriving the extension origin', async () => {
    const createItem = vi.fn().mockResolvedValue('item-created');
    const onClose = vi.fn();
    renderForm({ actions: { createItem } }, <ItemForm mode="new" onClose={onClose} />);

    await userEvent.type(screen.getByLabelText('标题 *'), '示例云子账号');
    await userEvent.type(screen.getByLabelText('账号'), 'sub-account-user');
    await userEvent.type(screen.getByLabelText('网址（可选）'), loginUrl);
    await userEvent.selectOptions(screen.getByLabelText('目录（可选）'), '工作/云服务/示例云');
    await userEvent.type(screen.getByLabelText(/^密码/), 'new-password-value');
    expect(screen.getByRole('checkbox', { name: '标记为高敏' })).not.toBeChecked();
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    await waitFor(() => expect(createItem).toHaveBeenCalledWith(vaultId, expect.objectContaining({
      title: '示例云子账号',
      username: 'sub-account-user',
      origin: 'https://accounts.example.test',
      loginUrl,
      folderPath: '工作/云服务/示例云',
      sensitivity: 'medium',
      secretValue: 'new-password-value',
    })));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('creates a server account password without a web address', async () => {
    const createItem = vi.fn().mockResolvedValue('server-item-created');
    renderForm({ actions: { createItem } }, <ItemForm mode="new" onClose={vi.fn()} />);

    expect(screen.getByRole('button', { name: '账号密码' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('账号')).toHaveAttribute('placeholder', '用户名 / 登录账号（可选）');
    expect(screen.getByLabelText('说明（可选）')).toHaveAttribute(
      'placeholder',
      '主机/IP、端口、实例/库名、环境、用途、归属等；不要填写密码或密钥',
    );

    await userEvent.type(screen.getByLabelText('标题 *'), '生产 Redis');
    await userEvent.type(screen.getByLabelText('账号'), 'default');
    await userEvent.type(screen.getByLabelText('说明（可选）'), '10.0.0.8:6379 · 生产缓存');
    await userEvent.type(screen.getByLabelText('密码（可选）'), 'redis-password-value');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    await waitFor(() => expect(createItem).toHaveBeenCalledWith(vaultId, expect.objectContaining({
      kind: 'login',
      username: 'default',
      origin: null,
      loginUrl: null,
      description: '10.0.0.8:6379 · 生产缓存',
      secretValue: 'redis-password-value',
    })));
  });

  it('creates a shared URL entry without a password and ignores browser injection', async () => {
    const createItem = vi.fn().mockResolvedValue('shared-entry-created');
    renderForm({ actions: { createItem } }, <ItemForm mode="new" onClose={vi.fn()} />);

    await userEvent.type(screen.getByLabelText('标题 *'), '示例云统一入口');
    await userEvent.type(screen.getByLabelText('网址（可选）'), loginUrl);
    const password = screen.getByLabelText('密码（可选）');
    fireEvent.input(password, {
      target: { value: 'browser-injected-main-password' },
      inputType: 'insertReplacementText',
    });
    expect(password).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    await waitFor(() => expect(createItem).toHaveBeenCalledWith(vaultId, expect.objectContaining({
      kind: 'login',
      origin: 'https://accounts.example.test',
      loginUrl,
      secretValue: null,
    })));
  });

  it('still requires sensitive content for API credentials', async () => {
    const createItem = vi.fn();
    renderForm({ actions: { createItem } }, <ItemForm mode="new" onClose={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: 'API 凭证' }));
    await userEvent.type(screen.getByLabelText('标题 *'), '发布凭证');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(await screen.findByRole('alert')).toHaveTextContent('密钥 / Token不能为空');
    expect(createItem).not.toHaveBeenCalled();
  });

  it('inherits the selected directory and only offers managed directories', async () => {
    useUi.setState({ selectedFolderPath: '工作/云服务' });
    renderForm(
      { actions: { createItem: vi.fn() } },
      <ItemForm mode="new" onClose={vi.fn()} />,
    );

    expect(screen.getByLabelText('目录（可选）')).toHaveValue('工作/云服务');
    expect(screen.getByRole('option', { name: '工作/云服务/示例云' })).toBeVisible();
    expect(screen.queryByRole('option', { name: '工作//云服务' })).not.toBeInTheDocument();
  });

  it('keeps legacy low sensitivity and an unchanged full URL out of unrelated patches', async () => {
    const updateItemMeta = vi.fn();
    const onClose = vi.fn();
    const item = testItem({ sensitivity: 'low', loginUrl });
    renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={onClose} />
    ), [item]);

    const title = screen.getByLabelText('标题 *');
    await replaceText(title, '示例云子账号已更新');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(updateItemMeta).toHaveBeenCalledWith(item.id, { title: '示例云子账号已更新' }, item.version);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('maps high back to ordinary and cancel never submits', async () => {
    const updateItemMeta = vi.fn();
    const onClose = vi.fn();
    const item = testItem({ sensitivity: 'high' });
    const { unmount } = renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={onClose} />
    ), [item]);

    await userEvent.click(screen.getByRole('checkbox', { name: '标记为高敏' }));
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));
    expect(updateItemMeta).toHaveBeenCalledWith(item.id, { sensitivity: 'medium' }, item.version);
    unmount();

    const createItem = vi.fn();
    const cancel = vi.fn();
    renderForm({ actions: { createItem } }, <ItemForm mode="new" onClose={cancel} />);
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(cancel).toHaveBeenCalledOnce();
    expect(createItem).not.toHaveBeenCalled();
  });

  it('clears both full URL and extension origin together', async () => {
    const updateItemMeta = vi.fn();
    const item = testItem();
    renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    await replaceText(screen.getByLabelText('网址（可选）'), '');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));
    expect(updateItemMeta).toHaveBeenCalledWith(
      item.id,
      { origin: null, loginUrl: null },
      item.version,
    );
  });

  it('uses credential-specific labels and creates a linked API credential', async () => {
    const login = testItem();
    const createItem = vi.fn().mockResolvedValue('credential-created');
    const preset = { kind: 'api_token' as const, vaultId, linkedLoginItemId: login.id };
    const initial = renderForm(
      { actions: { createItem: vi.fn() } },
      <ItemForm mode="new" onClose={vi.fn()} />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'API 凭证' }));
    expect(screen.getByLabelText('凭证标识')).toHaveAttribute(
      'placeholder',
      'SecretId / AccessKey ID / Client ID / 账号',
    );
    expect(screen.getByLabelText('密钥 / Token *')).toBeVisible();
    expect(screen.queryByLabelText(/标签（如所属服务账号）/)).not.toBeInTheDocument();

    initial.unmount();
    renderForm(
      { actions: { createItem } },
      <ItemForm mode="new" preset={preset} onClose={vi.fn()} />,
      [login],
    );
    expect(screen.getByLabelText('关联账号密码（可选）')).toHaveValue(login.id);
    await userEvent.type(screen.getAllByLabelText('标题 *').at(-1)!, '示例云子账号 API');
    await userEvent.type(screen.getAllByLabelText('凭证标识').at(-1)!, 'AKID-example');
    await userEvent.type(screen.getAllByLabelText('说明（可选）').at(-1)!, '用于发布流水线\n由平台组申请');
    await userEvent.type(screen.getAllByLabelText('密钥 / Token *').at(-1)!, 'secret-key-value');
    await userEvent.click(screen.getAllByRole('button', { name: '保存', exact: true }).at(-1)!);

    await waitFor(() => expect(createItem).toHaveBeenCalledWith(vaultId, expect.objectContaining({
      kind: 'api_token',
      username: 'AKID-example',
      description: '用于发布流水线\n由平台组申请',
      linkedLoginItemId: login.id,
      secretValue: 'secret-key-value',
    })));
  });

  it('never clears hidden legacy fields during an unrelated edit', async () => {
    const updateItemMeta = vi.fn();
    const item = testItem({
      kind: 'secure_note',
      username: 'legacy-hidden-value',
      origin: null,
      loginUrl: null,
    });
    renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    expect(screen.queryByLabelText('账号')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '保存', exact: true })).toBeDisabled();
    expect(updateItemMeta).not.toHaveBeenCalled();
  });

  it('keeps password input unmounted until the user explicitly chooses to replace it', async () => {
    const updateItemMeta = vi.fn();
    const rotateSecret = vi.fn();
    const item = testItem();
    renderForm({ actions: { updateItemMeta, rotateSecret } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    expect(screen.queryByLabelText('密码')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: '同时更换密码' }));
    const password = screen.getByLabelText('密码');
    expect(password).toHaveAttribute('readonly');

    fireEvent.input(password, {
      target: { value: 'browser-injected-main-password' },
      inputType: 'insertReplacementText',
    });
    await replaceText(screen.getByLabelText('标题 *'), '只修改标题');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(rotateSecret).not.toHaveBeenCalled();
    expect(updateItemMeta).toHaveBeenCalledWith(item.id, { title: '只修改标题' }, item.version);
  });

  it('rotates sensitive content only after direct input and advances the metadata base version', async () => {
    const updateItemMeta = vi.fn();
    const rotateSecret = vi.fn();
    const item = testItem();
    renderForm({ actions: { updateItemMeta, rotateSecret } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    await userEvent.click(screen.getByRole('checkbox', { name: '同时更换密码' }));
    await userEvent.type(screen.getByLabelText('密码'), 'explicit-new-password');
    await replaceText(screen.getByLabelText('标题 *'), '标题和密码都修改');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(rotateSecret).toHaveBeenCalledWith(item.id, 'explicit-new-password', item.version);
    expect(updateItemMeta).toHaveBeenCalledWith(
      item.id,
      { title: '标题和密码都修改' },
      item.version + 1,
    );
  });

  it('offers adding a password to an entry that does not have one', async () => {
    const rotateSecret = vi.fn().mockResolvedValue(undefined);
    const item = testItem({ secretState: 'absent' });
    renderForm({ actions: { updateItemMeta: vi.fn(), rotateSecret } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    expect(screen.queryByLabelText('密码')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: '添加密码' }));
    await userEvent.type(screen.getByLabelText('密码'), 'personal-password');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(rotateSecret).toHaveBeenCalledWith(item.id, 'personal-password', item.version);
  });

  it('rejects browser-filled metadata and preserves stale hidden relations on unrelated edits', async () => {
    const updateItemMeta = vi.fn();
    const item = testItem({
      kind: 'api_token',
      username: 'AKID-original',
      origin: null,
      loginUrl: null,
      linkedLoginItemId: '99999999-9999-4999-8999-999999999999',
    });
    renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    const auxiliary = screen.getByLabelText('凭证标识');
    fireEvent.input(auxiliary, {
      target: { value: 'browser-filled-user' },
      inputType: 'insertReplacementText',
    });
    await replaceText(screen.getByLabelText('标题 *'), 'API 凭证标题更新');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(updateItemMeta).toHaveBeenCalledWith(
      item.id,
      { title: 'API 凭证标题更新' },
      item.version,
    );
  });

  it('clears sensitive and type-specific drafts when a new item changes type', async () => {
    renderForm({ actions: { createItem: vi.fn() } }, <ItemForm mode="new" onClose={vi.fn()} />);

    await userEvent.type(screen.getByLabelText('账号'), 'draft-user');
    await userEvent.type(screen.getByLabelText('网址（可选）'), 'https://draft.example.test');
    await userEvent.type(screen.getByLabelText('密码（可选）'), 'draft-password');
    await userEvent.click(screen.getByRole('button', { name: 'API 凭证' }));

    expect(screen.getByLabelText('凭证标识')).toHaveValue('');
    expect(screen.getByLabelText('密钥 / Token *')).toHaveValue('');
    expect(screen.getByLabelText('密钥 / Token *')).toHaveAttribute('readonly');
  });

  it('blocks a stale open form and explains how to continue', async () => {
    const updateItemMeta = vi.fn();
    const item = testItem();
    const rendered = renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    await replaceText(screen.getByLabelText('标题 *'), '仍在编辑的草稿');
    rendered.store.setState({ items: { [item.id]: { ...item, version: item.version + 1 } } });

    expect(await screen.findByText('这条记录刚刚有了新修改')).toBeVisible();
    expect(screen.getByText(/系统已暂停保存.*你的输入仍保留在本页/)).toBeVisible();
    expect(screen.getByRole('button', { name: '保存', exact: true })).toBeDisabled();
    expect(updateItemMeta).not.toHaveBeenCalled();
  });

  it('submits at most once while an update is in flight', async () => {
    let finish!: () => void;
    const updateItemMeta = vi.fn().mockImplementation(() => new Promise<void>((resolve) => { finish = resolve; }));
    const item = testItem();
    renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={vi.fn()} />
    ), [item]);

    await replaceText(screen.getByLabelText('标题 *'), '只提交一次');
    const form = screen.getByRole('button', { name: '保存', exact: true }).closest('form')!;
    fireEvent.submit(form);
    fireEvent.submit(form);
    expect(updateItemMeta).toHaveBeenCalledTimes(1);
    finish();
    await waitFor(() => expect(screen.getByRole('button', { name: '保存中…' })).toBeDisabled());
  });

  it('keeps the form open with recovery guidance when the server protects a newer edit', async () => {
    const updateItemMeta = vi.fn();
    const onClose = vi.fn();
    const item = testItem();
    const rendered = renderForm({ actions: { updateItemMeta, rotateSecret: vi.fn() } }, (
      <ItemForm mode="edit" item={item} onClose={onClose} />
    ), [item]);
    updateItemMeta.mockImplementation(async () => {
      rendered.store.getState().setConflict({
        itemId: item.id,
        currentVersion: item.version + 1,
      }, item.id);
    });

    await replaceText(screen.getByLabelText('标题 *'), '不会覆盖的新标题');
    await userEvent.click(screen.getByRole('button', { name: '保存', exact: true }));

    expect(onClose).not.toHaveBeenCalled();
    expect(await screen.findByText(/系统已暂停保存.*你的输入仍保留在本页/)).toBeVisible();
    expect(screen.getByRole('heading', { name: `编辑「${item.title}」` })).toBeVisible();
  });
});

function renderForm(
  overrides: { actions: Record<string, unknown> },
  element: React.ReactNode,
  initialItems: DecryptedItemMeta[] = [],
) {
  const store = createMetaStore();
  store.getState().setConnection('online');
  store.setState({
    items: Object.fromEntries(initialItems.map((item) => [item.id, item])),
    vaultDirectories: {
      [vaultId]: [
        { path: '工作', aliases: [] },
        { path: '工作/云服务', aliases: [] },
        { path: '工作/云服务/示例云', aliases: [] },
      ],
    },
  });
  const services = { store, actions: overrides.actions } as unknown as AppServices;
  return { ...render(<AppContext.Provider value={services}>{element}</AppContext.Provider>), store };
}

async function replaceText(element: HTMLElement, value: string) {
  await userEvent.click(element);
  const control = element as HTMLInputElement | HTMLTextAreaElement;
  control.setSelectionRange(0, control.value.length);
  if (value) await userEvent.type(element, value, { skipClick: true });
  else await userEvent.keyboard('{Backspace}');
}

function testItem(overrides: Partial<DecryptedItemMeta> = {}): DecryptedItemMeta {
  return {
    id: '4e23c38e-d931-4b4b-88ee-b4f1716a86b0',
    vaultId,
    kind: 'login',
    title: '示例云子账号',
    username: 'sub-account-user',
    origin: 'https://accounts.example.test',
    loginUrl,
    tags: [],
    favorite: false,
    sensitivity: 'medium',
    secretState: 'present',
    version: 7,
    secretVersion: 4,
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T01:00:00.000Z',
    updatedBy: 'user-1',
    ...overrides,
  };
}
