import { describe, expect, it, vi } from 'vitest';
import type { PanelActions } from '../src/panel-actions.ts';
import { PanelModel } from '../src/panel-model.ts';
import { PanelView } from '../src/panel-view.ts';
import { extSession } from './helpers.ts';

function actions(): PanelActions {
  return {
    pair: vi.fn(),
    checkPairingApproval: vi.fn(),
    unlock: vi.fn(),
    tryTrustedUnlock: vi.fn(),
    lock: vi.fn(),
    refreshData: vi.fn(),
    refreshActiveTab: vi.fn(),
    unpair: vi.fn(),
    cancelPendingPairing: vi.fn(),
    fill: vi.fn(),
    copy: vi.fn(),
    open: vi.fn(),
  } as unknown as PanelActions;
}

describe('PanelView', () => {
  it('renders a visible loading state before asynchronous startup', () => {
    const root = document.createElement('div');
    new PanelView(root, new PanelModel(), actions(), vi.fn()).render();
    expect(root.querySelector('[role="status"]')?.textContent).toContain('正在加载扩展');
  });

  it('shows the device fingerprint before approval can complete', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.setAwaitingApproval({
      enrollmentId: 'enrollment-1',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      fingerprint: '1111 2222 3333 4444 5555 6666 7777 8888',
    });
    new PanelView(root, model, actions(), vi.fn()).render();

    expect(root.querySelector('.fingerprint')?.textContent).toBe('1111 2222 3333 4444 5555 6666 7777 8888');
    expect(root.textContent).toContain('核对设备指纹');
    expect(root.textContent).toContain('检查授权');
    expect(root.textContent).toContain('取消本次配对');
  });

  it('uses shared item semantics and hides unsafe fill actions', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.session = extSession();
    model.state.tabOrigin = 'https://example.test';
    model.setReady([
      extensionItem({ id: 'login-1', kind: 'login', title: '生产 Redis', username: 'default', origin: null }),
      extensionItem({ id: 'token-1', kind: 'api_token', title: 'Gitea', username: '发布服务', origin: null }),
      extensionItem({ id: 'note-1', kind: 'secure_note', title: '值班说明', username: 'legacy-hidden', origin: null }),
    ]);

    new PanelView(root, model, actions(), vi.fn()).render();

    expect([...root.querySelectorAll('button')].map((button) => button.textContent)).not.toContain('填充');
    expect(root.textContent).toContain('账号密码');
    expect(root.textContent).toContain('复制密码');
    expect(root.textContent).toContain('复制密钥 / Token');
    expect(root.textContent).toContain('复制备注');
    expect(root.textContent).not.toContain('legacy-hidden');
  });

  it('searches descriptions and linked login titles locally', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.session = extSession();
    model.state.search = '采购审批';
    model.setReady([
      extensionItem({ id: 'login-1', title: '示例云主账号登录' }),
      extensionItem({
        id: 'token-1',
        kind: 'api_token',
        title: '云平台发布凭证',
        username: 'AKID-example',
        origin: null,
        description: '采购审批后申请',
        linkedLoginItemId: 'login-1',
      }),
    ]);

    new PanelView(root, model, actions(), vi.fn()).render();
    expect(root.querySelector('.results')?.textContent).toContain('云平台发布凭证');

    const search = root.querySelector<HTMLInputElement>('[aria-label="搜索已解锁条目"]')!;
    search.value = '示例云主账号登录';
    search.dispatchEvent(new Event('input'));
    expect(root.querySelector('.results')?.textContent).toContain('云平台发布凭证');
  });

  it('lists the exact full login URL before same-origin fallbacks', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.session = extSession();
    model.state.tabOrigin = 'https://accounts.example.test';
    model.state.tabUrl = 'https://accounts.example.test/login/tenant/example-b';
    model.setReady([
      extensionItem({
        id: 'fallback',
        title: '示例云其他入口',
        origin: 'https://accounts.example.test',
        loginUrl: 'https://accounts.example.test/login',
      }),
      extensionItem({
        id: 'exact',
        title: '示例云目标子账号',
        origin: 'https://accounts.example.test',
        loginUrl: model.state.tabUrl,
      }),
    ]);

    new PanelView(root, model, actions(), vi.fn()).render();

    const matchedResults = root.querySelectorAll('.results')[0]!;
    const titles = [...matchedResults.querySelectorAll('.itemTitleText')]
      .map((node) => node.textContent);
    expect(titles).toEqual(['示例云目标子账号', '示例云其他入口']);
    expect([...matchedResults.querySelectorAll('.matchReason')].map((node) => node.textContent))
      .toEqual(['精确地址', '同站点']);
    expect(root.querySelector('.originBar code')?.textContent).toBe(model.state.tabUrl);
  });

  it('searches secondary login URLs without changing the displayed primary URL', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.session = extSession();
    model.setReady([extensionItem({
      id: 'multi-url',
      title: '多入口平台',
      origin: 'https://primary.example.test',
      loginUrl: 'https://primary.example.test/login',
      loginUrls: [
        'https://primary.example.test/login',
        'https://secondary.example.test/console',
      ],
    })]);

    new PanelView(root, model, actions(), vi.fn()).render();
    const search = root.querySelector<HTMLInputElement>('[aria-label="搜索已解锁条目"]')!;
    search.value = 'secondary.example.test';
    search.dispatchEvent(new Event('input'));

    expect(root.querySelector('.results')?.textContent).toContain('多入口平台');
    expect(root.querySelector('.itemSub')?.textContent).toContain('primary.example.test/login');
  });

  it('keeps URL-only entries searchable but never suggests or copies a password', async () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    const panelActions = actions();
    panelActions.open = vi.fn().mockResolvedValue('已打开网址');
    model.state.session = extSession();
    model.state.tabOrigin = 'https://accounts.example.test';
    model.state.tabUrl = 'https://accounts.example.test/login';
    model.setReady([extensionItem({
      id: 'entry-only',
      title: '示例云统一入口',
      origin: 'https://accounts.example.test',
      loginUrl: 'https://accounts.example.test/login',
      secretState: 'absent',
    })]);

    new PanelView(root, model, panelActions, vi.fn()).render();

    expect(root.textContent).toContain('建议填充（0）');
    expect(root.textContent).toContain('示例云统一入口');
    expect(root.textContent).toContain('仅入口');
    expect(root.textContent).not.toContain('复制密码');
    const open = [...root.querySelectorAll('button')].find((button) => button.textContent?.includes('打开网址'));
    open?.click();
    await vi.waitFor(() => expect(panelActions.open).toHaveBeenCalledWith(expect.objectContaining({ id: 'entry-only' })));
  });

  it('requires confirmation before unpairing', async () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    const panelActions = actions();
    model.state.session = extSession();
    model.setReady([]);
    new PanelView(root, model, panelActions, vi.fn()).render();

    root.querySelector<HTMLButtonElement>('button[aria-label="解除配对"]')?.click();
    expect(document.body.textContent).toContain('解除这台扩展的配对');
    expect(document.body.textContent).toContain('扩展授权和离线数据会立即清除');
    expect(document.body.textContent).not.toContain('密文缓存');
    expect(panelActions.unpair).not.toHaveBeenCalled();
    const cancel = [...document.body.querySelectorAll('button')].find((button) => button.textContent === '取消');
    cancel?.click();
    expect(panelActions.unpair).not.toHaveBeenCalled();
  });

  it('uses agreed Chinese terms in pairing and lock views', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    const view = new PanelView(root, model, actions(), vi.fn());
    model.setPairing();
    view.render();
    expect(root.textContent).toContain('无需在扩展重复输入主密码');
    expect(root.textContent).toContain('主密码');
    expect(root.querySelectorAll('input[type="password"]')).toHaveLength(0);
    expect(root.textContent).not.toMatch(/秘密|揭示|保险库|口令/);
  });

  it('asks for an existing main password only once during compatibility pairing', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.device = { deviceId: 'device-1', unlockFactorKind: 'web-main-password' } as never;
    model.setPairing();

    new PanelView(root, model, actions(), vi.fn()).render();

    expect(root.textContent).toContain('只需输入一次当前主密码');
    expect(root.querySelectorAll('input[type="password"]')).toHaveLength(1);
    expect(root.textContent).not.toContain('再次输入主密码');
  });

  it('keeps a trusted device out of pairing when its online connection needs restoring', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.device = { deviceId: 'device-1', name: 'Office Edge', webUnlock: { version: 1 } } as never;
    model.setLocked('在线连接已中断');

    new PanelView(root, model, actions(), vi.fn()).render();

    expect(root.textContent).toContain('恢复扩展连接');
    expect(root.textContent).toContain('无需重新配对');
    expect(root.querySelectorAll('input[type="password"]')).toHaveLength(0);
    expect([...root.querySelectorAll('button')].some(
      (button) => button.textContent === '从已解锁工作台恢复',
    )).toBe(true);
  });

  it('explains offline data without exposing storage internals', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.session = extSession();
    model.setReady([], true);

    new PanelView(root, model, actions(), vi.fn()).render();

    expect(root.querySelector('[role="status"]')?.textContent)
      .toBe('暂时无法连接服务，当前显示此浏览器保存的数据');
  });

  it('upgrades a legacy device with one password field and no pairing code', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.device = {
      deviceId: 'legacy-device-1',
      name: 'Office Edge',
      unlockFactorKind: 'web-main-password',
    } as never;
    model.setLocked('设备身份仍在');

    new PanelView(root, model, actions(), vi.fn()).render();

    expect(root.textContent).toContain('完成设备升级');
    expect(root.textContent).toContain('无需配对码');
    expect(root.querySelectorAll('input[type="password"]')).toHaveLength(1);
    expect(root.querySelector('input[aria-label="一次性配对码"]')).toBeNull();
  });

  it('re-renders immediately when refresh moves to a revoked security state', async () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    const panelActions = actions();
    panelActions.refreshData = vi.fn(async () => {
      model.setRevoked();
      throw new Error('当前设备已被撤销');
    });
    const view = new PanelView(root, model, panelActions, vi.fn());
    model.state.session = extSession();
    model.setReady([]);
    view.render();

    root.querySelector<HTMLButtonElement>('button[aria-label="刷新"]')?.click();

    await vi.waitFor(() => expect(root.textContent).toContain('此设备已被撤销'));
    expect(root.textContent).not.toContain('刷新中');
  });

  it('renders compact accessible icon controls in the ready header', () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    model.state.session = extSession();
    model.state.session.user.displayName = '一个需要截断显示的很长用户名';
    model.setReady([]);
    new PanelView(root, model, actions(), vi.fn()).render();

    const labels = ['刷新', '锁定', '解除配对'];
    const controls = labels.map((label) => root.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`));
    expect(controls.every(Boolean)).toBe(true);
    expect(controls.map((control) => control?.title)).toEqual(labels);
    expect(controls.every((control) => control?.classList.contains('iconBtn'))).toBe(true);
    expect(controls.every((control) => control?.textContent === '')).toBe(true);
    expect(controls.every((control) => control?.querySelector('svg[aria-hidden="true"]'))).toBe(true);
    expect(root.querySelector('.headerActions')?.children).toHaveLength(3);
  });

  it('marks refresh busy without changing its accessible name', async () => {
    const root = document.createElement('div');
    const model = new PanelModel();
    const panelActions = actions();
    let rejectRefresh: ((error: Error) => void) | undefined;
    panelActions.refreshData = vi.fn(() => new Promise<void>((_resolve, reject) => {
      rejectRefresh = reject;
    }));
    model.state.session = extSession();
    model.setReady([]);
    new PanelView(root, model, panelActions, vi.fn()).render();

    const refresh = root.querySelector<HTMLButtonElement>('button[aria-label="刷新"]');
    refresh?.click();
    expect(refresh?.disabled).toBe(true);
    expect(refresh?.getAttribute('aria-busy')).toBe('true');
    expect(refresh?.classList.contains('isLoading')).toBe(true);

    rejectRefresh?.(new Error('网络不可用'));
    await vi.waitFor(() => expect(refresh?.disabled).toBe(false));
    expect(refresh?.hasAttribute('aria-busy')).toBe(false);
    expect(refresh?.classList.contains('isLoading')).toBe(false);
  });
});

function extensionItem(overrides: Partial<import('../src/protocol.ts').DecryptedExtensionItem> = {}) {
  return {
    id: 'item-1',
    vaultId: 'vault-1',
    kind: 'login' as const,
    title: '条目',
    username: 'user',
    origin: 'https://example.test',
    tags: [],
    favorite: false,
    sensitivity: 'medium' as const,
    secretState: 'present' as const,
    version: 1,
    secretVersion: 1,
    keyEpoch: 1,
    ...overrides,
  };
}
