import { render, screen, fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { ItemList } from '../src/components/ItemList.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';
import { useDrag, ITEM_DRAG_MIME } from '../src/state/drag-store.ts';

const vaultId = '10000000-0000-4000-8000-000000000001';

/** 模拟浏览器 DataTransfer：记录所有 setData 写入，供安全断言检查。 */
class MockDataTransfer {
  readonly types: string[] = [];
  private data = new Map<string, string>();
  effectAllowed = 'none';
  dropEffect = 'none';
  setData(type: string, value: string) {
    if (!this.types.includes(type)) this.types.push(type);
    this.data.set(type, value);
  }
  getData(type: string) {
    return this.data.get(type) ?? '';
  }
  clearData() {
    this.types.length = 0;
    this.data.clear();
  }
}

function fireDrag(target: Element, type: string, transfer: MockDataTransfer) {
  // jsdom 没有原生 DragEvent；构造普通 Event 并预先挂上 dataTransfer，再派发。
  const event = new Event(type, { bubbles: true, cancelable: true, composed: true });
  Object.defineProperty(event, 'dataTransfer', { value: transfer, configurable: true });
  fireEvent(target, event);
}

function makeStore(items: { id: string; title: string; folderPath: string | null; sensitivity?: 'medium' | 'high' }[]) {
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
      username: 'sub-account-user',
      origin: 'https://example.test',
      loginUrl: 'https://example.test/',
      folderPath: item.folderPath,
      tags: [],
      favorite: false,
      sensitivity: item.sensitivity ?? 'medium',
      version: 1,
      secretVersion: 1,
      createdAt: '2026-07-20T00:00:00Z',
      updatedAt: '2026-07-20T00:00:00Z',
      updatedBy: 'u-1',
    })),
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: { [vaultId]: [{ path: '工作', aliases: [] }] },
    encryptedItems: {},
  });
  store.getState().setConnection('online');
  return store;
}

describe('item drag classification', () => {
  beforeEach(() => {
    useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: null, toasts: [] });
    // jsdom 没有 matchMedia；视口+细指针判定需要它返回 true 才能启用拖拽。
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: () => undefined, removeEventListener: () => undefined }));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    useDrag.getState().endDrag();
  });

  it('does not put item id or any decrypted metadata into the DataTransfer', () => {
    const store = makeStore([{ id: 'item-secret-id', title: '示例云子账号', folderPath: '工作' }]);
    render(<AppContext.Provider value={{ store, actions: { updateItemMeta: vi.fn() } } as unknown as AppServices}><ItemList /></AppContext.Provider>);

    const row = screen.getByRole('option', { name: /示例云子账号/ });
    const transfer = new MockDataTransfer();
    fireDrag(row, 'dragstart', transfer);

    // 唯一允许的内部 MIME，且其值是固定标记，不是条目 ID。
    expect(transfer.types).toEqual([ITEM_DRAG_MIME]);
    const payload = JSON.stringify({ types: transfer.types, values: transfer.types.map((t) => transfer.getData(t)) });
    // 不得包含 item ID、标题、用户名、网址、目录或标签等任何解密元数据。
    expect(payload).not.toContain('item-secret-id');
    expect(payload).not.toContain('示例云');
    expect(payload).not.toContain('sub-account-user');
    expect(payload).not.toContain('example.test');
    expect(payload).not.toContain('工作');
  });

  it('keeps item id only in transient memory and clears it after drag ends', () => {
    const store = makeStore([{ id: 'item-1', title: '条目一', folderPath: '工作' }]);
    render(<AppContext.Provider value={{ store, actions: { updateItemMeta: vi.fn() } } as unknown as AppServices}><ItemList /></AppContext.Provider>);

    const row = screen.getByRole('option', { name: /条目一/ });
    const transfer = new MockDataTransfer();
    fireDrag(row, 'dragstart', transfer);
    expect(useDrag.getState().draggingItemId).toBe('item-1');

    fireDrag(row, 'dragend', transfer);
    expect(useDrag.getState().draggingItemId).toBeNull();
  });

  it('never enables dragging when the viewport is not a fine-pointer desktop', () => {
    vi.unstubAllGlobals();
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: false, addEventListener: () => undefined, removeEventListener: () => undefined }));
    const store = makeStore([{ id: 'item-1', title: '条目一', folderPath: null }]);
    render(<AppContext.Provider value={{ store, actions: { updateItemMeta: vi.fn() } } as unknown as AppServices}><ItemList /></AppContext.Provider>);

    const row = screen.getByRole('option', { name: /条目一/ });
    expect(row).not.toHaveAttribute('draggable', 'true');
    expect(useDrag.getState().draggingItemId).toBeNull();
  });
});

describe('item drag role gating', () => {
  afterEach(() => useDrag.getState().endDrag());

  it('viewers and auditors on a team vault cannot drag items', () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: () => undefined, removeEventListener: () => undefined }));
    const store = createMetaStore();
    const teamVaultId = '20000000-0000-4000-8000-000000000001';
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: teamVaultId, kind: 'team', name: '团队库', ownerUserId: 'owner-1',
        createdAt: '2026-07-20T00:00:00Z', updatedAt: '2026-07-20T00:00:00Z',
      }],
      memberships: [{
        vaultId: teamVaultId, subjectKind: 'user', subjectId: 'u-1', role: 'viewer',
      }],
      items: [{
        id: 'i-1', vaultId: teamVaultId, kind: 'login', title: '团队条目', username: 'u',
        origin: 'https://example.test', loginUrl: 'https://example.test/', folderPath: null,
        tags: [], favorite: false, sensitivity: 'medium', version: 1, secretVersion: 1,
        createdAt: '2026-07-20T00:00:00Z', updatedAt: '2026-07-20T00:00:00Z', updatedBy: 'owner-1',
      }],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: { [teamVaultId]: [{ path: '工作', aliases: [] }] },
      encryptedItems: {},
    });
    store.getState().setConnection('online');
    useUi.setState({ selectedVaultId: teamVaultId, selectedFolderPath: null });

    render(<AppContext.Provider value={{ store, actions: { updateItemMeta: vi.fn() } } as unknown as AppServices}><ItemList /></AppContext.Provider>);
    const row = screen.getByRole('option', { name: /团队条目/ });
    expect(row).not.toHaveAttribute('draggable', 'true');
    vi.unstubAllGlobals();
  });
});
