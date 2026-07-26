import * as Tooltip from '@radix-ui/react-tooltip';
import { act, render, screen, fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { VaultNav } from '../src/components/VaultNav.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';
import { useDrag, ITEM_DRAG_MIME } from '../src/state/drag-store.ts';

const vaultId = '10000000-0000-4000-8000-000000000001';
const otherVaultId = '10000000-0000-4000-8000-000000000002';

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
}

function dropEvent(transfer: MockDataTransfer, type: string) {
  const event = new Event(type, { bubbles: true, cancelable: true, composed: true });
  Object.defineProperty(event, 'dataTransfer', { value: transfer, configurable: true });
  Object.defineProperty(event, 'relatedTarget', { value: null, configurable: true });
  return event;
}

function makeStore() {
  const store = createMetaStore();
  store.getState().applyDecryptedBootstrap({
    user: {
      id: 'u-1', username: 'bob', displayName: 'Bob Li', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
    },
    vaults: [
      {
        id: vaultId, kind: 'personal', name: '个人密码库', ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00Z', updatedAt: '2026-07-20T00:00:00Z',
      },
      {
        id: otherVaultId, kind: 'personal', name: '其他库', ownerUserId: 'u-1',
        createdAt: '2026-07-20T00:00:00Z', updatedAt: '2026-07-20T00:00:00Z',
      },
    ],
    memberships: [],
    items: [{
      id: 'item-1', vaultId, kind: 'login', title: '示例云子账号', username: 'user',
      origin: 'https://example.test', loginUrl: 'https://example.test/', folderPath: null,
      tags: [], favorite: false, sensitivity: 'medium', version: 1, secretVersion: 1,
      createdAt: '2026-07-20T00:00:00Z', updatedAt: '2026-07-20T00:00:00Z', updatedBy: 'u-1',
    }],
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: { [vaultId]: [{ path: '工作', aliases: [] }] },
    encryptedItems: {},
  });
  store.getState().setConnection('online');
  return store;
}

describe('folder drop target', () => {
  beforeEach(() => useUi.setState({ selectedVaultId: vaultId, selectedFolderPath: null, toasts: [] }));
  afterEach(() => useDrag.getState().endDrag());

  it('highlights every compatible folder during drag and strengthens the hovered target', () => {
    const store = makeStore();
    render(
      <AppContext.Provider value={{ store, actions: { updateItemMeta: vi.fn() } } as unknown as AppServices}>
        <Tooltip.Provider><VaultNav /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    const all = screen.getByRole('button', { name: '目录：全部' });
    const unclassified = screen.getByRole('button', { name: '目录：未分类' });
    const folder = screen.getByRole('button', { name: '目录：工作' });
    act(() => useDrag.getState().beginDrag({ id: 'item-1', vaultId }));

    expect(all).not.toHaveAttribute('data-drop-state');
    expect(unclassified).toHaveAttribute('data-drop-state', 'ready');
    expect(folder).toHaveAttribute('data-drop-state', 'ready');

    const transfer = new MockDataTransfer();
    transfer.setData(ITEM_DRAG_MIME, 'move');
    fireEvent(folder, dropEvent(transfer, 'dragenter'));
    expect(folder).toHaveAttribute('data-drop-state', 'over');
    expect(unclassified).toHaveAttribute('data-drop-state', 'ready');

    act(() => useDrag.getState().endDrag());
    expect(folder).not.toHaveAttribute('data-drop-state');
    expect(unclassified).not.toHaveAttribute('data-drop-state');
  });

  it('moves an item into a folder via updateItemMeta on drop', async () => {
    const store = makeStore();
    const updateItemMeta = vi.fn().mockResolvedValue(undefined);
    render(
      <AppContext.Provider value={{ store, actions: { updateItemMeta } } as unknown as AppServices}>
        <Tooltip.Provider><VaultNav /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    act(() => useDrag.getState().beginDrag({ id: 'item-1', vaultId }));
    const folder = screen.getByRole('button', { name: '目录：工作' });
    const transfer = new MockDataTransfer();
    transfer.setData(ITEM_DRAG_MIME, 'move');
    fireEvent(folder, dropEvent(transfer, 'dragover'));
    fireEvent(folder, dropEvent(transfer, 'drop'));

    await Promise.resolve();
    expect(updateItemMeta).toHaveBeenCalledTimes(1);
    expect(updateItemMeta).toHaveBeenCalledWith('item-1', { folderPath: '工作' });
    expect(useDrag.getState().draggingItemId).toBeNull();
  });

  it('writes folderPath null when dropped onto 未分类', async () => {
    const store = makeStore();
    // 条目已在 工作 目录，先改成 null 之外的状态以便移动到 未分类
    store.setState({
      items: { ...store.getState().items, 'item-1': { ...store.getState().items['item-1']!, folderPath: '工作' } },
    });
    const updateItemMeta = vi.fn().mockResolvedValue(undefined);
    render(
      <AppContext.Provider value={{ store, actions: { updateItemMeta } } as unknown as AppServices}>
        <Tooltip.Provider><VaultNav /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(screen.queryByRole('button', { name: '目录：未分类' })).not.toBeInTheDocument();
    act(() => useDrag.getState().beginDrag({ id: 'item-1', vaultId }));
    const unclassified = screen.getByRole('button', { name: '目录：未分类' });
    const transfer = new MockDataTransfer();
    transfer.setData(ITEM_DRAG_MIME, 'move');
    fireEvent(unclassified, dropEvent(transfer, 'dragover'));
    fireEvent(unclassified, dropEvent(transfer, 'drop'));

    await Promise.resolve();
    expect(updateItemMeta).toHaveBeenCalledWith('item-1', { folderPath: null });
  });

  it('does not move when dragging from another vault', async () => {
    const store = makeStore();
    const updateItemMeta = vi.fn().mockResolvedValue(undefined);
    render(
      <AppContext.Provider value={{ store, actions: { updateItemMeta } } as unknown as AppServices}>
        <Tooltip.Provider><VaultNav /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    act(() => useDrag.getState().beginDrag({ id: 'item-1', vaultId: otherVaultId }));
    const folder = screen.getByRole('button', { name: '目录：工作' });
    expect(folder).not.toHaveAttribute('data-drop-state');
    const transfer = new MockDataTransfer();
    transfer.setData(ITEM_DRAG_MIME, 'move');
    fireEvent(folder, dropEvent(transfer, 'dragover'));
    fireEvent(folder, dropEvent(transfer, 'drop'));

    await Promise.resolve();
    expect(updateItemMeta).not.toHaveBeenCalled();
  });

  it('keeps the item in place and does not report success on a 409 conflict', async () => {
    const store = makeStore();
    // 在线 409 被 client 记录为冲突（store.conflicts）后 updateItemMeta 仍 resolve。
    const updateItemMeta = vi.fn().mockImplementation(async (itemId: string) => {
      store.getState().setConflict({ itemId, currentVersion: 2 }, itemId);
    });
    render(
      <AppContext.Provider value={{ store, actions: { updateItemMeta } } as unknown as AppServices}>
        <Tooltip.Provider><VaultNav /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    act(() => useDrag.getState().beginDrag({ id: 'item-1', vaultId }));
    const folder = screen.getByRole('button', { name: '目录：工作' });
    const transfer = new MockDataTransfer();
    transfer.setData(ITEM_DRAG_MIME, 'move');
    fireEvent(folder, dropEvent(transfer, 'dragover'));
    fireEvent(folder, dropEvent(transfer, 'drop'));

    await Promise.resolve();
    expect(updateItemMeta).toHaveBeenCalled();
    // 冲突时不出现“已移动到”成功提示
    expect(useUi.getState().toasts.some((t) => /已移动到/.test(t.text))).toBe(false);
  });
});
