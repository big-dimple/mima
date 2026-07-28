import { afterEach, describe, expect, it } from 'vitest';
import { useUi } from '../src/state/ui-store.ts';

describe('workspace UI security boundary', () => {
  afterEach(() => useUi.getState().resetWorkspaceUi());

  it('clears decrypted navigation, search and editing state on reset', () => {
    useUi.setState({
      selectedVaultId: '10000000-0000-4000-8000-000000000001',
      selectedItemId: '20000000-0000-4000-8000-000000000001',
      selectedFolderPath: '客户/生产环境',
      search: '内部检索内容',
      editing: '20000000-0000-4000-8000-000000000001',
      groupsOpen: true,
      expandedTreeNodeIds: new Set(['folder:10000000-0000-4000-8000-000000000001:客户']),
    });

    useUi.getState().resetWorkspaceUi();

    expect(useUi.getState()).toMatchObject({
      selectedVaultId: 'all',
      selectedItemId: null,
      selectedFolderPath: null,
      search: '',
      editing: null,
      groupsOpen: false,
    });
    expect(useUi.getState().expandedTreeNodeIds.size).toBe(0);
  });

  it('keeps an edited item in place until the user explicitly discards its draft', async () => {
    useUi.setState({
      selectedVaultId: 'vault-a',
      selectedItemId: 'item-a',
      editing: 'item-a',
      itemDraftDirty: true,
    });

    useUi.getState().selectVault('vault-b');
    expect(useUi.getState()).toMatchObject({
      selectedVaultId: 'vault-a',
      selectedItemId: 'item-a',
      editing: 'item-a',
    });
    expect(useUi.getState().confirm?.title).toBe('放弃未保存的修改？');

    useUi.getState().closeConfirm(false);
    await Promise.resolve();
    expect(useUi.getState().selectedVaultId).toBe('vault-a');

    useUi.getState().selectVault('vault-b');
    useUi.getState().closeConfirm(true);
    await Promise.resolve();
    expect(useUi.getState()).toMatchObject({
      selectedVaultId: 'vault-b',
      selectedItemId: null,
      editing: null,
      itemDraftDirty: false,
    });
  });

  it('blocks navigation while an item save is still running', () => {
    useUi.setState({
      selectedVaultId: 'vault-a',
      selectedItemId: 'item-a',
      editing: 'item-a',
      itemDraftDirty: true,
      itemSavePending: true,
    });

    useUi.getState().selectItem('item-b');

    expect(useUi.getState()).toMatchObject({ selectedItemId: 'item-a', editing: 'item-a' });
    expect(useUi.getState().confirm).toBeNull();
    expect(useUi.getState().toasts.at(-1)?.text).toBe('正在保存这条记录，请稍候');
  });
});
