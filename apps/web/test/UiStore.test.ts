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
});
