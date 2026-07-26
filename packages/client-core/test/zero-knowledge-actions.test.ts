import { describe, expect, it, vi } from 'vitest';
import type { DecryptedItemMeta } from '../src/e2ee-model.ts';
import { createMetaStore } from '../src/meta-store.ts';
import { SecretLeaseStore } from '../src/secret-lease.ts';
import { ZeroKnowledgeActions } from '../src/zero-knowledge-actions.ts';

const item: DecryptedItemMeta = {
  id: '4e23c38e-d931-4b4b-88ee-b4f1716a86b0',
  vaultId: '10000000-0000-4000-8000-000000000001',
  kind: 'login',
  title: '共享登录',
  username: 'team-user',
  origin: 'https://team.example.test',
  loginUrl: 'https://team.example.test/login',
  folderPath: null,
  description: '团队共用',
  linkedLoginItemId: null,
  tags: ['team'],
  favorite: false,
  sensitivity: 'medium',
  secretState: 'present',
  version: 8,
  secretVersion: 5,
  createdAt: '2026-07-20T00:00:00.000Z',
  updatedAt: '2026-07-22T00:00:00.000Z',
  updatedBy: 'user-2',
};

describe('ZeroKnowledgeActions item version guard', () => {
  it('stops stale metadata before encryption or network work starts', async () => {
    const client = { updateItem: vi.fn(), rotateItem: vi.fn() };
    const actions = createActions(client);

    await expect(actions.updateItemMeta(item.id, { title: '我的草稿' }, item.version - 1))
      .rejects.toThrow('这条记录刚刚有了新修改');
    expect(client.updateItem).not.toHaveBeenCalled();
  });

  it('stops a stale sensitive-content rotation before encryption starts', async () => {
    const client = { updateItem: vi.fn(), rotateItem: vi.fn() };
    const actions = createActions(client);

    await expect(actions.rotateSecret(item.id, 'new-sensitive-value', item.version - 1))
      .rejects.toThrow('系统已暂停保存');
    expect(client.rotateItem).not.toHaveBeenCalled();
  });

  it('uses the captured version while preserving every unpatched field', async () => {
    const client = {
      updateItem: vi.fn().mockResolvedValue(undefined),
      rotateItem: vi.fn().mockResolvedValue(undefined),
    };
    const actions = createActions(client);

    await actions.updateItemMeta(item.id, { title: '团队登录已更新' }, item.version);

    expect(client.updateItem).toHaveBeenCalledWith(item, expect.objectContaining({
      title: '团队登录已更新',
      username: item.username,
      loginUrl: item.loginUrl,
      description: item.description,
      tags: item.tags,
    }));
  });
});

function createActions(client: { updateItem: ReturnType<typeof vi.fn>; rotateItem: ReturnType<typeof vi.fn> }) {
  const store = createMetaStore();
  store.setState({ items: { [item.id]: item } });
  return new ZeroKnowledgeActions(client as never, store, new SecretLeaseStore());
}
