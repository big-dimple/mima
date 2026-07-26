import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretLeaseStore } from '../src/secret-lease.ts';
import { createMetaStore, type MetaStore } from '../src/meta-store.ts';
import { CommandOutbox } from '../src/outbox.ts';
import { VaultActions, StaleRevealError } from '../src/actions.ts';
import type { ApiClient } from '../src/api-client.ts';
import type { ItemMeta, Vault } from '@mima/contracts';
import type { DecryptedItemMeta } from '../src/e2ee-model.ts';

function item(overrides: Partial<DecryptedItemMeta> = {}): DecryptedItemMeta {
  return {
    id: 'i-1',
    vaultId: 'v-1',
    kind: 'login',
    title: '条目',
    username: 'user',
    origin: 'https://a.example.test',
    tags: [],
    favorite: false,
    sensitivity: 'medium',
    secretState: 'present',
    version: 1,
    secretVersion: 1,
    createdAt: '2026-07-16T00:00:00.000Z',
    updatedAt: '2026-07-16T00:00:00.000Z',
    updatedBy: 'u-1',
    ...overrides,
  };
}

function vault(overrides: Partial<Vault> = {}): Vault {
  return {
    id: 'v-1',
    kind: 'team',
    name: 'T',
    ownerUserId: null,
    createdAt: '2026-07-16T00:00:00.000Z',
    updatedAt: '2026-07-16T00:00:00.000Z',
    ...overrides,
  };
}

/** 多数事件回放测试的前置：库 v-1 已在本地缓存（item.upserted 只接受已知库的条目）。 */
function bootstrapVault(store: MetaStore, items: ItemMeta[] = []): void {
  store.getState().applyBootstrap({
    user: {
      id: 'u-1', username: 'a', displayName: 'A', email: 'a@example.test',
      groups: [], isPlatformAdmin: false,
    },
    vaults: [vault()],
    memberships: [],
    items,
    cursor: 0,
  });
}

describe('SecretLeaseStore', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('默认 60 秒后自动销毁', () => {
    const store = new SecretLeaseStore();
    store.grant('i-1', 1);
    expect(store.get('i-1', 1)).toMatchObject({ itemId: 'i-1', secretVersion: 1 });
    expect(store.get('i-1', 1)).not.toHaveProperty('value');
    vi.advanceTimersByTime(59_000);
    expect(store.get('i-1', 1)).not.toBeNull();
    vi.advanceTimersByTime(1_100);
    expect(store.get('i-1', 1)).toBeNull();
  });

  it('revoke / revokeAll 立即清空并通知订阅者', () => {
    const store = new SecretLeaseStore();
    const events: string[] = [];
    store.subscribe((id) => events.push(id));
    store.grant('i-1', 1);
    store.grant('i-2', 1);
    store.revoke('i-1');
    expect(store.get('i-1', 1)).toBeNull();
    store.revokeAll();
    expect(store.get('i-2', 1)).toBeNull();
    expect(events).toContain('i-1');
    expect(events).toContain('i-2');
  });

  it('历史版本租约独立存放；revoke(itemId) 连同历史版本一起销毁', () => {
    const store = new SecretLeaseStore();
    store.grant('i-1', 3);
    store.grant('i-1', 1);
    expect(store.get('i-1', 3)).not.toBeNull();
    expect(store.get('i-1', 1)).not.toBeNull();
    // 条目切换：全部相关敏感内容（含历史版本）立即清除
    store.revoke('i-1');
    expect(store.get('i-1', 3)).toBeNull();
    expect(store.get('i-1', 1)).toBeNull();
  });

  it('revokeIfStale 只销毁版本不一致的租约', () => {
    const store = new SecretLeaseStore();
    store.grant('i-1', 2);
    store.revokeIfStale('i-1', 2);
    expect(store.get('i-1', 2)).not.toBeNull();
    store.revokeIfStale('i-1', 3);
    expect(store.get('i-1', 2)).toBeNull();
  });
});

describe('MetaStore 事件回放', () => {
  it('item.upserted 覆盖旧版本并触发 onItemStale', () => {
    const stale: string[] = [];
    const store = createMetaStore({ onItemStale: (id) => stale.push(id) });
    bootstrapVault(store);
    store.getState().applyEvent({ type: 'item.upserted', cursor: 1, item: item() });
    store.getState().applyEvent({ type: 'item.upserted', cursor: 2, item: item({ version: 2, title: '新标题' }) });
    expect(store.getState().items['i-1']?.title).toBe('新标题');
    expect(store.getState().cursor).toBe(2);
    expect(stale).toEqual(['i-1']);
  });

  it('过期事件（版本更低）不覆盖本地状态', () => {
    const store = createMetaStore();
    bootstrapVault(store);
    store.getState().applyEvent({ type: 'item.upserted', cursor: 5, item: item({ version: 3, title: '本地新' }) });
    store.getState().applyEvent({ type: 'item.upserted', cursor: 6, item: item({ version: 2, title: '旧' }) });
    expect(store.getState().items['i-1']?.title).toBe('本地新');
  });

  it('vault.revoked 丢弃库与条目并回调销毁租约', () => {
    const revoked: string[][] = [];
    const store = createMetaStore({ onVaultRevoked: (ids) => revoked.push(ids) });
    store.getState().applyBootstrap({
      user: {
        id: 'u-1', username: 'a', displayName: 'A', email: 'a@example.test',
        groups: [], isPlatformAdmin: false,
      },
      vaults: [{
        id: 'v-1', kind: 'team', name: 'T', ownerUserId: null,
        createdAt: '2026-07-16T00:00:00.000Z', updatedAt: '2026-07-16T00:00:00.000Z',
      }],
      memberships: [],
      items: [item()],
      cursor: 1,
    });
    store.getState().applyEvent({ type: 'vault.revoked', cursor: 2, vaultId: 'v-1' });
    expect(store.getState().vaults['v-1']).toBeUndefined();
    expect(store.getState().items['i-1']).toBeUndefined();
    expect(revoked).toEqual([['i-1']]);
    expect(store.getState().lastRevokedVaultId).toBe('v-1');
  });

  it('item.deleted 移除条目并销毁租约', () => {
    const stale: string[] = [];
    const store = createMetaStore({ onItemStale: (id) => stale.push(id) });
    bootstrapVault(store);
    store.getState().applyEvent({ type: 'item.upserted', cursor: 1, item: item() });
    store.getState().applyEvent({ type: 'item.deleted', cursor: 2, vaultId: 'v-1', itemId: 'i-1' });
    expect(store.getState().items['i-1']).toBeUndefined();
    expect(stale).toContain('i-1');
  });
});

describe('MetaStore 加固回归', () => {
  const bootstrapWith = (memberships: import('@mima/contracts').Membership[]) => ({
    user: {
      id: 'u-1', username: 'a', displayName: 'A', email: 'a@example.test',
      groups: ['group:default/qa'], isPlatformAdmin: false,
    },
    vaults: [{
      id: 'v-1', kind: 'team' as const, name: 'T', ownerUserId: null,
      createdAt: '2026-07-16T00:00:00.000Z', updatedAt: '2026-07-16T00:00:00.000Z',
    }],
    memberships,
    items: [item()],
    cursor: 1,
  });

  it('角色降为 auditor（vault.upserted）时销毁该库全部租约', () => {
    const stale: string[] = [];
    const store = createMetaStore({ onItemStale: (id) => stale.push(id) });
    store.getState().applyBootstrap(bootstrapWith([{
      id: 'm-1', vaultId: 'v-1', subjectKind: 'group', subjectId: 'group:default/qa',
      role: 'viewer', createdAt: '2026-07-16T00:00:00.000Z',
    }]));
    // 直接角色被设为 auditor：无条件覆盖组 viewer
    store.getState().applyEvent({
      type: 'vault.upserted',
      cursor: 2,
      vault: store.getState().vaults['v-1']!,
      memberships: [
        { id: 'm-1', vaultId: 'v-1', subjectKind: 'group', subjectId: 'group:default/qa', role: 'viewer', createdAt: '2026-07-16T00:00:00.000Z' },
        { id: 'm-2', vaultId: 'v-1', subjectKind: 'user', subjectId: 'u-1', role: 'auditor', createdAt: '2026-07-16T00:00:00.000Z' },
      ],
    });
    expect(stale).toContain('i-1');
  });

  it('sync.cursor / sync.ready 只推进游标，不动仍有权限的数据', () => {
    const store = createMetaStore();
    bootstrapVault(store);
    store.getState().applyEvent({ type: 'item.upserted', cursor: 1, item: item() });
    store.getState().applyEvent({ type: 'sync.cursor', cursor: 7 });
    expect(store.getState().cursor).toBe(7);
    expect(store.getState().items['i-1']).toBeDefined();
    store.getState().applyEvent({ type: 'sync.ready', cursor: 9, vaultIds: ['v-1'] });
    expect(store.getState().cursor).toBe(9);
    expect(store.getState().items['i-1']).toBeDefined();
  });

  it('rollbackItem 恢复非 409 写失败前的快照并清除 pending', () => {
    const store = createMetaStore();
    bootstrapVault(store);
    const before = item({ title: '原标题' });
    store.getState().applyEvent({ type: 'item.upserted', cursor: 1, item: before });
    store.getState().upsertItemOptimistic(item({ title: '乐观标题' }));
    expect(store.getState().items['i-1']?.title).toBe('乐观标题');
    expect(store.getState().pendingItemIds['i-1']).toBe(true);
    store.getState().rollbackItem(before);
    expect(store.getState().items['i-1']?.title).toBe('原标题');
    expect(store.getState().pendingItemIds['i-1']).toBeUndefined();
  });

  it('refresh keeps retained conflicts for accessible items and drops stale ones', () => {
    const store = createMetaStore();
    const bootstrap = {
      ...bootstrapWith([]),
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    };
    store.getState().applyDecryptedBootstrap(bootstrap);
    store.getState().setConflict({
      itemId: 'i-1',
      currentVersion: 2,
      commandId: 'conflicting-command',
      candidateKind: 'item.update',
      candidateCreatedAt: '2026-07-19T00:30:00.000Z',
    }, 'i-1');

    store.getState().applyDecryptedBootstrap({ ...bootstrap, items: [item({ version: 2 })] });
    expect(store.getState().conflicts['i-1']?.commandId).toBe('conflicting-command');

    store.getState().applyDecryptedBootstrap({ ...bootstrap, items: [] });
    expect(store.getState().conflicts['i-1']).toBeUndefined();
  });
});

describe('S1 晚到响应不得恢复已清除的敏感内容（安全代际）', () => {
  it('revokeAll（锁定/离线/退出/401）后，晚到的 grantIfCurrent 被拒绝', () => {
    const store = new SecretLeaseStore();
    const epoch = store.epoch('i-1');
    store.revokeAll();
    expect(store.grantIfCurrent('i-1', 1, epoch)).toBe(false);
    expect(store.get('i-1', 1)).toBeNull();
  });

  it('revoke(itemId)（条目切换/撤权/降级）即使没有租约也推进代际', () => {
    const store = new SecretLeaseStore();
    const epoch = store.epoch('i-1');
    store.revoke('i-1'); // 此刻没有任何租约——在途 Reveal 仍必须失效
    expect(store.isEpochCurrent('i-1', epoch)).toBe(false);
    expect(store.grantIfCurrent('i-1', 1, epoch)).toBe(false);
    // 其他条目的代际不受影响
    expect(store.isEpochCurrent('i-2', store.epoch('i-2'))).toBe(true);
  });

  it('代际未变时 grantIfCurrent 正常写入', () => {
    const store = new SecretLeaseStore();
    const epoch = store.epoch('i-1');
    expect(store.grantIfCurrent('i-1', 1, epoch)).toBe(true);
    expect(store.get('i-1', 1)).toMatchObject({ itemId: 'i-1', secretVersion: 1 });
    expect(store.get('i-1', 1)).not.toHaveProperty('value');
  });

  it('VaultActions.reveal：请求期间锁定 → 抛 StaleRevealError 且不入租约', async () => {
    const store = createMetaStore();
    bootstrapVault(store, [item()]);
    store.getState().setConnection('online');
    const leases = new SecretLeaseStore();
    const outbox = new CommandOutbox(store);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const api = {
      reveal: async () => {
        await gate;
        return { itemId: 'i-1', secretVersion: 1, value: 'late-secret' };
      },
    } as unknown as ApiClient;
    const actions = new VaultActions(api, store, leases, outbox);
    const pending = actions.reveal('i-1', 'view');
    leases.revokeAll(); // 请求在途时锁定
    release();
    await expect(pending).rejects.toBeInstanceOf(StaleRevealError);
    expect(leases.get('i-1', 1)).toBeNull();
  });

  it('VaultActions.revealForCopy：不授予展示租约（复制不上屏）', async () => {
    const store = createMetaStore();
    bootstrapVault(store, [item()]);
    store.getState().setConnection('online');
    const leases = new SecretLeaseStore();
    const api = {
      reveal: async () => ({ itemId: 'i-1', secretVersion: 1, value: 'copy-secret' }),
    } as unknown as ApiClient;
    const actions = new VaultActions(api, store, leases, new CommandOutbox(store));
    const value = await actions.revealForCopy('i-1');
    expect(value === 'copy-secret').toBe(true);
    // 界面租约不存在：SecretField 不会因复制而显示密码或 Token
    expect(leases.get('i-1', 1)).toBeNull();
  });
});

describe('S2 sync.ready 权威 vault 列表', () => {
  it('清除离线期间被撤权/删除的库、成员表与条目，并回调销毁租约', () => {
    const revoked: string[][] = [];
    const store = createMetaStore({ onVaultRevoked: (ids) => revoked.push(ids) });
    store.getState().applyBootstrap({
      user: {
        id: 'u-1', username: 'a', displayName: 'A', email: 'a@example.test',
        groups: [], isPlatformAdmin: false,
      },
      vaults: [vault(), vault({ id: 'v-2', name: 'T2' })],
      memberships: [],
      items: [item(), item({ id: 'i-2', vaultId: 'v-2' })],
      cursor: 1,
    });
    // 重连后 ready：权威列表只剩 v-1（v-2 在离线期间被撤权/删除）
    store.getState().applyEvent({ type: 'sync.ready', cursor: 10, vaultIds: ['v-1'] });
    expect(store.getState().vaults['v-2']).toBeUndefined();
    expect(store.getState().items['i-2']).toBeUndefined();
    expect(store.getState().vaults['v-1']).toBeDefined();
    expect(store.getState().items['i-1']).toBeDefined();
    expect(revoked).toEqual([['i-2']]);
    expect(store.getState().lastRevokedVaultId).toBe('v-2');
  });
});

describe('S3 回滚不得恢复越权数据', () => {
  it('库已被撤销：晚到的 item.upserted 确认被拒收', () => {
    const store = createMetaStore();
    bootstrapVault(store, [item()]);
    store.getState().applyEvent({ type: 'vault.revoked', cursor: 2, vaultId: 'v-1' });
    // 在途命令确认此刻返回：不得让条目在无权状态下"复活"
    store.getState().applyEvent({ type: 'item.upserted', cursor: 3, item: item({ version: 2 }) });
    expect(store.getState().items['i-1']).toBeUndefined();
    expect(store.getState().cursor).toBe(3);
  });

  it('rollbackItem：条目已删除 / 已有更新版本 / 库已撤销时不恢复快照', () => {
    const store = createMetaStore();
    bootstrapVault(store);
    const before = item({ title: '原', version: 2 });
    // 条目已删除：不恢复
    store.getState().rollbackItem(before);
    expect(store.getState().items['i-1']).toBeUndefined();
    // 已有更新的权威版本：不用旧快照覆盖
    store.getState().applyEvent({ type: 'item.upserted', cursor: 1, item: item({ title: '权威新版', version: 5 }) });
    store.getState().rollbackItem(before);
    expect(store.getState().items['i-1']?.title).toBe('权威新版');
    // 库被撤销后：整库连同条目已清空，回滚不得重建
    store.getState().applyEvent({ type: 'vault.revoked', cursor: 2, vaultId: 'v-1' });
    store.getState().rollbackItem(before);
    expect(store.getState().items['i-1']).toBeUndefined();
  });

  it('reset() 推进登录代际；Outbox.clear() 使在途命令失效', async () => {
    const store = createMetaStore();
    const epochBefore = store.getState().epoch;
    store.getState().reset();
    expect(store.getState().epoch).toBe(epochBefore + 1);

    // 在途命令执行中调用 clear()：完成后不得再动队列（不误删 clear 后入队的新命令）
    store.getState().setConnection('online');
    const outbox = new CommandOutbox(store);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let dropped = false;
    outbox.enqueue({
      id: 'cmd-1',
      label: '在途命令',
      execute: async () => { await gate; },
      onDrop: () => { dropped = true; },
    });
    outbox.clear();
    expect(outbox.size).toBe(0);
    let laterRan = false;
    outbox.enqueue({ id: 'cmd-2', label: '新命令', execute: async () => { laterRan = true; } });
    release();
    await new Promise((r) => setTimeout(r, 10));
    expect(dropped).toBe(false);
    expect(laterRan).toBe(true);
    expect(outbox.size).toBe(0);
  });

  it('VaultActions：401 重置后，在途 updateItemMeta 的确认不写回状态', async () => {
    const store = createMetaStore();
    bootstrapVault(store, [item()]);
    store.getState().setConnection('online');
    const leases = new SecretLeaseStore();
    const outbox = new CommandOutbox(store);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const api = {
      updateItemMeta: async () => {
        await gate;
        return item({ title: '晚到确认', version: 2 });
      },
    } as unknown as ApiClient;
    const actions = new VaultActions(api, store, leases, outbox);
    actions.updateItemMeta('i-1', { title: '修改' });
    // 请求在途：会话失效（401 处理路径）
    outbox.clear();
    store.getState().reset();
    release();
    await new Promise((r) => setTimeout(r, 10));
    // reset 清空了一切；晚到确认不得把旧条目写回
    expect(store.getState().items['i-1']).toBeUndefined();
    expect(Object.keys(store.getState().items)).toHaveLength(0);
  });
});
