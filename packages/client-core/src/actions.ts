import type { ItemMetaPatch, RevealPurpose, RevealResponse } from '@mima/contracts';
import { ApiRequestError, type ApiClient } from './api-client.ts';
import type { MetaStore } from './meta-store.ts';
import type { SecretLeaseStore } from './secret-lease.ts';
import type { CommandOutbox } from './outbox.ts';
import type { ZeroKnowledgeClient } from './zero-knowledge-client.ts';
import { itemPayload } from './e2ee-model.ts';

/** 晚到的 Reveal 响应：发起后发生了锁定/离线/退出/撤权/条目切换等销毁事件，结果被丢弃。 */
export class StaleRevealError extends Error {
  constructor() {
    super('状态已变化，本次读取结果已被丢弃');
  }
}

/**
 * 高层写操作编排：本地乐观状态 + 命令 Outbox + 服务端确认 + 事件回放。
 * - 元数据修改：乐观应用 → 入队 → 确认后以服务端版本覆盖；409 记录冲突，绝不自动合并。
 * - 携带密码或 Token 内容的操作（创建/换密）：仅在线执行，离线抛错由 UI 保留草稿。
 * - 安全代际：每个异步操作在发起时捕获租约代际（leases.epoch）与登录代际
 *   （store.epoch），响应返回后先比对再写入，晚到响应不得恢复已清除的内容或旧元数据。
 */
export class VaultActions {
  constructor(
    private api: ApiClient,
    private store: MetaStore,
    private leases: SecretLeaseStore,
    private outbox: CommandOutbox,
    /** 写失败等需要用户感知的提示（UI 注入 Toast 等）。 */
    private notifyError?: (message: string) => void,
    private zeroKnowledge?: ZeroKnowledgeClient,
  ) {}

  private requireOnline(): void {
    if (this.store.getState().connection !== 'online') {
      throw new ApiRequestError(0, { message: '当前离线，无法执行该操作' });
    }
  }

  private loginEpoch(): number {
    return this.store.getState().epoch;
  }

  private loginEpochIs(epoch: number): boolean {
    return this.store.getState().epoch === epoch;
  }

  /**
   * @param baseVersion 编辑起点版本（打开编辑器时捕获）。缺省用当前版本。
   * 服务端以 expectedVersion 做乐观并发控制，过期返回 409。
   */
  updateItemMeta(itemId: string, patch: ItemMetaPatch, baseVersion?: number): void {
    const state = this.store.getState();
    const item = state.items[itemId];
    if (!item) return;
    if (this.zeroKnowledge) {
      const payload = { ...itemPayload(item), ...normalizePatch(patch) };
      void this.zeroKnowledge.updateItem(item, payload).catch((error) => {
        this.notifyError?.(error instanceof Error ? error.message : '保存失败');
      });
      return;
    }
    const expectedVersion = baseVersion ?? item.version;
    const idempotencyKey = crypto.randomUUID();
    const epoch = this.loginEpoch();
    // 乐观应用前捕获快照，供非 409 失败时回滚（不显示伪成功）
    const before = item;
    state.upsertItemOptimistic({ ...item, ...normalizePatch(patch) });
    this.outbox.enqueue({
      id: idempotencyKey,
      label: `更新 ${item.title}`,
      itemId,
      execute: async () => {
        if (!this.loginEpochIs(epoch)) return; // 会话已换代（退出/401）：命令作废
        const updated = await this.api.updateItemMeta(itemId, {
          idempotencyKey,
          expectedVersion,
          patch,
        });
        if (!this.loginEpochIs(epoch)) return; // 晚到确认：不得写回已重置的状态
        const s = this.store.getState();
        s.applyEvent({ type: 'item.upserted', cursor: s.cursor, item: updated });
        s.markPending(itemId, false);
      },
      onDrop: (err) => this.handleWriteError(itemId, err, before, epoch),
    });
  }

  async createItem(
    vaultId: string,
    input: {
      kind: 'login' | 'api_token' | 'secure_note';
      title: string;
      username: string | null;
      origin: string | null;
      loginUrl?: string | null;
      folderPath?: string | null;
      description?: string | null;
      linkedLoginItemId?: string | null;
      tags: string[];
      favorite: boolean;
      sensitivity: 'low' | 'medium' | 'high';
      secretValue: string;
    },
  ): Promise<string> {
    if (this.zeroKnowledge) return this.zeroKnowledge.createItem(vaultId, input);
    this.requireOnline();
    const epoch = this.loginEpoch();
    const created = await this.api.createItem(vaultId, {
      idempotencyKey: crypto.randomUUID(),
      ...input,
    });
    if (this.loginEpochIs(epoch)) {
      const s = this.store.getState();
      s.applyEvent({ type: 'item.upserted', cursor: s.cursor, item: created });
    }
    return created.id;
  }

  async rotateSecret(itemId: string, secretValue: string, baseVersion?: number): Promise<void> {
    const item = this.store.getState().items[itemId];
    if (!item) throw new Error('条目不存在');
    if (this.zeroKnowledge) return this.zeroKnowledge.rotateItem(item, secretValue);
    this.requireOnline();
    const epoch = this.loginEpoch();
    try {
      const updated = await this.api.rotateSecret(itemId, {
        idempotencyKey: crypto.randomUUID(),
        expectedVersion: baseVersion ?? item.version,
        secretValue,
      });
      this.leases.revoke(itemId);
      if (!this.loginEpochIs(epoch)) return;
      const s = this.store.getState();
      s.applyEvent({ type: 'item.upserted', cursor: s.cursor, item: updated });
    } catch (err) {
      this.handleWriteError(itemId, err, undefined, epoch);
      throw err;
    }
  }

  deleteItem(itemId: string): void {
    const state = this.store.getState();
    const item = state.items[itemId];
    if (!item) return;
    if (this.zeroKnowledge) {
      void this.zeroKnowledge.deleteItem(item).catch((error) => {
        this.notifyError?.(error instanceof Error ? error.message : '删除失败');
      });
      return;
    }
    const expectedVersion = item.version;
    const idempotencyKey = crypto.randomUUID();
    const epoch = this.loginEpoch();
    state.markPending(itemId, true);
    this.leases.revoke(itemId);
    this.outbox.enqueue({
      id: idempotencyKey,
      label: `删除 ${item.title}`,
      itemId,
      execute: async () => {
        if (!this.loginEpochIs(epoch)) return;
        await this.api.deleteItem(itemId, { idempotencyKey, expectedVersion });
        if (!this.loginEpochIs(epoch)) return;
        const s = this.store.getState();
        s.applyEvent({ type: 'item.deleted', cursor: s.cursor, vaultId: item.vaultId, itemId });
      },
      onDrop: (err) => this.handleWriteError(itemId, err, undefined, epoch),
    });
  }

  /**
   * 读取敏感内容并登记不含正文的展示 Lease（含历史版本）。
   * 发起前捕获租约代际，响应经 grantIfCurrent 登记：期间发生锁定/离线/退出/401/
   * 撤权/降级/条目切换任一销毁事件，晚到响应被丢弃并抛出 StaleRevealError。
   */
  async reveal(itemId: string, purpose: RevealPurpose, secretVersion?: number): Promise<RevealResponse> {
    if (this.store.getState().locked) {
      throw new ApiRequestError(403, { message: '工作台已锁定' });
    }
    const epoch = this.leases.epoch(itemId);
    const res = this.zeroKnowledge
      ? await this.zeroKnowledge.reveal(itemId, purpose, secretVersion)
      : (this.requireOnline(), await this.api.reveal(itemId, purpose, secretVersion));
    if (!this.leases.grantIfCurrent(itemId, res.secretVersion, epoch)) {
      throw new StaleRevealError();
    }
    return res;
  }

  /**
   * 复制专用读取：完成服务端审计（purpose=copy）后返回值，但**不**授予展示租约。
   * 复制不应顺带在界面显示密码或 Token。晚到响应同样按代际丢弃。
   * 返回值仅供调用方立即写入剪贴板，用后即弃。
   */
  async revealForCopy(itemId: string): Promise<string> {
    if (this.store.getState().locked) {
      throw new ApiRequestError(403, { message: '工作台已锁定' });
    }
    const epoch = this.leases.epoch(itemId);
    const res = this.zeroKnowledge
      ? await this.zeroKnowledge.reveal(itemId, 'copy')
      : (this.requireOnline(), await this.api.reveal(itemId, 'copy'));
    if (!this.leases.isEpochCurrent(itemId, epoch)) {
      throw new StaleRevealError();
    }
    return res.value;
  }

  private handleWriteError(
    itemId: string,
    err: unknown,
    before?: import('@mima/contracts').ItemMeta,
    epoch?: number,
  ): void {
    // 登录代际已变（退出/401 后才失败的在途命令）：状态已整体清空，什么都不做
    if (epoch !== undefined && !this.loginEpochIs(epoch)) return;
    const s = this.store.getState();
    s.markPending(itemId, false);
    if (err instanceof ApiRequestError && err.status === 409) {
      this.leases.revoke(itemId);
      s.setConflict(
        {
          itemId,
          currentVersion: err.body.currentVersion ?? 0,
          currentItem: err.body.currentItem,
        },
        itemId,
      );
      // 服务端当前版本立即回放，本地不保留过期乐观状态
      if (err.body.currentItem) {
        s.applyEvent({ type: 'item.upserted', cursor: s.cursor, item: err.body.currentItem });
      }
      return;
    }
    // 非 409 失败：回滚乐观状态（rollbackItem 自带校验：条目/库仍存在且无更新版本）
    if (before) s.rollbackItem(before);
    const message = err instanceof ApiRequestError ? err.message : '写入失败';
    this.notifyError?.(`保存失败，已还原本地修改：${message}`);
  }

  /** 冲突确认：采用服务端版本。 */
  resolveConflict(itemId: string): void {
    this.store.getState().setConflict(null, itemId);
  }

  /** 锁定会话：立即清空全部租约。 */
  async lock(): Promise<void> {
    if (this.zeroKnowledge) return this.zeroKnowledge.lock();
    this.leases.revokeAll();
    this.store.getState().setLocked(true);
    await this.api.lock();
  }

  async unlock(password: string): Promise<void> {
    if (this.zeroKnowledge) return this.zeroKnowledge.unlock(password);
    await this.api.unlock(password);
    this.store.getState().setLocked(false);
  }

  /** 退出登录：清空租约与全部内存状态。 */
  async logout(): Promise<void> {
    if (this.zeroKnowledge) return this.zeroKnowledge.logout();
    this.leases.revokeAll();
    this.outbox.clear();
    try {
      await this.api.logout();
    } finally {
      this.store.getState().reset();
    }
  }
}

function normalizePatch(patch: ItemMetaPatch): Partial<import('@mima/contracts').ItemMeta> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(patch)) {
    if (v !== undefined) out[k] = v;
  }
  return out;
}
