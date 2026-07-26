import type { RevealPurpose, RevealResponse } from '@mima/contracts';
import {
  itemPayload,
  type CreateItemInput,
  type DecryptedItemMetaPatch,
  type ItemMetadataPayload,
} from './e2ee-model.ts';
import type { MetaStore } from './meta-store.ts';
import type { SecretLeaseStore } from './secret-lease.ts';
import { StaleRevealError } from './actions.ts';
import type { ZeroKnowledgeClient } from './zero-knowledge-client.ts';

export class ZeroKnowledgeActions {
  constructor(
    private client: ZeroKnowledgeClient,
    private store: MetaStore,
    private leases: SecretLeaseStore,
    private notifyError?: (message: string) => void,
  ) {}

  async updateItemMeta(itemId: string, patch: DecryptedItemMetaPatch, baseVersion?: number): Promise<void> {
    const item = this.store.getState().items[itemId];
    if (!item) throw new Error('条目已不存在，请关闭编辑页后刷新');
    assertBaseVersion(item.version, baseVersion);
    const payload: ItemMetadataPayload = { ...itemPayload(item), ...normalizePatch(patch) };
    try {
      await this.client.updateItem(item, payload);
    } catch (error) {
      this.notifyError?.(error instanceof Error ? error.message : '保存失败');
      throw error;
    }
  }

  createItem(
    vaultId: string,
    input: CreateItemInput,
  ): Promise<string> {
    return this.client.createItem(vaultId, input);
  }

  async rotateSecret(itemId: string, secretValue: string, baseVersion?: number): Promise<void> {
    const item = this.store.getState().items[itemId];
    if (!item) throw new Error('条目不存在');
    if (secretValue.length === 0) throw new Error('请输入要保存的密码或敏感内容');
    assertBaseVersion(item.version, baseVersion);
    await this.client.rotateItem(item, secretValue);
  }

  deleteItem(itemId: string): void {
    const item = this.store.getState().items[itemId];
    if (!item) return;
    void this.client.deleteItem(item).catch((error) => {
      this.notifyError?.(error instanceof Error ? error.message : '删除失败');
    });
  }

  async reveal(itemId: string, purpose: RevealPurpose, secretVersion?: number): Promise<RevealResponse> {
    if (this.store.getState().locked) throw new Error('工作台已锁定');
    const epoch = this.leases.epoch(itemId);
    const response = await this.client.reveal(itemId, purpose, secretVersion);
    if (!this.leases.grantIfCurrent(itemId, response.secretVersion, epoch)) {
      throw new StaleRevealError();
    }
    return response;
  }

  async revealForCopy(itemId: string): Promise<string> {
    if (this.store.getState().locked) throw new Error('工作台已锁定');
    const epoch = this.leases.epoch(itemId);
    const response = await this.client.reveal(itemId, 'copy');
    if (!this.leases.isEpochCurrent(itemId, epoch)) throw new StaleRevealError();
    return response.value;
  }

  resolveConflict(itemId: string): void {
    this.store.getState().setConflict(null, itemId);
  }

  lock(): Promise<void> {
    return this.client.lock();
  }

  unlock(mainPassword: string): Promise<void> {
    return this.client.unlock(mainPassword);
  }

  logout(): Promise<void> {
    return this.client.logout();
  }
}

function normalizePatch(patch: DecryptedItemMetaPatch): Partial<ItemMetadataPayload> {
  const normalized: Partial<ItemMetadataPayload> = {};
  for (const [key, value] of Object.entries(patch)) {
    if (value !== undefined) Object.assign(normalized, { [key]: value });
  }
  return normalized;
}

function assertBaseVersion(currentVersion: number, baseVersion?: number): void {
  if (baseVersion !== undefined && currentVersion !== baseVersion) {
    throw new Error('这条记录刚刚有了新修改。系统已暂停保存，避免覆盖他人的内容。你的输入仍保留在本页；请先复制需要保留的部分，再取消编辑并查看最新内容');
  }
}
