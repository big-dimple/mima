import { EventEmitter } from 'node:events';

/** 服务端内部同步事件行（与 sync_events 表一致，不含敏感内容明文）。 */
export interface SyncEventRow {
  id: number;
  type:
    | 'item.upserted'
    | 'item.encrypted_upserted'
    | 'item.deleted'
    | 'vault.upserted'
    | 'vault.deleted'
    | 'vault.crypto_changed'
    | 'vault.rekey_required'
    | 'crypto.profile_rewrapped'
    | 'device.revoked';
  vaultId: string;
  itemId: string | null;
  payload: Record<string, unknown>;
}

export class SyncBus {
  private emitter = new EventEmitter();

  constructor() {
    this.emitter.setMaxListeners(200);
  }

  publish(rows: SyncEventRow[]): void {
    for (const row of rows) this.emitter.emit('sync', row);
  }

  subscribe(listener: (row: SyncEventRow) => void): () => void {
    this.emitter.on('sync', listener);
    return () => this.emitter.off('sync', listener);
  }
}
