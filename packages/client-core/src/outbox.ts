import type { MetaStore } from './meta-store.ts';

export interface OutboxCommand {
  /** 同时作为 idempotencyKey，重试安全。 */
  id: string;
  label: string;
  itemId?: string;
  execute: () => Promise<void>;
  /** 网络失败重试；业务失败（409 等）由 execute 内部处理后正常返回。 */
  onDrop?: (err: unknown) => void;
}

/**
 * 命令 Outbox：串行执行写命令。
 * 离线时命令保留在内存队列（不持久化），恢复在线后按序冲刷。
 * 携带密码或 Token 内容的命令不允许进入队列（离线时由 UI 保留草稿并提示“尚未保存”）。
 * clear() 推进代际：正在执行中的命令随之失效——其完成/失败回调不再触碰队列，
 * 命令闭包内部另有登录代际（MetaStore.epoch）守卫，晚到响应不会写回状态。
 */
export class CommandOutbox {
  private queue: OutboxCommand[] = [];
  private running = false;
  private generation = 0;
  private listeners = new Set<() => void>();

  constructor(private store: MetaStore) {}

  get size(): number {
    return this.queue.length;
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    for (const l of this.listeners) l();
  }

  enqueue(cmd: OutboxCommand): void {
    this.queue.push(cmd);
    this.notify();
    void this.flush();
  }

  /** 连接恢复时调用。 */
  async flush(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      while (this.queue.length > 0) {
        if (this.store.getState().connection !== 'online') return;
        const gen = this.generation;
        const cmd = this.queue[0]!;
        try {
          await cmd.execute();
          if (gen !== this.generation) continue; // 执行期间被 clear()：旧命令已不在队列，直接处理新队列
          this.queue.shift();
          this.notify();
        } catch (err) {
          if (gen !== this.generation) continue; // 已失效的在途命令：不重试也不触发回滚
          const status = (err as { status?: number }).status;
          if (status === 0) {
            // 网络故障：保留队列，等待重连后重试（幂等键保证不重复执行）
            this.store.getState().setConnection('offline');
            return;
          }
          this.queue.shift();
          this.notify();
          cmd.onDrop?.(err);
        }
      }
    } finally {
      this.running = false;
    }
  }

  /** 退出/401/会话失效时调用：清空队列并使在途命令失效。 */
  clear(): void {
    this.generation += 1;
    this.queue = [];
    this.notify();
  }
}
