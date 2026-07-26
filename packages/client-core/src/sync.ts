import { SyncEventSchema } from '@mima/contracts';
import type { MetaStore } from './meta-store.ts';

/**
 * fetch-based SSE 客户端：携带 Cookie，按 cursor 断点续传，指数退避重连。
 * 收到服务端 `sync.ready`（backlog 回放完毕）之后才标记在线并触发 onOnline
 * （冲刷 Outbox）——避免在补齐历史事件之前基于过期状态发写命令。
 * 事件只包含元数据；应用事件时由 MetaStore 的 hooks 负责销毁过期 Secret Lease。
 */
export class SyncClient {
  private abortController: AbortController | null = null;
  private stopped = true;
  private onlineCallbacks = new Set<() => void>();
  private unauthorizedCallbacks = new Set<() => void>();

  constructor(
    private store: MetaStore,
    private baseUrl = '',
  ) {}

  /** 连接完成 backlog 回放（sync.ready）进入 online 时回调（用于冲刷 Outbox）。 */
  onOnline(cb: () => void): () => void {
    this.onlineCallbacks.add(cb);
    return () => this.onlineCallbacks.delete(cb);
  }

  /** SSE 返回 401（会话过期/被撤销）时回调：上层清空敏感内容并回登录页。 */
  onUnauthorized(cb: () => void): () => void {
    this.unauthorizedCallbacks.add(cb);
    return () => this.unauthorizedCallbacks.delete(cb);
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    void this.loop();
  }

  stop(): void {
    this.stopped = true;
    this.abortController?.abort();
    this.abortController = null;
  }

  private async loop(): Promise<void> {
    let backoffMs = 500;
    while (!this.stopped) {
      try {
        this.abortController = new AbortController();
        const cursor = this.store.getState().cursor;
        const res = await fetch(`${this.baseUrl}/api/events?cursor=${cursor}`, {
          credentials: 'include',
          headers: { accept: 'text/event-stream' },
          signal: this.abortController.signal,
        });
        if (res.status === 401) {
          // 会话失效：停止重连，通知上层清空敏感内容并跳转登录
          this.stopped = true;
          this.store.getState().setConnection('offline');
          for (const cb of this.unauthorizedCallbacks) cb();
          return;
        }
        if (!res.ok || !res.body) throw new Error(`SSE HTTP ${res.status}`);
        backoffMs = 500;
        await this.consume(res.body);
        throw new Error('stream ended');
      } catch {
        if (this.stopped) return;
        this.store.getState().setConnection('offline');
        await sleep(backoffMs);
        if (this.stopped) return;
        backoffMs = Math.min(backoffMs * 2, 15_000);
        this.store.getState().setConnection('connecting');
      }
    }
  }

  private async consume(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      let sep: number;
      while ((sep = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        this.handleFrame(frame);
      }
    }
  }

  private handleFrame(frame: string): void {
    const dataLines = frame
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim());
    if (dataLines.length === 0) return; // 注释/ping 帧
    try {
      const parsed = SyncEventSchema.parse(JSON.parse(dataLines.join('\n')));
      this.store.getState().applyEvent(parsed);
      if (parsed.type === 'sync.ready') {
        this.store.getState().setConnection('online');
        for (const cb of this.onlineCallbacks) cb();
      }
    } catch {
      console.warn('[sync] 丢弃无法解析的事件帧');
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
