import { EncryptedSyncEventSchema, type EncryptedSyncEvent } from '@mima/contracts';

export interface EncryptedSyncClientOptions {
  baseUrl?: string;
  getCursor: () => number;
  onEvent: (event: EncryptedSyncEvent) => Promise<void>;
}

export class EncryptedSyncClient {
  private baseUrl: string;
  private getCursor: () => number;
  private onEvent: (event: EncryptedSyncEvent) => Promise<void>;
  private abortController: AbortController | null = null;
  private stopped = true;
  private generation = 0;
  private readyCallbacks = new Set<() => void>();
  private unauthorizedCallbacks = new Set<() => void>();

  constructor(options: EncryptedSyncClientOptions) {
    this.baseUrl = options.baseUrl ?? '';
    this.getCursor = options.getCursor;
    this.onEvent = options.onEvent;
  }

  onReady(callback: () => void): () => void {
    this.readyCallbacks.add(callback);
    return () => this.readyCallbacks.delete(callback);
  }

  onUnauthorized(callback: () => void): () => void {
    this.unauthorizedCallbacks.add(callback);
    return () => this.unauthorizedCallbacks.delete(callback);
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    const generation = ++this.generation;
    void this.loop(generation);
  }

  stop(): void {
    this.stopped = true;
    this.generation += 1;
    this.abortController?.abort();
    this.abortController = null;
  }

  private async loop(generation: number): Promise<void> {
    let backoffMs = 500;
    while (!this.stopped && generation === this.generation) {
      try {
        this.abortController = new AbortController();
        const response = await fetch(`${this.baseUrl}/api/v2/events?cursor=${this.getCursor()}`, {
          credentials: 'include',
          headers: { accept: 'text/event-stream' },
          signal: this.abortController.signal,
        });
        if (response.status === 401) {
          this.stopped = true;
          this.unauthorizedCallbacks.forEach((callback) => callback());
          return;
        }
        if (!response.ok || !response.body) throw new Error(`SSE HTTP ${response.status}`);
        backoffMs = 500;
        await this.consume(response.body, generation);
        if (!this.stopped && generation === this.generation) throw new Error('stream ended');
      } catch {
        if (this.stopped || generation !== this.generation) return;
        await sleep(backoffMs);
        if (this.stopped || generation !== this.generation) return;
        backoffMs = Math.min(backoffMs * 2, 15_000);
      }
    }
  }

  private async consume(body: ReadableStream<Uint8Array>, generation: number): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true }).replaceAll('\r\n', '\n');
      let separator: number;
      while ((separator = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, separator);
        buffer = buffer.slice(separator + 2);
        await this.handleFrame(frame);
        if (this.stopped || generation !== this.generation) return;
      }
    }
  }

  private async handleFrame(frame: string): Promise<void> {
    const data = frame
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .join('\n');
    if (!data) return;
    const event = EncryptedSyncEventSchema.parse(JSON.parse(data));
    await this.onEvent(event);
    if (event.type === 'sync.ready') this.readyCallbacks.forEach((callback) => callback());
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
