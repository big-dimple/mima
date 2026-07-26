import type {
  EncryptedStorageBackend,
  PersistedEncryptedCommand,
} from './encrypted-storage.ts';

export interface EncryptedCommandApi {
  sendEncryptedCommand<T>(
    method: 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    path: string,
    body: unknown,
  ): Promise<T>;
}

export class EncryptedCommandOutbox {
  private accountId: string | null = null;
  private queue: PersistedEncryptedCommand[] = [];
  private flushing = false;
  private online = false;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryDelayMs = 500;
  private listeners = new Set<() => void>();
  private errorListeners = new Set<(error: unknown, command: PersistedEncryptedCommand) => void>();
  private conflictListeners = new Set<(command: PersistedEncryptedCommand) => void>();

  constructor(
    private api: EncryptedCommandApi,
    private storage: EncryptedStorageBackend,
  ) {}

  get size(): number {
    return this.queue.length;
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onError(listener: (error: unknown, command: PersistedEncryptedCommand) => void): () => void {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  onConflict(listener: (command: PersistedEncryptedCommand) => void): () => void {
    this.conflictListeners.add(listener);
    return () => this.conflictListeners.delete(listener);
  }

  replayConflicts(): void {
    this.notifyConflicts();
  }

  async restore(accountId: string): Promise<void> {
    this.accountId = accountId;
    this.queue = await this.storage.listCommands(accountId);
    this.notify();
    this.notifyConflicts();
    if (this.online) await this.flush();
  }

  setOnline(online: boolean): void {
    this.online = online;
    if (!online) {
      this.clearRetryTimer();
      return;
    }
    void this.flush();
  }

  async enqueue(command: PersistedEncryptedCommand): Promise<void> {
    if (!this.accountId || command.accountId !== this.accountId) {
      throw new Error('待同步命令与当前账号不匹配');
    }
    await this.storage.putCommand(command);
    this.queue.push(command);
    this.notify();
    if (this.online) await this.flush();
  }

  async retainConflict(command: PersistedEncryptedCommand, error: unknown): Promise<void> {
    if (!this.accountId || command.accountId !== this.accountId) {
      throw new Error('冲突命令与当前账号不匹配');
    }
    const conflicted = {
      ...command,
      conflict: {
        reason: conflictReason(error),
        currentVersion: conflictVersion(error),
        detectedAt: new Date().toISOString(),
      },
    };
    await this.storage.putCommand(conflicted);
    const index = this.queue.findIndex((candidate) => candidate.id === conflicted.id);
    if (index >= 0) this.queue[index] = conflicted;
    else this.queue.push(conflicted);
    this.conflictListeners.forEach((listener) => listener(conflicted));
    this.errorListeners.forEach((listener) => listener(error, conflicted));
    this.notify();
  }

  async discardConflict(commandId: string): Promise<number> {
    const conflict = this.queue.find((command) => command.id === commandId && command.conflict);
    if (!conflict) return 0;
    const itemId = encryptedCommandItemId(conflict);
    const discarded = this.queue.filter((command) =>
      itemId ? encryptedCommandItemId(command) === itemId : command.id === commandId);
    for (const command of discarded) await this.storage.deleteCommand(command.id);
    const discardedIds = new Set(discarded.map((command) => command.id));
    this.queue = this.queue.filter((command) => !discardedIds.has(command.id));
    this.notify();
    if (this.online) void this.flush();
    return discarded.length;
  }

  async flush(): Promise<void> {
    if (!this.online || this.flushing) return;
    this.flushing = true;
    try {
      while (this.online && this.queue.length > 0) {
        const command = this.nextSendableCommand();
        if (!command) {
          this.notifyConflicts();
          return;
        }
        try {
          await this.api.sendEncryptedCommand(command.method, command.path, command.body);
        } catch (error) {
          const status = (error as { status?: number }).status;
          if (status === 0 || status === 401) {
            this.online = false;
            return;
          }
          if (status === 409) {
            await this.retainConflict(command, error);
            continue;
          }
          if (!isPermanentCommandFailure(status)) {
            this.scheduleRetry();
            return;
          }
          this.removeCommand(command.id);
          await this.storage.deleteCommand(command.id);
          this.errorListeners.forEach((listener) => listener(error, command));
          this.notify();
          continue;
        }
        this.removeCommand(command.id);
        await this.storage.deleteCommand(command.id);
        this.retryDelayMs = 500;
        this.notify();
      }
    } finally {
      this.flushing = false;
    }
  }

  async clear(removePersistent = false): Promise<void> {
    const accountId = this.accountId;
    this.accountId = null;
    this.queue = [];
    this.online = false;
    this.clearRetryTimer();
    this.retryDelayMs = 500;
    this.notify();
    if (removePersistent && accountId) await this.storage.clearCommands(accountId);
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }

  private notifyConflicts(): void {
    this.queue.forEach((command) => {
      if (command.conflict) this.conflictListeners.forEach((listener) => listener(command));
    });
  }

  private nextSendableCommand(): PersistedEncryptedCommand | undefined {
    const conflictedItemIds = new Set(
      this.queue
        .filter((command) => command.conflict)
        .map(encryptedCommandItemId)
        .filter((itemId): itemId is string => itemId !== null),
    );
    return this.queue.find((command) => {
      if (command.conflict) return false;
      const itemId = encryptedCommandItemId(command);
      return itemId === null || !conflictedItemIds.has(itemId);
    });
  }

  private removeCommand(commandId: string): void {
    const index = this.queue.findIndex((command) => command.id === commandId);
    if (index >= 0) this.queue.splice(index, 1);
  }

  private scheduleRetry(): void {
    if (this.retryTimer || !this.online) return;
    const delay = this.retryDelayMs;
    this.retryDelayMs = Math.min(this.retryDelayMs * 2, 15_000);
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.flush();
    }, delay);
  }

  private clearRetryTimer(): void {
    if (!this.retryTimer) return;
    clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }
}

function isPermanentCommandFailure(status: number | undefined): boolean {
  return status === 400 || status === 403 || status === 404 || status === 410;
}

function conflictVersion(error: unknown): number {
  const version = (error as { body?: { currentVersion?: unknown } }).body?.currentVersion;
  return typeof version === 'number' && Number.isInteger(version) && version >= 0 ? version : 0;
}

function conflictReason(error: unknown): 'version_conflict' | 'metadata_format_outdated' {
  return (error as { body?: { code?: unknown } }).body?.code === 'metadata_format_outdated'
    ? 'metadata_format_outdated'
    : 'version_conflict';
}

export function encryptedCommandItemId(command: PersistedEncryptedCommand): string | null {
  if (typeof command.body === 'object' && command.body !== null && 'itemId' in command.body) {
    const itemId = (command.body as { itemId?: unknown }).itemId;
    if (typeof itemId === 'string' && itemId.length > 0) return itemId;
  }
  const match = /^\/api\/v2\/items\/([^/]+)(?:\/secret)?$/.exec(command.path);
  return match?.[1] ?? null;
}
