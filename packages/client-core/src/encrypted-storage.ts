import type { CachedAccountLocator, PendingAccountCryptoResetLocator } from './e2ee-model.ts';

const DATABASE_NAME = 'mima-zero-knowledge';
const DATABASE_VERSION = 2;
const ACCOUNT_STORE = 'accounts';
const OUTBOX_STORE = 'outbox';
const ACCOUNT_RESET_STORE = 'account-crypto-resets';

export type EncryptedCommandKind = 'item.create' | 'item.update' | 'item.rotate' | 'item.delete';

export interface PersistedEncryptedCommandConflict {
  reason: 'version_conflict' | 'metadata_format_outdated';
  currentVersion: number;
  detectedAt: string;
}

export interface PersistedEncryptedCommand {
  id: string;
  accountId: string;
  kind: EncryptedCommandKind;
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  path: string;
  body: unknown;
  createdAt: string;
  conflict?: PersistedEncryptedCommandConflict;
}

export interface EncryptedStorageBackend {
  putAccount(record: CachedAccountLocator): Promise<void>;
  replaceAccountAfterIdentityRotation(record: CachedAccountLocator): Promise<void>;
  getAccount(accountId: string): Promise<CachedAccountLocator | null>;
  getLatestAccount(): Promise<CachedAccountLocator | null>;
  deleteAccountLocator(accountId: string): Promise<void>;
  deleteAccount(accountId: string): Promise<void>;
  putCommand(command: PersistedEncryptedCommand): Promise<void>;
  listCommands(accountId: string): Promise<PersistedEncryptedCommand[]>;
  deleteCommand(id: string): Promise<void>;
  clearCommands(accountId: string): Promise<void>;
  putPendingAccountCryptoReset(record: PendingAccountCryptoResetLocator): Promise<void>;
  getPendingAccountCryptoReset(accountId: string): Promise<PendingAccountCryptoResetLocator | null>;
  deletePendingAccountCryptoReset(accountId: string): Promise<void>;
  activatePendingAccountCryptoReset(record: CachedAccountLocator): Promise<void>;
}

export class IndexedDbEncryptedStorage implements EncryptedStorageBackend {
  async putAccount(record: CachedAccountLocator): Promise<void> {
    assertCiphertextOnly(record);
    await this.transaction(ACCOUNT_STORE, 'readwrite', (store) => store.put(record));
  }

  async replaceAccountAfterIdentityRotation(record: CachedAccountLocator): Promise<void> {
    assertCiphertextOnly(record);
    const database = await openDatabase();
    return new Promise<void>((resolve, reject) => {
      const transaction = database.transaction([ACCOUNT_STORE, OUTBOX_STORE], 'readwrite');
      transaction.objectStore(ACCOUNT_STORE).put(record);
      const cursorRequest = transaction.objectStore(OUTBOX_STORE).openCursor();
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result;
        if (!cursor) return;
        const command = cursor.value as PersistedEncryptedCommand;
        if (command.accountId === record.accountId) cursor.delete();
        cursor.continue();
      };
      cursorRequest.onerror = () => transaction.abort();
      transaction.oncomplete = () => {
        database.close();
        resolve();
      };
      transaction.onerror = () => {
        database.close();
        reject(transaction.error ?? new Error('账号安全信息未能保存到本机，请重试'));
      };
      transaction.onabort = () => {
        database.close();
        reject(transaction.error ?? cursorRequest.error ?? new Error('账号安全信息未能保存到本机，本次更改已撤销'));
      };
    });
  }

  async putPendingAccountCryptoReset(record: PendingAccountCryptoResetLocator): Promise<void> {
    assertCiphertextOnly(record);
    await this.transaction(ACCOUNT_RESET_STORE, 'readwrite', (store) => store.put(record));
  }

  async getPendingAccountCryptoReset(accountId: string): Promise<PendingAccountCryptoResetLocator | null> {
    return this.transaction(ACCOUNT_RESET_STORE, 'readonly', (store) => store.get(accountId));
  }

  async deletePendingAccountCryptoReset(accountId: string): Promise<void> {
    await this.transaction(ACCOUNT_RESET_STORE, 'readwrite', (store) => store.delete(accountId));
  }

  async activatePendingAccountCryptoReset(record: CachedAccountLocator): Promise<void> {
    assertCiphertextOnly(record);
    const database = await openDatabase();
    return new Promise<void>((resolve, reject) => {
      const transaction = database.transaction([ACCOUNT_STORE, ACCOUNT_RESET_STORE, OUTBOX_STORE], 'readwrite');
      transaction.objectStore(ACCOUNT_STORE).put(record);
      transaction.objectStore(ACCOUNT_RESET_STORE).delete(record.accountId);
      const cursorRequest = transaction.objectStore(OUTBOX_STORE).openCursor();
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result;
        if (!cursor) return;
        const command = cursor.value as PersistedEncryptedCommand;
        if (command.accountId === record.accountId) cursor.delete();
        cursor.continue();
      };
      cursorRequest.onerror = () => transaction.abort();
      transaction.oncomplete = () => {
        database.close();
        resolve();
      };
      transaction.onerror = () => {
        database.close();
        reject(transaction.error ?? new Error('解锁重置信息未能保存到本机，请重试'));
      };
      transaction.onabort = () => {
        database.close();
        reject(transaction.error ?? cursorRequest.error ?? new Error('解锁重置信息未能保存到本机，本次更改已撤销'));
      };
    });
  }

  async getAccount(accountId: string): Promise<CachedAccountLocator | null> {
    return this.transaction(ACCOUNT_STORE, 'readonly', (store) => store.get(accountId));
  }

  async getLatestAccount(): Promise<CachedAccountLocator | null> {
    const records = await this.transaction<CachedAccountLocator[]>(
      ACCOUNT_STORE,
      'readonly',
      (store) => store.getAll(),
    );
    return records.sort((left, right) => right.cachedAt.localeCompare(left.cachedAt))[0] ?? null;
  }

  async deleteAccount(accountId: string): Promise<void> {
    await this.deleteAccountLocator(accountId);
    await this.deletePendingAccountCryptoReset(accountId);
    await this.clearCommands(accountId);
  }

  async deleteAccountLocator(accountId: string): Promise<void> {
    await this.transaction(ACCOUNT_STORE, 'readwrite', (store) => store.delete(accountId));
  }

  async putCommand(command: PersistedEncryptedCommand): Promise<void> {
    assertCiphertextOnly(command.body);
    await this.transaction(OUTBOX_STORE, 'readwrite', (store) => store.put(command));
  }

  async listCommands(accountId: string): Promise<PersistedEncryptedCommand[]> {
    const records = await this.transaction<PersistedEncryptedCommand[]>(
      OUTBOX_STORE,
      'readonly',
      (store) => store.getAll(),
    );
    return records
      .filter((record) => record.accountId === accountId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  async deleteCommand(id: string): Promise<void> {
    await this.transaction(OUTBOX_STORE, 'readwrite', (store) => store.delete(id));
  }

  async clearCommands(accountId: string): Promise<void> {
    const records = await this.listCommands(accountId);
    await Promise.all(records.map((record) => this.deleteCommand(record.id)));
  }

  private async transaction<T = unknown>(
    storeName: string,
    mode: IDBTransactionMode,
    operation: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const database = await openDatabase();
    return new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(storeName, mode);
      const request = operation(transaction.objectStore(storeName));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('离线数据未能保存到本机'));
      transaction.oncomplete = () => database.close();
      transaction.onabort = () => {
        database.close();
        reject(transaction.error ?? new Error('离线数据未能保存到本机'));
      };
    });
  }
}

export class MemoryEncryptedStorage implements EncryptedStorageBackend {
  readonly accounts = new Map<string, CachedAccountLocator>();
  readonly commands = new Map<string, PersistedEncryptedCommand>();
  readonly accountCryptoResets = new Map<string, PendingAccountCryptoResetLocator>();

  async putAccount(record: CachedAccountLocator): Promise<void> {
    assertCiphertextOnly(record);
    this.accounts.set(record.accountId, structuredClone(record));
  }

  async replaceAccountAfterIdentityRotation(record: CachedAccountLocator): Promise<void> {
    assertCiphertextOnly(record);
    this.accounts.set(record.accountId, structuredClone(record));
    await this.clearCommands(record.accountId);
  }

  async putPendingAccountCryptoReset(record: PendingAccountCryptoResetLocator): Promise<void> {
    assertCiphertextOnly(record);
    this.accountCryptoResets.set(record.accountId, structuredClone(record));
  }

  async getPendingAccountCryptoReset(accountId: string): Promise<PendingAccountCryptoResetLocator | null> {
    const record = this.accountCryptoResets.get(accountId);
    return record ? structuredClone(record) : null;
  }

  async deletePendingAccountCryptoReset(accountId: string): Promise<void> {
    this.accountCryptoResets.delete(accountId);
  }

  async activatePendingAccountCryptoReset(record: CachedAccountLocator): Promise<void> {
    assertCiphertextOnly(record);
    this.accounts.set(record.accountId, structuredClone(record));
    this.accountCryptoResets.delete(record.accountId);
    await this.clearCommands(record.accountId);
  }

  async getAccount(accountId: string): Promise<CachedAccountLocator | null> {
    const record = this.accounts.get(accountId);
    return record ? structuredClone(record) : null;
  }

  async getLatestAccount(): Promise<CachedAccountLocator | null> {
    const latest = [...this.accounts.values()].sort((left, right) => right.cachedAt.localeCompare(left.cachedAt))[0];
    return latest ? structuredClone(latest) : null;
  }

  async deleteAccount(accountId: string): Promise<void> {
    await this.deleteAccountLocator(accountId);
    this.accountCryptoResets.delete(accountId);
    await this.clearCommands(accountId);
  }

  async deleteAccountLocator(accountId: string): Promise<void> {
    this.accounts.delete(accountId);
  }

  async putCommand(command: PersistedEncryptedCommand): Promise<void> {
    assertCiphertextOnly(command.body);
    this.commands.set(command.id, structuredClone(command));
  }

  async listCommands(accountId: string): Promise<PersistedEncryptedCommand[]> {
    return [...this.commands.values()]
      .filter((command) => command.accountId === accountId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt))
      .map((command) => structuredClone(command));
  }

  async deleteCommand(id: string): Promise<void> {
    this.commands.delete(id);
  }

  async clearCommands(accountId: string): Promise<void> {
    for (const [id, command] of this.commands) {
      if (command.accountId === accountId) this.commands.delete(id);
    }
  }
}

export function assertCiphertextOnly(value: unknown): void {
  const forbidden = new Set([
    'password',
    'mainpassword',
    'secretvalue',
    'title',
    'username',
    'origin',
    'loginurl',
    'folderpath',
    'tags',
    'note',
    'notes',
    'token',
    'url',
    'value',
    'privatekey',
    'encryptionprivatekey',
    'signingprivatekey',
  ]);
  const visited = new WeakSet<object>();
  const visit = (entry: unknown): void => {
    if (Array.isArray(entry)) {
      entry.forEach(visit);
      return;
    }
    if (typeof entry !== 'object' || entry === null) return;
    if (visited.has(entry)) return;
    visited.add(entry);
    for (const [key, nested] of Object.entries(entry)) {
      const normalizedKey = key.replaceAll('_', '').replaceAll('-', '').toLowerCase();
      if (forbidden.has(normalizedKey)) throw new Error(`拒绝持久化明文字段：${key}`);
      visit(nested);
    }
  };
  visit(value);
}

function openDatabase(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') return Promise.reject(new Error('当前浏览器不支持离线使用，请升级浏览器'));
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(ACCOUNT_STORE)) {
        database.createObjectStore(ACCOUNT_STORE, { keyPath: 'accountId' });
      }
      if (!database.objectStoreNames.contains(OUTBOX_STORE)) {
        database.createObjectStore(OUTBOX_STORE, { keyPath: 'id' });
      }
      if (!database.objectStoreNames.contains(ACCOUNT_RESET_STORE)) {
        database.createObjectStore(ACCOUNT_RESET_STORE, { keyPath: 'accountId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('无法读取本机离线数据，请重新加载页面'));
  });
}
