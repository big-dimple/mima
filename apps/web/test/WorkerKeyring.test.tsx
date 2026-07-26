import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  EncryptedCommandOutbox,
  MemoryEncryptedStorage,
  SecretLeaseStore,
  ZeroKnowledgeClient,
  createMetaStore,
  type ApiClient,
  type EncryptedSyncClient,
} from '@mima/client-core';
import {
  isWebCryptoWorkerMethod,
  type WebCryptoWorkerResponse,
  WEB_CRYPTO_WORKER_METHODS,
} from '../src/crypto/crypto-worker-protocol.ts';
import { WorkerKeyring } from '../src/crypto/worker-keyring.ts';

class FakeWorker {
  onmessage: ((event: MessageEvent<WebCryptoWorkerResponse>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: ((event: MessageEvent) => void) | null = null;
  readonly messages: Array<{ id: number; method: string; args: unknown[] }> = [];
  terminated = false;
  postError: Error | null = null;

  postMessage(message: unknown): void {
    if (this.postError) throw this.postError;
    this.messages.push(message as { id: number; method: string; args: unknown[] });
  }

  terminate(): void {
    this.terminated = true;
  }

  respond(response: WebCryptoWorkerResponse): void {
    this.onmessage?.({ data: response } as MessageEvent<WebCryptoWorkerResponse>);
  }

  fail(kind: 'error' | 'messageerror'): void {
    if (kind === 'error') {
      this.onerror?.({ message: 'Worker crashed' } as ErrorEvent);
      return;
    }
    this.onmessageerror?.({} as MessageEvent);
  }
}

async function unlock(keyring: WorkerKeyring, worker: FakeWorker): Promise<void> {
  const pending = keyring.unlock(
    'main-password',
    {} as never,
    { id: 'device-1' } as never,
    {} as never,
  );
  worker.respond({ id: 1, ok: true, result: undefined });
  await pending;
}

describe('WorkerKeyring', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('fails closed when the browser cannot isolate cryptography in a Worker', async () => {
    vi.stubGlobal('Worker', undefined);
    const keyring = new WorkerKeyring();

    await expect(keyring.setup('must-not-run-on-main-thread', {
      accountId: 'user:worker-required',
      deviceId: '868bf37b-1a4d-4f04-85e9-bf9594e65342',
      deviceName: 'Test browser',
      platform: 'web:test',
    })).rejects.toThrow('当前浏览器不支持密码库所需的安全功能');

    expect(keyring.isUnlocked).toBe(false);
    expect(keyring.deviceId).toBeNull();
  });

  it('exposes only reviewed operations and rejects raw key access methods', () => {
    expect(WEB_CRYPTO_WORKER_METHODS).toContain('decryptContent');
    expect(isWebCryptoWorkerMethod('requireAccount')).toBe(false);
    expect(isWebCryptoWorkerMethod('requireVaultKeys')).toBe(false);
    expect(isWebCryptoWorkerMethod('requireFullVaultKeys')).toBe(false);
    expect(isWebCryptoWorkerMethod('constructor')).toBe(false);
    expect(isWebCryptoWorkerMethod('__proto__')).toBe(false);
  });

  it.each(['error', 'messageerror'] as const)(
    'destroys unlocked state and client projections after Worker %s',
    async (failureKind) => {
      const worker = new FakeWorker();
      const keyring = new WorkerKeyring(() => worker as unknown as Worker);
      await unlock(keyring, worker);
      const generation = keyring.currentGeneration;
      const api = { lock: vi.fn() } as unknown as ApiClient;
      const storage = new MemoryEncryptedStorage();
      const outbox = new EncryptedCommandOutbox(api, storage);
      const setOutboxOnline = vi.spyOn(outbox, 'setOnline');
      const leases = new SecretLeaseStore();
      leases.grant('item-1', 1);
      const store = createMetaStore();
      store.setState({
        locked: false,
        securityPhase: 'unlocked-online',
        vaults: { 'vault-1': {} as never },
        items: { 'item-1': {} as never },
      });
      const clipboardCleanup = vi.fn();
      const client = new ZeroKnowledgeClient({
        api,
        store,
        leases,
        keyring,
        storage,
        outbox,
        onKeyringFatal: clipboardCleanup,
      });
      const stopSync = vi.fn();
      client.attachSync({ stop: stopSync } as unknown as EncryptedSyncClient);
      const internal = client as unknown as {
        bootstrap: unknown;
        contents: Record<string, unknown>;
        preparedLegacyMigrations: Map<string, string>;
      };
      internal.bootstrap = { ciphertext: true };
      internal.contents = { 'item-1': { ciphertext: true } };
      internal.preparedLegacyMigrations.set('vault-1', 'job-1');
      const projectionEpoch = store.getState().epoch;
      const pending = keyring.decryptContent({} as never);
      const rejection = expect(pending).rejects.toThrow(
        failureKind === 'error'
          ? '浏览器安全模块运行失败，请重新加载页面'
          : '浏览器安全模块返回异常，请重新加载页面',
      );

      worker.fail(failureKind);

      await rejection;
      expect(worker.terminated).toBe(true);
      expect(keyring.isUnlocked).toBe(false);
      expect(keyring.deviceId).toBeNull();
      expect(keyring.currentGeneration).toBeGreaterThan(generation);
      expect(stopSync).toHaveBeenCalledOnce();
      expect(setOutboxOnline).toHaveBeenLastCalledWith(false);
      expect(leases.has('item-1', 1)).toBe(false);
      expect(client.hasPreparedLegacyMigration('vault-1')).toBe(false);
      expect(internal.bootstrap).toBeNull();
      expect(internal.contents).toEqual({});
      expect(store.getState()).toMatchObject({
        locked: true,
        securityPhase: 'authenticated-locked',
        vaults: {},
        items: {},
      });
      expect(store.getState().epoch).toBeGreaterThan(projectionEpoch);
      expect(clipboardCleanup).toHaveBeenCalledOnce();
      expect(api.lock).not.toHaveBeenCalled();
    },
  );

  it('fails closed when postMessage throws synchronously', async () => {
    const worker = new FakeWorker();
    const keyring = new WorkerKeyring(() => worker as unknown as Worker);
    await unlock(keyring, worker);
    const generation = keyring.currentGeneration;
    const fatal = vi.fn();
    keyring.onFatal(fatal);
    worker.postError = new Error('structured clone failed');

    await expect(keyring.decryptContent({} as never)).rejects.toThrow('structured clone failed');

    expect(worker.terminated).toBe(true);
    expect(keyring.isUnlocked).toBe(false);
    expect(keyring.deviceId).toBeNull();
    expect(keyring.currentGeneration).toBeGreaterThan(generation);
    expect(fatal).toHaveBeenCalledOnce();
  });
});
