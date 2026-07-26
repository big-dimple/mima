import type {
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
} from '@mima/contracts';
import { DeviceRevokedError } from './crypto-errors.ts';
import {
  DEVICE_REVOKED_ERROR_CODE,
  type ExtensionCryptoWorkerMethod,
  type ExtensionCryptoWorkerMethods,
  type ExtensionCryptoWorkerResponse,
  type ExtensionKeyringPort,
} from './crypto-worker-protocol.ts';
import type {
  AccountBundle,
  ExtensionTrustedUnlockRequest,
  ExtensionTrustedUnlockResponse,
} from '@mima/e2ee';
import type {
  DecryptedExtensionItem,
  LocalDeviceRecord,
  PairingApproval,
  PairingClaimRequest,
} from './protocol.ts';

export interface ExtensionCryptoWorker {
  postMessage(message: unknown): void;
  terminate(): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<ExtensionCryptoWorkerResponse>) => void): void;
  addEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
  addEventListener(type: 'messageerror', listener: (event: MessageEvent) => void): void;
}

export type ExtensionCryptoWorkerFactory = () => ExtensionCryptoWorker;

interface PendingRequest {
  resolve(value: unknown): void;
  reject(reason: Error): void;
}

export class WorkerCryptoKeyring implements ExtensionKeyringPort {
  private worker: ExtensionCryptoWorker | null = null;
  private readonly pending = new Map<number, PendingRequest>();
  private nextRequestId = 1;
  private lifecycle = 0;
  private unlockedState = false;
  private readonly fatalListeners = new Set<(error: Error) => void>();

  constructor(
    private readonly workerFactory: ExtensionCryptoWorkerFactory = createExtensionCryptoWorker,
  ) {}

  get unlocked(): boolean {
    return this.unlockedState;
  }

  onFatal(listener: (error: Error) => void): () => void {
    this.fatalListeners.add(listener);
    return () => this.fatalListeners.delete(listener);
  }

  async createLocalDevice(
    unlockFactor: string,
    input: { deviceId: string; name: string; platform: string },
  ): Promise<LocalDeviceRecord> {
    const lifecycle = this.lifecycle;
    const record = await this.request('createLocalDevice', unlockFactor, input);
    this.markUnlocked(lifecycle);
    return record;
  }

  async createPairingDevice(
    input: { deviceId: string; name: string; platform: string },
  ): Promise<LocalDeviceRecord> {
    const lifecycle = this.lifecycle;
    const record = await this.request('createPairingDevice', input);
    this.markUnlocked(lifecycle);
    return record;
  }

  async unlock(record: LocalDeviceRecord, unlockFactor: string): Promise<void> {
    this.destroyWorker(new Error('扩展已锁定，请先用主密码解锁'));
    const lifecycle = this.lifecycle;
    await this.request('unlock', record, unlockFactor);
    this.markUnlocked(lifecycle);
  }

  createTrustedUnlockRequest(
    record: LocalDeviceRecord,
    accountBundle?: AccountBundle,
  ): Promise<ExtensionTrustedUnlockRequest> {
    return this.request('createTrustedUnlockRequest', record, accountBundle);
  }

  async completeTrustedUnlock(
    record: LocalDeviceRecord,
    response: ExtensionTrustedUnlockResponse,
  ): Promise<LocalDeviceRecord> {
    const lifecycle = this.lifecycle;
    const updated = await this.request('completeTrustedUnlock', record, response);
    this.markUnlocked(lifecycle);
    return updated;
  }

  upgradeTrustedUnlock(
    record: LocalDeviceRecord,
    unlockFactor: string,
    accountBundle: AccountBundle,
  ): Promise<LocalDeviceRecord> {
    return this.request('upgradeTrustedUnlock', record, unlockFactor, accountBundle);
  }

  async lock(): Promise<void> {
    this.destroyWorker(new Error('扩展已锁定，请先用主密码解锁'));
  }

  pairingProof(code: string, record: LocalDeviceRecord): Promise<string> {
    return this.request('pairingProof', code, record);
  }

  pairingRequest(
    code: string,
    record: LocalDeviceRecord,
    proof?: string,
  ): Promise<PairingClaimRequest> {
    return this.request('pairingRequest', code, record, proof);
  }

  signChallenge(challenge: string): Promise<string> {
    return this.request('signChallenge', challenge);
  }

  openPairingApproval(sealedApproval: string): Promise<PairingApproval> {
    return this.request('openPairingApproval', sealedApproval);
  }

  verifyApprovedDevice(
    record: LocalDeviceRecord,
    device: CryptoDevice,
    profileSigningPublicKey: string,
  ): Promise<LocalDeviceRecord> {
    return this.request('verifyApprovedDevice', record, device, profileSigningPublicKey);
  }

  signContentIntent(input: {
    itemId: string;
    purpose: 'copy' | 'fill';
    secretVersion: number;
  }): Promise<string> {
    return this.request('signContentIntent', input);
  }

  loadBootstrap(bootstrap: EncryptedBootstrapResponse): Promise<DecryptedExtensionItem[]> {
    return this.request('loadBootstrap', bootstrap);
  }

  decryptContent(
    item: DecryptedExtensionItem,
    response: EncryptedContentResponse,
  ): Promise<string> {
    return this.request('decryptContent', item, response);
  }

  private request<Method extends ExtensionCryptoWorkerMethod>(
    method: Method,
    ...args: ExtensionCryptoWorkerMethods[Method]['args']
  ): Promise<ExtensionCryptoWorkerMethods[Method]['result']> {
    const worker = this.ensureWorker();
    const id = this.nextRequestId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      try {
        worker.postMessage({ id, method, args });
      } catch (error) {
        this.destroyWorker(asError(error, '扩展安全模块暂时不可用，请重新打开扩展'), true);
      }
    });
  }

  private markUnlocked(lifecycle: number): void {
    if (lifecycle !== this.lifecycle || !this.worker) {
      throw new Error('扩展已锁定，请先用主密码解锁');
    }
    this.unlockedState = true;
  }

  private ensureWorker(): ExtensionCryptoWorker {
    if (this.worker) return this.worker;
    const worker = this.workerFactory();
    worker.addEventListener('message', (event) => this.onMessage(worker, event.data));
    worker.addEventListener('error', (event) => {
      this.onWorkerFailure(worker, new Error('扩展安全模块运行失败，请重新打开扩展', {
        cause: event.message,
      }));
    });
    worker.addEventListener('messageerror', () => {
      this.onWorkerFailure(worker, new Error('扩展安全模块返回异常，请重新打开扩展'));
    });
    this.worker = worker;
    return worker;
  }

  private onMessage(worker: ExtensionCryptoWorker, response: ExtensionCryptoWorkerResponse): void {
    if (worker !== this.worker) return;
    const pending = this.pending.get(response.id);
    if (!pending) return;
    this.pending.delete(response.id);
    if (response.ok) {
      pending.resolve(response.result);
      return;
    }
    const error = response.error.code === DEVICE_REVOKED_ERROR_CODE
      ? new DeviceRevokedError()
      : new Error(response.error.message);
    error.name = response.error.name;
    pending.reject(error);
  }

  private onWorkerFailure(worker: ExtensionCryptoWorker, error: Error): void {
    if (worker !== this.worker) return;
    this.destroyWorker(error, true);
  }

  private destroyWorker(error: Error, fatal = false): void {
    const worker = this.worker;
    this.worker = null;
    this.lifecycle += 1;
    this.unlockedState = false;
    worker?.terminate();
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    if (!fatal) return;
    for (const listener of this.fatalListeners) {
      try {
        listener(error);
      } catch (listenerError) {
        void listenerError;
      }
    }
  }
}

function createExtensionCryptoWorker(): ExtensionCryptoWorker {
  return new Worker(new URL('./crypto.worker.ts', import.meta.url), {
    type: 'module',
    name: 'mima-extension-crypto',
  });
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}
