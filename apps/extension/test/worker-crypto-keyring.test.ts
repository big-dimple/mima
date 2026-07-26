// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { DeviceRevokedError } from '../src/crypto-errors.ts';
import { PanelModel } from '../src/panel-model.ts';
import {
  DEVICE_REVOKED_ERROR_CODE,
  type ExtensionCryptoWorkerResponse,
} from '../src/crypto-worker-protocol.ts';
import {
  WorkerCryptoKeyring,
  type ExtensionCryptoWorker,
} from '../src/worker-crypto-keyring.ts';
import type { DecryptedExtensionItem } from '../src/protocol.ts';
import { extSession } from './helpers.ts';

const decryptedItem = {
  id: 'item-1',
  vaultId: 'vault-1',
  kind: 'login',
  title: 'Internal',
  username: 'alice',
  origin: 'https://internal.example.test',
  tags: [],
  favorite: false,
  sensitivity: 'medium',
  version: 1,
  secretVersion: 1,
  keyEpoch: 1,
} satisfies DecryptedExtensionItem;

class FakeWorker implements ExtensionCryptoWorker {
  readonly messages: Array<{ id: number; method: string; args: unknown[] }> = [];
  terminated = false;
  private messageListener: ((event: MessageEvent<ExtensionCryptoWorkerResponse>) => void) | null = null;
  private errorListener: ((event: ErrorEvent) => void) | null = null;
  private messageErrorListener: ((event: MessageEvent) => void) | null = null;

  postMessage(message: unknown): void {
    this.messages.push(message as { id: number; method: string; args: unknown[] });
  }

  terminate(): void {
    this.terminated = true;
  }

  addEventListener(
    type: 'message' | 'error' | 'messageerror',
    listener:
      | ((event: MessageEvent<ExtensionCryptoWorkerResponse>) => void)
      | ((event: ErrorEvent) => void)
      | ((event: MessageEvent) => void),
  ): void {
    if (type === 'message') {
      this.messageListener = listener as (event: MessageEvent<ExtensionCryptoWorkerResponse>) => void;
    } else if (type === 'error') {
      this.errorListener = listener as (event: ErrorEvent) => void;
    } else {
      this.messageErrorListener = listener as (event: MessageEvent) => void;
    }
  }

  respond(response: ExtensionCryptoWorkerResponse): void {
    this.messageListener?.({ data: response } as MessageEvent<ExtensionCryptoWorkerResponse>);
  }

  fail(message: string): void {
    this.errorListener?.({ message } as ErrorEvent);
  }

  failMessage(): void {
    this.messageErrorListener?.({} as MessageEvent);
  }
}

describe('WorkerCryptoKeyring', () => {
  it('keeps a newly created pairing device unlocked until approval is claimed', async () => {
    const worker = new FakeWorker();
    const keyring = new WorkerCryptoKeyring(() => worker);
    const pending = keyring.createPairingDevice({
      deviceId: 'extension-device-1',
      name: 'Test extension',
      platform: 'browser-extension/test',
    });

    expect(keyring.unlocked).toBe(false);
    expect(worker.messages).toMatchObject([{
      id: 1,
      method: 'createPairingDevice',
      args: [{
        deviceId: 'extension-device-1',
        name: 'Test extension',
        platform: 'browser-extension/test',
      }],
    }]);
    worker.respond({ id: 1, ok: true, result: { deviceId: 'extension-device-1' } });
    await expect(pending).resolves.toMatchObject({ deviceId: 'extension-device-1' });
    expect(keyring.unlocked).toBe(true);
  });

  it('marks itself unlocked only after the dedicated Worker accepts the device bundle', async () => {
    const worker = new FakeWorker();
    const keyring = new WorkerCryptoKeyring(() => worker);
    const pending = keyring.unlock({ deviceId: 'device-1' } as never, 'extension-unlock-factor');

    expect(keyring.unlocked).toBe(false);
    expect(worker.messages).toMatchObject([{
      id: 1,
      method: 'unlock',
      args: [{ deviceId: 'device-1' }, 'extension-unlock-factor'],
    }]);
    worker.respond({ id: 1, ok: true, result: undefined });
    await pending;

    expect(keyring.unlocked).toBe(true);
  });

  it('marks itself unlocked after a trusted workbench response restores the device', async () => {
    const worker = new FakeWorker();
    const keyring = new WorkerCryptoKeyring(() => worker);
    const pending = keyring.completeTrustedUnlock(
      { deviceId: 'extension-device-1' } as never,
      { requestId: 'trusted-request-1' } as never,
    );

    expect(keyring.unlocked).toBe(false);
    expect(worker.messages).toMatchObject([{
      id: 1,
      method: 'completeTrustedUnlock',
      args: [
        { deviceId: 'extension-device-1' },
        { requestId: 'trusted-request-1' },
      ],
    }]);
    worker.respond({ id: 1, ok: true, result: { deviceId: 'extension-device-1' } });
    await expect(pending).resolves.toMatchObject({ deviceId: 'extension-device-1' });
    expect(keyring.unlocked).toBe(true);
  });

  it('terminates the Worker and rejects every in-flight request when locked', async () => {
    const workers: FakeWorker[] = [];
    const keyring = new WorkerCryptoKeyring(() => {
      const worker = new FakeWorker();
      workers.push(worker);
      return worker;
    });
    const fatal = vi.fn();
    keyring.onFatal(fatal);
    const unlock = keyring.unlock({ deviceId: 'device-1' } as never, 'extension-unlock-factor');
    workers[0]!.respond({ id: 1, ok: true, result: undefined });
    await unlock;

    const signing = keyring.signChallenge('challenge');
    const rejection = expect(signing).rejects.toThrow('扩展已锁定');
    await keyring.lock();

    await rejection;
    expect(workers[0]!.terminated).toBe(true);
    expect(keyring.unlocked).toBe(false);
    expect(fatal).not.toHaveBeenCalled();

    const nextRequest = keyring.pairingRequest('123456', { deviceId: 'device-1' } as never);
    expect(workers).toHaveLength(2);
    expect(workers[1]!.messages[0]).toMatchObject({ id: 3, method: 'pairingRequest' });
    workers[1]!.respond({ id: 3, ok: true, result: { code: '123456', device: {} } });
    await nextRequest;
  });

  it('does not let an old unlock response restore state after a concurrent lock', async () => {
    const worker = new FakeWorker();
    const keyring = new WorkerCryptoKeyring(() => worker);
    const unlock = keyring.unlock({ deviceId: 'device-1' } as never, 'extension-unlock-factor');

    worker.respond({ id: 1, ok: true, result: undefined });
    await keyring.lock();

    await expect(unlock).rejects.toThrow('扩展已锁定');
    expect(worker.terminated).toBe(true);
    expect(keyring.unlocked).toBe(false);
  });

  it('restores device revocation as a typed main-thread error', async () => {
    const worker = new FakeWorker();
    const keyring = new WorkerCryptoKeyring(() => worker);
    const pending = keyring.loadBootstrap({} as never);

    worker.respond({
      id: 1,
      ok: false,
      error: {
        name: 'DeviceRevokedError',
        message: '此扩展设备已被撤销，请重新配对',
        code: DEVICE_REVOKED_ERROR_CODE,
      },
    });

    await expect(pending).rejects.toBeInstanceOf(DeviceRevokedError);
  });

  it('fails closed and clears unlocked state when the Worker crashes', async () => {
    const worker = new FakeWorker();
    const factory = vi.fn(() => worker);
    const keyring = new WorkerCryptoKeyring(factory);
    const unlock = keyring.unlock({ deviceId: 'device-1' } as never, 'extension-unlock-factor');
    worker.respond({ id: 1, ok: true, result: undefined });
    await unlock;
    const pending = keyring.signChallenge('challenge');
    const rejection = expect(pending).rejects.toThrow('扩展安全模块运行失败，请重新打开扩展');

    worker.fail('Worker crashed');

    await rejection;
    expect(worker.terminated).toBe(true);
    expect(keyring.unlocked).toBe(false);
  });

  it.each(['error', 'messageerror'] as const)(
    'clears a ready panel model and redraws after Worker %s',
    async (failureKind) => {
      const worker = new FakeWorker();
      const keyring = new WorkerCryptoKeyring(() => worker);
      const model = new PanelModel();
      model.state.session = extSession();
      model.state.device = { deviceId: 'device-1' } as never;
      model.setReady([decryptedItem], true);
      model.state.search = 'internal';
      model.state.tabId = 7;
      model.state.tabOrigin = decryptedItem.origin;
      const redraw = vi.fn();
      keyring.onFatal((error) => {
        model.handleCryptoWorkerFailure(error.message);
        redraw();
      });
      const unlock = keyring.unlock({ deviceId: 'device-1' } as never, 'extension-unlock-factor');
      worker.respond({ id: 1, ok: true, result: undefined });
      await unlock;

      if (failureKind === 'error') worker.fail('Worker crashed');
      else worker.failMessage();

      expect(worker.terminated).toBe(true);
      expect(keyring.unlocked).toBe(false);
      expect(model.state).toMatchObject({
        phase: 'locked',
        items: [],
        search: '',
        tabId: null,
        tabOrigin: null,
        tabUrl: null,
        offline: false,
        error: failureKind === 'error'
          ? '扩展安全模块运行失败，请重新打开扩展'
          : '扩展安全模块返回异常，请重新打开扩展',
      });
      expect(redraw).toHaveBeenCalledOnce();
    },
  );
});
