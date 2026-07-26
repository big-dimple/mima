/// <reference lib="webworker" />
import { DeviceRevokedError } from './crypto-errors.ts';
import { ExtensionKeyring } from './crypto-keyring.ts';
import {
  DEVICE_REVOKED_ERROR_CODE,
  type ExtensionCryptoWorkerError,
  type ExtensionCryptoWorkerRequest,
  type ExtensionCryptoWorkerResponse,
} from './crypto-worker-protocol.ts';

const keyring = new ExtensionKeyring();

self.addEventListener('message', (event: MessageEvent<ExtensionCryptoWorkerRequest>) => {
  void execute(event.data);
});

async function execute(request: ExtensionCryptoWorkerRequest): Promise<void> {
  try {
    const result = await invoke(request);
    post({ id: request.id, ok: true, result });
  } catch (error) {
    post({ id: request.id, ok: false, error: serializeError(error) });
  }
}

function invoke(request: ExtensionCryptoWorkerRequest): Promise<unknown> {
  switch (request.method) {
    case 'createLocalDevice':
      return keyring.createLocalDevice(...request.args);
    case 'createPairingDevice':
      return keyring.createPairingDevice(...request.args);
    case 'unlock':
      return keyring.unlock(...request.args);
    case 'createTrustedUnlockRequest':
      return keyring.createTrustedUnlockRequest(...request.args);
    case 'completeTrustedUnlock':
      return keyring.completeTrustedUnlock(...request.args);
    case 'upgradeTrustedUnlock':
      return keyring.upgradeTrustedUnlock(...request.args);
    case 'pairingProof':
      return keyring.pairingProof(...request.args);
    case 'pairingRequest':
      return Promise.resolve(keyring.pairingRequest(...request.args));
    case 'signChallenge':
      return keyring.signChallenge(...request.args);
    case 'openPairingApproval':
      return keyring.openPairingApproval(...request.args);
    case 'verifyApprovedDevice':
      return keyring.verifyApprovedDevice(...request.args);
    case 'signContentIntent':
      return keyring.signContentIntent(...request.args);
    case 'loadBootstrap':
      return keyring.loadBootstrap(...request.args);
    case 'decryptContent':
      return keyring.decryptContent(...request.args);
  }
}

function serializeError(error: unknown): ExtensionCryptoWorkerError {
  if (error instanceof DeviceRevokedError) {
    return {
      name: error.name,
      message: error.message,
      code: DEVICE_REVOKED_ERROR_CODE,
    };
  }
  if (error instanceof Error) return { name: error.name, message: error.message };
  return { name: 'Error', message: '扩展安全模块执行失败，请重新打开扩展' };
}

function post(response: ExtensionCryptoWorkerResponse): void {
  self.postMessage(response);
}
