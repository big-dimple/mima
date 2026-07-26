import type {
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
} from '@mima/contracts';
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

export const DEVICE_REVOKED_ERROR_CODE = 'DEVICE_REVOKED' as const;

export interface ExtensionKeyringPort {
  readonly unlocked: boolean;
  createLocalDevice(
    unlockFactor: string,
    input: { deviceId: string; name: string; platform: string },
  ): Promise<LocalDeviceRecord>;
  createPairingDevice(
    input: { deviceId: string; name: string; platform: string },
  ): Promise<LocalDeviceRecord>;
  unlock(record: LocalDeviceRecord, unlockFactor: string): Promise<void>;
  createTrustedUnlockRequest(
    record: LocalDeviceRecord,
    accountBundle?: AccountBundle,
  ): Promise<ExtensionTrustedUnlockRequest>;
  completeTrustedUnlock(
    record: LocalDeviceRecord,
    response: ExtensionTrustedUnlockResponse,
  ): Promise<LocalDeviceRecord>;
  upgradeTrustedUnlock(
    record: LocalDeviceRecord,
    unlockFactor: string,
    accountBundle: AccountBundle,
  ): Promise<LocalDeviceRecord>;
  lock(): Promise<void>;
  pairingProof(code: string, record: LocalDeviceRecord): Promise<string>;
  pairingRequest(
    code: string,
    record: LocalDeviceRecord,
    proof?: string,
  ): Promise<PairingClaimRequest>;
  signChallenge(challenge: string): Promise<string>;
  openPairingApproval(sealedApproval: string): Promise<PairingApproval>;
  verifyApprovedDevice(
    record: LocalDeviceRecord,
    device: CryptoDevice,
    profileSigningPublicKey: string,
  ): Promise<LocalDeviceRecord>;
  signContentIntent(input: {
    itemId: string;
    purpose: 'copy' | 'fill';
    secretVersion: number;
  }): Promise<string>;
  loadBootstrap(bootstrap: EncryptedBootstrapResponse): Promise<DecryptedExtensionItem[]>;
  decryptContent(
    item: DecryptedExtensionItem,
    response: EncryptedContentResponse,
  ): Promise<string>;
}

export interface ExtensionCryptoWorkerMethods {
  createLocalDevice: {
    args: [
      unlockFactor: string,
      input: { deviceId: string; name: string; platform: string },
    ];
    result: LocalDeviceRecord;
  };
  createPairingDevice: {
    args: [input: { deviceId: string; name: string; platform: string }];
    result: LocalDeviceRecord;
  };
  unlock: {
    args: [record: LocalDeviceRecord, unlockFactor: string];
    result: void;
  };
  createTrustedUnlockRequest: {
    args: [record: LocalDeviceRecord, accountBundle?: AccountBundle];
    result: ExtensionTrustedUnlockRequest;
  };
  completeTrustedUnlock: {
    args: [record: LocalDeviceRecord, response: ExtensionTrustedUnlockResponse];
    result: LocalDeviceRecord;
  };
  upgradeTrustedUnlock: {
    args: [record: LocalDeviceRecord, unlockFactor: string, accountBundle: AccountBundle];
    result: LocalDeviceRecord;
  };
  pairingProof: {
    args: [code: string, record: LocalDeviceRecord];
    result: string;
  };
  pairingRequest: {
    args: [code: string, record: LocalDeviceRecord, proof?: string];
    result: PairingClaimRequest;
  };
  signChallenge: {
    args: [challenge: string];
    result: string;
  };
  openPairingApproval: {
    args: [sealedApproval: string];
    result: PairingApproval;
  };
  verifyApprovedDevice: {
    args: [
      record: LocalDeviceRecord,
      device: CryptoDevice,
      profileSigningPublicKey: string,
    ];
    result: LocalDeviceRecord;
  };
  signContentIntent: {
    args: [input: { itemId: string; purpose: 'copy' | 'fill'; secretVersion: number }];
    result: string;
  };
  loadBootstrap: {
    args: [bootstrap: EncryptedBootstrapResponse];
    result: DecryptedExtensionItem[];
  };
  decryptContent: {
    args: [item: DecryptedExtensionItem, response: EncryptedContentResponse];
    result: string;
  };
}

export type ExtensionCryptoWorkerMethod = keyof ExtensionCryptoWorkerMethods;

export type ExtensionCryptoWorkerRequest = {
  [Method in ExtensionCryptoWorkerMethod]: {
    id: number;
    method: Method;
    args: ExtensionCryptoWorkerMethods[Method]['args'];
  };
}[ExtensionCryptoWorkerMethod];

export interface ExtensionCryptoWorkerError {
  name: string;
  message: string;
  code?: typeof DEVICE_REVOKED_ERROR_CODE;
}

export type ExtensionCryptoWorkerResponse =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: ExtensionCryptoWorkerError };
