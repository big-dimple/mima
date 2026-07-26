import { E2EE_PROTOCOL, type E2eeErrorCode, E2eeError } from './constants.ts';
import {
  assertIdentifier,
  assertPositiveVersion,
  canonicalJson,
  utf8,
  type JsonValue,
} from './encoding.ts';

export type AadBlobType =
  | 'account-key-wrap'
  | 'account-private-key-bundle'
  | 'device-private-key-bundle'
  | 'extension-trusted-device-private-key-bundle'
  | 'offline-cache'
  | 'item-content'
  | 'item-content-key-wrap'
  | 'item-metadata'
  | 'vault-metadata';

export interface AadContext {
  blobType: AadBlobType;
  accountId?: string;
  deviceId?: string;
  vaultId?: string;
  itemId?: string;
  recipientId?: string;
  recordVersion?: number;
  secretVersion?: number;
  keyEpoch?: number;
}

export function aadJson(context: AadContext): JsonValue {
  assertIdentifier(context.blobType, 'blobType');
  validateOptionalIdentifier(context.accountId, 'accountId');
  validateOptionalIdentifier(context.deviceId, 'deviceId');
  validateOptionalIdentifier(context.vaultId, 'vaultId');
  validateOptionalIdentifier(context.itemId, 'itemId');
  validateOptionalIdentifier(context.recipientId, 'recipientId');
  validateOptionalVersion(context.recordVersion, 'recordVersion');
  validateOptionalVersion(context.secretVersion, 'secretVersion');
  validateOptionalVersion(context.keyEpoch, 'keyEpoch');

  return {
    accountId: context.accountId ?? null,
    blobType: context.blobType,
    deviceId: context.deviceId ?? null,
    itemId: context.itemId ?? null,
    keyEpoch: context.keyEpoch ?? null,
    protocol: E2EE_PROTOCOL,
    recipientId: context.recipientId ?? null,
    recordVersion: context.recordVersion ?? null,
    secretVersion: context.secretVersion ?? null,
    vaultId: context.vaultId ?? null,
  };
}

export function aadBytes(context: AadContext): Uint8Array {
  return utf8(canonicalJson(aadJson(context)));
}

function validateOptionalIdentifier(value: string | undefined, name: string): void {
  if (value !== undefined) {
    assertIdentifier(value, name);
  }
}

function validateOptionalVersion(value: number | undefined, name: string): void {
  if (value !== undefined) {
    assertPositiveVersion(value, name);
  }
}

export function normalizeCryptoError(
  error: unknown,
  code: E2eeErrorCode = 'authentication_failed',
): E2eeError {
  if (error instanceof E2eeError) {
    return error;
  }
  return new E2eeError(code, 'Cryptographic verification failed', { cause: error });
}
