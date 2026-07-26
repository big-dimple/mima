import type { AccountBundle } from './account.ts';
import { E2EE_PROTOCOL, E2eeError, KEY_BYTES } from './constants.ts';
import { assertIdentifier, canonicalJson, sodiumReady, utf8 } from './encoding.ts';

export const EXTENSION_TRUSTED_UNLOCK_PROTOCOL = 'mima-extension-trusted-unlock-v1' as const;
export const EXTENSION_TRUSTED_UNLOCK_TTL_MS = 15_000;
export const EXTENSION_WORKBENCH_WAKE_EVENT = 'mima-extension-wake-v1' as const;

export interface ExtensionTrustedUnlockBinding {
  protocol: typeof EXTENSION_TRUSTED_UNLOCK_PROTOCOL;
  requestId: string;
  issuedAt: string;
  expiresAt: string;
  accountId: string;
  accountKeyVersion: number;
  deviceId: string;
  deviceEncryptionPublicKey: string;
  deviceSigningPublicKey: string;
  fingerprint: string;
  recordDigest: string;
}

export interface ExtensionTrustedUnlockRequest extends ExtensionTrustedUnlockBinding {
  ephemeralEncryptionPublicKey: string;
}

export interface ExtensionTrustedUnlockResponse extends ExtensionTrustedUnlockBinding {
  ephemeralEncryptionPublicKey: string;
  accountBundle: AccountBundle;
  sealedDeviceUnlockKey: string;
}

export async function deriveExtensionDeviceUnlockKey(
  accountKey: Uint8Array,
  binding: Pick<ExtensionTrustedUnlockBinding, 'accountId' | 'accountKeyVersion' | 'deviceId'>,
): Promise<Uint8Array> {
  if (!(accountKey instanceof Uint8Array) || accountKey.byteLength !== KEY_BYTES) {
    throw new E2eeError('invalid_input', 'Account key is invalid');
  }
  assertIdentifier(binding.accountId, 'accountId');
  assertIdentifier(binding.deviceId, 'deviceId');
  if (!Number.isSafeInteger(binding.accountKeyVersion) || binding.accountKeyVersion < 1) {
    throw new E2eeError('invalid_input', 'Account key version is invalid');
  }
  const crypto = await sodiumReady();
  const context = utf8(canonicalJson({
    accountId: binding.accountId,
    accountKeyVersion: binding.accountKeyVersion,
    deviceId: binding.deviceId,
    kind: 'extension-device-unlock-key',
    protocol: E2EE_PROTOCOL,
  }));
  try {
    return crypto.crypto_generichash(KEY_BYTES, context, accountKey);
  } finally {
    crypto.memzero(context);
  }
}

export function assertExtensionTrustedUnlockRequest(
  request: ExtensionTrustedUnlockRequest,
  now = Date.now(),
): void {
  if (request.protocol !== EXTENSION_TRUSTED_UNLOCK_PROTOCOL) {
    throw new Error('扩展可信解锁协议版本不受支持');
  }
  if (
    !request.requestId ||
    !request.accountId ||
    !request.deviceId ||
    !request.deviceEncryptionPublicKey ||
    !request.deviceSigningPublicKey ||
    !request.fingerprint ||
    !request.recordDigest ||
    !request.ephemeralEncryptionPublicKey
  ) {
    throw new Error('扩展可信解锁请求不完整');
  }
  const issuedAt = Date.parse(request.issuedAt);
  const expiresAt = Date.parse(request.expiresAt);
  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > EXTENSION_TRUSTED_UNLOCK_TTL_MS ||
    now < issuedAt - 1_000 ||
    now >= expiresAt
  ) {
    throw new Error('扩展可信解锁请求已经过期');
  }
}

export function trustedUnlockBindingMatches(
  request: ExtensionTrustedUnlockRequest,
  response: ExtensionTrustedUnlockResponse,
): boolean {
  return request.protocol === response.protocol
    && request.requestId === response.requestId
    && request.issuedAt === response.issuedAt
    && request.expiresAt === response.expiresAt
    && request.accountId === response.accountId
    && request.accountKeyVersion === response.accountKeyVersion
    && request.deviceId === response.deviceId
    && request.deviceEncryptionPublicKey === response.deviceEncryptionPublicKey
    && request.deviceSigningPublicKey === response.deviceSigningPublicKey
    && request.fingerprint === response.fingerprint
    && request.recordDigest === response.recordDigest
    && request.ephemeralEncryptionPublicKey === response.ephemeralEncryptionPublicKey;
}
