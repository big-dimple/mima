import { describe, expect, it } from 'vitest';
import {
  EXTENSION_TRUSTED_UNLOCK_PROTOCOL,
  EXTENSION_TRUSTED_UNLOCK_TTL_MS,
  assertExtensionTrustedUnlockRequest,
  createAccountBundle,
  deriveExtensionDeviceUnlockKey,
  destroyUnlockedAccount,
  trustedUnlockBindingMatches,
  type ExtensionTrustedUnlockRequest,
  type ExtensionTrustedUnlockResponse,
} from '../src/index.ts';

function requestAt(issuedAt: number): ExtensionTrustedUnlockRequest {
  return {
    protocol: EXTENSION_TRUSTED_UNLOCK_PROTOCOL,
    requestId: 'request-1',
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(issuedAt + EXTENSION_TRUSTED_UNLOCK_TTL_MS).toISOString(),
    accountId: 'user-1',
    accountKeyVersion: 1,
    deviceId: 'extension-1',
    deviceEncryptionPublicKey: 'encryption-public-key',
    deviceSigningPublicKey: 'signing-public-key',
    fingerprint: '1111 2222 3333 4444',
    recordDigest: 'AAAA BBBB CCCC DDDD',
    ephemeralEncryptionPublicKey: 'ephemeral-public-key',
  };
}

describe('extension trusted unlock', () => {
  it('derives a stable device key that is separated by account version and extension device', async () => {
    const created = await createAccountBundle('one main password', {
      accountId: 'user-1',
      deviceId: 'web-device-1',
    });
    try {
      const binding = { accountId: 'user-1', accountKeyVersion: 1, deviceId: 'extension-1' };
      const first = await deriveExtensionDeviceUnlockKey(created.unlocked.accountKey, binding);
      const second = await deriveExtensionDeviceUnlockKey(created.unlocked.accountKey, binding);
      const otherDevice = await deriveExtensionDeviceUnlockKey(created.unlocked.accountKey, {
        ...binding,
        deviceId: 'extension-2',
      });
      const otherVersion = await deriveExtensionDeviceUnlockKey(created.unlocked.accountKey, {
        ...binding,
        accountKeyVersion: 2,
      });

      expect(first).toEqual(second);
      expect(first).not.toEqual(otherDevice);
      expect(first).not.toEqual(otherVersion);
      first.fill(0);
      second.fill(0);
      otherDevice.fill(0);
      otherVersion.fill(0);
    } finally {
      await destroyUnlockedAccount(created.unlocked);
    }
  });

  it('rejects expired or excessively long requests and binds every response field', () => {
    const issuedAt = Date.parse('2026-07-21T03:00:00.000Z');
    const request = requestAt(issuedAt);
    expect(() => assertExtensionTrustedUnlockRequest(request, issuedAt + 1_000)).not.toThrow();
    expect(() => assertExtensionTrustedUnlockRequest(request, issuedAt + EXTENSION_TRUSTED_UNLOCK_TTL_MS))
      .toThrow('扩展可信解锁请求已经过期');
    expect(() => assertExtensionTrustedUnlockRequest({
      ...request,
      expiresAt: new Date(issuedAt + EXTENSION_TRUSTED_UNLOCK_TTL_MS + 1).toISOString(),
    }, issuedAt + 1_000)).toThrow('扩展可信解锁请求已经过期');

    const response = {
      ...request,
      accountBundle: {} as never,
      sealedDeviceUnlockKey: 'sealed-device-key',
    } satisfies ExtensionTrustedUnlockResponse;
    expect(trustedUnlockBindingMatches(request, response)).toBe(true);
    expect(trustedUnlockBindingMatches(request, { ...response, recordDigest: 'different' })).toBe(false);
    expect(trustedUnlockBindingMatches(request, { ...response, deviceId: 'extension-2' })).toBe(false);
  });
});
