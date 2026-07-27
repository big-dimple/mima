// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { ExtensionKeyring } from '../src/crypto-keyring.ts';
import {
  createAccountBundle,
  createVaultKeyGrant,
  createVaultKeys,
  createSignedDeviceCertificate,
  deriveExtensionDeviceUnlockKey,
  destroyKeyPair,
  destroyUnlockedAccount,
  destroyVaultKeys,
  encodeJson,
  encryptItemVersion,
  generateSigningKeyPair,
  sealBytes,
  type JsonValue,
} from '@mima/e2ee';
import type { EncryptedBootstrapResponse, EncryptedContentResponse } from '@mima/contracts';
import { MemoryExtensionStorage } from './helpers.ts';

const correctFactor = 'a-correct-main-password';

describe('ExtensionKeyring local device protection', () => {
  it('rejects a wrong unlock factor and destroys unlocked keys on lock', async () => {
    const keyring = new ExtensionKeyring();
    const device = await keyring.createLocalDevice(correctFactor, {
      deviceId: crypto.randomUUID(),
      name: 'Test extension',
      platform: 'browser-extension/test',
    });

    await expect(keyring.unlock(device, 'wrong-main-password')).rejects.toThrow('主密码不正确');
    expect(keyring.unlocked).toBe(false);
    await keyring.unlock(device, correctFactor);
    expect(keyring.unlocked).toBe(true);
    await keyring.lock();
    expect(keyring.unlocked).toBe(false);
    await expect(keyring.signChallenge('AQ')).rejects.toThrow('扩展已锁定');
  });

  it('persists only encrypted private material and ciphertext cache', async () => {
    const keyring = new ExtensionKeyring();
    const storage = new MemoryExtensionStorage();
    const device = await keyring.createLocalDevice(correctFactor, {
      deviceId: crypto.randomUUID(),
      name: 'Browser extension',
      platform: 'browser-extension/test',
    });
    await storage.saveDevice(device);
    await storage.savePendingPollToken('session-only-pairing-token');
    await storage.savePendingEnrollment({
      enrollmentId: crypto.randomUUID(),
      expiresAt: '2026-07-18T00:02:00.000Z',
      fingerprint: device.fingerprint,
      sealedApproval: 'sealed-ciphertext-only',
    });
    await storage.saveCiphertextCache({
      version: 1,
      bootstrap: {
        user: {
          id: 'user-1', username: 'bob', displayName: 'Bob', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
        },
        profile: null,
        recoveryKey: null,
        devices: [],
        vaults: [],
        memberships: [],
        envelopes: [],
        headers: [],
        items: [{
          itemId: crypto.randomUUID(),
          vaultId: crypto.randomUUID(),
          version: 1,
          secretVersion: 1,
          keyEpoch: 1,
          deleted: false,
          blob: { suite: 'lm-e2ee-v1', aadVersion: 1, nonce: 'bm9uY2U', ciphertext: 'Y2lwaGVydGV4dA' },
          createdAt: '2026-07-18T00:00:00.000Z',
          updatedAt: '2026-07-18T00:00:00.000Z',
          updatedBy: 'user-1',
        }],
        cursor: 1,
      },
      contents: {},
      updatedAt: '2026-07-18T00:00:00.000Z',
    });

    const serialized = storage.serialized();
    expect(serialized).not.toContain(correctFactor);
    expect(serialized).not.toContain('session-only-pairing-token');
    expect(serialized).not.toContain('Plaintext title');
    expect(serialized).not.toContain('https://sensitive.example.test');
    expect(serialized).not.toContain('clear-text-password');
    expect(serialized).toContain('encryptedPrivateBundle');
    expect(serialized).toContain('sealed-ciphertext-only');
    expect(serialized).toContain('ciphertext');
  });

  it('opens its signed device envelope and decrypts metadata and content locally', async () => {
    const keyring = new ExtensionKeyring();
    const userId = 'user-1';
    const signerUserId = 'owner-2';
    const deviceId = crypto.randomUUID();
    const vaultId = crypto.randomUUID();
    const itemId = crypto.randomUUID();
    const local = await keyring.createLocalDevice(correctFactor, {
      deviceId,
      name: 'Test extension',
      platform: 'browser-extension/test',
    });
    const device = { ...local, userId };
    const signer = await generateSigningKeyPair();
    const vaultKeys = await createVaultKeys(1);
    await keyring.unlock(device, correctFactor);
    try {
      const grant = await createVaultKeyGrant(
        vaultKeys,
        device.encryptionPublicKey,
        signer.privateKey,
        {
          vaultId,
          recipientKind: 'device',
          recipientId: deviceId,
          recipientKeyVersion: 1,
          capability: 'full',
          signerUserId,
          signerKeyVersion: 1,
        },
      );
      const encrypted = await encryptItemVersion(
        vaultKeys,
        { vaultId, itemId, version: 1, secretVersion: 1, keyEpoch: 1 },
        {
          metadata: {
            kind: 'login',
            title: 'Internal portal',
            username: 'bob',
            origin: 'https://internal.example.test',
            loginUrl: 'https://internal.example.test/login?tenant=team',
            loginUrls: [
              'https://internal.example.test/login?tenant=team',
              'https://secondary.example.test/login',
            ],
            description: 'Only visible after local decryption',
            tags: ['team'],
            favorite: true,
            sensitivity: 'high',
          },
          content: { value: 'local-only-password' },
        },
      );
      const now = '2026-07-18T00:00:00.000Z';
      const bootstrap: EncryptedBootstrapResponse & {
        signerProfiles: Array<{
          userId: string;
          keyVersion: number;
          encryptionPublicKey: string;
          signingPublicKey: string;
        }>;
      } = {
        user: {
          id: userId, username: 'bob', displayName: 'Bob', email: 'bob@example.test', groups: [], isPlatformAdmin: false,
        },
        profile: {
          userId,
          profileVersion: 1,
          keyVersion: 1,
          suite: 'lm-e2ee-v1',
          kdf: device.kdf,
          encryptedAccountBundle: device.encryptedPrivateBundle,
          encryptionPublicKey: device.encryptionPublicKey,
          signingPublicKey: signer.publicKey,
          recoveryEnabled: true,
          createdAt: now,
          updatedAt: now,
        },
        recoveryKey: null,
        devices: [{
          id: deviceId,
          userId,
          deviceType: 'extension',
          encryptedLabel: null,
          encryptionPublicKey: device.encryptionPublicKey,
          signingPublicKey: device.signingPublicKey,
          certificate: 'Y2VydA',
          certificateSignature: 'c2lnbmF0dXJl',
          keyVersion: 1,
          trustedAt: now,
          lastSeenAt: now,
          revokedAt: null,
        }],
        vaults: [{
          id: vaultId,
          kind: 'team',
          ownerUserId: signerUserId,
          createdAt: now,
          updatedAt: now,
          crypto: {
            vaultId,
            status: 'e2ee',
            activeEpoch: 1,
            pendingEpoch: null,
            encryptedHeader: null,
            migrationJobId: null,
            updatedAt: now,
          },
        }],
        memberships: [{ id: crypto.randomUUID(), vaultId, subjectKind: 'user', subjectId: userId, role: 'viewer', createdAt: now }],
        envelopes: [{ id: crypto.randomUUID(), ...grant, createdAt: now }],
        signerProfiles: [{
          userId: signerUserId,
          keyVersion: 1,
          encryptionPublicKey: device.encryptionPublicKey,
          signingPublicKey: signer.publicKey,
        }],
        headers: [],
        items: [{
          itemId,
          vaultId,
          version: 1,
          secretVersion: 1,
          keyEpoch: 1,
          deleted: false,
          blob: encrypted.metadata,
          createdAt: now,
          updatedAt: now,
          updatedBy: userId,
        }],
        cursor: 1,
      };

      const [decrypted] = await keyring.loadBootstrap(bootstrap);
      expect(decrypted).toMatchObject({
        title: 'Internal portal',
        secretState: 'present',
        username: 'bob',
        origin: 'https://internal.example.test',
        loginUrl: 'https://internal.example.test/login?tenant=team',
        loginUrls: [
          'https://internal.example.test/login?tenant=team',
          'https://secondary.example.test/login',
        ],
        description: 'Only visible after local decryption',
      });
      const response: EncryptedContentResponse = {
        metadata: bootstrap.items[0]!,
        secret: {
          itemId,
          vaultId,
          recordVersion: 1,
          secretVersion: 1,
          encryptedValue: encrypted.encryptedValue,
          createdAt: now,
          createdBy: userId,
        },
        keyWrap: {
          itemId,
          vaultId,
          secretVersion: 1,
          keyEpoch: 1,
          wrappedDek: encrypted.wrappedDek,
          createdAt: now,
          createdBy: userId,
        },
      };
      await expect(keyring.decryptContent(decrypted!, response)).resolves.toBe('local-only-password');
    } finally {
      await keyring.lock();
      await destroyVaultKeys(vaultKeys);
      await destroyKeyPair(signer);
    }
  });

  it('opens a sealed pairing approval only after local unlock', async () => {
    const keyring = new ExtensionKeyring();
    const accountId = 'user-1';
    const deviceId = crypto.randomUUID();
    const local = await keyring.createLocalDevice(correctFactor, {
      deviceId,
      name: 'Test extension',
      platform: 'browser-extension/test',
    });
    const accountSigner = await generateSigningKeyPair();
    const issuedAt = '2026-07-18T00:00:00.000Z';
    const certificate = await createSignedDeviceCertificate({
      accountId,
      deviceId,
      deviceType: 'extension',
      encryptionPublicKey: local.encryptionPublicKey,
      signingPublicKey: local.signingPublicKey,
      keyVersion: 1,
      issuedAt,
    }, accountSigner.privateKey);
    const approval = {
      session: {
        token: 'opaque-extension-session-token',
        expiresAt: '2026-07-19T00:00:00.000Z',
        user: {
          id: accountId,
          username: 'bob',
          displayName: 'Bob',
          email: 'bob@example.test',
          groups: [],
          isPlatformAdmin: false,
        },
      },
      device: {
        id: deviceId,
        userId: accountId,
        deviceType: 'extension',
        encryptedLabel: null,
        encryptionPublicKey: local.encryptionPublicKey,
        signingPublicKey: local.signingPublicKey,
        certificate: certificate.certificate,
        certificateSignature: certificate.signature,
        keyVersion: 1,
        trustedAt: issuedAt,
        lastSeenAt: issuedAt,
        revokedAt: null,
      },
      profileSigningPublicKey: accountSigner.publicKey,
    };
    const plaintext = encodeJson(approval as unknown as JsonValue);
    const sealed = await sealBytes(plaintext, local.encryptionPublicKey);
    plaintext.fill(0);
    try {
      await expect(keyring.openPairingApproval(sealed)).rejects.toThrow('扩展已锁定');
      await keyring.unlock(local, correctFactor);
      await expect(keyring.openPairingApproval(sealed)).resolves.toMatchObject({
        session: { token: 'opaque-extension-session-token' },
        device: { id: deviceId, deviceType: 'extension' },
      });
    } finally {
      await keyring.lock();
      await destroyKeyPair(accountSigner);
    }
  });

  it('provisions a trusted record without transferring the main password and supports local fallback', async () => {
    const keyring = new ExtensionKeyring();
    const account = await createAccountBundle(correctFactor, {
      accountId: 'user-trusted',
      deviceId: 'web-device-1',
    });
    const pairing = await keyring.createPairingDevice({
      deviceId: 'extension-device-1',
      name: 'Trusted extension',
      platform: 'browser-extension/test',
    });
    const certificate = await createSignedDeviceCertificate({
      accountId: account.accountBundle.accountId,
      deviceId: pairing.deviceId,
      deviceType: 'extension',
      encryptionPublicKey: pairing.encryptionPublicKey,
      signingPublicKey: pairing.signingPublicKey,
      keyVersion: account.accountBundle.keyVersion,
      issuedAt: '2026-07-20T00:00:00.000Z',
    }, account.unlocked.signingKeyPair.privateKey);
    const approved = {
      ...pairing,
      userId: account.accountBundle.accountId,
      certificate: certificate.certificate,
      certificateSignature: certificate.signature,
    };
    const request = await keyring.createTrustedUnlockRequest(approved);
    const deviceUnlockKey = await deriveExtensionDeviceUnlockKey(account.unlocked.accountKey, request);
    try {
      const response = {
        ...request,
        accountBundle: account.accountBundle,
        sealedDeviceUnlockKey: await sealBytes(
          deviceUnlockKey,
          request.ephemeralEncryptionPublicKey,
        ),
      };
      const trusted = await keyring.completeTrustedUnlock(approved, response);

      expect(trusted.pairingOnly).toBeUndefined();
      expect(trusted.webUnlock?.accountBundle).toEqual(account.accountBundle);
      expect(JSON.stringify(trusted)).not.toContain(correctFactor);
      await expect(keyring.completeTrustedUnlock(approved, response))
        .rejects.toThrow('扩展可信解锁请求不存在或已经使用');

      await keyring.lock();
      await expect(keyring.unlock(trusted, 'wrong-main-password')).rejects.toThrow('主密码不正确');
      await keyring.unlock(trusted, correctFactor);
      await expect(keyring.signChallenge('AQ')).resolves.toEqual(expect.any(String));

      await keyring.lock();
      const restartedKeyring = new ExtensionKeyring();
      const dailyRequest = await restartedKeyring.createTrustedUnlockRequest(trusted);
      const dailyDeviceUnlockKey = await deriveExtensionDeviceUnlockKey(
        account.unlocked.accountKey,
        dailyRequest,
      );
      try {
        const refreshed = await restartedKeyring.completeTrustedUnlock(trusted, {
          ...dailyRequest,
          accountBundle: account.accountBundle,
          sealedDeviceUnlockKey: await sealBytes(
            dailyDeviceUnlockKey,
            dailyRequest.ephemeralEncryptionPublicKey,
          ),
        });
        expect(restartedKeyring.unlocked).toBe(true);
        expect(refreshed.webUnlock?.accountBundle).toEqual(account.accountBundle);
        await expect(restartedKeyring.signChallenge('AQ')).resolves.toEqual(expect.any(String));
      } finally {
        dailyDeviceUnlockKey.fill(0);
        await restartedKeyring.lock();
      }
    } finally {
      deviceUnlockKey.fill(0);
      await keyring.lock();
      await destroyUnlockedAccount(account.unlocked);
    }
  });

  it('rejects a trusted response whose device binding was changed', async () => {
    const keyring = new ExtensionKeyring();
    const account = await createAccountBundle(correctFactor, {
      accountId: 'user-binding',
      deviceId: 'web-device-1',
    });
    const pairing = await keyring.createPairingDevice({
      deviceId: 'extension-device-binding',
      name: 'Binding test',
      platform: 'browser-extension/test',
    });
    const approved = { ...pairing, userId: account.accountBundle.accountId };
    const request = await keyring.createTrustedUnlockRequest(approved, account.accountBundle);
    const deviceUnlockKey = await deriveExtensionDeviceUnlockKey(account.unlocked.accountKey, request);
    try {
      const response = {
        ...request,
        recordDigest: 'changed-record-digest',
        accountBundle: account.accountBundle,
        sealedDeviceUnlockKey: await sealBytes(
          deviceUnlockKey,
          request.ephemeralEncryptionPublicKey,
        ),
      };
      await expect(keyring.completeTrustedUnlock(approved, response))
        .rejects.toThrow('扩展可信解锁响应与本机请求不一致');
      expect(keyring.unlocked).toBe(true);
    } finally {
      deviceUnlockKey.fill(0);
      await keyring.lock();
      await destroyUnlockedAccount(account.unlocked);
    }
  });
});
