import { describe, expect, it } from 'vitest';
import {
  changeMasterPassword,
  createAccountBundle,
  createVaultKeyGrant,
  createVaultKeys,
  decryptItemContent,
  decryptItemMetadata,
  decryptItemVersion,
  decryptVaultMetadata,
  destroyUnlockedAccount,
  destroyVaultKeys,
  encryptItemVersion,
  encryptVaultMetadata,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  openVaultKeyGrant,
  rewrapItemContentKey,
  prepareAccountIdentityRotation,
  unlockAccountBundle,
  type CipherBlob,
} from '../src/index.ts';

function mutate(value: string): string {
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}

describe('account and device key hierarchy', () => {
  it('unlocks with the master password, rejects a wrong password, and wipes on lock', async () => {
    const created = await createAccountBundle('a strong master password', {
      accountId: 'user-1',
      deviceId: 'device-1',
      kdfSalt: Uint8Array.from({ length: 16 }, (_, index) => index),
    });
    expect(created.accountBundle.encryptedAccountBundle).toMatchObject({
      suite: 'lm-e2ee-v1',
      aadVersion: 1,
    });
    const unlocked = await unlockAccountBundle(
      'a strong master password',
      created.accountBundle,
      created.deviceBundle,
    );
    expect(unlocked.encryptionKeyPair.publicKey).toBe(
      created.accountBundle.encryptionPublicKey,
    );
    expect(unlocked.device?.signingKeyPair.publicKey).toBe(
      created.deviceBundle.signingPublicKey,
    );
    await expect(
      unlockAccountBundle('wrong password', created.accountBundle, created.deviceBundle),
    ).rejects.toMatchObject({ code: 'authentication_failed' });

    await destroyUnlockedAccount(unlocked);
    expect(Array.from(unlocked.accountKey).every((byte) => byte === 0)).toBe(true);
    expect(Array.from(unlocked.device!.signingKeyPair.privateKey).every((byte) => byte === 0)).toBe(
      true,
    );
    await destroyUnlockedAccount(created.unlocked);
  });

  it('prepares new account, user, and device keys without destroying the current identity', async () => {
    const created = await createAccountBundle('rotation password', {
      accountId: 'user-rotation',
      deviceId: 'device-rotation',
      kdfSalt: Uint8Array.from({ length: 16 }, (_, index) => index + 16),
    });
    const previousEncryptionPublicKey = created.unlocked.encryptionKeyPair.publicKey;
    const previousSigningPublicKey = created.unlocked.signingKeyPair.publicKey;
    const previousAccountKey = Uint8Array.from(created.unlocked.accountKey);
    const previousDeviceSigningKey = Uint8Array.from(
      created.unlocked.device!.signingKeyPair.privateKey,
    );

    const prepared = await prepareAccountIdentityRotation(
      'rotation password',
      created.accountBundle,
      created.unlocked,
      { deviceId: created.deviceBundle.deviceId },
    );

    expect(prepared.accountBundle.keyVersion).toBe(created.accountBundle.keyVersion + 1);
    expect(prepared.accountBundle.encryptionPublicKey).not.toBe(previousEncryptionPublicKey);
    expect(prepared.accountBundle.signingPublicKey).not.toBe(previousSigningPublicKey);
    expect(prepared.unlocked.accountKey).not.toEqual(previousAccountKey);
    expect(created.unlocked.accountKey).toEqual(previousAccountKey);
    expect(created.unlocked.encryptionKeyPair.publicKey).toBe(previousEncryptionPublicKey);
    expect(created.unlocked.device!.signingKeyPair.privateKey).toEqual(previousDeviceSigningKey);

    const unlocked = await unlockAccountBundle(
      'rotation password',
      prepared.accountBundle,
      prepared.deviceBundle,
    );
    expect(unlocked.accountKey).toEqual(prepared.unlocked.accountKey);
    expect(unlocked.encryptionKeyPair.publicKey).toBe(prepared.accountBundle.encryptionPublicKey);
    await expect(
      prepareAccountIdentityRotation(
        'wrong password',
        created.accountBundle,
        created.unlocked,
        { deviceId: created.deviceBundle.deviceId },
      ),
    ).rejects.toMatchObject({ code: 'authentication_failed' });

    await destroyUnlockedAccount(unlocked);
    await destroyUnlockedAccount(prepared.unlocked);
    await destroyUnlockedAccount(created.unlocked);
    previousAccountKey.fill(0);
    previousDeviceSigningKey.fill(0);
  });

  it('changes the master password without changing account public keys', async () => {
    const created = await createAccountBundle('old master password', {
      accountId: 'user-2',
      deviceId: 'device-2',
    });
    const changed = await changeMasterPassword(
      'old master password',
      'new master password',
      created.accountBundle,
    );
    expect(changed.encryptionPublicKey).toBe(created.accountBundle.encryptionPublicKey);
    expect(changed.signingPublicKey).toBe(created.accountBundle.signingPublicKey);
    await expect(unlockAccountBundle('old master password', changed)).rejects.toMatchObject({
      code: 'authentication_failed',
    });
    const unlocked = await unlockAccountBundle('new master password', changed);
    expect(unlocked.signingKeyPair.publicKey).toBe(changed.signingPublicKey);
    await destroyUnlockedAccount(unlocked);
    await destroyUnlockedAccount(created.unlocked);
  });
});

describe('vault grants and item version keys', () => {
  it('gives full recipients both vault keys and metadata recipients no content key', async () => {
    const keys = await createVaultKeys(7);
    const recipient = await generateEncryptionKeyPair();
    const signer = await generateSigningKeyPair();
    const baseScope = {
      vaultId: 'vault-1',
      recipientKind: 'user' as const,
      recipientId: 'user-1',
      recipientKeyVersion: 2,
      signerUserId: 'owner-1',
      signerKeyVersion: 3,
    };
    const fullGrant = await createVaultKeyGrant(keys, recipient.publicKey, signer.privateKey, {
      ...baseScope,
      capability: 'full',
    });
    const opened = await openVaultKeyGrant(fullGrant, recipient, signer.publicKey, {
      vaultId: 'vault-1',
      recipientId: 'user-1',
      epoch: 7,
      recipientKeyVersion: 2,
    });
    expect(opened.metadataKey).toEqual(keys.metadataKey);
    expect(opened.contentKey).toEqual(keys.contentKey);

    const metadataGrant = await createVaultKeyGrant(keys, recipient.publicKey, signer.privateKey, {
      ...baseScope,
      capability: 'metadata',
    });
    const metadataOnly = await openVaultKeyGrant(
      metadataGrant,
      recipient,
      signer.publicKey,
      { vaultId: 'vault-1', recipientId: 'user-1' },
    );
    expect(metadataOnly.metadataKey).toEqual(keys.metadataKey);
    expect(metadataOnly.contentKey).toBeUndefined();

    const otherRecipient = await generateEncryptionKeyPair();
    await expect(
      openVaultKeyGrant(fullGrant, otherRecipient, signer.publicKey, {
        vaultId: 'vault-1',
        recipientId: 'user-1',
      }),
    ).rejects.toMatchObject({ code: 'authentication_failed' });
    await expect(
      openVaultKeyGrant(
        { ...fullGrant, sealedKeyBundle: mutate(fullGrant.sealedKeyBundle) },
        recipient,
        signer.publicKey,
        { vaultId: 'vault-1', recipientId: 'user-1' },
      ),
    ).rejects.toMatchObject({ code: 'verification_failed' });

    await destroyVaultKeys(opened);
    await destroyVaultKeys(metadataOnly);
    await destroyVaultKeys(keys);
    recipient.privateKey.fill(0);
    otherRecipient.privateKey.fill(0);
    signer.privateKey.fill(0);
  });

  it('encrypts metadata separately and wraps a random key for each content version', async () => {
    const keys = await createVaultKeys(2);
    const vaultHeader = await encryptVaultMetadata(
      keys.metadataKey,
      { vaultId: 'vault-2', version: 1, keyEpoch: 2 },
      { name: 'Platform credentials' },
    );
    expect(JSON.stringify(vaultHeader)).not.toContain('Platform credentials');
    expect(await decryptVaultMetadata(keys.metadataKey, vaultHeader)).toEqual({
      name: 'Platform credentials',
    });
    const context = {
      vaultId: 'vault-2',
      itemId: 'item-2',
      version: 4,
      secretVersion: 3,
      keyEpoch: 2,
    };
    const encrypted = await encryptItemVersion(keys, context, {
      metadata: { title: 'Production API', username: 'service-account', tags: ['prod'] },
      content: { password: 'plaintext-canary', token: 'token-canary', notes: 'line 1\nline 2' },
    });
    expect(JSON.stringify(encrypted)).not.toContain('plaintext-canary');
    expect(await decryptItemMetadata(keys.metadataKey, encrypted)).toEqual({
      title: 'Production API',
      username: 'service-account',
      tags: ['prod'],
    });
    expect(await decryptItemVersion(keys, encrypted)).toEqual({
      metadata: { title: 'Production API', username: 'service-account', tags: ['prod'] },
      content: { password: 'plaintext-canary', token: 'token-canary', notes: 'line 1\nline 2' },
    });

    const tamperedWrap: CipherBlob = {
      ...encrypted.wrappedDek,
      ciphertext: mutate(encrypted.wrappedDek.ciphertext),
    };
    await expect(
      decryptItemContent(keys.contentKey, { ...encrypted, wrappedDek: tamperedWrap }),
    ).rejects.toMatchObject({ code: 'authentication_failed' });
    await expect(
      decryptItemContent(keys.contentKey, { ...encrypted, secretVersion: 4 }),
    ).rejects.toMatchObject({ code: 'authentication_failed' });

    await expect(
      decryptItemContent(keys.contentKey, { ...encrypted, itemId: 'other-item' }),
    ).rejects.toMatchObject({ code: 'authentication_failed' });

    const nextKeys = await createVaultKeys(3);
    const rewrapped = await rewrapItemContentKey(
      keys.contentKey,
      nextKeys.contentKey,
      encrypted,
      3,
    );
    const rotated = { ...encrypted, ...rewrapped };
    expect(rotated.encryptedValue).toEqual(encrypted.encryptedValue);
    expect(await decryptItemContent(nextKeys.contentKey, rotated)).toEqual({
      password: 'plaintext-canary',
      token: 'token-canary',
      notes: 'line 1\nline 2',
    });
    await expect(decryptItemContent(keys.contentKey, rotated)).rejects.toMatchObject({
      code: 'authentication_failed',
    });
    await expect(
      decryptItemContent(nextKeys.contentKey, { ...rotated, itemId: 'other-item' }),
    ).rejects.toMatchObject({ code: 'authentication_failed' });
    await destroyVaultKeys(nextKeys);
    await destroyVaultKeys(keys);
  });
});
