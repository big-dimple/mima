import type { AadContext } from './aad.ts';
import {
  decryptBytes,
  encryptBytes,
  validateAeadEnvelope,
  type CipherBlob,
} from './aead.ts';
import {
  encryptionPublicKeyFromPrivate,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  signingPublicKeyFromPrivate,
  type EncryptionKeyPair,
  type SigningKeyPair,
} from './asymmetric.ts';
import {
  AEAD_NONCE_BYTES,
  AAD_VERSION,
  E2EE_PROTOCOL,
  E2eeError,
  KEY_BYTES,
} from './constants.ts';
import {
  assertIdentifier,
  assertPositiveVersion,
  assertProtocol,
  fromBase64Url,
  sodiumReady,
  toBase64Url,
} from './encoding.ts';
import { createKdfProfile, deriveMasterKey, type KdfProfile } from './kdf.ts';

const ACCOUNT_PROFILE_VERSION = 1;
const ACCOUNT_KEY_VERSION = 1;

export interface AccountBundle {
  accountId: string;
  profileVersion: typeof ACCOUNT_PROFILE_VERSION;
  keyVersion: number;
  suite: typeof E2EE_PROTOCOL;
  kdf: KdfProfile;
  encryptedAccountBundle: CipherBlob;
  encryptionPublicKey: string;
  signingPublicKey: string;
}

export interface DeviceKeyBundle {
  suite: typeof E2EE_PROTOCOL;
  kind: 'device-key-bundle';
  accountId: string;
  deviceId: string;
  keyVersion: typeof ACCOUNT_KEY_VERSION;
  encryptionPublicKey: string;
  signingPublicKey: string;
  encryptedPrivateKeys: CipherBlob;
}

export interface UnlockedAccount {
  accountId: string;
  accountKey: Uint8Array;
  encryptionKeyPair: EncryptionKeyPair;
  signingKeyPair: SigningKeyPair;
  device?: {
    deviceId: string;
    encryptionKeyPair: EncryptionKeyPair;
    signingKeyPair: SigningKeyPair;
  };
}

export interface CreatedAccount {
  accountBundle: AccountBundle;
  deviceBundle: DeviceKeyBundle;
  unlocked: UnlockedAccount;
}

export type PreparedAccountIdentityRotation = CreatedAccount;

export async function createAccountBundle(
  masterPassword: string | Uint8Array,
  input: { accountId: string; deviceId: string; kdfSalt?: Uint8Array },
): Promise<CreatedAccount> {
  assertIdentifier(input.accountId, 'accountId');
  assertIdentifier(input.deviceId, 'deviceId');
  const crypto = await sodiumReady();
  const kdf = await createKdfProfile(input.kdfSalt);
  const masterKey = await deriveMasterKey(masterPassword, kdf);
  const accountKey = crypto.randombytes_buf(KEY_BYTES);
  const encryptionKeyPair = await generateEncryptionKeyPair();
  const signingKeyPair = await generateSigningKeyPair();
  let device:
    | Awaited<ReturnType<typeof createDeviceKeyBundle>>
    | undefined;
  try {
    const encryptedPrivateKeys = await encryptPrivateKeyPair(
      accountKey,
      encryptionKeyPair,
      signingKeyPair,
      accountPrivateKeysAad(input.accountId),
    );
    const packedAccount = await packAccountPayload(accountKey, encryptedPrivateKeys);
    let encryptedAccountBundle: CipherBlob;
    try {
      encryptedAccountBundle = await encryptBytes(
        masterKey,
        packedAccount,
        accountBundleAad(input.accountId),
      );
    } finally {
      crypto.memzero(packedAccount);
    }
    device = await createDeviceKeyBundle(accountKey, {
      accountId: input.accountId,
      deviceId: input.deviceId,
    });
    return {
      accountBundle: {
        accountId: input.accountId,
        profileVersion: ACCOUNT_PROFILE_VERSION,
        keyVersion: ACCOUNT_KEY_VERSION,
        suite: E2EE_PROTOCOL,
        kdf,
        encryptedAccountBundle,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        signingPublicKey: signingKeyPair.publicKey,
      },
      deviceBundle: device.bundle,
      unlocked: {
        accountId: input.accountId,
        accountKey,
        encryptionKeyPair,
        signingKeyPair,
        device: {
          deviceId: input.deviceId,
          encryptionKeyPair: device.encryptionKeyPair,
          signingKeyPair: device.signingKeyPair,
        },
      },
    };
  } catch (error) {
    crypto.memzero(accountKey);
    crypto.memzero(encryptionKeyPair.privateKey);
    crypto.memzero(signingKeyPair.privateKey);
    if (device) {
      crypto.memzero(device.encryptionKeyPair.privateKey);
      crypto.memzero(device.signingKeyPair.privateKey);
    }
    throw error;
  } finally {
    crypto.memzero(masterKey);
  }
}

export async function createDeviceKeyBundle(
  accountKey: Uint8Array,
  input: { accountId: string; deviceId: string },
): Promise<{
  bundle: DeviceKeyBundle;
  encryptionKeyPair: EncryptionKeyPair;
  signingKeyPair: SigningKeyPair;
}> {
  assertAccountKey(accountKey);
  assertIdentifier(input.accountId, 'accountId');
  assertIdentifier(input.deviceId, 'deviceId');
  const crypto = await sodiumReady();
  const encryptionKeyPair = await generateEncryptionKeyPair();
  const signingKeyPair = await generateSigningKeyPair();
  try {
    const encryptedPrivateKeys = await encryptPrivateKeyPair(
      accountKey,
      encryptionKeyPair,
      signingKeyPair,
      devicePrivateKeysAad(input.accountId, input.deviceId),
    );
    return {
      bundle: {
        suite: E2EE_PROTOCOL,
        kind: 'device-key-bundle',
        accountId: input.accountId,
        deviceId: input.deviceId,
        keyVersion: ACCOUNT_KEY_VERSION,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        signingPublicKey: signingKeyPair.publicKey,
        encryptedPrivateKeys,
      },
      encryptionKeyPair,
      signingKeyPair,
    };
  } catch (error) {
    crypto.memzero(encryptionKeyPair.privateKey);
    crypto.memzero(signingKeyPair.privateKey);
    throw error;
  }
}

export async function unlockAccountBundle(
  masterPassword: string | Uint8Array,
  accountBundle: AccountBundle,
  deviceBundle?: DeviceKeyBundle,
): Promise<UnlockedAccount> {
  validateAccountBundle(accountBundle);
  if (deviceBundle) validateDeviceBundle(deviceBundle, accountBundle.accountId);
  const crypto = await sodiumReady();
  const masterKey = await deriveMasterKey(masterPassword, accountBundle.kdf);
  let accountKey: Uint8Array | undefined;
  let accountPairs: Awaited<ReturnType<typeof decryptPrivateKeyPair>> | undefined;
  let devicePairs: Awaited<ReturnType<typeof decryptPrivateKeyPair>> | undefined;
  try {
    const packedAccount = await decryptBytes(
      masterKey,
      accountBundle.encryptedAccountBundle,
      accountBundleAad(accountBundle.accountId),
    );
    let encryptedPrivateKeys: CipherBlob;
    try {
      ({ accountKey, encryptedPrivateKeys } = await unpackAccountPayload(packedAccount));
    } finally {
      crypto.memzero(packedAccount);
    }
    accountPairs = await decryptPrivateKeyPair(
      accountKey,
      encryptedPrivateKeys,
      accountPrivateKeysAad(accountBundle.accountId),
      {
        encryptionPublicKey: accountBundle.encryptionPublicKey,
        signingPublicKey: accountBundle.signingPublicKey,
      },
    );
    if (deviceBundle) {
      devicePairs = await decryptPrivateKeyPair(
        accountKey,
        deviceBundle.encryptedPrivateKeys,
        devicePrivateKeysAad(accountBundle.accountId, deviceBundle.deviceId),
        deviceBundle,
      );
    }
    return {
      accountId: accountBundle.accountId,
      accountKey,
      encryptionKeyPair: accountPairs.encryptionKeyPair,
      signingKeyPair: accountPairs.signingKeyPair,
      device: devicePairs && deviceBundle
        ? {
            deviceId: deviceBundle.deviceId,
            encryptionKeyPair: devicePairs.encryptionKeyPair,
            signingKeyPair: devicePairs.signingKeyPair,
          }
        : undefined,
    };
  } catch (error) {
    if (accountKey) crypto.memzero(accountKey);
    destroyPrivatePairs(accountPairs);
    destroyPrivatePairs(devicePairs);
    if (error instanceof E2eeError && error.code === 'invalid_input') throw error;
    throw new E2eeError('authentication_failed', 'Unable to unlock account');
  } finally {
    crypto.memzero(masterKey);
  }
}

export async function changeMasterPassword(
  currentPassword: string | Uint8Array,
  newPassword: string | Uint8Array,
  accountBundle: AccountBundle,
  newSalt?: Uint8Array,
): Promise<AccountBundle> {
  validateAccountBundle(accountBundle);
  const crypto = await sodiumReady();
  const currentMasterKey = await deriveMasterKey(currentPassword, accountBundle.kdf);
  let packedAccount: Uint8Array | undefined;
  let newMasterKey: Uint8Array | undefined;
  try {
    packedAccount = await decryptBytes(
      currentMasterKey,
      accountBundle.encryptedAccountBundle,
      accountBundleAad(accountBundle.accountId),
    );
    const kdf = await createKdfProfile(newSalt);
    newMasterKey = await deriveMasterKey(newPassword, kdf);
    return {
      ...accountBundle,
      kdf,
      encryptedAccountBundle: await encryptBytes(
        newMasterKey,
        packedAccount,
        accountBundleAad(accountBundle.accountId),
      ),
    };
  } catch (error) {
    if (error instanceof E2eeError && error.code === 'invalid_input') throw error;
    throw new E2eeError('authentication_failed', 'Unable to change master password');
  } finally {
    crypto.memzero(currentMasterKey);
    if (newMasterKey) crypto.memzero(newMasterKey);
    if (packedAccount) crypto.memzero(packedAccount);
  }
}

export async function prepareAccountIdentityRotation(
  masterPassword: string | Uint8Array,
  accountBundle: AccountBundle,
  account: UnlockedAccount,
  input: { deviceId: string },
): Promise<PreparedAccountIdentityRotation> {
  validateAccountBundle(accountBundle);
  assertIdentifier(input.deviceId, 'deviceId');
  if (
    account.accountId !== accountBundle.accountId ||
    account.encryptionKeyPair.publicKey !== accountBundle.encryptionPublicKey ||
    account.signingKeyPair.publicKey !== accountBundle.signingPublicKey
  ) {
    throw new E2eeError('verification_failed', 'Unlocked account does not match profile');
  }
  const crypto = await sodiumReady();
  const masterKey = await deriveMasterKey(masterPassword, accountBundle.kdf);
  let authenticatedAccountKey: Uint8Array | undefined;
  let nextAccountKey: Uint8Array | undefined;
  let nextEncryptionKeyPair: EncryptionKeyPair | undefined;
  let nextSigningKeyPair: SigningKeyPair | undefined;
  let nextDevice: Awaited<ReturnType<typeof createDeviceKeyBundle>> | undefined;
  try {
    const currentPacked = await decryptBytes(
      masterKey,
      accountBundle.encryptedAccountBundle,
      accountBundleAad(accountBundle.accountId),
    );
    try {
      ({ accountKey: authenticatedAccountKey } = await unpackAccountPayload(currentPacked));
      if (!crypto.memcmp(authenticatedAccountKey, account.accountKey)) {
        throw new E2eeError('verification_failed', 'Unlocked account key does not match profile');
      }
    } finally {
      crypto.memzero(currentPacked);
      if (authenticatedAccountKey) crypto.memzero(authenticatedAccountKey);
    }

    nextAccountKey = crypto.randombytes_buf(KEY_BYTES);
    nextEncryptionKeyPair = await generateEncryptionKeyPair();
    nextSigningKeyPair = await generateSigningKeyPair();
    const encryptedPrivateKeys = await encryptPrivateKeyPair(
      nextAccountKey,
      nextEncryptionKeyPair,
      nextSigningKeyPair,
      accountPrivateKeysAad(accountBundle.accountId),
    );
    const packedAccount = await packAccountPayload(nextAccountKey, encryptedPrivateKeys);
    let encryptedAccountBundle: CipherBlob;
    try {
      encryptedAccountBundle = await encryptBytes(
        masterKey,
        packedAccount,
        accountBundleAad(accountBundle.accountId),
      );
    } finally {
      crypto.memzero(packedAccount);
    }
    nextDevice = await createDeviceKeyBundle(nextAccountKey, {
      accountId: accountBundle.accountId,
      deviceId: input.deviceId,
    });
    return {
      accountBundle: {
        ...accountBundle,
        keyVersion: accountBundle.keyVersion + 1,
        encryptedAccountBundle,
        encryptionPublicKey: nextEncryptionKeyPair.publicKey,
        signingPublicKey: nextSigningKeyPair.publicKey,
      },
      deviceBundle: nextDevice.bundle,
      unlocked: {
        accountId: accountBundle.accountId,
        accountKey: nextAccountKey,
        encryptionKeyPair: nextEncryptionKeyPair,
        signingKeyPair: nextSigningKeyPair,
        device: {
          deviceId: input.deviceId,
          encryptionKeyPair: nextDevice.encryptionKeyPair,
          signingKeyPair: nextDevice.signingKeyPair,
        },
      },
    };
  } catch (error) {
    if (nextAccountKey) crypto.memzero(nextAccountKey);
    if (nextEncryptionKeyPair) crypto.memzero(nextEncryptionKeyPair.privateKey);
    if (nextSigningKeyPair) crypto.memzero(nextSigningKeyPair.privateKey);
    if (nextDevice) {
      crypto.memzero(nextDevice.encryptionKeyPair.privateKey);
      crypto.memzero(nextDevice.signingKeyPair.privateKey);
    }
    if (error instanceof E2eeError && error.code === 'invalid_input') throw error;
    throw new E2eeError('authentication_failed', 'Unable to prepare account identity rotation');
  } finally {
    crypto.memzero(masterKey);
  }
}

export async function destroyUnlockedAccount(account: UnlockedAccount): Promise<void> {
  const crypto = await sodiumReady();
  crypto.memzero(account.accountKey);
  crypto.memzero(account.encryptionKeyPair.privateKey);
  crypto.memzero(account.signingKeyPair.privateKey);
  if (account.device) {
    crypto.memzero(account.device.encryptionKeyPair.privateKey);
    crypto.memzero(account.device.signingKeyPair.privateKey);
  }
}

function validateAccountBundle(bundle: AccountBundle): void {
  assertProtocol(bundle.suite);
  if (
    bundle.profileVersion !== ACCOUNT_PROFILE_VERSION ||
    !Number.isSafeInteger(bundle.keyVersion)
  ) {
    throw new E2eeError('unsupported_protocol', 'Unsupported account bundle');
  }
  assertIdentifier(bundle.accountId, 'accountId');
  assertPositiveVersion(bundle.keyVersion, 'keyVersion');
  validateAeadEnvelope(bundle.encryptedAccountBundle);
}

function validateDeviceBundle(bundle: DeviceKeyBundle, accountId: string): void {
  assertProtocol(bundle.suite);
  if (
    bundle.kind !== 'device-key-bundle' ||
    bundle.keyVersion !== ACCOUNT_KEY_VERSION ||
    bundle.accountId !== accountId
  ) {
    throw new E2eeError('verification_failed', 'Device bundle is not bound to this account');
  }
  assertIdentifier(bundle.deviceId, 'deviceId');
}

async function encryptPrivateKeyPair(
  accountKey: Uint8Array,
  encryptionKeyPair: EncryptionKeyPair,
  signingKeyPair: SigningKeyPair,
  context: AadContext,
): Promise<CipherBlob> {
  const crypto = await sodiumReady();
  const packed = new Uint8Array(
    encryptionKeyPair.privateKey.byteLength + signingKeyPair.privateKey.byteLength,
  );
  packed.set(encryptionKeyPair.privateKey, 0);
  packed.set(signingKeyPair.privateKey, encryptionKeyPair.privateKey.byteLength);
  try {
    return await encryptBytes(accountKey, packed, context);
  } finally {
    crypto.memzero(packed);
  }
}

async function decryptPrivateKeyPair(
  accountKey: Uint8Array,
  envelope: CipherBlob,
  context: AadContext,
  expectedPublicKeys: { encryptionPublicKey: string; signingPublicKey: string },
): Promise<{ encryptionKeyPair: EncryptionKeyPair; signingKeyPair: SigningKeyPair }> {
  const crypto = await sodiumReady();
  const packed = await decryptBytes(accountKey, envelope, context);
  const expectedLength = crypto.crypto_box_SECRETKEYBYTES + crypto.crypto_sign_SECRETKEYBYTES;
  if (packed.byteLength !== expectedLength) {
    crypto.memzero(packed);
    throw new E2eeError('verification_failed', 'Private key bundle has an invalid length');
  }
  const encryptionPrivateKey = packed.slice(0, crypto.crypto_box_SECRETKEYBYTES);
  const signingPrivateKey = packed.slice(crypto.crypto_box_SECRETKEYBYTES);
  crypto.memzero(packed);
  const encryptionPublicKey = await encryptionPublicKeyFromPrivate(encryptionPrivateKey);
  const signingPublicKey = await signingPublicKeyFromPrivate(signingPrivateKey);
  if (
    encryptionPublicKey !== expectedPublicKeys.encryptionPublicKey ||
    signingPublicKey !== expectedPublicKeys.signingPublicKey
  ) {
    crypto.memzero(encryptionPrivateKey);
    crypto.memzero(signingPrivateKey);
    throw new E2eeError('verification_failed', 'Private keys do not match the published keys');
  }
  return {
    encryptionKeyPair: { publicKey: encryptionPublicKey, privateKey: encryptionPrivateKey },
    signingKeyPair: { publicKey: signingPublicKey, privateKey: signingPrivateKey },
  };
}

async function packAccountPayload(
  accountKey: Uint8Array,
  encryptedPrivateKeys: CipherBlob,
): Promise<Uint8Array> {
  validateAeadEnvelope(encryptedPrivateKeys);
  const crypto = await sodiumReady();
  const nonce = await fromBase64Url(encryptedPrivateKeys.nonce, AEAD_NONCE_BYTES);
  const ciphertext = await fromBase64Url(encryptedPrivateKeys.ciphertext);
  const expectedCiphertextBytes =
    crypto.crypto_box_SECRETKEYBYTES +
    crypto.crypto_sign_SECRETKEYBYTES +
    crypto.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (ciphertext.byteLength !== expectedCiphertextBytes) {
    crypto.memzero(nonce);
    crypto.memzero(ciphertext);
    throw new E2eeError('verification_failed', 'Encrypted account private keys have an invalid length');
  }
  const packed = new Uint8Array(KEY_BYTES + nonce.byteLength + ciphertext.byteLength);
  packed.set(accountKey, 0);
  packed.set(nonce, KEY_BYTES);
  packed.set(ciphertext, KEY_BYTES + nonce.byteLength);
  crypto.memzero(nonce);
  crypto.memzero(ciphertext);
  return packed;
}

async function unpackAccountPayload(packed: Uint8Array): Promise<{
  accountKey: Uint8Array;
  encryptedPrivateKeys: CipherBlob;
}> {
  const crypto = await sodiumReady();
  const ciphertextBytes =
    crypto.crypto_box_SECRETKEYBYTES +
    crypto.crypto_sign_SECRETKEYBYTES +
    crypto.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (packed.byteLength !== KEY_BYTES + AEAD_NONCE_BYTES + ciphertextBytes) {
    throw new E2eeError('verification_failed', 'Encrypted account bundle has an invalid length');
  }
  return {
    accountKey: packed.slice(0, KEY_BYTES),
    encryptedPrivateKeys: {
      suite: E2EE_PROTOCOL,
      aadVersion: AAD_VERSION,
      nonce: await toBase64Url(packed.subarray(KEY_BYTES, KEY_BYTES + AEAD_NONCE_BYTES)),
      ciphertext: await toBase64Url(packed.subarray(KEY_BYTES + AEAD_NONCE_BYTES)),
    },
  };
}

function accountBundleAad(accountId: string) {
  return { blobType: 'account-key-wrap' as const, accountId, recordVersion: ACCOUNT_PROFILE_VERSION };
}

function accountPrivateKeysAad(accountId: string) {
  return {
    blobType: 'account-private-key-bundle' as const,
    accountId,
    recordVersion: ACCOUNT_KEY_VERSION,
  };
}

function devicePrivateKeysAad(accountId: string, deviceId: string) {
  return {
    blobType: 'device-private-key-bundle' as const,
    accountId,
    deviceId,
    recordVersion: ACCOUNT_KEY_VERSION,
  };
}

function assertAccountKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== KEY_BYTES) {
    throw new E2eeError('invalid_input', `Account key must be ${KEY_BYTES} bytes`);
  }
}

function destroyPrivatePairs(
  pairs: Awaited<ReturnType<typeof decryptPrivateKeyPair>> | undefined,
): void {
  pairs?.encryptionKeyPair.privateKey.fill(0);
  pairs?.signingKeyPair.privateKey.fill(0);
}
