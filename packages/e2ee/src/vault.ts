import {
  openSealedBytes,
  sealBytes,
  signBytes,
  verifyBytes,
  type EncryptionKeyPair,
} from './asymmetric.ts';
import { E2EE_PROTOCOL, E2eeError, KEY_BYTES } from './constants.ts';
import {
  assertIdentifier,
  assertPositiveVersion,
  canonicalJson,
  sodiumReady,
  utf8,
  type JsonValue,
} from './encoding.ts';

export type CryptoCapability = 'full' | 'metadata' | 'recovery';
export type VaultKeyRecipientKind = 'device' | 'recovery' | 'user';

export interface VaultKeys {
  keyEpoch: number;
  metadataKey: Uint8Array;
  contentKey?: Uint8Array;
}

export interface VaultKeyEnvelopeInput {
  vaultId: string;
  epoch: number;
  recipientKind: VaultKeyRecipientKind;
  recipientId: string;
  recipientKeyVersion: number;
  capability: CryptoCapability;
  sealedKeyBundle: string;
  signerUserId: string;
  signerKeyVersion: number;
  signature: string;
}

export type VaultKeyGrant = VaultKeyEnvelopeInput;
export type UnsignedVaultKeyEnvelopeInput = Omit<VaultKeyEnvelopeInput, 'signature'>;

type GrantScope = Omit<VaultKeyEnvelopeInput, 'sealedKeyBundle' | 'signature'>;

export async function createVaultKeys(keyEpoch = 1): Promise<Required<VaultKeys>> {
  assertPositiveVersion(keyEpoch, 'keyEpoch');
  const crypto = await sodiumReady();
  return {
    keyEpoch,
    metadataKey: crypto.randombytes_buf(KEY_BYTES),
    contentKey: crypto.randombytes_buf(KEY_BYTES),
  };
}

export async function createVaultKeyGrant(
  vaultKeys: Required<VaultKeys>,
  recipientPublicKey: string,
  signerPrivateKey: Uint8Array,
  scope: Omit<GrantScope, 'epoch'>,
): Promise<VaultKeyEnvelopeInput> {
  const unsigned = await createUnsignedVaultKeyGrant(vaultKeys, recipientPublicKey, scope);
  return signVaultKeyGrant(unsigned, signerPrivateKey);
}

export async function createUnsignedVaultKeyGrant(
  vaultKeys: Required<VaultKeys>,
  recipientPublicKey: string,
  scope: Omit<GrantScope, 'epoch'>,
): Promise<UnsignedVaultKeyEnvelopeInput> {
  const fullScope: GrantScope = { ...scope, epoch: vaultKeys.keyEpoch };
  validateGrantScope(fullScope);
  assertVaultKey(vaultKeys.metadataKey, 'metadataKey');
  assertVaultKey(vaultKeys.contentKey, 'contentKey');
  const payload = await vaultKeyPayload(vaultKeys, fullScope);
  let sealedKeyBundle: string;
  try {
    sealedKeyBundle = await sealBytes(payload, recipientPublicKey);
  } finally {
    payload.fill(0);
  }
  return { ...fullScope, sealedKeyBundle };
}

export async function signVaultKeyGrant(
  unsigned: UnsignedVaultKeyEnvelopeInput,
  signerPrivateKey: Uint8Array,
): Promise<VaultKeyEnvelopeInput> {
  validateGrantScope(unsigned);
  assertIdentifier(unsigned.sealedKeyBundle, 'sealedKeyBundle');
  const message = grantBytes(unsigned);
  try {
    return { ...unsigned, signature: await signBytes(message, signerPrivateKey) };
  } finally {
    message.fill(0);
  }
}

export async function verifyVaultKeyGrantSignature(
  grant: VaultKeyEnvelopeInput,
  trustedSignerPublicKey: string,
): Promise<boolean> {
  validateGrant(grant);
  const message = grantBytes(grant);
  try {
    return await verifyBytes(grant.signature, message, trustedSignerPublicKey);
  } finally {
    message.fill(0);
  }
}

export async function openVaultKeyGrant(
  grant: VaultKeyEnvelopeInput,
  recipient: EncryptionKeyPair,
  trustedSignerPublicKey: string,
  expected: {
    vaultId: string;
    recipientId: string;
    epoch?: number;
    recipientKeyVersion?: number;
  },
): Promise<VaultKeys> {
  validateGrant(grant);
  if (
    grant.vaultId !== expected.vaultId ||
    grant.recipientId !== expected.recipientId ||
    (expected.epoch !== undefined && grant.epoch !== expected.epoch) ||
    (expected.recipientKeyVersion !== undefined &&
      grant.recipientKeyVersion !== expected.recipientKeyVersion)
  ) {
    throw new E2eeError('verification_failed', 'Vault key envelope scope does not match');
  }
  if (!(await verifyVaultKeyGrantSignature(grant, trustedSignerPublicKey))) {
    throw new E2eeError('verification_failed', 'Vault key envelope signature is invalid');
  }

  const payload = await openSealedBytes(grant.sealedKeyBundle, recipient);
  const crypto = await sodiumReady();
  try {
    const hasContentKey = capabilityCanDecryptContent(grant.capability);
    const expectedLength = hasContentKey ? KEY_BYTES * 3 : KEY_BYTES * 2;
    if (payload.byteLength !== expectedLength) {
      throw new E2eeError('verification_failed', 'Vault key bundle has an invalid length');
    }
    const expectedBinding = await vaultKeyBinding(grant);
    try {
      if (!crypto.memcmp(payload.subarray(0, KEY_BYTES), expectedBinding)) {
        throw new E2eeError('verification_failed', 'Vault key bundle scope does not match');
      }
      return {
        keyEpoch: grant.epoch,
        metadataKey: payload.slice(KEY_BYTES, KEY_BYTES * 2),
        contentKey: hasContentKey ? payload.slice(KEY_BYTES * 2) : undefined,
      };
    } finally {
      crypto.memzero(expectedBinding);
    }
  } finally {
    crypto.memzero(payload);
  }
}

export function capabilityCanDecryptContent(capability: CryptoCapability): boolean {
  return capability === 'full' || capability === 'recovery';
}

export async function destroyVaultKeys(keys: VaultKeys): Promise<void> {
  const crypto = await sodiumReady();
  crypto.memzero(keys.metadataKey);
  if (keys.contentKey) crypto.memzero(keys.contentKey);
}

async function vaultKeyPayload(
  keys: Required<VaultKeys>,
  scope: GrantScope,
): Promise<Uint8Array> {
  const crypto = await sodiumReady();
  const binding = await vaultKeyBinding(scope);
  const hasContentKey = capabilityCanDecryptContent(scope.capability);
  const payload = new Uint8Array(hasContentKey ? KEY_BYTES * 3 : KEY_BYTES * 2);
  payload.set(binding, 0);
  payload.set(keys.metadataKey, KEY_BYTES);
  if (hasContentKey) payload.set(keys.contentKey, KEY_BYTES * 2);
  crypto.memzero(binding);
  return payload;
}

async function vaultKeyBinding(scope: GrantScope): Promise<Uint8Array> {
  const crypto = await sodiumReady();
  const encoded = utf8(canonicalJson(grantScopeJson(scope, 'vault-key-bundle')));
  try {
    return crypto.crypto_generichash(KEY_BYTES, encoded, null);
  } finally {
    crypto.memzero(encoded);
  }
}

function grantBytes(
  grant: Omit<VaultKeyEnvelopeInput, 'signature'> | VaultKeyEnvelopeInput,
): Uint8Array {
  const body: JsonValue = {
    ...grantScopeJson(grant, 'vault-key-envelope'),
    sealedKeyBundle: grant.sealedKeyBundle,
  };
  return utf8(canonicalJson(body));
}

function grantScopeJson(scope: GrantScope, kind: string): Record<string, JsonValue> {
  return {
    capability: scope.capability,
    epoch: scope.epoch,
    kind,
    protocol: E2EE_PROTOCOL,
    recipientId: scope.recipientId,
    recipientKeyVersion: scope.recipientKeyVersion,
    recipientKind: scope.recipientKind,
    signerKeyVersion: scope.signerKeyVersion,
    signerUserId: scope.signerUserId,
    vaultId: scope.vaultId,
  };
}

function validateGrant(grant: VaultKeyEnvelopeInput): void {
  validateGrantScope(grant);
  assertIdentifier(grant.sealedKeyBundle, 'sealedKeyBundle');
  assertIdentifier(grant.signature, 'signature');
}

function validateGrantScope(scope: GrantScope): void {
  assertIdentifier(scope.vaultId, 'vaultId');
  assertPositiveVersion(scope.epoch, 'epoch');
  assertIdentifier(scope.recipientId, 'recipientId');
  assertPositiveVersion(scope.recipientKeyVersion, 'recipientKeyVersion');
  assertIdentifier(scope.signerUserId, 'signerUserId');
  assertPositiveVersion(scope.signerKeyVersion, 'signerKeyVersion');
  if (!['device', 'recovery', 'user'].includes(scope.recipientKind)) {
    throw new E2eeError('invalid_input', 'Unsupported vault key recipient kind');
  }
  if (!['full', 'metadata', 'recovery'].includes(scope.capability)) {
    throw new E2eeError('invalid_input', 'Unsupported vault key capability');
  }
}

function assertVaultKey(key: Uint8Array, name: string): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== KEY_BYTES) {
    throw new E2eeError('invalid_input', `${name} must be ${KEY_BYTES} bytes`);
  }
}
