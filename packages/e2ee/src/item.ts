import { decryptBytes, encryptBytes, type AeadEnvelope } from './aead.ts';
import { E2eeError, KEY_BYTES } from './constants.ts';
import {
  assertIdentifier,
  assertPositiveVersion,
  decodeJson,
  encodeJson,
  sodiumReady,
  type JsonValue,
} from './encoding.ts';
import type { VaultKeys } from './vault.ts';

export interface ItemVersionContext {
  vaultId: string;
  itemId: string;
  itemKind?: 'login' | 'api_token' | 'secure_note';
  version: number;
  secretVersion: number;
  keyEpoch: number;
}

export interface EncryptedItemVersion extends ItemVersionContext {
  metadata: AeadEnvelope;
  wrappedDek: AeadEnvelope;
  encryptedValue: AeadEnvelope;
}

export interface RewrappedItemContentKey {
  keyEpoch: number;
  wrappedDek: AeadEnvelope;
}

export interface VaultMetadataContext {
  vaultId: string;
  version: number;
  keyEpoch: number;
}

export interface EncryptedVaultMetadata extends VaultMetadataContext {
  blob: AeadEnvelope;
}

export async function encryptVaultMetadata(
  metadataKey: Uint8Array,
  context: VaultMetadataContext,
  metadata: JsonValue,
): Promise<EncryptedVaultMetadata> {
  validateVaultMetadataContext(context);
  assertKey(metadataKey, 'metadataKey');
  const crypto = await sodiumReady();
  const plaintext = encodeJson(metadata);
  try {
    return {
      ...context,
      blob: await encryptBytes(metadataKey, plaintext, vaultMetadataAad(context)),
    };
  } finally {
    crypto.memzero(plaintext);
  }
}

export async function decryptVaultMetadata(
  metadataKey: Uint8Array,
  encrypted: EncryptedVaultMetadata,
): Promise<JsonValue> {
  validateEncryptedVaultMetadata(encrypted);
  assertKey(metadataKey, 'metadataKey');
  const crypto = await sodiumReady();
  const plaintext = await decryptBytes(metadataKey, encrypted.blob, vaultMetadataAad(encrypted));
  try {
    return decodeJson(plaintext);
  } finally {
    crypto.memzero(plaintext);
  }
}

export async function encryptItemVersion(
  vaultKeys: Required<VaultKeys>,
  context: ItemVersionContext,
  value: { metadata: JsonValue; content: JsonValue },
): Promise<EncryptedItemVersion> {
  validateItemContext(context);
  if (vaultKeys.keyEpoch !== context.keyEpoch) {
    throw new E2eeError('verification_failed', 'Vault key epoch does not match item epoch');
  }
  assertKey(vaultKeys.metadataKey, 'metadataKey');
  assertKey(vaultKeys.contentKey, 'contentKey');
  const crypto = await sodiumReady();
  const itemContentKey = crypto.randombytes_buf(KEY_BYTES);
  const metadataPlaintext = encodeJson(value.metadata);
  const contentPlaintext = encodeJson(value.content);
  try {
    const [metadata, wrappedDek, encryptedValue] = await Promise.all([
      encryptBytes(vaultKeys.metadataKey, metadataPlaintext, itemAad(context, 'item-metadata')),
      encryptBytes(
        vaultKeys.contentKey,
        itemContentKey,
        itemAad(context, 'item-content-key-wrap'),
      ),
      encryptBytes(itemContentKey, contentPlaintext, itemAad(context, 'item-content')),
    ]);
    return {
      ...context,
      metadata,
      wrappedDek,
      encryptedValue,
    };
  } finally {
    crypto.memzero(itemContentKey);
    crypto.memzero(metadataPlaintext);
    crypto.memzero(contentPlaintext);
  }
}

export async function decryptItemMetadata(
  metadataKey: Uint8Array,
  encrypted: EncryptedItemVersion,
): Promise<JsonValue> {
  validateEncryptedItemVersion(encrypted);
  assertKey(metadataKey, 'metadataKey');
  const crypto = await sodiumReady();
  const plaintext = await decryptBytes(
    metadataKey,
    encrypted.metadata,
    itemAad(encrypted, 'item-metadata'),
  );
  try {
    return decodeJson(plaintext);
  } finally {
    crypto.memzero(plaintext);
  }
}

export async function decryptItemContent(
  contentKey: Uint8Array,
  encrypted: EncryptedItemVersion,
): Promise<JsonValue> {
  validateEncryptedItemVersion(encrypted);
  assertKey(contentKey, 'contentKey');
  const crypto = await sodiumReady();
  let kindBound = encrypted.itemKind !== undefined;
  let itemContentKey: Uint8Array;
  try {
    itemContentKey = await decryptBytes(
      contentKey,
      encrypted.wrappedDek,
      itemAad(encrypted, 'item-content-key-wrap'),
    );
  } catch (error) {
    if (!kindBound) throw error;
    kindBound = false;
    itemContentKey = await decryptBytes(
      contentKey,
      encrypted.wrappedDek,
      itemAad({ ...encrypted, itemKind: undefined }, 'item-content-key-wrap'),
    );
  }
  try {
    assertKey(itemContentKey, 'itemContentKey');
    const plaintext = await decryptBytes(
      itemContentKey,
      encrypted.encryptedValue,
      itemAad(kindBound ? encrypted : { ...encrypted, itemKind: undefined }, 'item-content'),
    );
    try {
      return decodeJson(plaintext);
    } finally {
      crypto.memzero(plaintext);
    }
  } finally {
    crypto.memzero(itemContentKey);
  }
}

export async function rewrapItemContentKey(
  currentVaultContentKey: Uint8Array,
  nextVaultContentKey: Uint8Array,
  encrypted: EncryptedItemVersion,
  nextKeyEpoch: number,
): Promise<RewrappedItemContentKey> {
  validateEncryptedItemVersion(encrypted);
  assertKey(currentVaultContentKey, 'currentVaultContentKey');
  assertKey(nextVaultContentKey, 'nextVaultContentKey');
  assertPositiveVersion(nextKeyEpoch, 'nextKeyEpoch');
  if (nextKeyEpoch <= encrypted.keyEpoch) {
    throw new E2eeError('invalid_input', 'nextKeyEpoch must be greater than the current epoch');
  }
  const crypto = await sodiumReady();
  let kindBound = encrypted.itemKind !== undefined;
  let itemContentKey: Uint8Array;
  try {
    itemContentKey = await decryptBytes(
      currentVaultContentKey,
      encrypted.wrappedDek,
      itemAad(encrypted, 'item-content-key-wrap'),
    );
  } catch (error) {
    if (!kindBound) throw error;
    kindBound = false;
    itemContentKey = await decryptBytes(
      currentVaultContentKey,
      encrypted.wrappedDek,
      itemAad({ ...encrypted, itemKind: undefined }, 'item-content-key-wrap'),
    );
  }
  try {
    assertKey(itemContentKey, 'itemContentKey');
    return {
      keyEpoch: nextKeyEpoch,
      wrappedDek: await encryptBytes(
        nextVaultContentKey,
        itemContentKey,
        itemAad({
          ...encrypted,
          keyEpoch: nextKeyEpoch,
          itemKind: kindBound ? encrypted.itemKind : undefined,
        }, 'item-content-key-wrap'),
      ),
    };
  } finally {
    crypto.memzero(itemContentKey);
  }
}

export async function decryptItemVersion(
  vaultKeys: Required<VaultKeys>,
  encrypted: EncryptedItemVersion,
): Promise<{ metadata: JsonValue; content: JsonValue }> {
  if (vaultKeys.keyEpoch !== encrypted.keyEpoch) {
    throw new E2eeError('verification_failed', 'Vault key epoch does not match item epoch');
  }
  const metadata = await decryptItemMetadata(vaultKeys.metadataKey, encrypted);
  const content = await decryptItemContent(vaultKeys.contentKey, encrypted);
  return { metadata, content };
}

function validateEncryptedVaultMetadata(encrypted: EncryptedVaultMetadata): void {
  validateVaultMetadataContext(encrypted);
}

function validateEncryptedItemVersion(encrypted: EncryptedItemVersion): void {
  validateItemContext(encrypted);
}

function validateVaultMetadataContext(context: VaultMetadataContext): void {
  assertIdentifier(context.vaultId, 'vaultId');
  assertPositiveVersion(context.version, 'version');
  assertPositiveVersion(context.keyEpoch, 'keyEpoch');
}

function validateItemContext(context: ItemVersionContext): void {
  assertIdentifier(context.vaultId, 'vaultId');
  assertIdentifier(context.itemId, 'itemId');
  if (context.itemKind !== undefined && !['login', 'api_token', 'secure_note'].includes(context.itemKind)) {
    throw new E2eeError('invalid_input', 'Unsupported item kind');
  }
  assertPositiveVersion(context.version, 'version');
  assertPositiveVersion(context.secretVersion, 'secretVersion');
  assertPositiveVersion(context.keyEpoch, 'keyEpoch');
}

function vaultMetadataAad(context: VaultMetadataContext) {
  return {
    blobType: 'vault-metadata' as const,
    vaultId: context.vaultId,
    recordVersion: context.version,
    keyEpoch: context.keyEpoch,
  };
}

function itemAad(
  context: ItemVersionContext,
  blobType: 'item-content' | 'item-content-key-wrap' | 'item-metadata',
) {
  return {
    blobType,
    vaultId: context.vaultId,
    itemId: context.itemId,
    recipientId: blobType === 'item-metadata' || context.itemKind === undefined
      ? undefined
      : `item-kind:${context.itemKind}`,
    recordVersion: context.version,
    secretVersion: context.secretVersion,
    // Content keeps immutable item/version AAD so epoch rotation can rewrap only its DEK.
    // Revocation advances the epoch on metadata and the wrapper, never on old ciphertext.
    keyEpoch: blobType === 'item-content' ? undefined : context.keyEpoch,
  };
}

function assertKey(key: Uint8Array, name: string): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== KEY_BYTES) {
    throw new E2eeError('invalid_input', `${name} must be ${KEY_BYTES} bytes`);
  }
}
