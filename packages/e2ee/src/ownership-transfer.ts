import { E2EE_PROTOCOL, E2eeError, KEY_BYTES } from './constants.ts';
import {
  canonicalJson,
  fromBase64Url,
  sodiumReady,
  toBase64Url,
  utf8,
  type JsonValue,
} from './encoding.ts';

export interface OwnershipTransferAcceptanceEvidence {
  transferId: string;
  vaultId: string;
  keyEpoch: number;
  envelopeTaskId: string;
  fromOwnerUserId: string;
  toOwnerUserId: string;
  expectedAccessGeneration: number;
  actorDeviceId: string;
  idempotencyKey: string;
  completedEnvelopeId: string;
  envelopeCiphertextDigest: string;
}

export function ownershipTransferAcceptanceEvidence(
  input: OwnershipTransferAcceptanceEvidence,
): JsonValue {
  return {
    actorDeviceId: input.actorDeviceId,
    completedEnvelopeId: input.completedEnvelopeId,
    envelopeCiphertextDigest: input.envelopeCiphertextDigest,
    envelopeTaskId: input.envelopeTaskId,
    expectedAccessGeneration: input.expectedAccessGeneration,
    fromOwnerUserId: input.fromOwnerUserId,
    idempotencyKey: input.idempotencyKey,
    keyEpoch: input.keyEpoch,
    kind: 'vault-ownership-transfer-acceptance',
    protocol: E2EE_PROTOCOL,
    toOwnerUserId: input.toOwnerUserId,
    transferId: input.transferId,
    vaultId: input.vaultId,
  };
}

export interface VaultKeyPossessionContext {
  vaultId: string;
  keyEpoch: number;
}

export interface VaultKeyPossessionKeys {
  metadataKey: Uint8Array;
  contentKey: Uint8Array;
}

export async function vaultKeyPossessionPublicKey(
  keys: VaultKeyPossessionKeys,
  context: VaultKeyPossessionContext,
): Promise<string> {
  const sodium = await sodiumReady();
  const seed = await deriveVaultKeyPossessionSeed(keys, context);
  let privateKey: Uint8Array | null = null;
  try {
    const pair = sodium.crypto_sign_seed_keypair(seed);
    privateKey = pair.privateKey;
    return await toBase64Url(pair.publicKey);
  } finally {
    sodium.memzero(seed);
    if (privateKey) sodium.memzero(privateKey);
  }
}

export async function signVaultKeyPossession(
  keys: VaultKeyPossessionKeys,
  evidence: OwnershipTransferAcceptanceEvidence,
): Promise<string> {
  const sodium = await sodiumReady();
  const seed = await deriveVaultKeyPossessionSeed(keys, {
    vaultId: evidence.vaultId,
    keyEpoch: evidence.keyEpoch,
  });
  const message = ownershipTransferAcceptanceBytes(evidence);
  let privateKey: Uint8Array | null = null;
  try {
    const pair = sodium.crypto_sign_seed_keypair(seed);
    privateKey = pair.privateKey;
    return await toBase64Url(sodium.crypto_sign_detached(message, privateKey));
  } finally {
    sodium.memzero(seed);
    sodium.memzero(message);
    if (privateKey) sodium.memzero(privateKey);
  }
}

export async function verifyVaultKeyPossession(
  signature: string,
  publicKey: string,
  evidence: OwnershipTransferAcceptanceEvidence,
): Promise<boolean> {
  const sodium = await sodiumReady();
  const signatureBytes = await fromBase64Url(signature, sodium.crypto_sign_BYTES);
  const publicKeyBytes = await fromBase64Url(publicKey, sodium.crypto_sign_PUBLICKEYBYTES);
  const message = ownershipTransferAcceptanceBytes(evidence);
  try {
    return sodium.crypto_sign_verify_detached(signatureBytes, message, publicKeyBytes);
  } finally {
    sodium.memzero(signatureBytes);
    sodium.memzero(publicKeyBytes);
    sodium.memzero(message);
  }
}

export async function ownershipTransferAcceptanceDigest(
  input: OwnershipTransferAcceptanceEvidence,
): Promise<string> {
  const sodium = await sodiumReady();
  const bytes = ownershipTransferAcceptanceBytes(input);
  try {
    return await toBase64Url(sodium.crypto_hash_sha256(bytes));
  } finally {
    sodium.memzero(bytes);
  }
}

async function deriveVaultKeyPossessionSeed(
  keys: VaultKeyPossessionKeys,
  context: VaultKeyPossessionContext,
): Promise<Uint8Array> {
  if (keys.metadataKey.byteLength !== KEY_BYTES || keys.contentKey.byteLength !== KEY_BYTES) {
    throw new E2eeError('invalid_input', `Vault possession keys must be ${KEY_BYTES} bytes`);
  }
  if (!Number.isInteger(context.keyEpoch) || context.keyEpoch <= 0 || context.vaultId.length === 0) {
    throw new E2eeError('invalid_input', 'Vault possession context is invalid');
  }
  const sodium = await sodiumReady();
  const domain = utf8(canonicalJson({
    keyEpoch: context.keyEpoch,
    kind: 'vault-key-possession-ed25519-seed',
    protocol: E2EE_PROTOCOL,
    vaultId: context.vaultId,
  }));
  const input = new Uint8Array(domain.byteLength + 1 + keys.contentKey.byteLength);
  input.set(domain, 0);
  input[domain.byteLength] = 0;
  input.set(keys.contentKey, domain.byteLength + 1);
  try {
    return sodium.crypto_generichash(sodium.crypto_sign_SEEDBYTES, input, keys.metadataKey);
  } finally {
    sodium.memzero(domain);
    sodium.memzero(input);
  }
}

function ownershipTransferAcceptanceBytes(
  input: OwnershipTransferAcceptanceEvidence,
): Uint8Array {
  return utf8(canonicalJson(ownershipTransferAcceptanceEvidence(input)));
}
