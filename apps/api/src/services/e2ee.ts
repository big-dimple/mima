import { createHash, timingSafeEqual } from 'node:crypto';
import {
  canonicalJson,
  utf8,
  verifyBytes,
  verifySignedDeviceCertificate,
  type DeviceCertificate,
} from '@mima/e2ee';
import type {
  CipherBlob,
  CryptoDevice,
  UserCryptoProfile,
  VaultKeyEnvelope,
  VaultKeyEnvelopeInput,
} from '@mima/contracts';
import type { DbOrTx } from './audit.ts';
import {
  enterpriseRecoveryKeys,
  userCryptoProfiles,
  userDevices,
  users,
} from '../db/schema.ts';
import { and, eq, inArray } from 'drizzle-orm';

export const E2EE_PROTOCOL = 'lm-e2ee-v1' as const;

export function decodeBase64Url(
  value: string,
  options: { exact?: number; min?: number; max?: number } = {},
): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error('non-canonical base64url');
  if (options.exact !== undefined && decoded.length !== options.exact) throw new Error('invalid length');
  if (options.min !== undefined && decoded.length < options.min) throw new Error('invalid length');
  if (options.max !== undefined && decoded.length > options.max) throw new Error('invalid length');
  return decoded;
}

export function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

export function decodeCipherBlob(blob: CipherBlob, minimumCiphertextBytes = 17) {
  return {
    nonce: decodeBase64Url(blob.nonce, { exact: 24 }),
    ciphertext: decodeBase64Url(blob.ciphertext, { min: minimumCiphertextBytes, max: 150_000 }),
  };
}

export function encodeCipherBlob(nonce: Uint8Array, ciphertext: Uint8Array): CipherBlob {
  return {
    suite: E2EE_PROTOCOL,
    aadVersion: 1,
    nonce: encodeBase64Url(nonce),
    ciphertext: encodeBase64Url(ciphertext),
  };
}

export function sha256(value: Uint8Array | string): Buffer {
  return createHash('sha256').update(value).digest();
}

export function digestBlob(blob: CipherBlob): Buffer {
  const decoded = decodeCipherBlob(blob);
  return sha256(Buffer.concat([decoded.nonce, decoded.ciphertext]));
}

export function publicKeyFingerprint(publicKey: string): string {
  return sha256(decodeBase64Url(publicKey, { exact: 32 })).toString('base64url');
}

export function commandBytes(
  kind: string,
  input: {
    userId: string;
    vaultId?: string;
    itemId?: string;
    request: unknown;
  },
): Uint8Array {
  return utf8(canonicalJson({
    itemId: input.itemId ?? null,
    kind,
    protocol: E2EE_PROTOCOL,
    request: input.request as never,
    userId: input.userId,
    vaultId: input.vaultId ?? null,
  }));
}

export async function verifyCommandSignature(
  signature: string,
  publicKey: string,
  kind: string,
  input: { userId: string; vaultId?: string; itemId?: string; request: unknown },
): Promise<boolean> {
  const bytes = commandBytes(kind, input);
  try {
    return await verifyBytes(signature, bytes, publicKey);
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

export async function verifyDetachedBytes(
  signature: string,
  publicKey: string,
  bytes: Uint8Array,
): Promise<boolean> {
  try {
    return await verifyBytes(signature, bytes, publicKey);
  } catch {
    return false;
  }
}

export async function parseDeviceCertificate(
  encoded: string,
  signature: string,
  trustedUserSigningPublicKey: string,
  expected: {
    accountId: string;
    deviceId: string;
    deviceType: 'web' | 'extension' | 'desktop' | 'mobile';
    encryptionPublicKey: string;
    signingPublicKey: string;
    keyVersion?: number;
  },
): Promise<{ bytes: Buffer; certificate: DeviceCertificate }> {
  const bytes = decodeBase64Url(encoded, { min: 32, max: 100_000 });
  const parsed = await verifySignedDeviceCertificate(
    { certificate: encoded, signature },
    trustedUserSigningPublicKey,
    { accountId: expected.accountId, deviceId: expected.deviceId, deviceType: expected.deviceType },
  );
  if (
    parsed.keyVersion !== (expected.keyVersion ?? 1) ||
    parsed.encryptionPublicKey !== expected.encryptionPublicKey ||
    parsed.signingPublicKey !== expected.signingPublicKey
  ) {
    throw new Error('device certificate scope mismatch');
  }
  const issuedAt = Date.parse(parsed.issuedAt);
  if (!Number.isFinite(issuedAt) || issuedAt > Date.now() + 300_000 || issuedAt < Date.now() - 366 * 86_400_000) {
    throw new Error('device certificate timestamp is invalid');
  }
  decodeBase64Url(parsed.encryptionPublicKey, { exact: 32 });
  decodeBase64Url(parsed.signingPublicKey, { exact: 32 });
  return { bytes, certificate: parsed };
}

export function equalDigest(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export async function getActiveDevice(db: DbOrTx, userId: string, deviceId: string) {
  return (
    await db
      .select()
      .from(userDevices)
      .where(and(
        eq(userDevices.id, deviceId),
        eq(userDevices.userId, userId),
        eq(userDevices.status, 'active'),
      ))
      .limit(1)
  )[0] ?? null;
}

export async function getCryptoProfile(db: DbOrTx, userId: string) {
  return (
    await db
      .select()
      .from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, userId))
      .limit(1)
  )[0] ?? null;
}

export function toCryptoProfileDto(row: typeof userCryptoProfiles.$inferSelect): UserCryptoProfile {
  return {
    userId: row.userId,
    profileVersion: row.profileVersion,
    keyVersion: row.cryptoGeneration,
    suite: E2EE_PROTOCOL,
    kdf: {
      algorithm: 'argon2id13',
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      salt: encodeBase64Url(row.kdfSalt),
      outputBytes: 32,
    },
    encryptedAccountBundle: encodeCipherBlob(
      row.wrappedAccountKeyNonce,
      row.wrappedAccountKeyCiphertext,
    ),
    encryptionPublicKey: encodeBase64Url(row.publicEncryptionKey),
    signingPublicKey: encodeBase64Url(row.publicSigningKey),
    recoveryEnabled: true,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toCryptoDeviceDto(row: typeof userDevices.$inferSelect): CryptoDevice {
  return {
    id: row.id,
    userId: row.userId,
    deviceType: row.deviceType,
    encryptedLabel: row.encryptedLabel && row.labelNonce
      ? encodeCipherBlob(row.labelNonce, row.encryptedLabel)
      : null,
    encryptionPublicKey: encodeBase64Url(row.publicEncryptionKey),
    signingPublicKey: encodeBase64Url(row.publicSigningKey),
    certificate: encodeBase64Url(row.certificatePayload),
    certificateSignature: encodeBase64Url(row.certificateSignature),
    keyVersion: row.deviceGeneration,
    trustedAt: (row.activatedAt ?? row.createdAt).toISOString(),
    lastSeenAt: row.lastSeenAt?.toISOString() ?? null,
    revokedAt: row.revokedAt?.toISOString() ?? null,
  };
}

function envelopeBytes(envelope: Omit<VaultKeyEnvelopeInput, 'signature'> | VaultKeyEnvelopeInput) {
  return utf8(canonicalJson({
    capability: envelope.capability,
    epoch: envelope.epoch,
    kind: 'vault-key-envelope',
    protocol: E2EE_PROTOCOL,
    recipientId: envelope.recipientId,
    recipientKeyVersion: envelope.recipientKeyVersion,
    recipientKind: envelope.recipientKind,
    sealedKeyBundle: envelope.sealedKeyBundle,
    signerKeyVersion: envelope.signerKeyVersion,
    signerUserId: envelope.signerUserId,
    vaultId: envelope.vaultId,
  }));
}

export async function verifyVaultEnvelope(envelope: VaultKeyEnvelopeInput, signerPublicKey: string) {
  const bytes = envelopeBytes(envelope);
  try {
    return await verifyBytes(envelope.signature, bytes, signerPublicKey);
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

export async function resolveEnvelopeRecipient(
  db: DbOrTx,
  envelope: VaultKeyEnvelopeInput,
): Promise<{
  recipientKind: 'user' | 'device' | 'enterprise_recovery';
  recipientUserId: string | null;
  recipientDeviceId: string | null;
  recipientRecoveryKeyId: string | null;
  fingerprint: string;
}> {
  if (envelope.recipientKind === 'user') {
    const profile = await getCryptoProfile(db, envelope.recipientId);
    if (!profile || profile.cryptoGeneration !== envelope.recipientKeyVersion) throw new Error('recipient key version mismatch');
    return {
      recipientKind: 'user',
      recipientUserId: envelope.recipientId,
      recipientDeviceId: null,
      recipientRecoveryKeyId: null,
      fingerprint: publicKeyFingerprint(encodeBase64Url(profile.publicEncryptionKey)),
    };
  }
  if (envelope.recipientKind === 'device') {
    const device = (
      await db.select().from(userDevices).where(and(
        eq(userDevices.id, envelope.recipientId),
        eq(userDevices.status, 'active'),
      )).limit(1)
    )[0];
    if (!device || device.deviceGeneration !== envelope.recipientKeyVersion) throw new Error('recipient key version mismatch');
    return {
      recipientKind: 'device',
      recipientUserId: null,
      recipientDeviceId: device.id,
      recipientRecoveryKeyId: null,
      fingerprint: device.keyFingerprint,
    };
  }
  const recovery = (
    await db
      .select()
      .from(enterpriseRecoveryKeys)
      .where(and(
        eq(enterpriseRecoveryKeys.status, 'active'),
        eq(enterpriseRecoveryKeys.id, envelope.recipientId),
      ))
      .limit(1)
  )[0] ?? (
    await db
      .select()
      .from(enterpriseRecoveryKeys)
      .where(and(
        eq(enterpriseRecoveryKeys.status, 'active'),
        eq(enterpriseRecoveryKeys.keyFingerprint, envelope.recipientId),
      ))
      .limit(1)
  )[0];
  if (!recovery || envelope.recipientKeyVersion !== 1) throw new Error('recovery key mismatch');
  return {
    recipientKind: 'enterprise_recovery',
    recipientUserId: null,
    recipientDeviceId: null,
    recipientRecoveryKeyId: recovery.id,
    fingerprint: recovery.keyFingerprint,
  };
}

export async function listPublicCryptoProfiles(db: DbOrTx, userIds: string[]) {
  const unique = [...new Set(userIds)].slice(0, 1000);
  if (unique.length === 0) return [];
  const rows = await db
    .select({
      userId: userCryptoProfiles.userId,
      keyVersion: userCryptoProfiles.cryptoGeneration,
      encryptionPublicKey: userCryptoProfiles.publicEncryptionKey,
      signingPublicKey: userCryptoProfiles.publicSigningKey,
    })
    .from(userCryptoProfiles)
    .where(inArray(userCryptoProfiles.userId, unique));
  return rows.map((row) => ({
    userId: row.userId,
    keyVersion: row.keyVersion,
    encryptionPublicKey: encodeBase64Url(row.encryptionPublicKey),
    signingPublicKey: encodeBase64Url(row.signingPublicKey),
  }));
}

export function envelopeSignerProfiles(rows: Array<{
  envelope: {
    signerUserId: string | null;
    signerKeyVersion: number | null;
    signerPublicKey: Uint8Array | null;
  };
  sender: { userId: string };
  signer: {
    cryptoGeneration: number;
    publicEncryptionKey: Uint8Array;
    publicSigningKey: Uint8Array;
  };
}>) {
  const profiles = new Map<string, {
    userId: string;
    keyVersion: number;
    encryptionPublicKey: string;
    signingPublicKey: string;
  }>();
  for (const { envelope, sender, signer } of rows) {
    const userId = envelope.signerUserId ?? sender.userId;
    const keyVersion = envelope.signerKeyVersion ?? signer.cryptoGeneration;
    const signingPublicKey = envelope.signerPublicKey ?? signer.publicSigningKey;
    const key = `${userId}:${keyVersion}`;
    if (!profiles.has(key)) {
      profiles.set(key, {
        userId,
        keyVersion,
        encryptionPublicKey: encodeBase64Url(signer.publicEncryptionKey),
        signingPublicKey: encodeBase64Url(signingPublicKey),
      });
    }
  }
  return [...profiles.values()];
}

export async function assertKnownUser(db: DbOrTx, userId: string): Promise<void> {
  const row = (await db.select({ id: users.id }).from(users).where(eq(users.id, userId)).limit(1))[0];
  if (!row) throw new Error('unknown user');
}

export function toEnvelopeDto(
  row: {
    id: string;
    vaultId: string;
    keyEpoch: number;
    recipientKind: 'user' | 'device' | 'enterprise_recovery';
    recipientUserId: string | null;
    recipientDeviceId: string | null;
    recipientRecoveryKeyId: string | null;
    envelopeVersion: number;
    accessScope: 'metadata' | 'full' | 'recovery';
    ciphertext: Uint8Array;
    signature: Uint8Array;
    createdAt: Date;
    signerUserId?: string | null;
    signerKeyVersion?: number | null;
  },
  signer: { userId: string; keyVersion: number },
): VaultKeyEnvelope {
  return {
    id: row.id,
    vaultId: row.vaultId,
    epoch: row.keyEpoch,
    recipientKind: row.recipientKind === 'enterprise_recovery' ? 'recovery' : row.recipientKind,
    recipientId: row.recipientUserId ?? row.recipientDeviceId ?? row.recipientRecoveryKeyId!,
    recipientKeyVersion: row.envelopeVersion,
    capability: row.accessScope,
    sealedKeyBundle: encodeBase64Url(row.ciphertext),
    signerUserId: row.signerUserId ?? signer.userId,
    signerKeyVersion: row.signerKeyVersion ?? signer.keyVersion,
    signature: encodeBase64Url(row.signature),
    createdAt: row.createdAt.toISOString(),
  };
}
