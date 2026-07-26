import { combine, split } from 'shamir-secret-sharing';
import {
  encryptionPublicKeyFromPrivate,
  type EncryptionKeyPair,
} from './asymmetric.ts';
import { E2EE_PROTOCOL, E2eeError, KEY_BYTES } from './constants.ts';
import {
  assertIdentifier,
  canonicalJson,
  decodeUtf8,
  fromBase64Url,
  sodiumReady,
  toBase64Url,
  utf8,
  type JsonValue,
} from './encoding.ts';
import type { UnsignedVaultKeyEnvelopeInput } from './vault.ts';

const RECOVERY_THRESHOLD = 2 as const;
const RECOVERY_SHARE_COUNT = 3 as const;

export interface EnterpriseRecoveryKit {
  ceremonyId: string;
  ceremonyDigest: string;
  publicKey: string;
  publicKeyFingerprint: string;
  threshold: typeof RECOVERY_THRESHOLD;
  shareCount: typeof RECOVERY_SHARE_COUNT;
  shares: [string, string, string];
}

export interface RecoveryShareInfo {
  ceremonyId: string;
  ceremonyDigest: string;
  publicKey: string;
  publicKeyFingerprint: string;
  shareIndex: number;
  threshold: typeof RECOVERY_THRESHOLD;
  shareCount: typeof RECOVERY_SHARE_COUNT;
}

export interface EnterpriseRecoveryTransferEvidenceInput {
  requestId: string;
  requestDigest: string;
  vaultId: string;
  epoch: number;
  recoveryKeyId: string;
  ceremonyId: string;
  recoveryCeremonyDigest: string;
  targetUserId: string;
  targetCapability: 'metadata' | 'full';
  recoveredEnvelope: UnsignedVaultKeyEnvelopeInput;
}

export type EnterpriseRecoveryTransferEvidenceFormat =
  | 'recovered-envelope-v1'
  | 'unsigned-envelope-v0';

interface RecoveryShareEnvelope extends RecoveryShareInfo {
  protocol: typeof E2EE_PROTOCOL;
  kind: 'enterprise-recovery-share';
  share: string;
  checksum: string;
}

export async function createEnterpriseRecoveryKit(ceremonyId: string): Promise<EnterpriseRecoveryKit> {
  assertIdentifier(ceremonyId, 'ceremonyId');
  const crypto = await sodiumReady();
  const keyPair = crypto.crypto_box_keypair();
  try {
    const publicKey = await toBase64Url(keyPair.publicKey);
    const publicKeyFingerprint = await sha256Base64Url(keyPair.publicKey);
    const ceremonyDigest = await enterpriseRecoveryCeremonyDigest({
      ceremonyId,
      publicKey,
      publicKeyFingerprint,
    });
    const rawShares = await split(keyPair.privateKey, RECOVERY_SHARE_COUNT, RECOVERY_THRESHOLD);
    try {
      const encodedShares = await Promise.all(rawShares.map(async (share, index) => {
        const unsigned = {
          protocol: E2EE_PROTOCOL,
          kind: 'enterprise-recovery-share' as const,
          ceremonyId,
          ceremonyDigest,
          publicKey,
          publicKeyFingerprint,
          shareIndex: index + 1,
          threshold: RECOVERY_THRESHOLD,
          shareCount: RECOVERY_SHARE_COUNT,
          share: await toBase64Url(share),
        };
        return encodeRecoveryShare({
          ...unsigned,
          checksum: await shareChecksum(unsigned),
        });
      }));
      return {
        ceremonyId,
        ceremonyDigest,
        publicKey,
        publicKeyFingerprint,
        threshold: RECOVERY_THRESHOLD,
        shareCount: RECOVERY_SHARE_COUNT,
        shares: encodedShares as [string, string, string],
      };
    } finally {
      rawShares.forEach((share) => crypto.memzero(share));
    }
  } finally {
    crypto.memzero(keyPair.privateKey);
    crypto.memzero(keyPair.publicKey);
  }
}

export async function recoverEnterpriseRecoveryKey(
  encodedShares: readonly string[],
  expected: { ceremonyId?: string; ceremonyDigest?: string; publicKey?: string } = {},
): Promise<EncryptionKeyPair> {
  if (encodedShares.length < RECOVERY_THRESHOLD || encodedShares.length > RECOVERY_SHARE_COUNT) {
    throw new E2eeError('invalid_input', 'Enterprise recovery requires two or three shares');
  }
  const envelopes = await Promise.all(encodedShares.map(decodeRecoveryShareEnvelope));
  const first = envelopes[0]!;
  const uniqueIndexes = new Set(envelopes.map((share) => share.shareIndex));
  if (uniqueIndexes.size !== envelopes.length) {
    throw new E2eeError('verification_failed', 'Enterprise recovery shares must be distinct');
  }
  for (const envelope of envelopes) {
    if (
      envelope.ceremonyId !== first.ceremonyId ||
      envelope.ceremonyDigest !== first.ceremonyDigest ||
      envelope.publicKey !== first.publicKey ||
      envelope.publicKeyFingerprint !== first.publicKeyFingerprint
    ) {
      throw new E2eeError('verification_failed', 'Enterprise recovery shares do not belong together');
    }
  }
  if (
    (expected.ceremonyId && expected.ceremonyId !== first.ceremonyId) ||
    (expected.ceremonyDigest && expected.ceremonyDigest !== first.ceremonyDigest) ||
    (expected.publicKey && expected.publicKey !== first.publicKey)
  ) {
    throw new E2eeError('verification_failed', 'Enterprise recovery ceremony does not match');
  }

  const rawShares = await Promise.all(envelopes.map((envelope) => fromBase64Url(envelope.share)));
  const crypto = await sodiumReady();
  let privateKey: Uint8Array | undefined;
  try {
    privateKey = await combine(rawShares);
    if (privateKey.byteLength !== KEY_BYTES) {
      throw new E2eeError('verification_failed', 'Recovered enterprise key has an invalid length');
    }
    const derivedPublicKey = await encryptionPublicKeyFromPrivate(privateKey);
    if (derivedPublicKey !== first.publicKey) {
      throw new E2eeError('verification_failed', 'Recovered enterprise key failed verification');
    }
    const publicKeyBytes = await fromBase64Url(first.publicKey, crypto.crypto_box_PUBLICKEYBYTES);
    try {
      if (await sha256Base64Url(publicKeyBytes) !== first.publicKeyFingerprint) {
        throw new E2eeError('verification_failed', 'Enterprise recovery key fingerprint is invalid');
      }
    } finally {
      crypto.memzero(publicKeyBytes);
    }
    const result = { publicKey: first.publicKey, privateKey };
    privateKey = undefined;
    return result;
  } finally {
    rawShares.forEach((share) => crypto.memzero(share));
    if (privateKey) crypto.memzero(privateKey);
  }
}

export async function inspectRecoveryShare(encodedShare: string): Promise<RecoveryShareInfo> {
  const envelope = await decodeRecoveryShareEnvelope(encodedShare);
  return {
    ceremonyId: envelope.ceremonyId,
    ceremonyDigest: envelope.ceremonyDigest,
    publicKey: envelope.publicKey,
    publicKeyFingerprint: envelope.publicKeyFingerprint,
    shareIndex: envelope.shareIndex,
    threshold: envelope.threshold,
    shareCount: envelope.shareCount,
  };
}

async function encodeRecoveryShare(envelope: RecoveryShareEnvelope): Promise<string> {
  return toBase64Url(utf8(canonicalJson(envelope as unknown as JsonValue)));
}

async function decodeRecoveryShareEnvelope(encodedShare: string): Promise<RecoveryShareEnvelope> {
  const decoded = await fromBase64Url(encodedShare);
  try {
    const parsed = JSON.parse(decodeUtf8(decoded)) as Partial<RecoveryShareEnvelope>;
    if (
      parsed.protocol !== E2EE_PROTOCOL ||
      parsed.kind !== 'enterprise-recovery-share' ||
      typeof parsed.ceremonyId !== 'string' ||
      typeof parsed.ceremonyDigest !== 'string' ||
      typeof parsed.publicKey !== 'string' ||
      typeof parsed.publicKeyFingerprint !== 'string' ||
      !Number.isSafeInteger(parsed.shareIndex) ||
      parsed.shareIndex! < 1 ||
      parsed.shareIndex! > RECOVERY_SHARE_COUNT ||
      parsed.threshold !== RECOVERY_THRESHOLD ||
      parsed.shareCount !== RECOVERY_SHARE_COUNT ||
      typeof parsed.share !== 'string' ||
      typeof parsed.checksum !== 'string'
    ) {
      throw new E2eeError('invalid_input', 'Enterprise recovery share is invalid');
    }
    assertIdentifier(parsed.ceremonyId, 'ceremonyId');
    const envelope = parsed as RecoveryShareEnvelope;
    const expectedDigest = await enterpriseRecoveryCeremonyDigest(envelope);
    if (expectedDigest !== envelope.ceremonyDigest) {
      throw new E2eeError('verification_failed', 'Enterprise recovery ceremony digest is invalid');
    }
    const { checksum, ...unsigned } = envelope;
    if (await shareChecksum(unsigned) !== checksum) {
      throw new E2eeError('verification_failed', 'Enterprise recovery share checksum is invalid');
    }
    return envelope;
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError('invalid_input', 'Enterprise recovery share is invalid', { cause: error });
  } finally {
    decoded.fill(0);
  }
}

export async function enterpriseRecoveryCeremonyDigest(input: {
  ceremonyId: string;
  publicKey: string;
  publicKeyFingerprint: string;
}): Promise<string> {
  const body: JsonValue = {
    ceremonyId: input.ceremonyId,
    kind: 'enterprise-recovery-ceremony',
    protocol: E2EE_PROTOCOL,
    publicKey: input.publicKey,
    publicKeyFingerprint: input.publicKeyFingerprint,
    shareCount: RECOVERY_SHARE_COUNT,
    threshold: RECOVERY_THRESHOLD,
  };
  return sha256Base64Url(utf8(canonicalJson(body)));
}

export async function enterpriseRecoveryTransferEvidenceDigest(
  input: EnterpriseRecoveryTransferEvidenceInput,
  format: EnterpriseRecoveryTransferEvidenceFormat = 'recovered-envelope-v1',
): Promise<string> {
  const common = {
    protocol: E2EE_PROTOCOL,
    kind: 'enterprise-recovery-transfer',
    requestId: input.requestId,
    requestDigest: input.requestDigest,
    vaultId: input.vaultId,
    epoch: input.epoch,
    recoveryKeyId: input.recoveryKeyId,
    ceremonyId: input.ceremonyId,
    recoveryCeremonyDigest: input.recoveryCeremonyDigest,
    targetUserId: input.targetUserId,
    targetCapability: input.targetCapability,
  };
  const body = format === 'recovered-envelope-v1'
    ? { ...common, formatVersion: 1, recoveredEnvelope: input.recoveredEnvelope }
    : { ...common, unsignedEnvelope: input.recoveredEnvelope };
  return sha256Base64Url(utf8(canonicalJson(body as unknown as JsonValue)));
}

async function shareChecksum(input: Omit<RecoveryShareEnvelope, 'checksum'>): Promise<string> {
  return sha256Base64Url(utf8(canonicalJson(input as unknown as JsonValue)));
}

async function sha256Base64Url(input: Uint8Array): Promise<string> {
  const crypto = await sodiumReady();
  const digest = crypto.crypto_hash_sha256(input);
  try {
    return await toBase64Url(digest);
  } finally {
    crypto.memzero(digest);
  }
}
