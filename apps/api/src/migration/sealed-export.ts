import type { MasterKeyProvider } from '@mima/crypto';
import { decryptSecret } from '@mima/crypto';
import { canonicalJson, sealBytes } from '@mima/e2ee';
import {
  LEGACY_EXPORT_FORMAT,
  legacySourceRecords,
  type LegacySourceManifest,
} from './legacy-source.ts';

export interface SealedLegacyExportInput {
  jobId: string;
  sourceDigest: string;
  recipientUserId: string;
  recipientKeyVersion: number;
  recipientPublicKey: string;
  manifest: LegacySourceManifest;
}

export async function sealLegacyExport(
  input: SealedLegacyExportInput,
  keys: MasterKeyProvider,
): Promise<string> {
  const sourceDigests = new Map(legacySourceRecords(input.manifest).map((record) => [
    `${record.sourceKind}:${record.sourceId}:${record.sourceVersion}`,
    record.sourceDigest.toString('base64url'),
  ]));
  const plaintext = {
    format: LEGACY_EXPORT_FORMAT,
    jobId: input.jobId,
    sourceDigest: input.sourceDigest,
    recipient: {
      userId: input.recipientUserId,
      keyVersion: input.recipientKeyVersion,
    },
    vault: {
      ...input.manifest.vault,
      items: input.manifest.items.map(({ metadata, secretVersions }) => ({
        metadata,
        metadataSourceDigest: requiredSourceDigest(
          sourceDigests,
          `item_metadata:${metadata.id}:${metadata.version}`,
        ),
        secretVersions: secretVersions.map((secret) => ({
          id: secret.id,
          itemId: secret.itemId,
          vaultId: secret.vaultId,
          itemKind: secret.itemKind,
          secretVersion: secret.secretVersion,
          sourceDigest: requiredSourceDigest(
            sourceDigests,
            `item_secret:${secret.id}:${secret.secretVersion}`,
          ),
          value: decryptLegacyValue(secret, keys),
          createdAt: secret.createdAt,
          createdBy: secret.createdBy,
        })),
      })),
    },
    sourceAudit: input.manifest.audit,
  };
  const plaintextBytes = Buffer.from(canonicalJson(plaintext as never), 'utf8');
  try {
    return await sealBytes(plaintextBytes, input.recipientPublicKey);
  } finally {
    plaintextBytes.fill(0);
    for (const item of plaintext.vault.items) {
      for (const secret of item.secretVersions) secret.value = '';
    }
  }
}

function requiredSourceDigest(sourceDigests: Map<string, string>, key: string): string {
  const digest = sourceDigests.get(key);
  if (!digest) throw new Error('legacy_source_record_missing');
  return digest;
}

function decryptLegacyValue(
  secret: LegacySourceManifest['items'][number]['secretVersions'][number],
  keys: MasterKeyProvider,
): string {
  const ciphertext = decodeBase64Url(secret.ciphertext);
  const iv = decodeBase64Url(secret.iv);
  const authTag = decodeBase64Url(secret.authTag);
  const wrappedDek = decodeBase64Url(secret.wrappedDek);
  try {
    return decryptSecret(keys, {
      vaultId: secret.vaultId,
      itemId: secret.itemId,
      secretVersion: secret.secretVersion,
      itemKind: secret.itemKind,
    }, { ciphertext, iv, authTag, wrappedDek, keyVersion: secret.keyVersion });
  } finally {
    ciphertext.fill(0);
    iv.fill(0);
    authTag.fill(0);
    wrappedDek.fill(0);
  }
}

function decodeBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('legacy_source_encoding_invalid');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error('legacy_source_encoding_invalid');
  return decoded;
}
