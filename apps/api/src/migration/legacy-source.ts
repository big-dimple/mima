import { createHash } from 'node:crypto';
import { asc, eq } from 'drizzle-orm';
import { canonicalJson, type JsonValue } from '@mima/e2ee';
import {
  auditEvents,
  itemSecretVersions,
  items,
  vaults,
} from '../db/schema.ts';
import type { DbOrTx } from '../services/audit.ts';

export const LEGACY_EXPORT_FORMAT = 'mima-legacy-export-v1' as const;
export const LEGACY_EXPORT_ALGORITHM = 'x25519-xsalsa20-poly1305-sealed-box' as const;

export interface LegacyVaultHeader {
  vaultId: string;
  kind: 'personal' | 'team';
  name: string;
  ownerUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface LegacyItemMetadata {
  id: string;
  vaultId: string;
  kind: 'login' | 'api_token' | 'secure_note';
  title: string;
  username: string | null;
  origin: string | null;
  tags: string[];
  favorite: boolean;
  sensitivity: 'low' | 'medium' | 'high';
  version: number;
  secretVersion: number;
  deleted: boolean;
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
}

export interface LegacyCiphertextVersion {
  id: string;
  itemId: string;
  vaultId: string;
  itemKind: string;
  secretVersion: number;
  ciphertext: string;
  iv: string;
  authTag: string;
  wrappedDek: string;
  keyVersion: string;
  createdAt: string;
  createdBy: string;
}

export interface LegacySourceManifest {
  format: typeof LEGACY_EXPORT_FORMAT;
  vault: LegacyVaultHeader;
  items: Array<{
    metadata: LegacyItemMetadata;
    secretVersions: LegacyCiphertextVersion[];
  }>;
  audit: {
    eventCount: number;
    headHash: string | null;
  };
}

export interface LegacySourceRecord {
  sourceKind: 'vault_header' | 'item_metadata' | 'item_secret';
  sourceId: string;
  sourceVersion: number;
  sourceDigest: Buffer;
}

export async function buildLegacySourceManifest(
  db: DbOrTx,
  vaultId: string,
  frozenAudit?: LegacySourceManifest['audit'],
): Promise<LegacySourceManifest> {
  const vaultRows = await db.select({
    id: vaults.id,
    kind: vaults.kind,
    name: vaults.name,
    ownerUserId: vaults.ownerUserId,
    createdAt: vaults.createdAt,
    updatedAt: vaults.updatedAt,
  }).from(vaults).where(eq(vaults.id, vaultId)).limit(1);
  const itemRows = await db.select().from(items).where(eq(items.vaultId, vaultId)).orderBy(asc(items.id));
  const secretRows = await db.select().from(itemSecretVersions).where(eq(itemSecretVersions.vaultId, vaultId))
    .orderBy(asc(itemSecretVersions.itemId), asc(itemSecretVersions.secretVersion));
  const auditRows = frozenAudit
    ? []
    : await db.select({ id: auditEvents.id, hash: auditEvents.hash }).from(auditEvents)
      .where(eq(auditEvents.vaultId, vaultId)).orderBy(asc(auditEvents.id));
  const vault = vaultRows[0];
  if (!vault) throw new Error('legacy_source_missing');

  const header: LegacyVaultHeader = {
    vaultId: vault.id,
    kind: vault.kind,
    name: vault.name,
    ownerUserId: vault.ownerUserId,
    createdAt: vault.createdAt.toISOString(),
    updatedAt: vault.updatedAt.toISOString(),
  };
  const manifestItems = itemRows.map((item) => {
    const metadata: LegacyItemMetadata = {
      id: item.id,
      vaultId: item.vaultId,
      kind: item.kind,
      title: item.title,
      username: item.username,
      origin: item.origin,
      tags: item.tags,
      favorite: item.favorite,
      sensitivity: item.sensitivity,
      version: item.version,
      secretVersion: item.secretVersion,
      deleted: item.deleted,
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
      updatedBy: item.updatedBy,
    };
    const versions = secretRows
      .filter((secret) => secret.itemId === item.id)
      .map((secret): LegacyCiphertextVersion => {
        if (secret.itemKind !== item.kind || secret.vaultId !== item.vaultId) {
          throw new Error('legacy_source_context_mismatch');
        }
        return {
          id: secret.id,
          itemId: secret.itemId,
          vaultId: secret.vaultId,
          itemKind: secret.itemKind,
          secretVersion: secret.secretVersion,
          ciphertext: encodeBase64Url(secret.ciphertext),
          iv: encodeBase64Url(secret.iv),
          authTag: encodeBase64Url(secret.authTag),
          wrappedDek: encodeBase64Url(secret.wrappedDek),
          keyVersion: secret.keyVersion,
          createdAt: secret.createdAt.toISOString(),
          createdBy: secret.createdBy,
        };
      });
    return { metadata, secretVersions: versions };
  });
  const audit = frozenAudit ?? {
    eventCount: auditRows.length,
    headHash: auditRows.at(-1)?.hash ?? null,
  };
  return { format: LEGACY_EXPORT_FORMAT, vault: header, items: manifestItems, audit };
}

export function legacySourceDigest(manifest: LegacySourceManifest): Buffer {
  return digestCanonical(manifest);
}

export function legacySourceRecords(manifest: LegacySourceManifest): LegacySourceRecord[] {
  return [
    {
      sourceKind: 'vault_header',
      sourceId: manifest.vault.vaultId,
      sourceVersion: 1,
      sourceDigest: digestCanonical(manifest.vault),
    },
    ...manifest.items.flatMap(({ metadata, secretVersions }) => [
      {
        sourceKind: 'item_metadata' as const,
        sourceId: metadata.id,
        sourceVersion: metadata.version,
        sourceDigest: digestCanonical(metadata),
      },
      ...secretVersions.map((secret) => ({
        sourceKind: 'item_secret' as const,
        sourceId: secret.id,
        sourceVersion: secret.secretVersion,
        sourceDigest: digestCanonical(secret),
      })),
    ]),
  ];
}

export function digestCanonical(value: unknown): Buffer {
  return createHash('sha256').update(canonicalJson(value as JsonValue)).digest();
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}
