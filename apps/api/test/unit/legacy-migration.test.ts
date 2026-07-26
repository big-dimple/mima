import { describe, expect, it } from 'vitest';
import { encryptSecret, type MasterKeyProvider } from '@mima/crypto';
import {
  decodeUtf8,
  destroyKeyPair,
  generateEncryptionKeyPair,
  openSealedBytes,
} from '@mima/e2ee';
import {
  LEGACY_EXPORT_FORMAT,
  legacySourceDigest,
  legacySourceRecords,
  type LegacyCiphertextVersion,
  type LegacySourceManifest,
} from '../../src/migration/legacy-source.ts';
import { sealLegacyExport } from '../../src/migration/sealed-export.ts';

const provider: MasterKeyProvider = {
  activeVersion: () => 'v1',
  getKey: (version) => {
    if (version !== 'v1') throw new Error('unknown key');
    return Buffer.alloc(32, 7);
  },
  listVersions: () => ['v1'],
};

describe('isolated legacy migration export', () => {
  it('binds every ciphertext history row into the canonical source digest', () => {
    const manifest = createManifest(['first', 'second']);
    expect(legacySourceRecords(manifest)).toHaveLength(4);
    const original = legacySourceDigest(manifest);
    const changed = structuredClone(manifest);
    changed.items[0]!.secretVersions[1]!.ciphertext = 'AA';
    expect(legacySourceDigest(changed).equals(original)).toBe(false);
  });

  it('decrypts only for an X25519 sealed export addressed to the owner key', async () => {
    const recipient = await generateEncryptionKeyPair();
    const wrongRecipient = await generateEncryptionKeyPair();
    try {
      const manifest = createManifest(['first', 'second']);
      const sourceDigest = legacySourceDigest(manifest).toString('base64url');
      const sealed = await sealLegacyExport({
        jobId: '10000000-0000-4000-8000-000000000001',
        sourceDigest,
        recipientUserId: 'u-owner',
        recipientKeyVersion: 3,
        recipientPublicKey: recipient.publicKey,
        manifest,
      }, provider);
      const opened = await openSealedBytes(sealed, recipient);
      try {
        const payload = JSON.parse(decodeUtf8(opened)) as {
          sourceDigest: string;
          vault: { items: Array<{ secretVersions: Array<{ value: string }> }> };
        };
        expect(payload.sourceDigest).toBe(sourceDigest);
        expect(payload.vault.items[0]!.secretVersions.map((version) => version.value))
          .toEqual(['first', 'second']);
      } finally {
        opened.fill(0);
      }
      await expect(openSealedBytes(sealed, wrongRecipient)).rejects.toThrow();
    } finally {
      await destroyKeyPair(recipient);
      await destroyKeyPair(wrongRecipient);
    }
  });
});

function createManifest(values: string[]): LegacySourceManifest {
  const vaultId = '20000000-0000-4000-8000-000000000001';
  const itemId = '30000000-0000-4000-8000-000000000001';
  const now = '2026-07-18T00:00:00.000Z';
  const secretVersions = values.map((value, index): LegacyCiphertextVersion => {
    const secretVersion = index + 1;
    const encrypted = encryptSecret(provider, {
      vaultId,
      itemId,
      secretVersion,
      itemKind: 'login',
    }, value);
    return {
      id: `40000000-0000-4000-8000-00000000000${secretVersion}`,
      itemId,
      vaultId,
      itemKind: 'login',
      secretVersion,
      ciphertext: encrypted.ciphertext.toString('base64url'),
      iv: encrypted.iv.toString('base64url'),
      authTag: encrypted.authTag.toString('base64url'),
      wrappedDek: encrypted.wrappedDek.toString('base64url'),
      keyVersion: encrypted.keyVersion,
      createdAt: now,
      createdBy: 'u-owner',
    };
  });
  return {
    format: LEGACY_EXPORT_FORMAT,
    vault: {
      vaultId,
      kind: 'team',
      name: 'legacy vault',
      ownerUserId: 'u-owner',
      createdAt: now,
      updatedAt: now,
    },
    items: [{
      metadata: {
        id: itemId,
        vaultId,
        kind: 'login',
        title: 'legacy item',
        username: 'svc',
        origin: 'https://example.test',
        tags: ['legacy'],
        favorite: false,
        sensitivity: 'high',
        version: 2,
        secretVersion: 2,
        deleted: false,
        createdAt: now,
        updatedAt: now,
        updatedBy: 'u-owner',
      },
      secretVersions,
    }],
    audit: { eventCount: 2, headHash: 'a'.repeat(64) },
  };
}
