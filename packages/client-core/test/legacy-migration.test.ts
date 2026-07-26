import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { UserCryptoProfile } from '@mima/contracts';
import {
  canonicalJson,
  decryptItemContent,
  destroyKeyPair,
  destroyVaultKeys,
  generateEncryptionKeyPair,
  openVaultKeyGrant,
  sealBytes,
  utf8,
  type EncryptionKeyPair,
  type JsonValue,
} from '@mima/e2ee';
import {
  E2eeKeyring,
  ApiRequestError,
  EncryptedCommandOutbox,
  MemoryEncryptedStorage,
  SecretLeaseStore,
  ZeroKnowledgeClient,
  createMetaStore,
  type ApiClient,
  type LegacyMigrationJob,
  type LegacyMigrationMaterials,
} from '../src/index.ts';

const USER_ID = 'u-owner';
const DEVICE_ID = '10000000-0000-4000-8000-000000000001';
const VAULT_ID = '20000000-0000-4000-8000-000000000001';
const JOB_ID = '30000000-0000-4000-8000-000000000001';
const ITEM_ID = '40000000-0000-4000-8000-000000000001';
const SECRET_ONE_ID = '50000000-0000-4000-8000-000000000001';
const SECRET_TWO_ID = '50000000-0000-4000-8000-000000000002';
const RECOVERY_ID = '60000000-0000-4000-8000-000000000001';
const EXTENSION_ID = '70000000-0000-4000-8000-000000000001';
const NOW = '2026-07-18T00:00:00.000Z';

const keyrings: E2eeKeyring[] = [];
const keyPairs: EncryptionKeyPair[] = [];

afterEach(async () => {
  await Promise.all(keyrings.splice(0).map((keyring) => keyring.lock()));
  await Promise.all(keyPairs.splice(0).map((pair) => destroyKeyPair(pair)));
});

describe('legacy migration client cryptography', () => {
  it('encrypts every historical version and keeps old plaintext out of returned requests', async () => {
    const fixture = await createFixture();
    const prepared = await fixture.keyring.prepareLegacyMigration(
      USER_ID,
      fixture.profile,
      fixture.job,
      fixture.materials,
      await sealedResponse(fixture.profile, fixture.job, createPayload(fixture.job.sourceDigest!)),
    );

    const records = prepared.recordBatches.flatMap((batch) => batch.records);
    expect(records.map((record) => `${record.kind}:${record.sourceVersion}`)).toEqual([
      'metadata:2',
      'secret:1',
      'secret:2',
    ]);
    expect(JSON.stringify(prepared)).not.toContain('first legacy password');
    expect(JSON.stringify(prepared)).not.toContain('second legacy password');
    expect(prepared.target.envelopes.map((envelope) => `${envelope.recipientKind}:${envelope.recipientId}`))
      .toEqual([`user:${USER_ID}`, `device:${EXTENSION_ID}`, `recovery:${RECOVERY_ID}`]);

    const verification = await fixture.keyring.migrationVerificationIntent(USER_ID, VAULT_ID, JOB_ID);
    expect(verification.legacySecretVersionCount).toBe(2);
    expect(verification.encryptedSecretVersionCount).toBe(2);
    expect(verification.encryptedDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);

    await fixture.keyring.commitLegacyMigration(VAULT_ID, JOB_ID);
    const metadata = records.find((record) => record.kind === 'metadata')!;
    const secrets = records.filter((record) => record.kind === 'secret');
    const extensionEnvelope = prepared.target.envelopes.find((envelope) => envelope.recipientKind === 'device')!;
    const extensionKeys = await openVaultKeyGrant(
      extensionEnvelope,
      fixture.extension,
      fixture.profile.signingPublicKey,
      { vaultId: VAULT_ID, recipientId: EXTENSION_ID, epoch: 1, recipientKeyVersion: 1 },
    );
    try {
      const first = secrets[0];
      if (!first || first.kind !== 'secret' || metadata.kind !== 'metadata' || !extensionKeys.contentKey) {
        throw new Error('invalid fixture');
      }
      await expect(decryptItemContent(extensionKeys.contentKey, {
        vaultId: VAULT_ID,
        itemId: ITEM_ID,
        itemKind: 'login',
        version: 1,
        secretVersion: 1,
        keyEpoch: 1,
        metadata: metadata.blob,
        wrappedDek: first.wrappedDek,
        encryptedValue: first.encryptedValue,
      })).resolves.toMatchObject({ value: 'first legacy password' });
      await expect(decryptItemContent(extensionKeys.contentKey, {
        vaultId: VAULT_ID,
        itemId: ITEM_ID,
        itemKind: 'api_token',
        version: 1,
        secretVersion: 1,
        keyEpoch: 1,
        metadata: metadata.blob,
        wrappedDek: first.wrappedDek,
        encryptedValue: first.encryptedValue,
      })).rejects.toThrow();
    } finally {
      await destroyVaultKeys(extensionKeys);
    }
    for (const [index, secret] of secrets.entries()) {
      if (secret.kind !== 'secret' || metadata.kind !== 'metadata') throw new Error('invalid fixture');
      await expect(fixture.keyring.decryptContent({
        metadata: {
          itemId: ITEM_ID,
          vaultId: VAULT_ID,
          version: 2,
          secretVersion: 2,
          keyEpoch: 1,
          deleted: false,
          blob: metadata.blob,
          createdAt: NOW,
          updatedAt: NOW,
          updatedBy: USER_ID,
        },
        secret: {
          itemId: ITEM_ID,
          vaultId: VAULT_ID,
          recordVersion: secret.recordVersion,
          secretVersion: secret.secretVersion,
          encryptedValue: secret.encryptedValue,
          createdAt: NOW,
          createdBy: USER_ID,
        },
        keyWrap: {
          itemId: ITEM_ID,
          vaultId: VAULT_ID,
          secretVersion: secret.secretVersion,
          keyEpoch: 1,
          wrappedDek: secret.wrappedDek,
          createdAt: NOW,
          createdBy: USER_ID,
        },
      })).resolves.toBe(index === 0 ? 'first legacy password' : 'second legacy password');
    }
  });

  it('accepts a team vault whose direct owner is stored only in memberships', async () => {
    const fixture = await createFixture();
    const payload = createPayload(fixture.job.sourceDigest!);
    payload.vault.ownerUserId = null;

    await expect(fixture.keyring.prepareLegacyMigration(
      USER_ID,
      fixture.profile,
      fixture.job,
      fixture.materials,
      await sealedResponse(fixture.profile, fixture.job, payload),
    )).resolves.toMatchObject({ jobId: JOB_ID, vaultId: VAULT_ID });
  });

  it.each([
    ['job id', (payload: ReturnType<typeof createPayload>) => { payload.jobId = '30000000-0000-4000-8000-000000000002'; }],
    ['source digest', (payload: ReturnType<typeof createPayload>) => { payload.sourceDigest = digestLiteral(31); }],
    ['recipient user', (payload: ReturnType<typeof createPayload>) => { payload.recipient.userId = 'u-other'; }],
    ['recipient key version', (payload: ReturnType<typeof createPayload>) => { payload.recipient.keyVersion = 2; }],
    ['legacy owner', (payload: ReturnType<typeof createPayload>) => { payload.vault.ownerUserId = 'u-other'; }],
  ])('rejects a sealed export with tampered %s binding', async (_label, mutate) => {
    const fixture = await createFixture();
    const payload = createPayload(fixture.job.sourceDigest!);
    mutate(payload);
    await expect(fixture.keyring.prepareLegacyMigration(
      USER_ID,
      fixture.profile,
      fixture.job,
      fixture.materials,
      await sealedResponse(fixture.profile, fixture.job, payload),
    )).rejects.toThrow(/不匹配/);
  });

  it('rejects a sealed export encrypted for a different private key', async () => {
    const fixture = await createFixture();
    const wrongRecipient = await generateEncryptionKeyPair();
    keyPairs.push(wrongRecipient);
    const response = await sealedResponse(
      fixture.profile,
      fixture.job,
      createPayload(fixture.job.sourceDigest!),
      wrongRecipient.publicKey,
    );
    await expect(fixture.keyring.prepareLegacyMigration(
      USER_ID,
      fixture.profile,
      fixture.job,
      fixture.materials,
      response,
    )).rejects.toThrow();
  });

  it('rejects sealed metadata whose declared source digest was tampered', async () => {
    const fixture = await createFixture();
    const payload = createPayload(fixture.job.sourceDigest!);
    payload.vault.items[0]!.metadataSourceDigest = digestLiteral(31);
    await expect(fixture.keyring.prepareLegacyMigration(
      USER_ID,
      fixture.profile,
      fixture.job,
      fixture.materials,
      await sealedResponse(fixture.profile, fixture.job, payload),
    )).rejects.toThrow('元数据摘要不匹配');
  });

  it('destroys pending vault keys on rollback', async () => {
    const fixture = await createFixture();
    await fixture.keyring.prepareLegacyMigration(
      USER_ID,
      fixture.profile,
      fixture.job,
      fixture.materials,
      await sealedResponse(fixture.profile, fixture.job, createPayload(fixture.job.sourceDigest!)),
    );
    await fixture.keyring.abortLegacyMigration(VAULT_ID, JOB_ID);
    await expect(fixture.keyring.commitLegacyMigration(VAULT_ID, JOB_ID)).rejects.toThrow('没有可提交');
  });
});

describe('legacy migration transaction boundary', () => {
  it('does not commit keys when the server rejects the target concurrently', async () => {
    const fixture = await createFixture();
    const status = migrationStatus(fixture);
    const api = migrationApi(status, await sealedResponse(
      fixture.profile,
      fixture.job,
      createPayload(fixture.job.sourceDigest!),
    ));
    api.submitLegacyMigrationTarget = vi.fn().mockRejectedValue(
      new ApiRequestError(409, { message: '迁移任务状态已经变化' }),
    );
    const { client, commit, abort } = migrationClient(fixture, api);

    await expect(client.convertLegacyMigration(VAULT_ID)).rejects.toThrow('服务器已恢复旧格式写入');
    expect(commit).not.toHaveBeenCalled();
    expect(abort).toHaveBeenCalledWith(VAULT_ID, JOB_ID);
    expect(api.rollbackLegacyMigration).toHaveBeenCalledOnce();
  });

  it('does not commit keys when server verification reports missing records', async () => {
    const fixture = await createFixture();
    const status = migrationStatus(fixture);
    const api = migrationApi(status, await sealedResponse(
      fixture.profile,
      fixture.job,
      createPayload(fixture.job.sourceDigest!),
    ));
    api.verifyLegacyMigration = vi.fn().mockRejectedValue(
      new ApiRequestError(409, { message: '迁移记录覆盖不完整' }),
    );
    const { client, commit, abort } = migrationClient(fixture, api);

    await client.convertLegacyMigration(VAULT_ID);
    await expect(client.verifyLegacyMigration(VAULT_ID)).rejects.toThrow('服务器已恢复旧格式写入');
    expect(commit).not.toHaveBeenCalled();
    expect(abort).toHaveBeenCalledWith(VAULT_ID, JOB_ID);
    expect(api.rollbackLegacyMigration).toHaveBeenCalledOnce();
  });
});

async function createFixture() {
  const keyring = new E2eeKeyring();
  keyrings.push(keyring);
  const setup = await keyring.setup('correct horse battery staple', {
    accountId: USER_ID,
    deviceId: DEVICE_ID,
    deviceName: 'test browser',
    platform: 'test',
  });
  const profile: UserCryptoProfile = {
    userId: USER_ID,
    profileVersion: 1,
    keyVersion: 1,
    suite: setup.request.suite,
    kdf: setup.request.kdf,
    encryptedAccountBundle: setup.request.encryptedAccountBundle,
    encryptionPublicKey: setup.request.encryptionPublicKey,
    signingPublicKey: setup.request.signingPublicKey,
    recoveryEnabled: true,
    createdAt: NOW,
    updatedAt: NOW,
  };
  const recovery = await generateEncryptionKeyPair();
  const extension = await generateEncryptionKeyPair();
  keyPairs.push(recovery, extension);
  const materials: LegacyMigrationMaterials = {
    recipients: [{
      userId: USER_ID,
      role: 'owner',
      capability: 'full',
      keyVersion: 1,
      encryptionPublicKey: profile.encryptionPublicKey,
      signingPublicKey: profile.signingPublicKey,
    }],
    devices: [{
      deviceId: EXTENSION_ID,
      userId: USER_ID,
      capability: 'full',
      keyVersion: 1,
      encryptionPublicKey: extension.publicKey,
      signingPublicKey: digestLiteral(8),
    }],
    recoveryKey: {
      id: RECOVERY_ID,
      ceremonyId: 'ceremony-1',
      keyFingerprint: digestLiteral(6),
      publicEncryptionKey: recovery.publicKey,
      threshold: 2,
      shareCount: 3,
      status: 'active',
      ceremonyEvidenceDigest: digestLiteral(7),
      approvalUserIds: ['admin-1', 'admin-2'],
      createdAt: NOW,
      retiredAt: null,
    },
  };
  const job: LegacyMigrationJob = {
    id: JOB_ID,
    vaultId: VAULT_ID,
    attempt: 1,
    status: 'encrypting',
    targetEpoch: 1,
    expectedItemCount: 1,
    expectedMetadataVersionCount: 1,
    expectedSecretVersionCount: 2,
    expectedRecipientCount: 0,
    verifiedItemCount: 0,
    verifiedMetadataVersionCount: 0,
    verifiedSecretVersionCount: 0,
    verifiedRecipientCount: 0,
    sourceDigest: digestLiteral(9),
    lastErrorCode: null,
    createdAt: NOW,
    updatedAt: NOW,
    completedAt: null,
    rolledBackAt: null,
  };
  return { keyring, profile, materials, job, extension };
}

function migrationStatus(fixture: Awaited<ReturnType<typeof createFixture>>) {
  return {
    status: 'encrypting' as const,
    job: fixture.job,
    materials: fixture.materials,
  };
}

function migrationApi(
  status: ReturnType<typeof migrationStatus>,
  migrationExport: Awaited<ReturnType<typeof sealedResponse>>,
) {
  return {
    legacyMigrationStatus: vi.fn().mockResolvedValue(status),
    claimLegacyMigrationExport: vi.fn().mockResolvedValue(migrationExport),
    submitLegacyMigrationTarget: vi.fn().mockResolvedValue({ ok: true, jobId: JOB_ID }),
    uploadLegacyMigrationRecords: vi.fn().mockResolvedValue({ ok: true }),
    verifyLegacyMigration: vi.fn().mockResolvedValue({ ...status, status: 'verifying' }),
    rollbackLegacyMigration: vi.fn().mockResolvedValue({ ok: true }),
    encryptedBootstrap: vi.fn().mockRejectedValue(new Error('skip refresh in unit test')),
  } as unknown as ApiClient & Record<string, ReturnType<typeof vi.fn>>;
}

function migrationClient(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  api: ApiClient,
) {
  const storage = new MemoryEncryptedStorage();
  const store = createMetaStore();
  store.getState().setUser({
    id: USER_ID,
    username: 'owner',
    displayName: 'Owner',
    email: 'owner@example.test',
    groups: [],
    isPlatformAdmin: false,
  });
  const commit = vi.spyOn(fixture.keyring, 'commitLegacyMigration');
  const abort = vi.spyOn(fixture.keyring, 'abortLegacyMigration');
  const client = new ZeroKnowledgeClient({
    api,
    store,
    leases: new SecretLeaseStore(),
    keyring: fixture.keyring,
    storage,
    outbox: new EncryptedCommandOutbox(api, storage),
  });
  (client as unknown as { profile: UserCryptoProfile | null }).profile = fixture.profile;
  return { client, commit, abort };
}

function createPayload(sourceDigest: string) {
  const metadata = {
    id: ITEM_ID,
    vaultId: VAULT_ID,
    kind: 'login' as const,
    title: 'production login',
    username: 'service-user',
    origin: 'https://example.test',
    tags: ['legacy'],
    favorite: true,
    sensitivity: 'high' as const,
    version: 2,
    secretVersion: 2,
    deleted: false,
    createdAt: NOW,
    updatedAt: NOW,
    updatedBy: USER_ID,
  };
  return {
    format: 'mima-legacy-export-v1' as const,
    jobId: JOB_ID,
    sourceDigest,
    recipient: { userId: USER_ID, keyVersion: 1 },
    vault: {
      vaultId: VAULT_ID,
      kind: 'team' as const,
      name: 'legacy team vault',
      ownerUserId: USER_ID as string | null,
      createdAt: NOW,
      updatedAt: NOW,
      items: [{
        metadata,
        metadataSourceDigest: createHash('sha256')
          .update(canonicalJson(metadata as unknown as JsonValue))
          .digest('base64url'),
        secretVersions: [
          {
            id: SECRET_ONE_ID,
            itemId: ITEM_ID,
            vaultId: VAULT_ID,
            itemKind: 'login' as const,
            secretVersion: 1,
            sourceDigest: digestLiteral(2),
            value: 'first legacy password',
            createdAt: NOW,
            createdBy: USER_ID,
          },
          {
            id: SECRET_TWO_ID,
            itemId: ITEM_ID,
            vaultId: VAULT_ID,
            itemKind: 'login' as const,
            secretVersion: 2,
            sourceDigest: digestLiteral(3),
            value: 'second legacy password',
            createdAt: NOW,
            createdBy: USER_ID,
          },
        ],
      }],
    },
    sourceAudit: { eventCount: 2, headHash: 'a'.repeat(64) },
  };
}

async function sealedResponse(
  profile: UserCryptoProfile,
  job: LegacyMigrationJob,
  payload: ReturnType<typeof createPayload>,
  publicKey = profile.encryptionPublicKey,
) {
  const bytes = utf8(canonicalJson(payload as unknown as JsonValue));
  try {
    return {
      sealedExport: await sealBytes(bytes, publicKey),
      recipientKeyVersion: profile.keyVersion,
      sourceDigest: job.sourceDigest!,
    };
  } finally {
    bytes.fill(0);
  }
}

function digestLiteral(byte: number): string {
  return Buffer.from(new Uint8Array(32).fill(byte)).toString('base64url');
}
