import { describe, expect, it, vi } from 'vitest';
import type {
  CryptoDevice,
  EncryptedBootstrapResponse,
  EnterpriseRecoveryRequest,
  UserCryptoProfile,
} from '@mima/contracts';
import {
  EncryptedCommandOutbox,
  MemoryEncryptedStorage,
  SecretLeaseStore,
  ZeroKnowledgeClient,
  createMetaStore,
  type ApiClient,
  type DecryptedBootstrapProjection,
  type E2eeKeyringPort,
  type OfflineRecoveryResult,
} from '../src/index.ts';

const accountId = 'user:recovery-client';
const deviceId = 'f62a2afb-32a8-46ec-a57d-4e7e4ae82ccf';
const vaultId = '387e07b7-3fb5-48cd-8237-512155857feb';
const user = {
  id: accountId,
  username: 'recovery-client',
  displayName: 'Recovery client',
  email: 'recovery-client@example.test',
  groups: [],
  isPlatformAdmin: false,
};

describe('enterprise recovery client rekey state', () => {
  it.each([
    { capability: 'full' as const, phase: 'rekey-blocked' as const },
    { capability: 'metadata' as const, phase: 'unlocked-online' as const },
  ])('keeps the $capability completion phase honest', async ({ capability, phase }) => {
    const fixture = recoveryClientFixture(capability);
    await fixture.client.prepare({ user, csrfToken: 'csrf-test', locked: false });

    await fixture.client.completeRecovery(fixture.request, {} as OfflineRecoveryResult);

    expect(fixture.client.phase).toBe(phase);
    expect(fixture.api.completeRecovery).toHaveBeenCalledOnce();
  });

  it('uses the task id from a recovery event to finish the rotation', async () => {
    const fixture = recoveryClientFixture('full', 'e2ee');
    await fixture.client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    const taskId = 'ac4d8f6e-26b0-4b98-a1c1-6797a4944394';

    await fixture.client.applyEncryptedSyncEvent({
      type: 'vault.rekey_required',
      cursor: 11,
      vaultId,
      pendingEpoch: 2,
      taskId,
    });
    expect(fixture.client.rekeyTaskId(vaultId)).toBe(taskId);

    await fixture.client.completeVaultRekey(vaultId);

    expect(fixture.keyring.rekeyMaterialIntent).toHaveBeenCalledWith(accountId, vaultId, taskId);
    expect(fixture.api.rekeyMaterial).toHaveBeenCalledWith(vaultId, expect.anything());
    expect(fixture.api.commitVaultRekey).toHaveBeenCalledOnce();
    expect(fixture.keyring.commitVaultRekey).toHaveBeenCalledWith(vaultId);
    expect(fixture.client.rekeyTaskId(vaultId)).toBeNull();
    expect(fixture.client.phase).toBe('unlocked-online');
  });

  it('keeps a committed rotation complete when the follow-up refresh is interrupted', async () => {
    const fixture = recoveryClientFixture('full', 'e2ee');
    await fixture.client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    const taskId = '5f61e16f-10f5-428c-8e3b-b748944f8117';
    await fixture.client.applyEncryptedSyncEvent({
      type: 'vault.rekey_required',
      cursor: 11,
      vaultId,
      pendingEpoch: 2,
      taskId,
    });
    fixture.api.encryptedBootstrap.mockRejectedValueOnce(new Error('network interrupted'));

    await expect(fixture.client.completeVaultRekey(vaultId)).resolves.toBeUndefined();

    expect(fixture.client.rekeyTaskId(vaultId)).toBeNull();
    expect(fixture.client.phase).toBe('unlocked-online');
    expect(fixture.keyring.abortVaultRekey).not.toHaveBeenCalled();
  });

  it('ignores a replayed rekey event older than the decrypted bootstrap cursor', async () => {
    const fixture = recoveryClientFixture('full', 'e2ee');
    await fixture.client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    await fixture.client.applyEncryptedSyncEvent({ type: 'sync.cursor', cursor: 10 });

    await fixture.client.applyEncryptedSyncEvent({
      type: 'vault.rekey_required',
      cursor: 9,
      vaultId,
      pendingEpoch: 2,
      taskId: '7053ef30-9624-48d7-b744-3dc27fd005d5',
    });

    expect(fixture.client.rekeyTaskId(vaultId)).toBeNull();
  });

  it('does not upload recovery coverage after the keyring generation changes', async () => {
    const fixture = recoveryClientFixture('full', 'e2ee');
    await fixture.client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    let resolvePreparation: ((value: object) => void) | undefined;
    fixture.keyring.prepareEnterpriseRecoveryEnvelope.mockReturnValue(new Promise((resolve) => {
      resolvePreparation = resolve;
    }));

    const distribution = fixture.client.distributeEnterpriseRecoveryEnvelope(
      { ...fixture.recoveryKey, status: 'staged' },
      {
        vaultId,
        epoch: 1,
        covered: false,
        canManage: true,
        ownerUserIds: [accountId],
      },
    );
    (fixture.keyring as { currentGeneration: number }).currentGeneration = 2;
    resolvePreparation?.({});

    await expect(distribution).rejects.toThrow('工作台状态已变化');
    expect(fixture.api.distributeRecoveryEnvelope).not.toHaveBeenCalled();
  });
});

function recoveryClientFixture(
  capability: 'metadata' | 'full',
  refreshedStatus: 'e2ee' | 'rekey_required' = capability === 'full' ? 'rekey_required' : 'e2ee',
) {
  const now = new Date().toISOString();
  const profile = {
    userId: accountId,
    profileVersion: 1,
    keyVersion: 1,
    suite: 'lm-e2ee-v1',
    kdf: {
      algorithm: 'argon2id13',
      salt: 'AAAAAAAAAAAAAAAAAAAAAA',
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      outputBytes: 32,
    },
    encryptedAccountBundle: { nonce: 'A'.repeat(32), ciphertext: 'B'.repeat(64) },
    encryptionPublicKey: 'C'.repeat(43),
    signingPublicKey: 'D'.repeat(43),
    recoveryEnabled: true,
    createdAt: now,
    updatedAt: now,
  } as UserCryptoProfile;
  const device = {
    id: deviceId,
    userId: accountId,
    deviceType: 'web',
    encryptedLabel: null,
    encryptionPublicKey: 'E'.repeat(43),
    signingPublicKey: 'F'.repeat(43),
    certificate: 'G'.repeat(64),
    certificateSignature: 'H'.repeat(86),
    keyVersion: 1,
    trustedAt: now,
    lastSeenAt: now,
    revokedAt: null,
  } as CryptoDevice;
  const recoveryKey = {
    id: '2935205b-b84f-47b9-90d1-88004de10dca',
    ceremonyId: 'client-recovery-rekey',
    keyFingerprint: 'I'.repeat(43),
    publicEncryptionKey: 'J'.repeat(43),
    threshold: 2,
    shareCount: 3,
    status: 'active',
    ceremonyEvidenceDigest: 'K'.repeat(43),
    approvalUserIds: ['admin-1', 'admin-2'] as string[],
    createdAt: now,
    retiredAt: null,
  } as const;
  const request = {
    id: '25226487-1027-4af8-ac8a-f229e9a70b51',
    vaultId,
    recoveryKeyId: recoveryKey.id,
    targetUserId: accountId,
    targetDeviceId: deviceId,
    targetEncryptionPublicKey: profile.encryptionPublicKey,
    targetKeyVersion: 1,
    targetCapability: capability,
    accountResetRequestId: null,
    requestDigest: 'L'.repeat(43),
    status: 'approved',
    approvalUserIds: ['admin-1', 'admin-2'],
    createdAt: now,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    completedAt: null,
  } as EnterpriseRecoveryRequest;
  const taskId = refreshedStatus === 'rekey_required'
    ? 'c66db6e7-8d76-4f09-bfdf-8e2f2b1ca26a'
    : null;
  const cryptoState = {
    vaultId,
    status: refreshedStatus,
    activeEpoch: 1,
    accessGeneration: 1,
    pendingEpoch: refreshedStatus === 'rekey_required' ? 2 : null,
    rekeyTaskId: taskId,
    encryptedHeader: null,
    migrationJobId: null,
    updatedAt: now,
  } as const;
  const memberships = [{
    id: '04f97aea-3ffe-4113-82a0-e60553518e8b',
    vaultId,
    subjectKind: 'user' as const,
    subjectId: accountId,
    role: 'owner' as const,
    createdAt: now,
  }];
  const bootstrap = {
    user,
    profile,
    recoveryKey,
    devices: [device],
    vaults: [{
      id: vaultId,
      kind: 'team',
      ownerUserId: null,
      crypto: cryptoState,
      createdAt: now,
      updatedAt: now,
    }],
    memberships,
    envelopes: [],
    signerProfiles: [],
    headers: [{
      vaultId,
      version: 1,
      keyEpoch: 1,
      blob: {
        suite: 'lm-e2ee-v1',
        aadVersion: 1,
        nonce: 'M'.repeat(32),
        ciphertext: 'N'.repeat(64),
      },
      updatedAt: now,
      updatedBy: accountId,
    }],
    items: [],
    cursor: 1,
  } as EncryptedBootstrapResponse;
  const projection = {
    user,
    vaults: [{
      id: vaultId,
      kind: 'team',
      name: 'Recovery vault',
      ownerUserId: null,
      createdAt: now,
      updatedAt: now,
    }],
    memberships,
    items: [],
    cursor: 10,
    vaultCrypto: { [vaultId]: cryptoState },
    vaultDirectories: {},
    encryptedItems: {},
  } as DecryptedBootstrapProjection;
  const api = {
    setCsrfToken: vi.fn(),
    encryptedBootstrap: vi.fn().mockResolvedValue(bootstrap),
    accountCryptoResetRequests: vi.fn().mockResolvedValue([]),
    completeRecovery: vi.fn().mockResolvedValue({ ...request, status: 'completed' }),
    distributeRecoveryEnvelope: vi.fn().mockResolvedValue({ ok: true, alreadyCovered: false }),
    rekeyMaterial: vi.fn().mockResolvedValue({}),
    commitVaultRekey: vi.fn().mockResolvedValue(cryptoState),
  } as unknown as ApiClient & {
    encryptedBootstrap: ReturnType<typeof vi.fn>;
    completeRecovery: ReturnType<typeof vi.fn>;
    distributeRecoveryEnvelope: ReturnType<typeof vi.fn>;
    rekeyMaterial: ReturnType<typeof vi.fn>;
    commitVaultRekey: ReturnType<typeof vi.fn>;
  };
  const keyring = {
    isUnlocked: true,
    deviceId,
    currentGeneration: 1,
    completeRecovery: vi.fn().mockResolvedValue({ idempotencyKey: crypto.randomUUID() }),
    prepareEnterpriseRecoveryEnvelope: vi.fn().mockResolvedValue({}),
    decryptBootstrap: vi.fn().mockResolvedValue(projection),
    rekeyMaterialIntent: vi.fn().mockResolvedValue({ taskId: '', actorDeviceId: deviceId, signature: 'signature' }),
    prepareVaultRekey: vi.fn().mockResolvedValue({ idempotencyKey: crypto.randomUUID() }),
    commitVaultRekey: vi.fn().mockResolvedValue(undefined),
    abortVaultRekey: vi.fn().mockResolvedValue(undefined),
  } as unknown as E2eeKeyringPort & {
    rekeyMaterialIntent: ReturnType<typeof vi.fn>;
    prepareEnterpriseRecoveryEnvelope: ReturnType<typeof vi.fn>;
    commitVaultRekey: ReturnType<typeof vi.fn>;
  };
  const storage = new MemoryEncryptedStorage();
  const client = new ZeroKnowledgeClient({
    api,
    store: createMetaStore(),
    leases: new SecretLeaseStore(),
    keyring,
    storage,
    outbox: new EncryptedCommandOutbox(api, storage),
  });
  return { api, keyring, client, profile, recoveryKey, request };
}
