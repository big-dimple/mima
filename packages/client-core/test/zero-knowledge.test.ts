import { describe, expect, it, vi } from 'vitest';
import { ITEM_METADATA_FORMAT_VERSION } from '@mima/contracts';
import type {
  CryptoDevice,
  EncryptedBootstrapResponse,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
  UserCryptoProfile,
} from '@mima/contracts';
import {
  createUnsignedVaultKeyGrant,
  createVaultKeys,
  canonicalJson,
  destroyKeyPair,
  destroyVaultKeys,
  encryptVaultMetadata,
  enterpriseRecoveryTransferEvidenceDigest,
  generateEncryptionKeyPair,
  type JsonValue,
  type UnsignedVaultKeyEnvelopeInput,
  utf8,
  verifyBytes,
} from '@mima/e2ee';
import {
  E2eeKeyring,
  EncryptedCommandOutbox,
  IndexedDbEncryptedStorage,
  MemoryEncryptedStorage,
  ApiRequestError,
  SecretLeaseStore,
  ZeroKnowledgeClient,
  assertCiphertextOnly,
  createMetaStore,
  itemPayload,
  type ApiClient,
  type CachedAccountLocator,
  type EncryptedStorageBackend,
  type OfflineRecoveryResult,
  type PendingAccountCryptoResetLocator,
} from '../src/index.ts';

const accountId = 'user:zero-knowledge-test';
const deviceId = 'bc94f99e-a319-4cb1-90aa-d55f4d5ab391';
const user = {
  id: accountId,
  username: 'alice',
  displayName: 'Alice',
  email: 'alice@example.test',
  groups: [],
  isPlatformAdmin: false,
};

async function currentOfflineRecoveryResult(
  request: EnterpriseRecoveryRequest,
  recoveryKey: EnterpriseRecoveryKey,
  recoveredEnvelope: UnsignedVaultKeyEnvelopeInput,
): Promise<OfflineRecoveryResult> {
  const evidence = {
    requestId: request.id,
    requestDigest: request.requestDigest,
    vaultId: request.vaultId,
    epoch: recoveredEnvelope.epoch,
    recoveryKeyId: recoveryKey.id,
    ceremonyId: recoveryKey.ceremonyId,
    recoveryCeremonyDigest: recoveryKey.ceremonyEvidenceDigest,
    targetUserId: request.targetUserId,
    targetCapability: request.targetCapability,
    recoveredEnvelope,
  };
  return {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-transfer',
    formatVersion: 1,
    ...evidence,
    toolEvidenceDigest: await enterpriseRecoveryTransferEvidenceDigest(evidence),
    evidenceFormat: 'recovered-envelope-v1',
  };
}

async function setupAccount(password = 'correct horse battery staple') {
  const keyring = new E2eeKeyring();
  const setup = await keyring.setup(password, {
    accountId,
    deviceId,
    deviceName: 'Test browser',
    platform: 'web:test',
  });
  const now = new Date().toISOString();
  const profile: UserCryptoProfile = {
    userId: accountId,
    profileVersion: 1,
    keyVersion: 1,
    suite: setup.request.suite,
    kdf: setup.request.kdf,
    encryptedAccountBundle: setup.request.encryptedAccountBundle,
    encryptionPublicKey: setup.request.encryptionPublicKey,
    signingPublicKey: setup.request.signingPublicKey,
    recoveryEnabled: true,
    createdAt: now,
    updatedAt: now,
  };
  const device: CryptoDevice = {
    id: deviceId,
    userId: accountId,
    deviceType: 'web',
    encryptedLabel: null,
    encryptionPublicKey: setup.request.device.encryptionPublicKey,
    signingPublicKey: setup.request.device.signingPublicKey,
    certificate: setup.request.device.certificate,
    certificateSignature: setup.request.device.certificateSignature,
    keyVersion: 1,
    trustedAt: now,
    lastSeenAt: now,
    revokedAt: null,
  };
  return { keyring, setup, profile, device };
}

function emptyBootstrap(profile: UserCryptoProfile, device: CryptoDevice): EncryptedBootstrapResponse {
  return {
    user,
    profile,
    recoveryKey: null,
    devices: [device],
    vaults: [],
    memberships: [],
    envelopes: [],
    headers: [],
    items: [],
    signerProfiles: [],
    cursor: 0,
  };
}

type RewrapRequest = Parameters<ApiClient['rewrapCryptoProfile']>[0];

function profileAfterRewrap(profile: UserCryptoProfile, request: RewrapRequest): UserCryptoProfile {
  return {
    ...profile,
    profileVersion: profile.profileVersion + 1,
    kdf: request.kdf,
    encryptedAccountBundle: request.encryptedAccountBundle,
    updatedAt: new Date().toISOString(),
  };
}

function passwordChangeApi(
  profile: UserCryptoProfile,
  device: CryptoDevice,
  overrides: {
    rewrap?: (request: RewrapRequest) => Promise<UserCryptoProfile>;
    profile?: () => Promise<UserCryptoProfile | null>;
  } = {},
): ApiClient {
  let currentProfile = profile;
  const rewrap = overrides.rewrap ?? (async (request: RewrapRequest) => {
    currentProfile = profileAfterRewrap(profile, request);
    return currentProfile;
  });
  return {
    setCsrfToken: vi.fn(),
    encryptedBootstrap: vi.fn().mockResolvedValue(emptyBootstrap(profile, device)),
    accountCryptoResetRequests: vi.fn().mockResolvedValue([]),
    rewrapCryptoProfile: vi.fn(rewrap),
    cryptoProfile: vi.fn(overrides.profile ?? (async () => currentProfile)),
  } as unknown as ApiClient;
}

function createZeroKnowledgeClient(
  api: ApiClient,
  keyring: E2eeKeyring,
  storage: MemoryEncryptedStorage,
): ZeroKnowledgeClient {
  return new ZeroKnowledgeClient({
    api,
    store: createMetaStore(),
    leases: new SecretLeaseStore(),
    keyring,
    storage,
    outbox: new EncryptedCommandOutbox(api, storage),
  });
}

describe('zero-knowledge client key lifecycle', () => {
  it('rejects a wrong main password and destroys all key references on lock', async () => {
    const { keyring, setup, profile, device } = await setupAccount();
    await keyring.lock();
    const generation = keyring.currentGeneration;
    await expect(
      keyring.unlock('wrong main password', profile, device, setup.deviceBundle),
    ).rejects.toMatchObject({ code: 'authentication_failed' });
    expect(keyring.isUnlocked).toBe(false);
    await keyring.unlock('correct horse battery staple', profile, device, setup.deviceBundle);
    expect(keyring.isUnlocked).toBe(true);
    await keyring.lock();
    expect(keyring.isUnlocked).toBe(false);
    expect(keyring.deviceId).toBeNull();
    expect(keyring.currentGeneration).toBeGreaterThan(generation);
  });

  it('returns to the locked phase after a wrong main password', async () => {
    const { keyring, setup, profile, device } = await setupAccount();
    await keyring.lock();
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    const api = {
      setCsrfToken: vi.fn(),
      encryptedBootstrap: vi.fn().mockResolvedValue(emptyBootstrap(profile, device)),
    } as unknown as ApiClient;
    const store = createMetaStore();
    const client = new ZeroKnowledgeClient({
      api,
      store,
      leases: new SecretLeaseStore(),
      keyring,
      storage,
      outbox: new EncryptedCommandOutbox(api, storage),
    });
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    await expect(client.unlock('wrong main password')).rejects.toThrow('主密码不正确');
    expect(client.phase).toBe('authenticated-locked');
    expect(store.getState().securityPhase).toBe('authenticated-locked');
  });

  it('prepares a locked session from profile and device routes before downloading vault ciphertext', async () => {
    const { keyring, setup, profile, device } = await setupAccount();
    await keyring.lock();
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    const api = {
      setCsrfToken: vi.fn(),
      encryptedBootstrap: vi.fn().mockRejectedValue(new ApiRequestError(423, { message: 'locked' })),
      cryptoProfile: vi.fn().mockResolvedValue(profile),
      cryptoDevices: vi.fn().mockResolvedValue([device]),
      accountCryptoResetRequests: vi.fn().mockResolvedValue([]),
    } as unknown as ApiClient;
    const client = createZeroKnowledgeClient(api, keyring, storage);

    await expect(client.prepare({
      user,
      csrfToken: 'csrf-test',
      locked: true,
      cryptoProfileInitialized: true,
      cryptoDeviceId: null,
    })).resolves.toBe('authenticated-locked');
    expect(api.encryptedBootstrap).not.toHaveBeenCalled();
    expect(api.cryptoProfile).toHaveBeenCalledOnce();
    expect(api.cryptoDevices).toHaveBeenCalledOnce();
  });

  it('creates a team vault without recovery and retries the same atomic request after network uncertainty', async () => {
    const { keyring, profile, device } = await setupAccount();
    const storage = new MemoryEncryptedStorage();
    const createEncryptedVault = vi.fn()
      .mockRejectedValueOnce(new ApiRequestError(0, { message: 'connection reset after upload' }))
      .mockImplementation(async (request: { vaultId: string }) => ({ id: request.vaultId }));
    const initializeVaultCrypto = vi.fn().mockResolvedValue(undefined);
    const api = {
      setCsrfToken: vi.fn(),
      encryptedBootstrap: vi.fn().mockResolvedValue(emptyBootstrap(profile, device)),
      accountCryptoResetRequests: vi.fn().mockResolvedValue([]),
      createEncryptedVault,
      legacyMigrationStatus: vi.fn().mockResolvedValue({
        status: 'pending',
        emptyVaultInitializationAllowed: true,
        job: null,
        materials: {
          recipients: [{
            userId: accountId,
            role: 'owner',
            capability: 'full',
            keyVersion: profile.keyVersion,
            encryptionPublicKey: profile.encryptionPublicKey,
            signingPublicKey: profile.signingPublicKey,
          }],
          devices: [],
          recoveryKey: null,
        },
      }),
      initializeVaultCrypto,
    } as unknown as ApiClient;
    const client = createZeroKnowledgeClient(api, keyring, storage);

    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    const createdVaultId = await client.createVault('Engineering');
    expect(createdVaultId).toMatch(/^[0-9a-f-]{36}$/);
    expect(createEncryptedVault).toHaveBeenCalledWith(expect.objectContaining({
      vaultId: createdVaultId,
      epoch: 1,
      envelopes: [expect.objectContaining({ recipientKind: 'user', recipientId: accountId })],
    }));
    expect(createEncryptedVault).toHaveBeenCalledTimes(2);
    expect(createEncryptedVault.mock.calls[1]?.[0]).toEqual(createEncryptedVault.mock.calls[0]?.[0]);
    expect(initializeVaultCrypto).not.toHaveBeenCalled();
    await keyring.lock();
  });

  it('persists only an outer ciphertext for the offline snapshot', async () => {
    const { keyring, setup, profile, device } = await setupAccount();
    const storage = new MemoryEncryptedStorage();
    const snapshot = emptyBootstrap(profile, device);
    snapshot.user.displayName = 'PLAINTEXT-METADATA-MARKER';
    const encryptedBootstrap = await keyring.encryptOfflineSnapshot({
      bootstrap: snapshot,
      contents: {},
    });
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap,
      cachedAt: new Date().toISOString(),
    });
    const persisted = JSON.stringify([...storage.accounts.values()]);
    expect(persisted).not.toContain('PLAINTEXT-METADATA-MARKER');
    expect(persisted).not.toContain('correct horse battery staple');
    expect(persisted).toContain('ciphertext');
    const restored = await keyring.decryptOfflineSnapshot(encryptedBootstrap);
    expect(restored.bootstrap.user.displayName).toBe('PLAINTEXT-METADATA-MARKER');
    await keyring.lock();
  });

  it('enrolls a new browser with a public-only certificate and keeps private keys local', async () => {
    const { keyring, profile } = await setupAccount();
    await keyring.lock();
    const enrolled = await keyring.enrollWebDevice(
      'correct horse battery staple',
      profile,
      '72a9cab4-4f28-410c-afd6-bcf5f3e6c332',
    );
    const uploaded = JSON.stringify(enrolled.request);
    expect(uploaded).not.toContain('encryptedPrivateKeys');
    expect(uploaded).not.toContain(enrolled.deviceBundle.encryptedPrivateKeys.ciphertext);
    expect(enrolled.request.deviceType).toBe('web');
    expect(enrolled.deviceBundle.encryptedPrivateKeys.ciphertext).toMatch(/^[A-Za-z0-9_-]+$/);
    const { approvalSignature, ...unsigned } = enrolled.request;
    const approvalBytes = utf8(canonicalJson({
      itemId: null,
      kind: 'crypto.device.register',
      protocol: profile.suite,
      request: unsigned,
      userId: profile.userId,
      vaultId: null,
    } as never));
    await expect(verifyBytes(approvalSignature, approvalBytes, profile.signingPublicKey)).resolves.toBe(true);
    approvalBytes.fill(0);
    expect(keyring.isUnlocked).toBe(true);
    await keyring.lock();
  });

  it('binds newly enrolled devices to the current rotated profile generation', async () => {
    const { keyring, profile } = await setupAccount();
    await keyring.lock();
    const rotatedProfile = { ...profile, keyVersion: 2 };
    const enrolled = await keyring.enrollWebDevice(
      'correct horse battery staple',
      rotatedProfile,
      '90fa696c-3412-4d17-b958-431eac0ad44c',
    );
    const certificateBytes = Buffer.from(enrolled.request.certificate, 'base64url');
    const certificate = JSON.parse(certificateBytes.toString('utf8')) as { keyVersion: number };
    expect(certificate.keyVersion).toBe(2);
    await keyring.lock();
  });

  it('changes only the main-password wrapping and signs the exact server request', async () => {
    const currentPassword = 'correct horse battery staple';
    const newPassword = 'new correct horse battery staple';
    const { keyring, setup, profile, device } = await setupAccount(currentPassword);
    const request = await keyring.prepareMasterPasswordChange(currentPassword, newPassword, profile);
    const { signature, ...unsigned } = request;
    const bytes = utf8(canonicalJson({
      itemId: null,
      kind: 'crypto.profile.rewrap',
      protocol: 'lm-e2ee-v1',
      request: unsigned,
      userId: accountId,
      vaultId: null,
    }));
    expect(await verifyBytes(signature, bytes, device.signingPublicKey)).toBe(true);
    bytes.fill(0);
    expect(request.expectedProfileVersion).toBe(profile.profileVersion);
    expect(request.kdf.salt).not.toBe(profile.kdf.salt);
    expect(JSON.stringify(request)).not.toContain(currentPassword);
    expect(JSON.stringify(request)).not.toContain(newPassword);

    const updatedProfile = profileAfterRewrap(profile, request);
    await keyring.lock();
    await expect(keyring.unlock(currentPassword, updatedProfile, device, setup.deviceBundle))
      .rejects.toMatchObject({ code: 'authentication_failed' });
    await keyring.unlock(newPassword, updatedProfile, device, setup.deviceBundle);
    expect(keyring.deviceId).toBe(device.id);
    await keyring.lock();
  });

  it('persists the new profile in both the account locator and encrypted offline snapshot', async () => {
    const currentPassword = 'correct horse battery staple';
    const newPassword = 'new correct horse battery staple';
    const { keyring, setup, profile, device } = await setupAccount(currentPassword);
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    const api = passwordChangeApi(profile, device);
    const client = createZeroKnowledgeClient(api, keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });

    await expect(client.changeMainPassword(currentPassword, newPassword, newPassword))
      .resolves.toEqual({ localCachePersisted: true });
    const cached = await storage.getAccount(accountId);
    expect(cached?.profile.profileVersion).toBe(2);
    expect(cached?.encryptedBootstrap).not.toBeNull();
    const snapshot = await keyring.decryptOfflineSnapshot(cached!.encryptedBootstrap!);
    expect(snapshot.bootstrap.profile?.profileVersion).toBe(2);
    const persisted = JSON.stringify([...storage.accounts.values()]);
    expect(persisted).not.toContain(currentPassword);
    expect(persisted).not.toContain(newPassword);

    await keyring.lock();
    await expect(keyring.unlock(currentPassword, cached!.profile, cached!.device, cached!.deviceBundle))
      .rejects.toMatchObject({ code: 'authentication_failed' });
    await keyring.unlock(newPassword, cached!.profile, cached!.device, cached!.deviceBundle);
    await keyring.lock();
  });

  it('reconciles a lost update response and preserves pending commands when snapshot persistence fails', async () => {
    const currentPassword = 'correct horse battery staple';
    const newPassword = 'new correct horse battery staple';
    const { keyring, setup, profile, device } = await setupAccount(currentPassword);
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    await storage.putCommand({
      id: 'pending-command',
      accountId,
      kind: 'item.update',
      method: 'PATCH',
      path: '/api/v2/items/00000000-0000-4000-8000-000000000001',
      body: { idempotencyKey: 'pending-command' },
      createdAt: new Date().toISOString(),
    });
    let committedProfile: UserCryptoProfile | null = null;
    const api = passwordChangeApi(profile, device, {
      rewrap: async (request) => {
        committedProfile = profileAfterRewrap(profile, request);
        throw new ApiRequestError(0, { message: 'response lost' });
      },
      profile: async () => committedProfile,
    });
    const client = createZeroKnowledgeClient(api, keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    vi.spyOn(keyring, 'encryptOfflineSnapshot').mockRejectedValueOnce(new Error('quota'));

    await expect(client.changeMainPassword(currentPassword, newPassword, newPassword))
      .resolves.toEqual({ localCachePersisted: false });
    const cached = await storage.getAccount(accountId);
    expect(cached?.profile.profileVersion).toBe(2);
    expect(cached?.encryptedBootstrap).toBeNull();
    expect(await storage.listCommands(accountId)).toHaveLength(1);
    await keyring.lock();
  });

  it('drops only the stale account locator when the server commit result cannot be determined', async () => {
    const currentPassword = 'correct horse battery staple';
    const newPassword = 'new correct horse battery staple';
    const { keyring, setup, profile, device } = await setupAccount(currentPassword);
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    await storage.putCommand({
      id: 'uncertain-command',
      accountId,
      kind: 'item.update',
      method: 'PATCH',
      path: '/api/v2/items/00000000-0000-4000-8000-000000000002',
      body: { idempotencyKey: 'uncertain-command' },
      createdAt: new Date().toISOString(),
    });
    const api = passwordChangeApi(profile, device, {
      rewrap: async () => {
        throw new ApiRequestError(0, { message: 'response lost' });
      },
      profile: async () => {
        throw new ApiRequestError(0, { message: 'still offline' });
      },
    });
    const client = createZeroKnowledgeClient(api, keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });

    await expect(client.changeMainPassword(currentPassword, newPassword, newPassword))
      .rejects.toThrow('服务器可能已经接受主密码更新');
    expect(await storage.getAccount(accountId)).toBeNull();
    expect(await storage.listCommands(accountId)).toHaveLength(1);
    await keyring.lock();
  });

  it('adopts a compatible password rewrap from another device during bootstrap refresh', async () => {
    const currentPassword = 'correct horse battery staple';
    const newPassword = 'new correct horse battery staple';
    const { keyring, setup, profile, device } = await setupAccount(currentPassword);
    const request = await keyring.prepareMasterPasswordChange(currentPassword, newPassword, profile);
    const updatedProfile = profileAfterRewrap(profile, request);
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    const api = passwordChangeApi(profile, device) as ApiClient & {
      encryptedBootstrap: ReturnType<typeof vi.fn>;
    };
    api.encryptedBootstrap
      .mockResolvedValueOnce(emptyBootstrap(profile, device))
      .mockResolvedValueOnce(emptyBootstrap(updatedProfile, device));
    const client = createZeroKnowledgeClient(api, keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });
    await client.refresh();

    const cached = await storage.getAccount(accountId);
    expect(cached?.profile.profileVersion).toBe(2);
    const snapshot = await keyring.decryptOfflineSnapshot(cached!.encryptedBootstrap!);
    expect(snapshot.bootstrap.profile?.profileVersion).toBe(2);
    await keyring.lock();
    await keyring.unlock(newPassword, cached!.profile, cached!.device, cached!.deviceBundle);
    await keyring.lock();
  });

  it('locks immediately and replaces the offline profile after another device changes the main password', async () => {
    const currentPassword = 'correct horse battery staple';
    const newPassword = 'new correct horse battery staple';
    const { keyring, setup, profile, device } = await setupAccount(currentPassword);
    const request = await keyring.prepareMasterPasswordChange(currentPassword, newPassword, profile);
    const updatedProfile = profileAfterRewrap(profile, request);
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    const api = passwordChangeApi(profile, device, { profile: async () => updatedProfile });
    const client = createZeroKnowledgeClient(api, keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });

    await client.applyEncryptedSyncEvent({
      type: 'crypto.profile_rewrapped',
      cursor: 2,
      actorDeviceId: 'a69a55f8-dbc8-4c72-a50a-71d8cd4b8f60',
      profileVersion: 2,
    });

    expect(client.isUnlocked).toBe(false);
    expect(client.phase).toBe('authenticated-locked');
    const cached = await storage.getAccount(accountId);
    expect(cached?.profile.profileVersion).toBe(2);
    await expect(keyring.unlock(currentPassword, cached!.profile, cached!.device, cached!.deviceBundle))
      .rejects.toMatchObject({ code: 'authentication_failed' });
    await keyring.unlock(newPassword, cached!.profile, cached!.device, cached!.deviceBundle);
    await keyring.lock();
  });

  it('does not lock the device that initiated the main-password rewrap', async () => {
    const { keyring, profile, device } = await setupAccount();
    const storage = new MemoryEncryptedStorage();
    const client = createZeroKnowledgeClient(passwordChangeApi(profile, device), keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });

    await client.applyEncryptedSyncEvent({
      type: 'crypto.profile_rewrapped',
      cursor: 2,
      actorDeviceId: device.id,
      profileVersion: 2,
    });

    expect(client.isUnlocked).toBe(true);
    await keyring.lock();
  });

  it('removes the stale offline locator when a remote rewrap profile cannot be refreshed', async () => {
    const { keyring, setup, profile, device } = await setupAccount();
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    const api = passwordChangeApi(profile, device, {
      profile: async () => { throw new ApiRequestError(0, { message: 'offline' }); },
    });
    const client = createZeroKnowledgeClient(api, keyring, storage);
    await client.prepare({ user, csrfToken: 'csrf-test', locked: false });

    await client.applyEncryptedSyncEvent({
      type: 'crypto.profile_rewrapped',
      cursor: 2,
      actorDeviceId: 'a69a55f8-dbc8-4c72-a50a-71d8cd4b8f60',
      profileVersion: 2,
    });

    expect(client.isUnlocked).toBe(false);
    expect(await storage.getAccount(accountId)).toBeNull();
    await expect(client.unlock('correct horse battery staple')).rejects.toThrow('offline');
  });

  it('prepares a dual-signed identity rotation and keeps the old identity until commit', async () => {
    const { keyring, profile, device } = await setupAccount();
    const generation = keyring.currentGeneration;
    const prepared = await keyring.prepareIdentityRotation(
      'correct horse battery staple',
      profile,
      device,
    );
    const { actorSignature, newSigningKeyProof, ...newKeyPayload } = prepared.request;
    const newProofBytes = utf8(canonicalJson({
      itemId: null,
      kind: 'crypto.profile.rotate.new-key',
      protocol: 'lm-e2ee-v1',
      request: newKeyPayload,
      userId: accountId,
      vaultId: null,
    }));
    expect(await verifyBytes(newSigningKeyProof, newProofBytes, prepared.request.signingPublicKey)).toBe(true);
    newProofBytes.fill(0);
    const actorBytes = utf8(canonicalJson({
      itemId: null,
      kind: 'crypto.profile.rotate',
      protocol: 'lm-e2ee-v1',
      request: { ...newKeyPayload, newSigningKeyProof },
      userId: accountId,
      vaultId: null,
    }));
    expect(await verifyBytes(actorSignature, actorBytes, device.signingPublicKey)).toBe(true);
    actorBytes.fill(0);
    expect(prepared.request.newKeyVersion).toBe(profile.keyVersion + 1);
    expect(prepared.deviceBundle.signingPublicKey).not.toBe(device.signingPublicKey);
    expect(keyring.currentGeneration).toBe(generation);

    await keyring.abortIdentityRotation();
    expect(keyring.isUnlocked).toBe(true);
    await expect(keyring.commitIdentityRotation()).rejects.toThrow('没有待提交');

    await keyring.prepareIdentityRotation('correct horse battery staple', profile, device);
    await keyring.commitIdentityRotation();
    expect(keyring.isUnlocked).toBe(true);
    expect(keyring.deviceId).toBe(device.id);
    expect(keyring.currentGeneration).toBeGreaterThan(generation);
    await keyring.lock();
  });

  it('keeps an account reset candidate ciphertext-only and requires candidate user/device signatures', async () => {
    const { keyring, profile } = await setupAccount();
    const newPassword = 'new correct horse battery staple';
    const prepared = await keyring.prepareAccountCryptoReset(
      newPassword,
      profile,
      'f4fcb9bc-895e-4e90-b4ca-56ae9c41e8e8',
    );
    const { candidateUserProof, ...candidatePayload } = prepared.request;
    const createBytes = utf8(canonicalJson({
      itemId: null,
      kind: 'crypto.account_reset.create.user',
      protocol: 'lm-e2ee-v1',
      request: candidatePayload,
      userId: accountId,
      vaultId: null,
    }));
    expect(await verifyBytes(
      candidateUserProof,
      createBytes,
      prepared.request.signingPublicKey,
    )).toBe(true);
    createBytes.fill(0);

    const now = new Date().toISOString();
    const reset = {
      id: '01e9e130-e245-49ac-8c87-30285e78d0e5',
      targetUserId: accountId,
      expectedProfileVersion: profile.profileVersion,
      expectedKeyVersion: profile.keyVersion,
      newKeyVersion: profile.keyVersion + 1,
      suite: prepared.request.suite,
      kdf: prepared.request.kdf,
      encryptedAccountBundle: prepared.request.encryptedAccountBundle,
      encryptionPublicKey: prepared.request.encryptionPublicKey,
      signingPublicKey: prepared.request.signingPublicKey,
      candidateDevice: prepared.request.candidateDevice,
      requestDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      status: 'approved' as const,
      approvalUserIds: ['admin-1', 'admin-2'],
      affectedVaultIds: [],
      createdAt: now,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      approvedAt: now,
      activatedAt: null,
      cancelledAt: null,
    };
    const storage = new MemoryEncryptedStorage();
    await storage.putPendingAccountCryptoReset({
      accountId,
      request: reset,
      accountBundle: prepared.accountBundle,
      deviceBundle: prepared.deviceBundle,
      cachedAt: now,
    });
    const persisted = JSON.stringify([...storage.accountCryptoResets.values()]);
    expect(persisted).not.toContain(newPassword);
    expect(persisted).not.toContain('privateKey');
    expect(persisted).toContain('encryptedPrivateKeys');

    const activation = await keyring.prepareAccountCryptoResetActivation(accountId, reset);
    const activationPayload = {
      idempotencyKey: activation.request.idempotencyKey,
      requestId: reset.id,
      requestDigest: reset.requestDigest,
    };
    for (const [kind, signature, publicKey] of [
      ['crypto.account_reset.activate.device', activation.request.candidateDevicePossessionSignature, reset.candidateDevice.signingPublicKey],
      ['crypto.account_reset.activate.user', activation.request.candidateUserSignature, reset.signingPublicKey],
    ] as const) {
      const bytes = utf8(canonicalJson({
        itemId: null,
        kind,
        protocol: 'lm-e2ee-v1',
        request: activationPayload,
        userId: accountId,
        vaultId: null,
      }));
      expect(await verifyBytes(signature, bytes, publicKey)).toBe(true);
      bytes.fill(0);
    }

    await keyring.abortAccountCryptoReset();
    await expect(keyring.unlockPendingAccountCryptoReset(
      'wrong new password',
      prepared.accountBundle,
      prepared.deviceBundle,
    )).rejects.toMatchObject({ code: 'authentication_failed' });
    await keyring.unlockPendingAccountCryptoReset(
      newPassword,
      prepared.accountBundle,
      prepared.deviceBundle,
    );
    await keyring.commitAccountCryptoReset();
    expect(keyring.deviceId).toBe(reset.candidateDevice.id);
    await keyring.lock();
  });

  it('wipes decrypted metadata projection when locking', () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user,
      vaults: [{
        id: 'b88e81ca-93de-46ca-94cf-2fa17f98a426',
        kind: 'personal',
        name: 'Finance',
        ownerUserId: accountId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }],
      memberships: [],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    store.getState().lockProjection();
    expect(store.getState().user?.id).toBe(accountId);
    expect(store.getState().vaults).toEqual({});
    expect(store.getState().items).toEqual({});
    expect(store.getState().locked).toBe(true);
  });

  it('encrypts sync metadata and signs the exact v2 command preimage', async () => {
    const { keyring, setup, profile } = await setupAccount();
    const vaultId = 'b05e411a-75c2-46f4-a039-3216df04cf20';
    const recovery = await generateEncryptionKeyPair();
    try {
      await keyring.initializeVault(accountId, vaultId, 'Engineering', profile, {
        id: '5d63a0ed-f4da-488e-bbe0-e7f1164bc490',
        ceremonyId: 'test-ceremony',
        keyFingerprint: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
        publicEncryptionKey: recovery.publicKey,
        threshold: 2,
        shareCount: 3,
        status: 'active',
        ceremonyEvidenceDigest: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        retiredAt: null,
      });
      const request = await keyring.encryptCreate(accountId, vaultId, {
        kind: 'login',
        title: 'Internal portal',
        username: 'alice',
        origin: 'https://portal.example.test',
        loginUrl: 'https://portal.example.test/login?tenant=engineering',
        folderPath: '工作/内部系统',
        description: 'Engineering owner account',
        tags: ['team'],
        favorite: false,
        sensitivity: 'high',
        secretValue: 'not-in-metadata',
      });
      const { signature, ...unsigned } = request;
      const bytes = utf8(canonicalJson({
        itemId: request.itemId,
        kind: 'item.create',
        protocol: 'lm-e2ee-v1',
        request: unsigned,
        userId: accountId,
        vaultId,
      }));
      expect(await verifyBytes(signature, bytes, setup.request.device.signingPublicKey)).toBe(true);
      bytes.fill(0);
      const item = await keyring.decryptMetadataRecord({
        itemId: request.itemId,
        vaultId,
        version: 1,
        secretVersion: 1,
        keyEpoch: 1,
        deleted: false,
        blob: request.metadata,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        updatedBy: accountId,
      });
      expect(item.title).toBe('Internal portal');
      expect(item.loginUrl).toBe('https://portal.example.test/login?tenant=engineering');
      expect(item.folderPath).toBe('工作/内部系统');
      expect(item.description).toBe('Engineering owner account');
      expect(JSON.stringify(request.metadata)).not.toContain('Internal portal');
      expect(JSON.stringify(request.metadata)).not.toContain('tenant=engineering');
      expect(JSON.stringify(request.metadata)).not.toContain('内部系统');
      expect(JSON.stringify(request.metadata)).not.toContain('Engineering owner account');
      expect(JSON.stringify(request.metadata)).not.toContain('not-in-metadata');

      const metadataUpdate = await keyring.encryptMetadataUpdate(accountId, item, {
        ...itemPayload(item),
        title: 'Internal portal renamed',
      });
      expect(metadataUpdate.metadataFormatVersion).toBe(ITEM_METADATA_FORMAT_VERSION);
      const updated = await keyring.decryptMetadataRecord({
        itemId: item.id,
        vaultId,
        version: 2,
        secretVersion: 1,
        keyEpoch: 1,
        deleted: false,
        blob: metadataUpdate.metadata,
        createdAt: item.createdAt,
        updatedAt: new Date().toISOString(),
        updatedBy: accountId,
      });
      expect(updated.loginUrl).toBe('https://portal.example.test/login?tenant=engineering');
      expect(updated.folderPath).toBe('工作/内部系统');
      expect(updated.description).toBe('Engineering owner account');

      const rotation = await keyring.encryptRotation(accountId, updated, 'rotated-password');
      expect(rotation.metadataFormatVersion).toBe(ITEM_METADATA_FORMAT_VERSION);
      const rotated = await keyring.decryptMetadataRecord({
        itemId: item.id,
        vaultId,
        version: 3,
        secretVersion: 3,
        keyEpoch: 1,
        deleted: false,
        blob: rotation.metadata,
        createdAt: item.createdAt,
        updatedAt: new Date().toISOString(),
        updatedBy: accountId,
      });
      expect(rotated.loginUrl).toBe('https://portal.example.test/login?tenant=engineering');
      expect(rotated.description).toBe('Engineering owner account');
    } finally {
      await destroyKeyPair(recovery);
      await keyring.lock();
    }
  });

  it('initializes a personal vault without an enterprise recovery envelope', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = '434ddae4-c5a1-4dbf-877e-24a126fb2712';
    try {
      const initialized = await keyring.initializeVault(
        accountId,
        vaultId,
        '个人密码库',
        profile,
        null,
        'legacy',
        [],
        {
          recipients: [{
            userId: accountId,
            role: 'owner',
            capability: 'full',
            keyVersion: profile.keyVersion,
            encryptionPublicKey: profile.encryptionPublicKey,
            signingPublicKey: profile.signingPublicKey,
          }],
          devices: [],
          recoveryKey: null,
        },
      );
      expect(initialized.envelopes).toHaveLength(1);
      expect(initialized.envelopes[0]).toMatchObject({
        recipientKind: 'user',
        recipientId: accountId,
        capability: 'full',
      });
    } finally {
      await keyring.lock();
    }
  });

  it('encrypts URL-only logins with an empty compatibility sentinel and adds a password atomically', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = '12e53359-42b4-43d2-a84a-c6f4d299f99a';
    const now = new Date().toISOString();
    try {
      await keyring.initializeVault(accountId, vaultId, 'Shared entries', profile, null);
      const created = await keyring.encryptCreate(accountId, vaultId, {
        kind: 'login',
        title: 'Tencent Cloud entry',
        username: null,
        origin: 'https://accounts.example.test',
        loginUrl: 'https://accounts.example.test/login',
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        secretValue: null,
      });
      const metadata = {
        itemId: created.itemId,
        vaultId,
        version: 1,
        secretVersion: 1,
        keyEpoch: 1,
        deleted: false,
        blob: created.metadata,
        createdAt: now,
        updatedAt: now,
        updatedBy: accountId,
      };
      const decrypted = await keyring.decryptMetadataRecord(metadata);
      expect(decrypted.secretState).toBe('absent');
      await expect(keyring.decryptContent({
        metadata,
        secret: {
          itemId: created.itemId,
          vaultId,
          recordVersion: 1,
          secretVersion: 1,
          encryptedValue: created.encryptedValue,
          createdAt: now,
          createdBy: deviceId,
        },
        keyWrap: {
          itemId: created.itemId,
          vaultId,
          secretVersion: 1,
          keyEpoch: 1,
          wrappedDek: created.wrappedDek,
          createdAt: now,
          createdBy: deviceId,
        },
      })).resolves.toBe('');

      const rotation = await keyring.encryptRotation(accountId, decrypted, 'personal-password');
      expect(rotation.metadataFormatVersion).toBe(ITEM_METADATA_FORMAT_VERSION);
      const withPassword = await keyring.decryptMetadataRecord({
        ...metadata,
        version: 2,
        secretVersion: 2,
        blob: rotation.metadata,
      });
      expect(withPassword.secretState).toBe('present');
      await expect(keyring.encryptRotation(accountId, withPassword, ''))
        .rejects.toThrow('请输入要保存的密码或敏感内容');
      await expect(keyring.encryptCreate(accountId, vaultId, {
        kind: 'api_token',
        title: 'Invalid empty token',
        username: null,
        origin: null,
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        secretValue: null,
      })).rejects.toThrow('密钥 / Token不能为空');
    } finally {
      await keyring.lock();
    }
  });

  it('signs a short-lived extension session resume request with the current workbench device', async () => {
    const { keyring, setup, profile } = await setupAccount();
    const issuedAt = new Date();
    const trustedRequest = {
      protocol: 'mima-extension-trusted-unlock-v1' as const,
      requestId: '3d5f51da-670d-4a20-a11c-92a6bd6014c7',
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + 10_000).toISOString(),
      accountId,
      accountKeyVersion: profile.keyVersion,
      deviceId: 'f0f424b8-9cf8-40dc-af69-1df03ca8d94d',
      deviceEncryptionPublicKey: 'extension-encryption-public-key',
      deviceSigningPublicKey: 'extension-signing-public-key',
      fingerprint: '1111 2222 3333 4444 5555 6666 7777 8888',
      recordDigest: 'extension-record-digest',
      ephemeralEncryptionPublicKey: 'extension-ephemeral-public-key',
    };
    try {
      const prepared = await keyring.prepareExtensionSessionResume(accountId, trustedRequest);
      expect(prepared.approverDeviceId).toBe(setup.request.device.id);
      const { signature, ...unsigned } = prepared;
      const bytes = utf8(canonicalJson({
        itemId: null,
        kind: 'crypto.extension.session.resume',
        protocol: 'lm-e2ee-v1',
        request: unsigned as unknown as JsonValue,
        userId: accountId,
        vaultId: null,
      }));
      expect(await verifyBytes(signature, bytes, setup.request.device.signingPublicKey)).toBe(true);
      bytes.fill(0);
    } finally {
      await keyring.lock();
    }
  });

  it('includes every active extension device when initializing a new vault epoch', async () => {
    const { keyring, profile, device } = await setupAccount();
    const recovery = await generateEncryptionKeyPair();
    const extensionKeys = await generateEncryptionKeyPair();
    const vaultId = 'd64139dd-a18e-4f1e-9132-b91e2a1c90c9';
    const extension: CryptoDevice = {
      ...device,
      id: '1ea53fd1-56ea-44c9-b605-486c4c69e72d',
      deviceType: 'extension',
      encryptionPublicKey: extensionKeys.publicKey,
    };
    try {
      const initialized = await keyring.initializeVault(accountId, vaultId, 'Extension team', profile, {
        id: '23313154-2e80-4b49-a2f0-f2534c0f450e',
        ceremonyId: 'extension-initialize-test',
        keyFingerprint: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
        publicEncryptionKey: recovery.publicKey,
        threshold: 2,
        shareCount: 3,
        status: 'active',
        ceremonyEvidenceDigest: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        retiredAt: null,
      }, 'preparing', [device, extension]);
      expect(initialized.envelopes).toHaveLength(3);
      expect(initialized.envelopes).toEqual(expect.arrayContaining([
        expect.objectContaining({
          recipientKind: 'device',
          recipientId: extension.id,
          recipientKeyVersion: extension.keyVersion,
          capability: 'full',
        }),
      ]));
    } finally {
      await destroyKeyPair(extensionKeys);
      await destroyKeyPair(recovery);
      await keyring.lock();
    }
  });

  it('keeps offline create and rotate ciphertext readable without persisting plaintext', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = 'f7827df5-d3ec-4651-aabc-f0b0a6396866';
    const recovery = await generateEncryptionKeyPair();
    const storage = new MemoryEncryptedStorage();
    const store = createMetaStore();
    const outbox = new EncryptedCommandOutbox({ sendEncryptedCommand: vi.fn() } as unknown as ApiClient, storage);
    await outbox.restore(accountId);
    const zeroKnowledge = new ZeroKnowledgeClient({
      api: {} as ApiClient,
      store,
      leases: new SecretLeaseStore(),
      keyring,
      storage,
      outbox,
    });
    try {
      await keyring.initializeVault(accountId, vaultId, 'Offline team', profile, {
        id: 'e8c73489-a62c-4270-816f-6e643b1768db',
        ceremonyId: 'offline-test',
        keyFingerprint: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
        publicEncryptionKey: recovery.publicKey,
        threshold: 2,
        shareCount: 3,
        status: 'active',
        ceremonyEvidenceDigest: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        retiredAt: null,
      });
      store.getState().applyDecryptedBootstrap({
        user,
        vaults: [{
          id: vaultId,
          kind: 'team',
          name: 'Offline team',
          ownerUserId: null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }],
        memberships: [],
        items: [],
        cursor: 0,
        vaultCrypto: {},
        vaultDirectories: {},
        encryptedItems: {},
      });
      zeroKnowledge.setOnline(false);
      const itemId = await zeroKnowledge.createItem(vaultId, {
        kind: 'login',
        title: 'Offline portal',
        username: 'alice',
        origin: 'https://offline.example.test',
        tags: [],
        favorite: false,
        sensitivity: 'high',
        secretValue: 'offline-created-value',
      });
      await expect(zeroKnowledge.reveal(itemId, 'view')).resolves.toMatchObject({
        value: 'offline-created-value',
      });
      const item = store.getState().items[itemId]!;
      await zeroKnowledge.rotateItem(item, 'offline-rotated-value');
      await expect(zeroKnowledge.reveal(itemId, 'view')).resolves.toMatchObject({
        value: 'offline-rotated-value',
      });
      const persisted = JSON.stringify([...storage.commands.values()]);
      expect(persisted).not.toContain('offline-created-value');
      expect(persisted).not.toContain('offline-rotated-value');
      expect(outbox.size).toBe(2);
    } finally {
      await destroyKeyPair(recovery);
      await keyring.lock();
    }
  });

  it('retains an encrypted candidate when an online item update conflicts', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = 'f8a03c98-a3e2-49e2-8385-aeb75c715c89';
    const itemId = '5e0d634c-a006-4632-bf09-8667698550f6';
    const recovery = await generateEncryptionKeyPair();
    const storage = new MemoryEncryptedStorage();
    const store = createMetaStore();
    const api = {
      updateEncryptedItem: vi.fn().mockRejectedValue(new ApiRequestError(409, {
        statusCode: 409,
        error: 'Conflict',
        message: '版本冲突',
        currentVersion: 3,
      })),
    } as unknown as ApiClient;
    const outbox = new EncryptedCommandOutbox(api, storage);
    const onConflict = vi.fn();
    outbox.onConflict(onConflict);
    await outbox.restore(accountId);
    const zeroKnowledge = new ZeroKnowledgeClient({
      api,
      store,
      leases: new SecretLeaseStore(),
      keyring,
      storage,
      outbox,
    });
    const item = {
      id: itemId,
      vaultId,
      kind: 'login' as const,
      title: 'Server title',
      username: 'alice',
      origin: 'https://conflict.example.test',
      tags: [],
      favorite: false,
      sensitivity: 'high' as const,
      secretState: 'present' as const,
      version: 2,
      secretVersion: 1,
      createdAt: '2026-07-19T00:00:00.000Z',
      updatedAt: '2026-07-19T01:00:00.000Z',
      updatedBy: 'user-2',
    };
    try {
      await keyring.initializeVault(accountId, vaultId, 'Conflict team', profile, {
        id: '7d8f377d-afca-4ed0-a505-2a62cbb06a7b',
        ceremonyId: 'online-conflict-test',
        keyFingerprint: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
        publicEncryptionKey: recovery.publicKey,
        threshold: 2,
        shareCount: 3,
        status: 'active',
        ceremonyEvidenceDigest: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        retiredAt: null,
      });
      store.getState().applyDecryptedBootstrap({
        user,
        vaults: [{
          id: vaultId,
          kind: 'team',
          name: 'Conflict team',
          ownerUserId: null,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt,
        }],
        memberships: [],
        items: [item],
        cursor: 0,
        vaultCrypto: {},
        vaultDirectories: {},
        encryptedItems: {},
      });

      await expect(zeroKnowledge.updateItem(item, {
        kind: 'login',
        title: 'Local candidate title',
        username: 'alice',
        origin: 'https://conflict.example.test',
        tags: ['local'],
        favorite: false,
        sensitivity: 'high',
        secretState: 'present',
      })).resolves.toBeUndefined();

      expect(onConflict).toHaveBeenCalledWith(expect.objectContaining({
        kind: 'item.update',
        path: `/api/v2/items/${itemId}`,
        conflict: expect.objectContaining({ currentVersion: 3 }),
      }));
      const persisted = JSON.stringify(await storage.listCommands(accountId));
      expect(persisted).not.toContain('Local candidate title');
      expect(persisted).toContain('version_conflict');
    } finally {
      await destroyKeyPair(recovery);
      await keyring.lock();
    }
  });

  it('rekeys metadata and every content-key wrap before committing the new vault keys', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = '845768cb-0975-47cf-bf08-cc598ff1fc7f';
    const recovery = await generateEncryptionKeyPair();
    const extension = await generateEncryptionKeyPair();
    const recoveryKey = {
      id: '85178050-0476-4c90-928e-97daf91967d7',
      ceremonyId: 'rekey-test',
      keyFingerprint: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
      publicEncryptionKey: recovery.publicKey,
      threshold: 2 as const,
      shareCount: 3 as const,
      status: 'active' as const,
      ceremonyEvidenceDigest: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
      approvalUserIds: ['admin-1', 'admin-2'],
      createdAt: new Date().toISOString(),
      retiredAt: null,
    };
    try {
      const initialized = await keyring.initializeVault(accountId, vaultId, 'Rekey team', profile, recoveryKey);
      const created = await keyring.encryptCreate(accountId, vaultId, {
        kind: 'api_token',
        title: 'Rekey credential',
        username: 'AKID-rekey',
        origin: null,
        description: 'Keep this encrypted description',
        linkedLoginItemId: 'a96b4f4a-9abd-4e10-85dd-3ae86bbb9582',
        tags: [],
        favorite: false,
        sensitivity: 'high',
        secretValue: 'value-survives-rewrap',
      });
      const now = new Date().toISOString();
      const metadata = {
        itemId: created.itemId,
        vaultId,
        version: 1,
        secretVersion: 1,
        keyEpoch: 1,
        deleted: false,
        blob: created.metadata,
        signature: created.signature,
        createdAt: now,
        updatedAt: now,
        updatedBy: accountId,
      };
      const request = await keyring.prepareVaultRekey(accountId, vaultId, profile, {
        task: {
          id: '5cbc09ac-530f-4e25-92df-32e52381b3a5',
          fromEpoch: 1,
          toEpoch: 2,
          reason: 'manual',
          freezeGeneration: 1,
        },
        state: {
          vaultId,
          status: 'rekey_required',
          activeEpoch: 1,
          pendingEpoch: 2,
          rekeyTaskId: '5cbc09ac-530f-4e25-92df-32e52381b3a5',
          encryptedHeader: initialized.header.blob,
          migrationJobId: null,
          updatedAt: now,
        },
        header: { ...initialized.header, updatedAt: now, updatedBy: accountId, signature: initialized.manifestSignature },
        metadata: [metadata],
        keyWraps: [{
          itemId: created.itemId,
          vaultId,
          secretVersion: 1,
          recordVersion: 1,
          keyEpoch: 1,
          wrappedDek: created.wrappedDek,
          signature: created.signature,
          createdAt: now,
          createdBy: deviceId,
        }],
        recipients: [{
          userId: accountId,
          role: 'owner',
          capability: 'full',
          keyVersion: profile.keyVersion,
          encryptionPublicKey: profile.encryptionPublicKey,
          signingPublicKey: profile.signingPublicKey,
        }],
        devices: [{
          deviceId: 'd8aa403c-7c0d-4d06-8747-fc91ca86f484',
          userId: accountId,
          capability: 'full',
          keyVersion: 1,
          encryptionPublicKey: extension.publicKey,
          signingPublicKey: profile.signingPublicKey,
        }],
        recoveryKey,
      });
      expect(request.metadataFormatVersion).toBe(ITEM_METADATA_FORMAT_VERSION);
      expect(request.header.keyEpoch).toBe(2);
      expect(request.reencryptedMetadata).toHaveLength(1);
      expect(request.rewrappedSecrets).toHaveLength(1);
      expect(request.envelopes).toHaveLength(3);
      expect(request.envelopes).toEqual(expect.arrayContaining([
        expect.objectContaining({
          recipientKind: 'device',
          recipientId: 'd8aa403c-7c0d-4d06-8747-fc91ca86f484',
          recipientKeyVersion: 1,
        }),
      ]));
      await keyring.commitVaultRekey(vaultId);
      const item = await keyring.decryptMetadataRecord({
        ...metadata,
        keyEpoch: 2,
        blob: request.reencryptedMetadata[0]!.blob,
      });
      expect(item.title).toBe('Rekey credential');
      expect(item.description).toBe('Keep this encrypted description');
      expect(item.linkedLoginItemId).toBe('a96b4f4a-9abd-4e10-85dd-3ae86bbb9582');
      await expect(keyring.decryptContent({
        metadata: { ...metadata, keyEpoch: 2, blob: request.reencryptedMetadata[0]!.blob },
        secret: {
          itemId: created.itemId,
          vaultId,
          secretVersion: 1,
          recordVersion: 1,
          encryptedValue: created.encryptedValue,
          createdAt: now,
          createdBy: deviceId,
        },
        keyWrap: {
          itemId: created.itemId,
          vaultId,
          secretVersion: 1,
          keyEpoch: 2,
          wrappedDek: request.rewrappedSecrets[0]!.wrappedDek,
          createdAt: now,
          createdBy: deviceId,
        },
      })).resolves.toBe('value-survives-rewrap');
    } finally {
      await destroyKeyPair(extension);
      await destroyKeyPair(recovery);
      await keyring.lock();
    }
  });

  it('selects only the opened epoch header and rejects conflicting header ciphertext', async () => {
    const { keyring, profile, device } = await setupAccount();
    const vaultId = '8eac111d-6935-488d-a8db-97ca35d128a0';
    const recovery = await generateEncryptionKeyPair();
    const now = new Date().toISOString();
    const recoveryKey = {
      id: 'ba563ec8-2538-49e5-af81-6953989d4759',
      ceremonyId: 'bootstrap-header-selection',
      keyFingerprint: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
      publicEncryptionKey: recovery.publicKey,
      threshold: 2 as const,
      shareCount: 3 as const,
      status: 'active' as const,
      ceremonyEvidenceDigest: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
      approvalUserIds: ['admin-1', 'admin-2'],
      createdAt: now,
      retiredAt: null,
    };
    try {
      const initialized = await keyring.initializeVault(accountId, vaultId, 'Current epoch vault', profile, recoveryKey);
      const created = await keyring.encryptCreate(accountId, vaultId, {
        kind: 'login',
        title: 'Current epoch item',
        username: null,
        origin: null,
        folderPath: '工作/云服务/示例云',
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        secretValue: 'current-epoch-content',
      });
      const metadata = {
        itemId: created.itemId,
        vaultId,
        version: 1,
        secretVersion: 1,
        keyEpoch: 1,
        deleted: false,
        blob: created.metadata,
        createdAt: now,
        updatedAt: now,
        updatedBy: accountId,
      };
      const request = await keyring.prepareVaultRekey(accountId, vaultId, profile, {
        task: {
          id: '6239b413-14cb-443e-9899-ee8e2b51a9a0',
          fromEpoch: 1,
          toEpoch: 2,
          reason: 'manual',
          freezeGeneration: 1,
        },
        state: {
          vaultId,
          status: 'rekey_required',
          activeEpoch: 1,
          pendingEpoch: 2,
          rekeyTaskId: '6239b413-14cb-443e-9899-ee8e2b51a9a0',
          encryptedHeader: initialized.header.blob,
          migrationJobId: null,
          updatedAt: now,
        },
        header: { ...initialized.header, updatedAt: now, updatedBy: accountId, signature: initialized.manifestSignature },
        metadata: [{ ...metadata, signature: created.signature }],
        keyWraps: [{
          itemId: created.itemId,
          vaultId,
          secretVersion: 1,
          recordVersion: 1,
          keyEpoch: 1,
          wrappedDek: created.wrappedDek,
          signature: created.signature,
          createdAt: now,
          createdBy: device.id,
        }],
        recipients: [{
          userId: accountId,
          role: 'owner',
          capability: 'full',
          keyVersion: profile.keyVersion,
          encryptionPublicKey: profile.encryptionPublicKey,
          signingPublicKey: profile.signingPublicKey,
        }],
        recoveryKey,
      });
      await keyring.commitVaultRekey(vaultId);
      const directoryUpdate = await keyring.encryptVaultDirectories(accountId, vaultId, [
        { path: '个人', aliases: [] },
        { path: '工作', aliases: [] },
        { path: '工作/云平台', aliases: ['工作/云服务'] },
        { path: '工作/云平台/示例云', aliases: ['工作/云服务/示例云'] },
      ], { ...request.header, updatedAt: now, updatedBy: accountId });
      expect(JSON.stringify(directoryUpdate)).not.toContain('云平台');
      const userEnvelope = request.envelopes.find((envelope) => envelope.recipientKind === 'user')!;
      const bootstrap: EncryptedBootstrapResponse = {
        ...emptyBootstrap(profile, device),
        vaults: [{
          id: vaultId,
          kind: 'team',
          ownerUserId: null,
          createdAt: now,
          updatedAt: now,
          crypto: {
            vaultId,
            status: 'e2ee',
            activeEpoch: 2,
            pendingEpoch: null,
            rekeyTaskId: null,
            encryptedHeader: directoryUpdate.header.blob,
            migrationJobId: null,
            updatedAt: now,
          },
        }],
        envelopes: [{ ...userEnvelope, id: crypto.randomUUID(), createdAt: now }],
        headers: [
          { ...initialized.header, updatedAt: now, updatedBy: accountId },
          { ...request.header, updatedAt: now, updatedBy: accountId },
          { ...directoryUpdate.header, updatedAt: now, updatedBy: accountId },
          { ...request.header, keyEpoch: 3, version: 999, updatedAt: now, updatedBy: accountId },
        ],
        items: [{ ...metadata, keyEpoch: 2, blob: request.reencryptedMetadata[0]!.blob }],
      };
      const projection = await keyring.decryptBootstrap(bootstrap);
      expect(projection.vaults[0]?.name).toBe('Current epoch vault');
      expect(projection.items[0]?.title).toBe('Current epoch item');
      expect(projection.items[0]?.folderPath).toBe('工作/云平台/示例云');
      expect(projection.vaultDirectories[vaultId]).toContainEqual({ path: '个人', aliases: [] });

      await expect(keyring.decryptBootstrap({
        ...bootstrap,
        headers: [
          ...bootstrap.headers,
          {
            ...directoryUpdate.header,
            blob: request.header.blob,
            updatedAt: now,
            updatedBy: accountId,
          },
        ],
      })).rejects.toThrow('密码库加密头存在冲突版本');
    } finally {
      await destroyKeyPair(recovery);
      await keyring.lock();
    }
  });

  it('signs and locally verifies an approved offline recovery envelope before submission', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = 'f25eb2fc-8972-4d74-9f2c-bc45255faec7';
    const requestId = '8c2cd2a9-ec55-49b3-b649-ec5b966522ea';
    const vaultKeys = await createVaultKeys(3);
    try {
      const recoveredEnvelope = await createUnsignedVaultKeyGrant(
        vaultKeys,
        profile.encryptionPublicKey,
        {
          vaultId,
          recipientKind: 'user',
          recipientId: accountId,
          recipientKeyVersion: 1,
          capability: 'full',
          signerUserId: accountId,
          signerKeyVersion: 1,
        },
      );
      const header = await encryptVaultMetadata(
        vaultKeys.metadataKey,
        { vaultId, version: 1, keyEpoch: 3 },
        { name: 'Recovered team vault' },
      );
      const request = {
        id: requestId,
        vaultId,
        keyEpoch: 3,
        recoveryKeyId: '08f85828-fe08-4728-b7ea-bbd78e627b8e',
        targetUserId: accountId,
        targetDeviceId: deviceId,
        targetEncryptionPublicKey: profile.encryptionPublicKey,
        targetKeyVersion: 1,
        targetCapability: 'full' as const,
        accountResetRequestId: null,
        requestDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        status: 'approved' as const,
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        completedAt: null,
      };
      const recoveryKey = {
        id: request.recoveryKeyId,
        ceremonyId: 'quarterly-recovery-ceremony',
        keyFingerprint: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
        publicEncryptionKey: profile.encryptionPublicKey,
        threshold: 2 as const,
        shareCount: 3 as const,
        status: 'active' as const,
        ceremonyEvidenceDigest: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        retiredAt: null,
      };
      const offlineResult = await currentOfflineRecoveryResult(request, recoveryKey, recoveredEnvelope);
      await expect(keyring.completeRecovery(
        accountId,
        request,
        recoveryKey,
        {
          vaultId,
          version: 1,
          keyEpoch: 3,
          blob: header.blob,
          updatedAt: new Date().toISOString(),
          updatedBy: accountId,
        },
        { ...offlineResult, toolEvidenceDigest: 'tampered' },
      )).rejects.toThrow('离线恢复结果证据摘要不匹配');
      const wrongSignerResult = await currentOfflineRecoveryResult(
        request,
        recoveryKey,
        { ...recoveredEnvelope, signerKeyVersion: 2 },
      );
      await expect(keyring.completeRecovery(
        accountId,
        request,
        recoveryKey,
        {
          vaultId,
          version: 1,
          keyEpoch: 3,
          blob: header.blob,
          updatedAt: new Date().toISOString(),
          updatedBy: accountId,
        },
        wrongSignerResult,
      )).rejects.toThrow('接收人绑定不正确');
      const complete = await keyring.completeRecovery(
        accountId,
        request,
        recoveryKey,
        {
          vaultId,
          version: 1,
          keyEpoch: 3,
          blob: header.blob,
          updatedAt: new Date().toISOString(),
          updatedBy: accountId,
        },
        offlineResult,
      );
      expect(complete.recoveredEnvelope.signature).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(complete.targetConfirmationSignature).toMatch(/^[A-Za-z0-9_-]+$/);
      await expect(keyring.encryptCreate(accountId, vaultId, {
        kind: 'secure_note',
        title: 'Full recovery proof',
        username: null,
        origin: null,
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        secretValue: 'content key is available',
      })).resolves.toMatchObject({ keyEpoch: 3 });
      await expect(keyring.completeRecovery(
        accountId,
        request,
        recoveryKey,
        { ...header, vaultId: '9665aa9f-a07b-4437-8b0d-5816419cec43', updatedAt: '', updatedBy: '' },
        offlineResult,
      )).rejects.toThrow();
    } finally {
      await destroyVaultKeys(vaultKeys);
      await keyring.lock();
    }
  });

  it('recovers metadata-only access for an auditor without exposing a content key', async () => {
    const { keyring, profile } = await setupAccount();
    const vaultId = 'a55097f4-4e58-48b7-90f7-d293e67f94af';
    const requestId = 'b2da2be7-28dc-4076-ad9a-218568629422';
    const vaultKeys = await createVaultKeys(4);
    try {
      const recoveredEnvelope = await createUnsignedVaultKeyGrant(
        vaultKeys,
        profile.encryptionPublicKey,
        {
          vaultId,
          recipientKind: 'user',
          recipientId: accountId,
          recipientKeyVersion: 1,
          capability: 'metadata',
          signerUserId: accountId,
          signerKeyVersion: 1,
        },
      );
      const header = await encryptVaultMetadata(
        vaultKeys.metadataKey,
        { vaultId, version: 1, keyEpoch: 4 },
        { name: 'Audited team vault' },
      );
      const request = {
        id: requestId,
        vaultId,
        keyEpoch: 4,
        recoveryKeyId: '73370211-c7d0-4ca3-ad2d-9b13a4fd4b40',
        targetUserId: accountId,
        targetDeviceId: deviceId,
        targetEncryptionPublicKey: profile.encryptionPublicKey,
        targetKeyVersion: 1,
        targetCapability: 'metadata' as const,
        accountResetRequestId: null,
        requestDigest: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
        status: 'approved' as const,
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        completedAt: null,
      };
      const recoveryKey = {
        id: request.recoveryKeyId,
        ceremonyId: 'auditor-recovery-ceremony',
        keyFingerprint: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        publicEncryptionKey: profile.encryptionPublicKey,
        threshold: 2 as const,
        shareCount: 3 as const,
        status: 'active' as const,
        ceremonyEvidenceDigest: 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG',
        approvalUserIds: ['admin-1', 'admin-2'],
        createdAt: new Date().toISOString(),
        retiredAt: null,
      };
      const offlineResult = await currentOfflineRecoveryResult(request, recoveryKey, recoveredEnvelope);
      const complete = await keyring.completeRecovery(
        accountId,
        request,
        recoveryKey,
        { ...header, updatedAt: new Date().toISOString(), updatedBy: accountId },
        offlineResult,
      );
      expect(complete.recoveredEnvelope.capability).toBe('metadata');
      await expect(keyring.encryptCreate(accountId, vaultId, {
        kind: 'secure_note',
        title: 'Must stay unreadable',
        username: null,
        origin: null,
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        secretValue: 'must not encrypt',
      })).rejects.toThrow('当前权限不能修改密码或敏感内容');
    } finally {
      await destroyVaultKeys(vaultKeys);
      await keyring.lock();
    }
  });
});

describe('encrypted persistent outbox', () => {
  it.each([
    'password',
    'mainPassword',
    'secretValue',
    'title',
    'username',
    'origin',
    'loginUrl',
    'loginUrls',
    'folderPath',
    'tags',
    'note',
    'notes',
    'token',
    'url',
    'value',
    'privateKey',
    'encryptionPrivateKey',
    'signingPrivateKey',
  ])('rejects nested plaintext alias %s', (field) => {
    expect(() => assertCiphertextOnly({ envelope: [{ nested: { [field]: 'never-store-this' } }] })).toThrow(field);
  });

  it('normalizes plaintext aliases without using substring matches', () => {
    expect(() => assertCiphertextOnly({ nested: { main_password: 'never-store-this' } })).toThrow('main_password');
    expect(() => assertCiphertextOnly({ nested: { SECRET_VALUE: 'never-store-this' } })).toThrow('SECRET_VALUE');
    expect(() => assertCiphertextOnly({
      encryptedPrivateKeys: { nonce: 'n', ciphertext: 'c' },
      encryptedBootstrap: { nonce: 'n', ciphertext: 'c' },
      encryptedPassword: { nonce: 'n', ciphertext: 'c' },
    })).not.toThrow();
  });

  it.each([
    {
      name: 'IndexedDB putAccount',
      create: () => new IndexedDbEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.putAccount(record as CachedAccountLocator),
    },
    {
      name: 'IndexedDB replaceAccountAfterIdentityRotation',
      create: () => new IndexedDbEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.replaceAccountAfterIdentityRotation(record as CachedAccountLocator),
    },
    {
      name: 'IndexedDB putPendingAccountCryptoReset',
      create: () => new IndexedDbEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.putPendingAccountCryptoReset(record as PendingAccountCryptoResetLocator),
    },
    {
      name: 'IndexedDB activatePendingAccountCryptoReset',
      create: () => new IndexedDbEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.activatePendingAccountCryptoReset(record as CachedAccountLocator),
    },
    {
      name: 'memory putAccount',
      create: () => new MemoryEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.putAccount(record as CachedAccountLocator),
    },
    {
      name: 'memory replaceAccountAfterIdentityRotation',
      create: () => new MemoryEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.replaceAccountAfterIdentityRotation(record as CachedAccountLocator),
    },
    {
      name: 'memory putPendingAccountCryptoReset',
      create: () => new MemoryEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.putPendingAccountCryptoReset(record as PendingAccountCryptoResetLocator),
    },
    {
      name: 'memory activatePendingAccountCryptoReset',
      create: () => new MemoryEncryptedStorage(),
      write: (storage: EncryptedStorageBackend, record: unknown) =>
        storage.activatePendingAccountCryptoReset(record as CachedAccountLocator),
    },
  ])('$name validates before persistence', async ({ create, write }) => {
    const storage = create();
    await expect(write(storage, {
      accountId,
      encryptedPrivateKeys: { nonce: 'bm9uY2U', ciphertext: 'Y2lwaGVy' },
      nested: { records: [{ token: 'never-store-this' }] },
    })).rejects.toThrow('token');
  });

  it('restores and flushes signed ciphertext commands without closures', async () => {
    const storage = new MemoryEncryptedStorage();
    const sendEncryptedCommand = vi.fn().mockResolvedValue({ ok: true });
    const outbox = new EncryptedCommandOutbox({ sendEncryptedCommand } as unknown as ApiClient, storage);
    await outbox.restore(accountId);
    await outbox.enqueue({
      id: 'command-0001',
      accountId,
      kind: 'item.update',
      method: 'PATCH',
      path: '/api/v2/items/b88e81ca-93de-46ca-94cf-2fa17f98a426',
      body: {
        idempotencyKey: 'command-0001',
        metadata: { suite: 'lm-e2ee-v1', aadVersion: 1, nonce: 'bm9uY2U', ciphertext: 'Y2lwaGVy' },
        signature: 'c2lnbmF0dXJl',
      },
      createdAt: new Date().toISOString(),
    });
    expect(outbox.size).toBe(1);
    outbox.setOnline(true);
    await vi.waitFor(() => expect(outbox.size).toBe(0));
    expect(sendEncryptedCommand).toHaveBeenCalledOnce();
    expect(await storage.listCommands(accountId)).toEqual([]);
  });

  it('atomically replaces the local identity locator and clears old commands', async () => {
    const { setup, profile, device } = await setupAccount();
    const storage = new MemoryEncryptedStorage();
    await storage.putAccount({
      accountId,
      profile,
      device,
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: '2026-01-01T00:00:00.000Z',
    });
    await storage.putCommand({
      id: 'command-before-rotation',
      accountId,
      kind: 'item.delete',
      method: 'DELETE',
      path: '/api/v2/items/b88e81ca-93de-46ca-94cf-2fa17f98a426',
      body: { idempotencyKey: 'command-before-rotation', signature: 'c2lnbmF0dXJl' },
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    const nextProfile = { ...profile, profileVersion: 2, keyVersion: 2 };
    await storage.replaceAccountAfterIdentityRotation({
      accountId,
      profile: nextProfile,
      device: { ...device, keyVersion: 2 },
      deviceBundle: setup.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: '2026-01-02T00:00:00.000Z',
    });
    expect((await storage.getAccount(accountId))?.profile.keyVersion).toBe(2);
    expect(await storage.listCommands(accountId)).toEqual([]);
  });
});
