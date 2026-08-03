import type {
  CipherBlob,
  AcceptVaultOwnershipTransferRequest,
  CancelVaultOwnershipTransferRequest,
  ActivateAccountCryptoResetRequest,
  AccountCryptoResetRequest,
  CompleteCryptoUnlockRequest,
  AtomicCreateEncryptedVaultRequest,
  CreateEncryptedProjectRequest,
  CreateCryptoProfileRequest,
  CreateEncryptedItemRequest,
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  EncryptedItemMetadata,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
  CompleteEnterpriseRecoveryRequest,
  CompleteVaultEnvelopeTaskRequest,
  CreateAccountCryptoResetRequest,
  DistributeEnterpriseRecoveryEnvelopeRequest,
  EncryptedVaultHeader,
  InitializeVaultCryptoRequest,
  RotateCryptoProfileRequest,
  RotateEncryptedSecretRequest,
  RegisterCryptoDeviceRequest,
  RevokeCryptoDeviceRequest,
  RekeyMaterial,
  RekeyMaterialQuery,
  RekeyVaultRequest,
  RemoveEncryptedMembershipRequest,
  RewrapCryptoProfileRequest,
  SetEncryptedMembershipRequest,
  UpdateEncryptedVaultHeaderRequest,
  UpdateEncryptedItemRequest,
  UnlockChallenge as ApiUnlockChallenge,
  UserCryptoProfile,
  VaultKeyEnvelope,
  VaultEnvelopeTask,
  VaultOwnershipTransfer,
  CreateVaultOwnershipTransferRequest,
  ApproveLegacyKeyRetirementRequest,
  CompleteLegacyKeyRetirementRequest,
  CreateLegacyKeyRetirementRequest,
  DeleteUninitializedVaultRequest,
} from '@mima/contracts';
import { ITEM_METADATA_FORMAT_VERSION, VAULT_HEADER_FORMAT_VERSION } from '@mima/contracts';
import {
  E2EE_PROTOCOL,
  canonicalJson,
  changeMasterPassword,
  createAccountBundle,
  createDeviceKeyBundle,
  createSignedDeviceCertificate,
  createVaultKeyGrant,
  createVaultKeys,
  decryptBytes,
  decryptItemContent,
  decryptItemMetadata,
  decryptVaultMetadata,
  destroyUnlockedAccount,
  destroyVaultKeys,
  encodeJson,
  encryptBytes,
  encryptItemVersion,
  encryptVaultMetadata,
  enterpriseRecoveryTransferEvidenceDigest,
  assertExtensionTrustedUnlockRequest,
  deriveExtensionDeviceUnlockKey,
  fromBase64Url,
  openVaultKeyGrant,
  ownershipTransferAcceptanceDigest,
  signVaultKeyPossession,
  openSealedBytes,
  prepareAccountIdentityRotation,
  rewrapItemContentKey,
  signVaultKeyGrant,
  signBytes,
  sealBytes,
  signUnlockChallenge,
  sodiumReady,
  toBase64Url,
  unlockAccountBundle,
  utf8,
  vaultKeyPossessionPublicKey,
  type AccountBundle,
  type DeviceKeyBundle,
  type EnterpriseRecoveryTransferEvidenceFormat,
  type ExtensionTrustedUnlockRequest,
  type ExtensionTrustedUnlockResponse,
  type JsonValue,
  type UnlockChallenge,
  type UnlockedAccount,
  type VaultKeys,
  type UnsignedVaultKeyEnvelopeInput,
} from '@mima/e2ee';
import type { ItemMeta } from '@mima/contracts';
import {
  materializeVaultDirectories,
  normalizeVaultDirectories,
  normalizeVaultGroupName,
  resolveVaultDirectoryPath,
  type VaultDirectoryEntry,
} from '@mima/domain';
import {
  itemPayload,
  parseItemMetadataPayload,
  parseVaultHeaderPayload,
  type CreateItemInput,
  type DecryptedBootstrapProjection,
  type DecryptedItemMeta,
  type ItemMetadataPayload,
} from './e2ee-model.ts';
import type { PublicCryptoProfile } from './api-client.ts';
import type {
  LegacyMigrationActionRequest,
  LegacyMigrationExportClaimRequest,
  LegacyMigrationExportResponse,
  LegacyMigrationJob,
  LegacyMigrationMaterials,
  LegacyMigrationRecord,
  LegacyMigrationStartRequest,
  LegacyMigrationUploadRequest,
  LegacyMigrationVerifyRequest,
  PreparedLegacyMigration,
} from './legacy-migration.ts';

const CACHE_RECORD_VERSION = 1;

export interface SetupAccountResult {
  request: CreateCryptoProfileRequest;
  deviceId: string;
  deviceBundle: DeviceKeyBundle;
}

export interface EnrollWebDeviceResult {
  request: RegisterCryptoDeviceRequest;
  deviceBundle: DeviceKeyBundle;
}

export interface PreparedIdentityRotationResult {
  request: RotateCryptoProfileRequest;
  deviceBundle: DeviceKeyBundle;
}

export interface PreparedAccountCryptoResetResult {
  request: CreateAccountCryptoResetRequest;
  accountBundle: AccountBundle;
  deviceBundle: DeviceKeyBundle;
}

export interface PreparedAccountCryptoResetActivation {
  request: ActivateAccountCryptoResetRequest;
}

export type RekeyVaultCommitRequest = RekeyVaultRequest & {
  header: Omit<EncryptedVaultHeader, 'updatedAt' | 'updatedBy'>;
};

export interface SignerPublicKeys {
  [userAndKeyVersion: string]: string;
}

export interface EncryptedOfflineSnapshot {
  bootstrap: EncryptedBootstrapResponse;
  contents: Record<string, EncryptedContentResponse>;
}

export interface OfflineRecoveryResult {
  protocol: 'lm-e2ee-v1';
  kind: 'enterprise-recovery-transfer';
  formatVersion: 1;
  requestId: string;
  requestDigest: string;
  vaultId: string;
  epoch: number;
  recoveryKeyId: string;
  ceremonyId: string;
  recoveryCeremonyDigest: string;
  targetUserId: string;
  targetCapability: 'metadata' | 'full';
  toolEvidenceDigest: string;
  recoveredEnvelope: UnsignedVaultKeyEnvelopeInput;
  evidenceFormat: EnterpriseRecoveryTransferEvidenceFormat;
}

export interface ExtensionEnrollment {
  id: string;
  deviceId: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
  fingerprint: string;
  joinChannelPublicKey: string;
  status: 'pending' | 'approved' | 'expired' | 'rejected';
  expiresAt: string;
}

export interface ExtensionPairingEnrollmentStatus {
  status: 'waiting' | 'claimed' | 'expired';
  enrollment: ExtensionEnrollment | null;
}

export interface ApproveExtensionEnrollmentRequest {
  approverDeviceId: string;
  certificate: string;
  certificateSignature: string;
  envelopes: import('@mima/contracts').VaultKeyEnvelopeInput[];
  approvalSignature: string;
}

export interface ResumeExtensionSessionRequest {
  approverDeviceId: string;
  trustedRequest: ExtensionTrustedUnlockRequest;
  signature: string;
}

export function parseOfflineRecoveryResult(value: unknown): OfflineRecoveryResult {
  if (!isRecord(value)) throw new Error('离线恢复结果不是有效的 JSON 对象');
  const currentEnvelope = isRecord(value.recoveredEnvelope) ? value.recoveredEnvelope : null;
  const legacyEnvelope = isRecord(value.unsignedEnvelope) ? value.unsignedEnvelope : null;
  if (Boolean(currentEnvelope) === Boolean(legacyEnvelope)) {
    throw new Error('离线恢复结果必须且只能包含一个恢复 envelope');
  }
  const evidenceFormat: EnterpriseRecoveryTransferEvidenceFormat = currentEnvelope
    ? 'recovered-envelope-v1'
    : 'unsigned-envelope-v0';
  if (
    (currentEnvelope && value.formatVersion !== 1) ||
    (legacyEnvelope && value.formatVersion !== undefined)
  ) {
    throw new Error('离线恢复结果版本不受支持');
  }
  const recovered = currentEnvelope ?? legacyEnvelope!;
  if (
    value.protocol !== 'lm-e2ee-v1' ||
    value.kind !== 'enterprise-recovery-transfer' ||
    typeof value.requestId !== 'string' ||
    typeof value.requestDigest !== 'string' ||
    typeof value.vaultId !== 'string' ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1 ||
    typeof value.recoveryKeyId !== 'string' ||
    typeof value.ceremonyId !== 'string' ||
    typeof value.recoveryCeremonyDigest !== 'string' ||
    typeof value.targetUserId !== 'string' ||
    (value.targetCapability !== 'metadata' && value.targetCapability !== 'full') ||
    typeof value.toolEvidenceDigest !== 'string' ||
    !isRecord(recovered) ||
    typeof recovered.vaultId !== 'string' ||
    typeof recovered.epoch !== 'number' ||
    (recovered.recipientKind !== 'user' && recovered.recipientKind !== 'device') ||
    typeof recovered.recipientId !== 'string' ||
    typeof recovered.recipientKeyVersion !== 'number' ||
    (recovered.capability !== 'full' && recovered.capability !== 'metadata' && recovered.capability !== 'recovery') ||
    typeof recovered.sealedKeyBundle !== 'string' ||
    typeof recovered.signerUserId !== 'string' ||
    typeof recovered.signerKeyVersion !== 'number'
  ) {
    throw new Error('离线恢复结果字段不完整');
  }
  return {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-transfer',
    formatVersion: 1,
    requestId: value.requestId,
    requestDigest: value.requestDigest,
    vaultId: value.vaultId,
    epoch: value.epoch as number,
    recoveryKeyId: value.recoveryKeyId,
    ceremonyId: value.ceremonyId,
    recoveryCeremonyDigest: value.recoveryCeremonyDigest,
    targetUserId: value.targetUserId,
    targetCapability: value.targetCapability,
    toolEvidenceDigest: value.toolEvidenceDigest,
    recoveredEnvelope: recovered as unknown as UnsignedVaultKeyEnvelopeInput,
    evidenceFormat,
  };
}

export class E2eeKeyring {
  private account: UnlockedAccount | null = null;
  private pendingIdentityRotation: UnlockedAccount | null = null;
  private pendingAccountCryptoReset: UnlockedAccount | null = null;
  private vaultKeys = new Map<string, VaultKeys>();
  private vaultDirectories = new Map<string, VaultDirectoryEntry[]>();
  private pendingVaultRekeys = new Map<string, Required<VaultKeys>>();
  private pendingLegacyMigrations = new Map<string, {
    jobId: string;
    keys: Required<VaultKeys>;
    verification: Omit<LegacyMigrationVerifyRequest, 'signature'>;
  }>();
  private generation = 0;

  get isUnlocked(): boolean {
    return this.account !== null;
  }

  get deviceId(): string | null {
    return this.account?.device?.deviceId ?? null;
  }

  get currentGeneration(): number {
    return this.generation;
  }

  async setup(
    mainPassword: string,
    input: { accountId: string; deviceId: string; deviceName: string; platform: string },
  ): Promise<SetupAccountResult> {
    await this.lock();
    const created = await createAccountBundle(mainPassword, {
      accountId: input.accountId,
      deviceId: input.deviceId,
    });
    this.account = created.unlocked;
    try {
      const certificate = await createSignedDeviceCertificate({
        accountId: input.accountId,
        deviceId: input.deviceId,
        deviceType: 'web',
        encryptionPublicKey: created.deviceBundle.encryptionPublicKey,
        signingPublicKey: created.deviceBundle.signingPublicKey,
        keyVersion: 1,
        issuedAt: new Date().toISOString(),
      },
        created.unlocked.signingKeyPair.privateKey,
      );
      return {
        deviceId: input.deviceId,
        deviceBundle: created.deviceBundle,
        request: {
          profileVersion: 1,
          keyVersion: 1,
          suite: E2EE_PROTOCOL,
          kdf: created.accountBundle.kdf,
          encryptedAccountBundle: created.accountBundle.encryptedAccountBundle,
          encryptionPublicKey: created.accountBundle.encryptionPublicKey,
          signingPublicKey: created.accountBundle.signingPublicKey,
          recoveryEnabled: true,
          device: {
            id: input.deviceId,
            deviceType: 'web',
            encryptedLabel: null,
            encryptionPublicKey: created.deviceBundle.encryptionPublicKey,
            signingPublicKey: created.deviceBundle.signingPublicKey,
            certificate: certificate.certificate,
            certificateSignature: certificate.signature,
          },
        },
      };
    } catch (error) {
      await this.lock();
      throw error;
    }
  }

  async prepareAccountCryptoReset(
    mainPassword: string,
    profile: UserCryptoProfile,
    deviceId: string,
  ): Promise<PreparedAccountCryptoResetResult> {
    await this.abortAccountCryptoReset();
    const created = await createAccountBundle(mainPassword, {
      accountId: profile.userId,
      deviceId,
    });
    const newKeyVersion = profile.keyVersion + 1;
    try {
      const certificate = await createSignedDeviceCertificate({
        accountId: profile.userId,
        deviceId,
        deviceType: 'web',
        encryptionPublicKey: created.deviceBundle.encryptionPublicKey,
        signingPublicKey: created.deviceBundle.signingPublicKey,
        keyVersion: newKeyVersion,
        issuedAt: new Date().toISOString(),
      }, created.unlocked.signingKeyPair.privateKey);
      const unsigned = {
        idempotencyKey: crypto.randomUUID(),
        expectedProfileVersion: profile.profileVersion,
        expectedKeyVersion: profile.keyVersion,
        newKeyVersion,
        suite: created.accountBundle.suite,
        kdf: created.accountBundle.kdf,
        encryptedAccountBundle: created.accountBundle.encryptedAccountBundle,
        encryptionPublicKey: created.accountBundle.encryptionPublicKey,
        signingPublicKey: created.accountBundle.signingPublicKey,
        candidateDevice: {
          id: deviceId,
          deviceType: 'web' as const,
          encryptedLabel: null,
          encryptionPublicKey: created.deviceBundle.encryptionPublicKey,
          signingPublicKey: created.deviceBundle.signingPublicKey,
          certificate: certificate.certificate,
          certificateSignature: certificate.signature,
        },
      };
      const request: CreateAccountCryptoResetRequest = {
        ...unsigned,
        candidateUserProof: await this.signCommandWith(
          created.unlocked.signingKeyPair.privateKey,
          'crypto.account_reset.create.user',
          profile.userId,
          {},
          unsigned,
        ),
      };
      this.pendingAccountCryptoReset = created.unlocked;
      return {
        request,
        accountBundle: { ...created.accountBundle, keyVersion: newKeyVersion },
        deviceBundle: created.deviceBundle,
      };
    } catch (error) {
      await destroyUnlockedAccount(created.unlocked);
      throw error;
    }
  }

  async unlockPendingAccountCryptoReset(
    mainPassword: string,
    accountBundle: AccountBundle,
    deviceBundle: DeviceKeyBundle,
  ): Promise<void> {
    await this.abortAccountCryptoReset();
    this.pendingAccountCryptoReset = await unlockAccountBundle(
      mainPassword,
      accountBundle,
      deviceBundle,
    );
  }

  async prepareAccountCryptoResetActivation(
    userId: string,
    reset: Pick<AccountCryptoResetRequest, 'id' | 'requestDigest'>,
    idempotencyKey = crypto.randomUUID(),
  ): Promise<PreparedAccountCryptoResetActivation> {
    const candidate = this.pendingAccountCryptoReset;
    if (!candidate || candidate.accountId !== userId) {
      throw new Error('请先使用新主密码验证这次解锁重置');
    }
    const device = this.requireDevice(candidate);
    const payload = {
      idempotencyKey,
      requestId: reset.id,
      requestDigest: reset.requestDigest,
    };
    return {
      request: {
        idempotencyKey,
        requestDigest: reset.requestDigest,
        candidateDevicePossessionSignature: await this.signCommandWith(
          device.signingKeyPair.privateKey,
          'crypto.account_reset.activate.device',
          userId,
          {},
          payload,
        ),
        candidateUserSignature: await this.signCommandWith(
          candidate.signingKeyPair.privateKey,
          'crypto.account_reset.activate.user',
          userId,
          {},
          payload,
        ),
      },
    };
  }

  async commitAccountCryptoReset(): Promise<void> {
    const next = this.pendingAccountCryptoReset;
    if (!next) throw new Error('没有待完成的解锁重置');
    const previous = this.account;
    const vaults = [...this.vaultKeys.values()];
    const pendingVaults = [...this.pendingVaultRekeys.values()];
    this.pendingAccountCryptoReset = null;
    this.account = next;
    this.vaultKeys.clear();
    this.pendingVaultRekeys.clear();
    this.generation += 1;
    if (previous) await destroyUnlockedAccount(previous);
    await Promise.all(vaults.map((keys) => destroyVaultKeys(keys)));
    await Promise.all(pendingVaults.map((keys) => destroyVaultKeys(keys)));
  }

  async abortAccountCryptoReset(): Promise<void> {
    const pending = this.pendingAccountCryptoReset;
    this.pendingAccountCryptoReset = null;
    if (pending) await destroyUnlockedAccount(pending);
  }

  async unlock(
    mainPassword: string,
    profile: UserCryptoProfile,
    device: CryptoDevice,
    deviceBundle: DeviceKeyBundle,
  ): Promise<void> {
    await this.lock();
    const accountBundle: AccountBundle = {
      accountId: profile.userId,
      profileVersion: 1,
      keyVersion: profile.keyVersion as 1,
      suite: profile.suite,
      kdf: profile.kdf,
      encryptedAccountBundle: profile.encryptedAccountBundle,
      encryptionPublicKey: profile.encryptionPublicKey,
      signingPublicKey: profile.signingPublicKey,
    };
    if (
      deviceBundle.accountId !== profile.userId ||
      deviceBundle.deviceId !== device.id ||
      deviceBundle.encryptionPublicKey !== device.encryptionPublicKey ||
      deviceBundle.signingPublicKey !== device.signingPublicKey
    ) {
      throw new Error('本机授权与服务器记录不一致，请重新登录');
    }
    this.account = await unlockAccountBundle(mainPassword, accountBundle, deviceBundle);
  }

  async enrollWebDevice(
    mainPassword: string,
    profile: UserCryptoProfile,
    deviceId: string,
  ): Promise<EnrollWebDeviceResult> {
    await this.lock();
    const accountBundle: AccountBundle = {
      accountId: profile.userId,
      profileVersion: 1,
      keyVersion: profile.keyVersion as 1,
      suite: profile.suite,
      kdf: profile.kdf,
      encryptedAccountBundle: profile.encryptedAccountBundle,
      encryptionPublicKey: profile.encryptionPublicKey,
      signingPublicKey: profile.signingPublicKey,
    };
    const account = await unlockAccountBundle(mainPassword, accountBundle);
    try {
      const created = await createDeviceKeyBundle(account.accountKey, {
        accountId: profile.userId,
        deviceId,
      });
      account.device = {
        deviceId,
        encryptionKeyPair: created.encryptionKeyPair,
        signingKeyPair: created.signingKeyPair,
      };
      this.account = account;
      const certificate = await createSignedDeviceCertificate({
        accountId: profile.userId,
        deviceId,
        deviceType: 'web',
        encryptionPublicKey: created.bundle.encryptionPublicKey,
        signingPublicKey: created.bundle.signingPublicKey,
        keyVersion: profile.keyVersion,
        issuedAt: new Date().toISOString(),
      }, account.signingKeyPair.privateKey);
      const unsigned = {
        id: deviceId,
        deviceType: 'web' as const,
        encryptedLabel: null,
        encryptionPublicKey: created.bundle.encryptionPublicKey,
        signingPublicKey: created.bundle.signingPublicKey,
        certificate: certificate.certificate,
        certificateSignature: certificate.signature,
      };
      return {
        deviceBundle: created.bundle,
        request: {
          ...unsigned,
          approvalSignature: await this.signCommandWith(
            account.signingKeyPair.privateKey,
            'crypto.device.register',
            profile.userId,
            {},
            unsigned,
          ),
        },
      };
    } catch (error) {
      await destroyUnlockedAccount(account);
      this.account = null;
      throw error;
    }
  }

  async signServerChallenge(challenge: ApiUnlockChallenge): Promise<CompleteCryptoUnlockRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const encoded = await fromBase64Url(challenge.challenge);
    let parsed: UnlockChallenge;
    try {
      parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(encoded)) as UnlockChallenge;
    } finally {
      encoded.fill(0);
    }
    if (parsed.challengeId !== challenge.id || parsed.deviceId !== device.deviceId) {
      throw new Error('解锁挑战与当前设备不匹配');
    }
    const signed = await signUnlockChallenge(parsed, device.signingKeyPair.privateKey);
    return { challengeId: challenge.id, deviceId: device.deviceId, signature: signed.signature };
  }

  async prepareMasterPasswordChange(
    currentPassword: string,
    newPassword: string,
    profile: UserCryptoProfile,
  ): Promise<RewrapCryptoProfileRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (
      profile.userId !== account.accountId ||
      profile.encryptionPublicKey !== account.encryptionKeyPair.publicKey ||
      profile.signingPublicKey !== account.signingKeyPair.publicKey
    ) {
      throw new Error('当前账号安全信息与本机记录不一致，请重新登录');
    }
    const accountBundle: AccountBundle = {
      accountId: profile.userId,
      profileVersion: 1,
      keyVersion: profile.keyVersion,
      suite: profile.suite,
      kdf: profile.kdf,
      encryptedAccountBundle: profile.encryptedAccountBundle,
      encryptionPublicKey: profile.encryptionPublicKey,
      signingPublicKey: profile.signingPublicKey,
    };
    const changed = await changeMasterPassword(currentPassword, newPassword, accountBundle);
    const unsigned = {
      expectedProfileVersion: profile.profileVersion,
      kdf: changed.kdf,
      encryptedAccountBundle: changed.encryptedAccountBundle,
      deviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('crypto.profile.rewrap', profile.userId, {}, unsigned),
    };
  }

  async prepareIdentityRotation(
    mainPassword: string,
    profile: UserCryptoProfile,
    currentDevice: CryptoDevice,
  ): Promise<PreparedIdentityRotationResult> {
    await this.abortIdentityRotation();
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (
      profile.userId !== account.accountId ||
      currentDevice.id !== device.deviceId ||
      currentDevice.encryptionPublicKey !== device.encryptionKeyPair.publicKey ||
      currentDevice.signingPublicKey !== device.signingKeyPair.publicKey
    ) {
      throw new Error('当前设备与账号安全信息不匹配，请重新登录');
    }
    const accountBundle: AccountBundle = {
      accountId: profile.userId,
      profileVersion: 1,
      keyVersion: profile.keyVersion as 1,
      suite: profile.suite,
      kdf: profile.kdf,
      encryptedAccountBundle: profile.encryptedAccountBundle,
      encryptionPublicKey: profile.encryptionPublicKey,
      signingPublicKey: profile.signingPublicKey,
    };
    const prepared = await prepareAccountIdentityRotation(
      mainPassword,
      accountBundle,
      account,
      { deviceId: device.deviceId },
    );
    try {
      const newKeyVersion = profile.keyVersion + 1;
      const certificate = await createSignedDeviceCertificate({
        accountId: profile.userId,
        deviceId: device.deviceId,
        deviceType: currentDevice.deviceType,
        encryptionPublicKey: prepared.deviceBundle.encryptionPublicKey,
        signingPublicKey: prepared.deviceBundle.signingPublicKey,
        keyVersion: newKeyVersion,
        issuedAt: new Date().toISOString(),
      }, prepared.unlocked.signingKeyPair.privateKey);
      const unsigned = {
        idempotencyKey: crypto.randomUUID(),
        expectedProfileVersion: profile.profileVersion,
        expectedKeyVersion: profile.keyVersion,
        newKeyVersion,
        encryptedAccountBundle: prepared.accountBundle.encryptedAccountBundle,
        encryptionPublicKey: prepared.accountBundle.encryptionPublicKey,
        signingPublicKey: prepared.accountBundle.signingPublicKey,
        actorDeviceId: device.deviceId,
        actorDevice: {
          encryptionPublicKey: prepared.deviceBundle.encryptionPublicKey,
          signingPublicKey: prepared.deviceBundle.signingPublicKey,
          certificate: certificate.certificate,
          certificateSignature: certificate.signature,
        },
      };
      const withNewKeyProof = {
        ...unsigned,
        newSigningKeyProof: await this.signCommandWith(
          prepared.unlocked.signingKeyPair.privateKey,
          'crypto.profile.rotate.new-key',
          profile.userId,
          {},
          unsigned,
        ),
      };
      const request = {
        ...withNewKeyProof,
        actorSignature: await this.signCommandWith(
          device.signingKeyPair.privateKey,
          'crypto.profile.rotate',
          profile.userId,
          {},
          withNewKeyProof,
        ),
      };
      this.pendingIdentityRotation = prepared.unlocked;
      return { request, deviceBundle: prepared.deviceBundle };
    } catch (error) {
      await destroyUnlockedAccount(prepared.unlocked);
      throw error;
    }
  }

  async migrationStartIntent(userId: string, vaultId: string): Promise<LegacyMigrationStartRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = { idempotencyKey: crypto.randomUUID(), actorDeviceId: device.deviceId };
    return {
      ...unsigned,
      signature: await this.signCommand('migration.start', userId, { vaultId }, unsigned),
    };
  }

  async createLegacyKeyRetirementIntent(
    userId: string,
    input: Pick<
      CreateLegacyKeyRetirementRequest,
      'reasonCode' | 'retireBy' | 'copyInventoryDigest' | 'copyManifestDigest' | 'kekFingerprintDigest'
    >,
  ): Promise<CreateLegacyKeyRetirementRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = { idempotencyKey: crypto.randomUUID(), ...input, actorDeviceId: device.deviceId };
    return {
      ...unsigned,
      signature: await this.signCommand('legacy_key_retirement.create', userId, {}, unsigned),
    };
  }

  async approveLegacyKeyRetirementIntent(
    userId: string,
    planDigest: string,
    evidenceDigest: string,
  ): Promise<ApproveLegacyKeyRetirementRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      planDigest,
      evidenceDigest,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('legacy_key_retirement.approve', userId, {}, unsigned),
    };
  }

  async completeLegacyKeyRetirementIntent(
    userId: string,
    planDigest: string,
    completionEvidenceDigest: string,
  ): Promise<CompleteLegacyKeyRetirementRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      planDigest,
      completionEvidenceDigest,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('legacy_key_retirement.complete', userId, {}, unsigned),
    };
  }

  async migrationExportClaimIntent(
    userId: string,
    vaultId: string,
  ): Promise<LegacyMigrationExportClaimRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = { actorDeviceId: device.deviceId };
    return {
      ...unsigned,
      signature: await this.signCommand('migration.export.claim', userId, { vaultId }, unsigned),
    };
  }

  async prepareLegacyMigration(
    userId: string,
    profile: UserCryptoProfile,
    job: LegacyMigrationJob,
    materials: LegacyMigrationMaterials,
    migrationExport: LegacyMigrationExportResponse,
  ): Promise<PreparedLegacyMigration> {
    await this.abortLegacyMigration(job.vaultId);
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const recoveryKey = materials.recoveryKey;
    if (
      account.accountId !== userId ||
      profile.userId !== userId ||
      profile.encryptionPublicKey !== account.encryptionKeyPair.publicKey ||
      job.status !== 'encrypting' ||
      !job.sourceDigest ||
      migrationExport.recipientKeyVersion !== profile.keyVersion ||
      migrationExport.sourceDigest !== job.sourceDigest ||
      (recoveryKey !== null && recoveryKey.status !== 'active')
    ) {
      throw new Error('迁移导出与当前账号、任务或恢复公钥不匹配');
    }

    const opened = await openSealedBytes(migrationExport.sealedExport, account.encryptionKeyPair);
    let payload: LegacySealedPayload | null = null;
    const keys = await createVaultKeys(job.targetEpoch);
    try {
      payload = parseLegacySealedPayload(opened);
      assertLegacyPayloadBinding(payload, {
        userId,
        keyVersion: profile.keyVersion,
        vaultId: job.vaultId,
        jobId: job.id,
        sourceDigest: job.sourceDigest,
        itemCount: job.expectedItemCount,
        metadataCount: job.expectedMetadataVersionCount,
        secretCount: job.expectedSecretVersionCount,
      });
      await validateLegacyRecordDigests(payload);

      const encryptedHeader = await encryptVaultMetadata(keys.metadataKey, {
        vaultId: job.vaultId,
        version: 1,
        keyEpoch: job.targetEpoch,
      }, { name: payload.vault.name, directories: [], vaultGroupName: null });
      const verifiedHeader = await decryptVaultMetadata(keys.metadataKey, encryptedHeader);
      if (canonicalJson(verifiedHeader) !== canonicalJson({
        name: payload.vault.name,
        directories: [],
        vaultGroupName: null,
      })) {
        throw new Error('迁移生成的密码库密文回解校验失败');
      }

      const records: LegacyMigrationRecord[] = [];
      const targetDigests: LegacyTargetDigestRecord[] = [{
        sourceKind: 'vault_header',
        sourceId: job.vaultId,
        sourceVersion: 1,
        targetDigest: await digestCipherBlob(encryptedHeader.blob),
      }];
      for (const item of payload.vault.items) {
        const metadataPlaintext = encodeJson({
          kind: item.metadata.kind,
          title: item.metadata.title,
          username: item.metadata.username,
          origin: item.metadata.origin,
          tags: item.metadata.tags,
          favorite: item.metadata.favorite,
          sensitivity: item.metadata.sensitivity,
        });
        try {
          const blob = await encryptBytes(keys.metadataKey, metadataPlaintext, {
            blobType: 'item-metadata',
            vaultId: job.vaultId,
            itemId: item.metadata.id,
            recordVersion: item.metadata.version,
            secretVersion: item.metadata.secretVersion,
            keyEpoch: job.targetEpoch,
          });
          await assertEncryptedBytesRoundTrip(
            keys.metadataKey,
            blob,
            {
              blobType: 'item-metadata',
              vaultId: job.vaultId,
              itemId: item.metadata.id,
              recordVersion: item.metadata.version,
              secretVersion: item.metadata.secretVersion,
              keyEpoch: job.targetEpoch,
            },
            metadataPlaintext,
          );
          records.push({
            kind: 'metadata',
            sourceId: item.metadata.id,
            sourceVersion: item.metadata.version,
            sourceDigest: item.metadataSourceDigest,
            itemId: item.metadata.id,
            version: item.metadata.version,
            blob,
          });
          targetDigests.push({
            sourceKind: 'item_metadata',
            sourceId: item.metadata.id,
            sourceVersion: item.metadata.version,
            targetDigest: await digestCipherBlob(blob),
          });
        } finally {
          metadataPlaintext.fill(0);
        }

        for (const secret of item.secretVersions) {
          const encrypted = await encryptLegacySecret(keys, secret);
          records.push({
            kind: 'secret',
            sourceId: secret.id,
            sourceVersion: secret.secretVersion,
            sourceDigest: secret.sourceDigest,
            itemId: secret.itemId,
            recordVersion: secret.secretVersion,
            secretVersion: secret.secretVersion,
            encryptedValue: encrypted.encryptedValue,
            wrappedDek: encrypted.wrappedDek,
          });
          const [contentDigest, wrapDigest] = await Promise.all([
            digestCipherBlob(encrypted.encryptedValue),
            digestCipherBlob(encrypted.wrappedDek),
          ]);
          try {
            targetDigests.push({
              sourceKind: 'item_secret',
              sourceId: secret.id,
              sourceVersion: secret.secretVersion,
              targetDigest: await hashBytes(contentDigest, wrapDigest),
            });
          } finally {
            contentDigest.fill(0);
            wrapDigest.fill(0);
          }
        }
      }

      const userEnvelopes = await Promise.all(materials.recipients.map((recipient) =>
        createVaultKeyGrant(keys, recipient.encryptionPublicKey, account.signingKeyPair.privateKey, {
          vaultId: job.vaultId,
          recipientKind: 'user',
          recipientId: recipient.userId,
          recipientKeyVersion: recipient.keyVersion,
          capability: recipient.capability,
          signerUserId: userId,
          signerKeyVersion: profile.keyVersion,
        })));
      const deviceEnvelopes = await Promise.all((materials.devices ?? []).map((recipient) =>
        createVaultKeyGrant(keys, recipient.encryptionPublicKey, account.signingKeyPair.privateKey, {
          vaultId: job.vaultId,
          recipientKind: 'device',
          recipientId: recipient.deviceId,
          recipientKeyVersion: recipient.keyVersion,
          capability: recipient.capability,
          signerUserId: userId,
          signerKeyVersion: profile.keyVersion,
        })));
      const recoveryEnvelope = recoveryKey
        ? await createVaultKeyGrant(
            keys,
            recoveryKey.publicEncryptionKey,
            account.signingKeyPair.privateKey,
            {
              vaultId: job.vaultId,
              recipientKind: 'recovery',
              recipientId: recoveryKey.id,
              recipientKeyVersion: 1,
              capability: 'recovery',
              signerUserId: userId,
              signerKeyVersion: profile.keyVersion,
            },
          )
        : null;
      const envelopes = [
        ...userEnvelopes,
        ...deviceEnvelopes,
        ...(recoveryEnvelope ? [recoveryEnvelope] : []),
      ];
      const targetUnsigned = {
        idempotencyKey: crypto.randomUUID(),
        jobId: job.id,
        headerFormatVersion: VAULT_HEADER_FORMAT_VERSION,
        keyPossessionPublicKey: await vaultKeyPossessionPublicKey(keys, {
          vaultId: job.vaultId,
          keyEpoch: job.targetEpoch,
        }),
        header: {
          vaultId: job.vaultId,
          version: 1,
          keyEpoch: job.targetEpoch,
          blob: encryptedHeader.blob,
        },
        envelopes,
        actorDeviceId: device.deviceId,
      };
      const target = {
        ...targetUnsigned,
        manifestSignature: await this.signCommand(
          'migration.target.prepare',
          userId,
          { vaultId: job.vaultId },
          targetUnsigned,
        ),
      };
      const recordBatches: LegacyMigrationUploadRequest[] = [];
      for (let offset = 0; offset < records.length; offset += 100) {
        const unsigned = {
          idempotencyKey: crypto.randomUUID(),
          jobId: job.id,
          actorDeviceId: device.deviceId,
          records: records.slice(offset, offset + 100),
        };
        recordBatches.push({
          ...unsigned,
          signature: await this.signCommand(
            'migration.records.upload',
            userId,
            { vaultId: job.vaultId },
            unsigned,
          ),
        });
      }
      const encryptedDigest = await migrationTargetDigest(targetDigests);
      const verification = {
        vaultId: job.vaultId,
        legacyItemCount: payload.vault.items.length,
        legacySecretVersionCount: records.filter((record) => record.kind === 'secret').length,
        encryptedItemCount: records.filter((record) => record.kind === 'metadata').length,
        encryptedSecretVersionCount: records.filter((record) => record.kind === 'secret').length,
        legacyDigest: job.sourceDigest,
        encryptedDigest,
        envelopeRecipientIds: envelopes.map((envelope) => envelope.recipientId).sort(),
        toolRevision: 'mima-web-migrator/1',
        actorDeviceId: device.deviceId,
      };
      this.pendingLegacyMigrations.set(job.vaultId, { jobId: job.id, keys, verification });
      return { jobId: job.id, vaultId: job.vaultId, target, recordBatches };
    } catch (error) {
      await destroyVaultKeys(keys);
      throw error;
    } finally {
      opened.fill(0);
      if (payload) clearLegacyPayload(payload);
    }
  }

  async migrationVerificationIntent(
    userId: string,
    vaultId: string,
    jobId: string,
  ): Promise<LegacyMigrationVerifyRequest> {
    const pending = this.pendingLegacyMigrations.get(vaultId);
    if (!pending || pending.jobId !== jobId) throw new Error('本页没有可验证的迁移密文，请回滚后重新开始');
    return {
      ...pending.verification,
      signature: await this.signCommand('migration.verify', userId, { vaultId }, pending.verification),
    };
  }

  async migrationActionIntent(
    userId: string,
    vaultId: string,
    jobId: string,
    action: 'cutover' | 'rollback',
  ): Promise<LegacyMigrationActionRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      jobId,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(`migration.${action}`, userId, { vaultId }, unsigned),
    };
  }

  async commitLegacyMigration(vaultId: string, jobId: string): Promise<void> {
    const pending = this.pendingLegacyMigrations.get(vaultId);
    if (!pending || pending.jobId !== jobId) throw new Error('没有可提交的迁移密钥');
    const previous = this.vaultKeys.get(vaultId);
    this.pendingLegacyMigrations.delete(vaultId);
    this.vaultKeys.set(vaultId, pending.keys);
    this.generation += 1;
    if (previous) await destroyVaultKeys(previous);
  }

  async abortLegacyMigration(vaultId: string, jobId?: string): Promise<void> {
    const pending = this.pendingLegacyMigrations.get(vaultId);
    if (!pending || (jobId !== undefined && pending.jobId !== jobId)) return;
    this.pendingLegacyMigrations.delete(vaultId);
    await destroyVaultKeys(pending.keys);
  }

  async commitIdentityRotation(): Promise<void> {
    const next = this.pendingIdentityRotation;
    if (!next) throw new Error('没有待提交的身份密钥轮换');
    const previous = this.account;
    this.pendingIdentityRotation = null;
    this.account = next;
    this.generation += 1;
    if (previous) await destroyUnlockedAccount(previous);
  }

  async abortIdentityRotation(): Promise<void> {
    const pending = this.pendingIdentityRotation;
    this.pendingIdentityRotation = null;
    if (pending) await destroyUnlockedAccount(pending);
  }

  async openVaultEnvelopes(
    envelopes: VaultKeyEnvelope[],
    signerPublicKeys: SignerPublicKeys,
  ): Promise<{ openedVaultIds: string[]; unavailableVaultIds: string[] }> {
    const account = this.requireAccount();
    const device = account.device;
    const byVault = new Map<string, VaultKeyEnvelope[]>();
    for (const envelope of envelopes) {
      const list = byVault.get(envelope.vaultId) ?? [];
      list.push(envelope);
      byVault.set(envelope.vaultId, list);
    }
    const openedVaultIds: string[] = [];
    const unavailableVaultIds: string[] = [];
    for (const [vaultId, grants] of byVault) {
      const sorted = [...grants].sort((left, right) => right.epoch - left.epoch);
      let opened = false;
      for (const grant of sorted) {
        const signerPublicKey = signerPublicKeys[`${grant.signerUserId}:${grant.signerKeyVersion}`]
          ?? signerPublicKeys[grant.signerUserId];
        if (!signerPublicKey) continue;
        const recipient = grant.recipientKind === 'user' && grant.recipientId === account.accountId
          ? account.encryptionKeyPair
          : grant.recipientKind === 'device' && device && grant.recipientId === device.deviceId
            ? device.encryptionKeyPair
            : null;
        if (!recipient) continue;
        try {
          const keys = await openVaultKeyGrant(grant, recipient, signerPublicKey, {
            vaultId,
            recipientId: grant.recipientId,
            epoch: grant.epoch,
            recipientKeyVersion: grant.recipientKeyVersion,
          });
          const previous = this.vaultKeys.get(vaultId);
          if (previous) await destroyVaultKeys(previous);
          this.vaultKeys.set(vaultId, keys);
          openedVaultIds.push(vaultId);
          opened = true;
          break;
        } catch {
          continue;
        }
      }
      if (!opened) unavailableVaultIds.push(vaultId);
    }
    return { openedVaultIds, unavailableVaultIds };
  }

  async decryptBootstrap(
    bootstrap: EncryptedBootstrapResponse,
    signerPublicKeys: SignerPublicKeys = {},
  ): Promise<DecryptedBootstrapProjection> {
    const account = this.requireAccount();
    const opened = await this.openVaultEnvelopes(bootstrap.envelopes, {
      [account.accountId]: bootstrap.profile?.signingPublicKey ?? account.signingKeyPair.publicKey,
      ...signerPublicKeys,
    });
    const activeGrants = new Set(opened.openedVaultIds);
    for (const vaultId of [...this.vaultKeys.keys()]) {
      if (!activeGrants.has(vaultId)) await this.dropVault(vaultId);
    }
    const headers = new Map<string, EncryptedVaultHeader>();
    for (const header of bootstrap.headers) {
      const keys = this.vaultKeys.get(header.vaultId);
      if (!keys || header.keyEpoch !== keys.keyEpoch) continue;
      const current = headers.get(header.vaultId);
      if (
        current
        && header.version === current.version
        && !sameCipherBlob(header.blob, current.blob)
      ) {
        throw new Error('密码库加密头存在冲突版本');
      }
      if (!current || header.version > current.version) {
        headers.set(header.vaultId, header);
      }
    }
    const vaults = [];
    const vaultCrypto: DecryptedBootstrapProjection['vaultCrypto'] = {};
    const pendingVaultAccessIds: Record<string, true> = {};
    const vaultDirectories: DecryptedBootstrapProjection['vaultDirectories'] = {};
    for (const record of bootstrap.vaults) {
      vaultCrypto[record.id] = record.crypto;
      const keys = this.vaultKeys.get(record.id);
      const header = headers.get(record.id);
      const pendingTeamAccess = record.kind === 'team' &&
        !keys &&
        !record.crypto.recoveryRequired &&
        record.crypto.activeEpoch > 0 &&
        record.crypto.encryptedHeader === null &&
        (record.crypto.status === 'e2ee' || record.crypto.status === 'rekey_required');
      let name = record.crypto.recoveryRequired
        ? '需要企业恢复'
        : pendingTeamAccess
          ? '正在自动准备团队访问'
          : '密码库尚未就绪';
      if (pendingTeamAccess) pendingVaultAccessIds[record.id] = true;
      if (keys && header) {
        let value: JsonValue;
        try {
          value = await decryptVaultMetadata(keys.metadataKey, {
            vaultId: header.vaultId,
            version: header.version,
            keyEpoch: header.keyEpoch,
            blob: header.blob,
          });
        } catch (error) {
          throw new Error('密码库加密信息完整性验证失败', { cause: error });
        }
        const headerPayload = parseVaultHeaderPayload(value);
        name = headerPayload.name;
        vaultDirectories[record.id] = headerPayload.directories;
      }
      vaults.push({
        id: record.id,
        kind: record.kind,
        name,
        ownerUserId: record.ownerUserId,
        ...(record.kind === 'team' ? {
          projectContext: record.projectContext ?? { kind: 'root' as const },
        } : {}),
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      });
    }

    const decryptedRecords: { record: EncryptedItemMetadata; payload: ItemMetadataPayload }[] = [];
    const encryptedItems: Record<string, EncryptedItemMetadata> = {};
    for (const record of bootstrap.items) {
      encryptedItems[record.itemId] = record;
      if (record.deleted) continue;
      const keys = this.vaultKeys.get(record.vaultId);
      if (!keys) continue;
      let payload: JsonValue;
      try {
        payload = await decryptItemMetadata(keys.metadataKey, encryptedRecord(record));
      } catch (error) {
        throw new Error('条目信息校验失败，已拒绝显示', { cause: error });
      }
      decryptedRecords.push({ record, payload: parseItemMetadataPayload(payload) });
    }
    for (const record of bootstrap.vaults) {
      if (!this.vaultKeys.has(record.id)) continue;
      const directories = materializeVaultDirectories(
        vaultDirectories[record.id] ?? [],
        decryptedRecords
          .filter((entry) => entry.record.vaultId === record.id)
          .map((entry) => entry.payload.folderPath),
      );
      vaultDirectories[record.id] = directories;
      this.vaultDirectories.set(record.id, directories);
    }
    const items = decryptedRecords.map(({ record, payload }) => recordToItem(record, {
      ...payload,
      folderPath: resolveVaultDirectoryPath(vaultDirectories[record.vaultId], payload.folderPath),
    }));
    return {
      user: bootstrap.user,
      vaults,
      memberships: bootstrap.memberships,
      items,
      cursor: bootstrap.cursor,
      vaultCrypto,
      pendingVaultAccessIds,
      vaultDirectories,
      encryptedItems,
    };
  }

  async decryptMetadataRecord(record: EncryptedItemMetadata): Promise<DecryptedItemMeta> {
    const keys = this.requireVaultKeys(record.vaultId);
    const value = await decryptItemMetadata(keys.metadataKey, encryptedRecord(record));
    const payload = parseItemMetadataPayload(value);
    return recordToItem(record, {
      ...payload,
      folderPath: resolveVaultDirectoryPath(this.vaultDirectories.get(record.vaultId), payload.folderPath),
    });
  }

  async decryptContent(response: EncryptedContentResponse): Promise<string> {
    const keys = this.requireVaultKeys(response.metadata.vaultId);
    if (!keys.contentKey) throw new Error('当前权限不能查看密码或敏感内容');
    const metadataPayload = parseItemMetadataPayload(await decryptItemMetadata(
      keys.metadataKey,
      encryptedRecord(response.metadata),
    ));
    const recordVersion = (response.secret as typeof response.secret & { recordVersion?: number }).recordVersion
      ?? response.secret.secretVersion;
    const value = await decryptItemContent(keys.contentKey, {
      vaultId: response.metadata.vaultId,
      itemId: response.metadata.itemId,
      itemKind: metadataPayload.kind,
      version: recordVersion,
      secretVersion: response.secret.secretVersion,
      keyEpoch: response.keyWrap.keyEpoch,
      metadata: response.metadata.blob,
      encryptedValue: response.secret.encryptedValue,
      wrappedDek: response.keyWrap.wrappedDek,
    });
    if (
      !isRecord(value) ||
      typeof value.value !== 'string' ||
      (value.itemKind !== undefined && value.itemKind !== metadataPayload.kind) ||
      (value.itemId !== undefined && value.itemId !== response.metadata.itemId) ||
      (value.secretVersion !== undefined && value.secretVersion !== response.secret.secretVersion)
    ) {
      throw new Error('敏感内容格式不正确');
    }
    return value.value;
  }

  async encryptCreate(
    userId: string,
    vaultId: string,
    input: CreateItemInput,
  ): Promise<CreateEncryptedItemRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const keys = this.requireFullVaultKeys(vaultId);
    const itemId = crypto.randomUUID();
    if (input.kind !== 'login' && !input.secretValue) {
      throw new Error(`${input.kind === 'api_token' ? '密钥 / Token' : '备注'}不能为空`);
    }
    const secretState = input.kind === 'login' && input.secretValue === null ? 'absent' : 'present';
    const metadata = itemPayload(parseItemMetadataPayload(itemPayload({ ...input, secretState })));
    const encrypted = await encryptItemVersion(keys, {
      vaultId,
      itemId,
      itemKind: input.kind,
      version: 1,
      secretVersion: 1,
      keyEpoch: keys.keyEpoch,
    }, { metadata: metadata as unknown as JsonValue, content: { value: input.secretValue ?? '' } });
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      itemId,
      keyEpoch: keys.keyEpoch,
      metadata: encrypted.metadata,
      encryptedValue: encrypted.encryptedValue,
      wrappedDek: encrypted.wrappedDek,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('item.create', userId, { vaultId, itemId }, unsigned),
    };
  }

  async initializeVault(
    userId: string,
    vaultId: string,
    name: string,
    profile: UserCryptoProfile,
    recoveryKey: EnterpriseRecoveryKey | null,
    expectedStatus: 'legacy' | 'preparing' = 'preparing',
    devices: CryptoDevice[] = [],
    materials?: LegacyMigrationMaterials,
    vaultGroupName: string | null = null,
  ): Promise<InitializeVaultCryptoRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (profile.userId !== userId || account.accountId !== userId) {
      throw new Error('只能为当前账号初始化密码库密钥');
    }
    if (
      (recoveryKey !== null && recoveryKey.status !== 'active') ||
      (materials && (
        materials.recoveryKey?.status !== recoveryKey?.status ||
        materials.recoveryKey?.id !== recoveryKey?.id
      ))
    ) throw new Error('密码库恢复设置与服务端材料不一致');
    const keys = await createVaultKeys(1);
    try {
      const recipients = materials?.recipients ?? [{
        userId,
        keyVersion: profile.keyVersion,
        capability: 'full' as const,
        encryptionPublicKey: profile.encryptionPublicKey,
      }];
      if (!recipients.some((recipient) =>
        recipient.userId === userId && recipient.keyVersion === profile.keyVersion && recipient.capability === 'full'
      )) throw new Error('密码库初始化所需数据不完整，请刷新后重试');
      const fallbackDevices = devices.filter((candidate) =>
        candidate.userId === userId && candidate.deviceType === 'extension' && candidate.revokedAt === null
      ).map((candidate) => ({
        deviceId: candidate.id,
        keyVersion: candidate.keyVersion,
        capability: 'full' as const,
        encryptionPublicKey: candidate.encryptionPublicKey,
      }));
      const deviceRecipients = materials?.devices ?? fallbackDevices;
      const [userEnvelopes, recoveryEnvelope, header, extensionEnvelopes] = await Promise.all([
        Promise.all(recipients.map((recipient) => createVaultKeyGrant(
          keys,
          recipient.encryptionPublicKey,
          account.signingKeyPair.privateKey,
          {
            vaultId,
            recipientKind: 'user',
            recipientId: recipient.userId,
            recipientKeyVersion: recipient.keyVersion,
            capability: recipient.capability,
            signerUserId: userId,
            signerKeyVersion: profile.keyVersion,
          },
        ))),
        recoveryKey
          ? createVaultKeyGrant(keys, recoveryKey.publicEncryptionKey, account.signingKeyPair.privateKey, {
              vaultId,
              recipientKind: 'recovery',
              recipientId: recoveryKey.id,
              recipientKeyVersion: 1,
              capability: 'recovery',
              signerUserId: userId,
              signerKeyVersion: profile.keyVersion,
            })
          : Promise.resolve(null),
        encryptVaultMetadata(keys.metadataKey, { vaultId, version: 1, keyEpoch: 1 }, {
          name,
          directories: [],
          vaultGroupName: normalizeVaultGroupName(vaultGroupName),
        }),
        Promise.all(deviceRecipients.map((candidate) => createVaultKeyGrant(
          keys,
          candidate.encryptionPublicKey,
          account.signingKeyPair.privateKey,
          {
            vaultId,
            recipientKind: 'device',
            recipientId: candidate.deviceId,
            recipientKeyVersion: candidate.keyVersion,
            capability: candidate.capability,
            signerUserId: userId,
            signerKeyVersion: profile.keyVersion,
          },
        ))),
      ]);
      const unsigned = {
        idempotencyKey: crypto.randomUUID(),
        expectedStatus,
        epoch: 1 as const,
        headerFormatVersion: VAULT_HEADER_FORMAT_VERSION,
        keyPossessionPublicKey: await vaultKeyPossessionPublicKey(keys, { vaultId, keyEpoch: 1 }),
        header: {
          vaultId,
          version: 1,
          keyEpoch: 1,
          blob: header.blob,
        },
        envelopes: [
          ...userEnvelopes,
          ...extensionEnvelopes,
          ...(recoveryEnvelope ? [recoveryEnvelope] : []),
        ],
        actorDeviceId: device.deviceId,
      };
      const result = {
        ...unsigned,
        manifestSignature: await this.signCommand('vault.initialize', userId, { vaultId }, unsigned),
      };
      const previous = this.vaultKeys.get(vaultId);
      if (previous) await destroyVaultKeys(previous);
      this.vaultKeys.set(vaultId, keys);
      return result;
    } catch (error) {
      await destroyVaultKeys(keys);
      throw error;
    }
  }

  async prepareVaultCreation(
    userId: string,
    vaultId: string,
    name: string,
    profile: UserCryptoProfile,
    recoveryKey: EnterpriseRecoveryKey | null,
    devices: CryptoDevice[],
    project?: { parentVaultId: string; expectedParentAccessGeneration: number },
  ): Promise<AtomicCreateEncryptedVaultRequest | CreateEncryptedProjectRequest> {
    const initialized = await this.initializeVault(
      userId,
      vaultId,
      name,
      profile,
      recoveryKey,
      'preparing',
      devices,
    );
    const base = {
      idempotencyKey: initialized.idempotencyKey,
      vaultId,
      epoch: initialized.epoch,
      headerFormatVersion: VAULT_HEADER_FORMAT_VERSION,
      keyPossessionPublicKey: initialized.keyPossessionPublicKey,
      header: initialized.header,
      envelopes: initialized.envelopes,
      actorDeviceId: initialized.actorDeviceId,
    };
    if (project) {
      const unsigned = {
        ...base,
        expectedParentAccessGeneration: project.expectedParentAccessGeneration,
      };
      return {
        ...unsigned,
        manifestSignature: await this.signCommand(
          'vault.project.create',
          userId,
          { vaultId: project.parentVaultId },
          unsigned,
        ),
      };
    }
    return {
      ...base,
      manifestSignature: await this.signCommand('vault.create', userId, { vaultId }, base),
    };
  }

  async prepareEnterpriseRecoveryEnvelope(
    userId: string,
    profile: UserCryptoProfile,
    recoveryKey: EnterpriseRecoveryKey,
    vaultId: string,
    expectedEpoch: number,
  ): Promise<DistributeEnterpriseRecoveryEnvelopeRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (account.accountId !== userId || profile.userId !== userId) {
      throw new Error('只能为当前账号拥有的密码库添加公司恢复保护');
    }
    if (recoveryKey.status !== 'staged') {
      throw new Error('企业恢复公钥尚未完成双人批准或已经启用');
    }
    const keys = this.requireFullVaultKeys(vaultId);
    if (keys.keyEpoch !== expectedEpoch) {
      throw new Error('密码库刚刚完成安全更新，请刷新状态后重试');
    }
    const envelope = await createVaultKeyGrant(
      keys,
      recoveryKey.publicEncryptionKey,
      account.signingKeyPair.privateKey,
      {
        vaultId,
        recipientKind: 'recovery',
        recipientId: recoveryKey.id,
        recipientKeyVersion: 1,
        capability: 'recovery',
        signerUserId: userId,
        signerKeyVersion: profile.keyVersion,
      },
    );
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      actorDeviceId: device.deviceId,
      envelope,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'recovery.key.distribute',
        userId,
        { vaultId },
        unsigned,
      ),
    };
  }

  async completeRecovery(
    userId: string,
    request: EnterpriseRecoveryRequest,
    recoveryKey: EnterpriseRecoveryKey,
    header: EncryptedVaultHeader,
    offlineResult: OfflineRecoveryResult,
  ): Promise<CompleteEnterpriseRecoveryRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (request.status !== 'approved' || Date.parse(request.expiresAt) <= Date.now()) {
      throw new Error('恢复请求尚未获得双人审批或已经过期');
    }
    if (
      request.targetUserId !== userId ||
      request.targetDeviceId !== device.deviceId ||
      offlineResult.requestId !== request.id ||
      offlineResult.requestDigest !== request.requestDigest ||
      offlineResult.vaultId !== request.vaultId ||
      offlineResult.epoch !== header.keyEpoch ||
      offlineResult.recoveryKeyId !== request.recoveryKeyId ||
      offlineResult.recoveryKeyId !== recoveryKey.id ||
      offlineResult.ceremonyId !== recoveryKey.ceremonyId ||
      offlineResult.recoveryCeremonyDigest !== recoveryKey.ceremonyEvidenceDigest ||
      offlineResult.targetUserId !== userId ||
      offlineResult.targetCapability !== request.targetCapability
    ) {
      throw new Error('离线恢复结果与当前请求或设备不匹配');
    }
    const unsignedEnvelope = offlineResult.recoveredEnvelope;
    const expectedEvidenceDigest = await enterpriseRecoveryTransferEvidenceDigest({
      requestId: offlineResult.requestId,
      requestDigest: offlineResult.requestDigest,
      vaultId: offlineResult.vaultId,
      epoch: offlineResult.epoch,
      recoveryKeyId: offlineResult.recoveryKeyId,
      ceremonyId: offlineResult.ceremonyId,
      recoveryCeremonyDigest: offlineResult.recoveryCeremonyDigest,
      targetUserId: offlineResult.targetUserId,
      targetCapability: offlineResult.targetCapability,
      recoveredEnvelope: unsignedEnvelope,
    }, offlineResult.evidenceFormat);
    if (expectedEvidenceDigest !== offlineResult.toolEvidenceDigest) {
      throw new Error('离线恢复结果证据摘要不匹配');
    }
    if (
      unsignedEnvelope.vaultId !== request.vaultId ||
      unsignedEnvelope.recipientKind !== 'user' ||
      unsignedEnvelope.recipientId !== userId ||
      unsignedEnvelope.recipientKeyVersion !== request.targetKeyVersion ||
      unsignedEnvelope.capability !== request.targetCapability ||
      unsignedEnvelope.signerUserId !== userId ||
      unsignedEnvelope.signerKeyVersion !== request.targetKeyVersion
    ) {
      throw new Error('离线恢复结果的密码库或接收人绑定不正确');
    }
    const recoveredEnvelope = await signVaultKeyGrant(
      unsignedEnvelope,
      account.signingKeyPair.privateKey,
    );
    const keys = await openVaultKeyGrant(
      recoveredEnvelope,
      account.encryptionKeyPair,
      account.signingKeyPair.publicKey,
      {
        vaultId: request.vaultId,
        recipientId: userId,
        epoch: recoveredEnvelope.epoch,
        recipientKeyVersion: recoveredEnvelope.recipientKeyVersion,
      },
    );
    try {
      if (header.vaultId !== request.vaultId || header.keyEpoch !== recoveredEnvelope.epoch) {
        throw new Error('恢复密钥版本与密码库头不匹配');
      }
      parseVaultHeaderPayload(await decryptVaultMetadata(keys.metadataKey, {
        vaultId: header.vaultId,
        version: header.version,
        keyEpoch: header.keyEpoch,
        blob: header.blob,
      }));
      const unsigned = {
        idempotencyKey: crypto.randomUUID(),
        requestDigest: request.requestDigest,
        recoveredEnvelope,
        actorDeviceId: device.deviceId,
        toolEvidenceDigest: offlineResult.toolEvidenceDigest,
      };
      const result = {
        ...unsigned,
        targetConfirmationSignature: await this.signCommand(
          'recovery.complete',
          userId,
          { vaultId: request.vaultId },
          { requestId: request.id, ...unsigned },
        ),
      };
      const previous = this.vaultKeys.get(request.vaultId);
      if (previous) await destroyVaultKeys(previous);
      this.vaultKeys.set(request.vaultId, keys);
      return result;
    } catch (error) {
      await destroyVaultKeys(keys);
      throw error;
    }
  }

  async encryptVaultRename(
    userId: string,
    vaultId: string,
    name: string,
    currentHeader: EncryptedVaultHeader,
  ): Promise<UpdateEncryptedVaultHeaderRequest> {
    return this.encryptVaultHeaderUpdate(userId, vaultId, currentHeader, 'rename', (current) => ({
      ...current,
      name: name.trim(),
    }));
  }

  async encryptVaultDetails(
    userId: string,
    vaultId: string,
    details: { name: string; vaultGroupName: string | null },
    currentHeader: EncryptedVaultHeader,
  ): Promise<UpdateEncryptedVaultHeaderRequest> {
    const normalizedGroupName = normalizeVaultGroupName(details.vaultGroupName);
    if (details.vaultGroupName?.trim() && normalizedGroupName === null) {
      throw new Error('密码库旧版设置格式不正确');
    }
    return this.encryptVaultHeaderUpdate(userId, vaultId, currentHeader, 'details', (current) => ({
      ...current,
      name: details.name.trim(),
      vaultGroupName: normalizedGroupName,
    }));
  }

  async encryptVaultDirectories(
    userId: string,
    vaultId: string,
    directories: VaultDirectoryEntry[],
    currentHeader: EncryptedVaultHeader,
  ): Promise<UpdateEncryptedVaultHeaderRequest> {
    const normalized = normalizeVaultDirectories(directories);
    if (!normalized) throw new Error('密码库目录清单格式不正确');
    return this.encryptVaultHeaderUpdate(userId, vaultId, currentHeader, 'directories', (current) => ({
      ...current,
      directories: normalized,
    }));
  }

  private async encryptVaultHeaderUpdate(
    userId: string,
    vaultId: string,
    currentHeader: EncryptedVaultHeader,
    operation: 'rename' | 'details' | 'directories',
    update: (current: ReturnType<typeof parseVaultHeaderPayload>) => ReturnType<typeof parseVaultHeaderPayload>,
  ): Promise<UpdateEncryptedVaultHeaderRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const keys = this.requireVaultKeys(vaultId);
    if (
      currentHeader.vaultId !== vaultId ||
      currentHeader.keyEpoch !== keys.keyEpoch ||
      !Number.isSafeInteger(currentHeader.version) ||
      currentHeader.version < 1
    ) {
      throw new Error('密码库加密信息版本无效，请刷新后重试');
    }
    const current = parseVaultHeaderPayload(await decryptVaultMetadata(keys.metadataKey, {
      vaultId,
      version: currentHeader.version,
      keyEpoch: currentHeader.keyEpoch,
      blob: currentHeader.blob,
    }));
    const payload = parseVaultHeaderPayload(update(current));
    const header = await encryptVaultMetadata(keys.metadataKey, {
      vaultId,
      version: currentHeader.version + 1,
      keyEpoch: keys.keyEpoch,
    }, payload as unknown as JsonValue);
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedHeaderVersion: currentHeader.version,
      headerFormatVersion: VAULT_HEADER_FORMAT_VERSION,
      operation,
      header: {
        vaultId,
        version: currentHeader.version + 1,
        keyEpoch: keys.keyEpoch,
        blob: header.blob,
      },
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        operation === 'rename'
          ? 'vault.rename'
          : operation === 'details'
            ? 'vault.details.update'
            : 'vault.directories.update',
        userId,
        { vaultId },
        unsigned,
      ),
    };
  }

  async approveExtensionEnrollment(
    userId: string,
    profile: UserCryptoProfile,
    enrollment: ExtensionEnrollment,
  ): Promise<ApproveExtensionEnrollmentRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (enrollment.status !== 'pending' || Date.parse(enrollment.expiresAt) <= Date.now()) {
      throw new Error('扩展配对请求已经失效');
    }
    const expectedFingerprint = await extensionDeviceFingerprint({
      deviceId: enrollment.deviceId,
      encryptionPublicKey: enrollment.encryptionPublicKey,
      signingPublicKey: enrollment.signingPublicKey,
    });
    if (normalizeFingerprint(expectedFingerprint) !== normalizeFingerprint(enrollment.fingerprint)) {
      throw new Error('扩展设备信息与本次配对不一致，请重新配对');
    }
    const certificate = await createSignedDeviceCertificate({
      accountId: userId,
      deviceId: enrollment.deviceId,
      deviceType: 'extension',
      encryptionPublicKey: enrollment.encryptionPublicKey,
      signingPublicKey: enrollment.signingPublicKey,
      keyVersion: profile.keyVersion,
      issuedAt: new Date().toISOString(),
    }, account.signingKeyPair.privateKey);
    const envelopes = [];
    for (const [vaultId, keys] of this.vaultKeys) {
      if (!keys.contentKey) continue;
      envelopes.push(await createVaultKeyGrant(
        { ...keys, contentKey: keys.contentKey },
        enrollment.encryptionPublicKey,
        account.signingKeyPair.privateKey,
        {
          vaultId,
          recipientKind: 'device',
          recipientId: enrollment.deviceId,
          recipientKeyVersion: profile.keyVersion,
          capability: 'full',
          signerUserId: userId,
          signerKeyVersion: profile.keyVersion,
        },
      ));
    }
    const unsigned = {
      approverDeviceId: device.deviceId,
      certificate: certificate.certificate,
      certificateSignature: certificate.signature,
      envelopes,
    };
    return {
      ...unsigned,
      approvalSignature: await this.signCommand(
        'crypto.extension.approve',
        userId,
        {},
        { enrollmentId: enrollment.id, ...unsigned },
      ),
    };
  }

  async prepareExtensionTrustedUnlock(
    profile: UserCryptoProfile,
    request: ExtensionTrustedUnlockRequest,
  ): Promise<ExtensionTrustedUnlockResponse> {
    assertExtensionTrustedUnlockRequest(request);
    const account = this.requireAccount();
    if (
      profile.userId !== account.accountId ||
      request.accountId !== account.accountId ||
      request.accountKeyVersion !== profile.keyVersion ||
      profile.encryptionPublicKey !== account.encryptionKeyPair.publicKey ||
      profile.signingPublicKey !== account.signingKeyPair.publicKey
    ) {
      throw new Error('扩展可信解锁请求与当前账号不一致');
    }
    const deviceUnlockKey = await deriveExtensionDeviceUnlockKey(account.accountKey, request);
    try {
      return {
        ...request,
        accountBundle: {
          accountId: profile.userId,
          profileVersion: 1,
          keyVersion: profile.keyVersion,
          suite: profile.suite,
          kdf: profile.kdf,
          encryptedAccountBundle: profile.encryptedAccountBundle,
          encryptionPublicKey: profile.encryptionPublicKey,
          signingPublicKey: profile.signingPublicKey,
        },
        sealedDeviceUnlockKey: await sealBytes(
          deviceUnlockKey,
          request.ephemeralEncryptionPublicKey,
        ),
      };
    } finally {
      const crypto = await sodiumReady();
      crypto.memzero(deviceUnlockKey);
    }
  }

  async prepareExtensionSessionResume(
    userId: string,
    request: ExtensionTrustedUnlockRequest,
  ): Promise<ResumeExtensionSessionRequest> {
    assertExtensionTrustedUnlockRequest(request);
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      approverDeviceId: device.deviceId,
      trustedRequest: request,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'crypto.extension.session.resume',
        userId,
        {},
        unsigned,
      ),
    };
  }

  async revokeDevice(
    userId: string,
    targetDeviceId: string,
    expectedKeyVersion: number,
  ): Promise<RevokeCryptoDeviceRequest> {
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedKeyVersion,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'crypto.device.revoke',
        userId,
        {},
        { ...unsigned, deviceId: targetDeviceId },
      ),
    };
  }

  async prepareMembershipSet(
    userId: string,
    vaultId: string,
    input: {
      subjectKind: 'user' | 'group' | 'custom_group';
      subjectId: string;
      role: 'viewer' | 'editor' | 'owner' | 'auditor';
      mode?: 'replace' | 'grant_or_upgrade';
      expectedAccessGeneration: number;
      distribution?: {
        signerKeyVersion: number;
        recipientProfile: PublicCryptoProfile;
      };
    },
  ): Promise<SetEncryptedMembershipRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const envelopes = [];
    if (input.distribution) {
      if (
        input.subjectKind !== 'user' ||
        input.role === 'auditor' ||
        input.distribution.recipientProfile.userId !== input.subjectId
      ) throw new Error('成员自动访问交付信息与当前权限不一致，请刷新后重试');
      const keys = this.requireFullVaultKeys(vaultId);
      envelopes.push(await createVaultKeyGrant(
        keys,
        input.distribution.recipientProfile.encryptionPublicKey,
        account.signingKeyPair.privateKey,
        {
          vaultId,
          recipientKind: 'user',
          recipientId: input.subjectId,
          recipientKeyVersion: input.distribution.recipientProfile.keyVersion,
          capability: 'full',
          signerUserId: userId,
          signerKeyVersion: input.distribution.signerKeyVersion,
        },
      ));
    }
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      subjectKind: input.subjectKind,
      subjectId: input.subjectId,
      role: input.role,
      ...(input.mode ? { mode: input.mode } : {}),
      expectedAccessGeneration: input.expectedAccessGeneration,
      actorDeviceId: device.deviceId,
      envelopes,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('vault.membership.set', userId, { vaultId }, unsigned),
    };
  }

  async prepareMembershipRemoval(
    userId: string,
    vaultId: string,
    input: {
      subjectKind: 'user' | 'group' | 'custom_group';
      subjectId: string;
      expectedAccessGeneration: number;
    },
  ): Promise<RemoveEncryptedMembershipRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      subjectKind: input.subjectKind,
      subjectId: input.subjectId,
      expectedAccessGeneration: input.expectedAccessGeneration,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('vault.membership.remove', userId, { vaultId }, unsigned),
    };
  }

  async prepareVaultDeletion(
    userId: string,
    vaultId: string,
    expectedAccessGeneration: number,
    currentHeader: EncryptedVaultHeader,
  ): Promise<import('@mima/contracts').DeleteEncryptedVaultRequest> {
    const device = this.requireDevice(this.requireAccount());
    const keys = this.requireVaultKeys(vaultId);
    if (currentHeader.vaultId !== vaultId || currentHeader.keyEpoch !== keys.keyEpoch) {
      throw new Error('密码库加密信息版本无效，请刷新后重试');
    }
    const payload = parseVaultHeaderPayload(await decryptVaultMetadata(keys.metadataKey, {
      vaultId,
      version: currentHeader.version,
      keyEpoch: currentHeader.keyEpoch,
      blob: currentHeader.blob,
    }));
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedAccessGeneration,
      expectedHeaderVersion: currentHeader.version,
      directoryCount: payload.directories.length,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('vault.delete', userId, { vaultId }, unsigned),
    };
  }

  async prepareUninitializedVaultDeletion(
    userId: string,
    vaultId: string,
    expectedAccessGeneration: number,
  ): Promise<DeleteUninitializedVaultRequest> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedAccessGeneration,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('vault.uninitialized.delete', userId, { vaultId }, unsigned),
    };
  }

  async prepareEnvelopeTaskCompletion(
    userId: string,
    profile: UserCryptoProfile,
    task: VaultEnvelopeTask,
  ): Promise<CompleteVaultEnvelopeTaskRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    if (task.status !== 'pending') throw new Error('这项团队访问已经自动处理');
    if (!task.recipientProfile) throw new Error('对方尚未设置主密码');
    if (task.expectedProfileGeneration !== task.recipientProfile.keyVersion) {
      throw new Error('对方的账号安全信息已更新，系统将按最新信息自动重试');
    }
    const keys = this.requireFullVaultKeys(task.vaultId);
    const envelope = await createVaultKeyGrant(
      keys,
      task.recipientProfile.encryptionPublicKey,
      account.signingKeyPair.privateKey,
      {
        vaultId: task.vaultId,
        recipientKind: 'user',
        recipientId: task.recipientUserId,
        recipientKeyVersion: task.recipientProfile.keyVersion,
        capability: task.capability,
        signerUserId: userId,
        signerKeyVersion: profile.keyVersion,
      },
    );
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      actorDeviceId: device.deviceId,
      envelope,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'vault.envelope-task.complete',
        userId,
        { vaultId: task.vaultId },
        { taskId: task.id, ...unsigned },
      ),
    };
  }

  async prepareOwnershipTransfer(
    userId: string,
    vaultId: string,
    newOwnerUserId: string,
    expectedAccessGeneration: number,
  ): Promise<CreateVaultOwnershipTransferRequest> {
    this.requireFullVaultKeys(vaultId);
    const device = this.requireDevice(this.requireAccount());
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      newOwnerUserId,
      expectedAccessGeneration,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand('vault.ownership-transfer.create', userId, { vaultId }, unsigned),
    };
  }

  async prepareOwnershipTransferAcceptance(
    userId: string,
    transfer: VaultOwnershipTransfer,
  ): Promise<AcceptVaultOwnershipTransferRequest> {
    if (!transfer.envelopeReady) throw new Error('系统正在自动准备当前密码库访问，请稍后重试');
    const keys = this.requireFullVaultKeys(transfer.vaultId);
    const device = this.requireDevice(this.requireAccount());
    if (transfer.status !== 'pending' || !transfer.acceptanceRequired) {
      throw new Error('该所有权转移不再等待确认');
    }
    if (transfer.toOwnerUserId !== userId) throw new Error('只有目标用户可以确认接收所有权');
    if (
      !transfer.keyPossessionProofAvailable ||
      !transfer.completedEnvelopeId ||
      !transfer.envelopeCiphertextDigest
    ) throw new Error('当前密码库需要先完成一次安全更新，再确认接收所有权');
    if (keys.keyEpoch !== transfer.keyEpoch) throw new Error('本机密码库状态已过期，请先同步');
    const idempotencyKey = crypto.randomUUID();
    const evidence = {
      transferId: transfer.id,
      vaultId: transfer.vaultId,
      keyEpoch: transfer.keyEpoch,
      envelopeTaskId: transfer.envelopeTaskId,
      fromOwnerUserId: transfer.fromOwnerUserId,
      toOwnerUserId: transfer.toOwnerUserId,
      expectedAccessGeneration: transfer.expectedAccessGeneration,
      actorDeviceId: device.deviceId,
      idempotencyKey,
      completedEnvelopeId: transfer.completedEnvelopeId,
      envelopeCiphertextDigest: transfer.envelopeCiphertextDigest,
    };
    const acceptanceDigest = await ownershipTransferAcceptanceDigest(evidence);
    const unsigned = {
      idempotencyKey,
      transferId: transfer.id,
      envelopeTaskId: transfer.envelopeTaskId,
      expectedAccessGeneration: transfer.expectedAccessGeneration,
      acceptanceDigest,
      keyPossessionSignature: await signVaultKeyPossession(keys, evidence),
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'vault.ownership-transfer.accept',
        userId,
        { vaultId: transfer.vaultId },
        unsigned,
      ),
    };
  }

  async prepareOwnershipTransferCancellation(
    userId: string,
    transfer: VaultOwnershipTransfer,
    decision: 'cancel' | 'decline',
  ): Promise<CancelVaultOwnershipTransferRequest> {
    const device = this.requireDevice(this.requireAccount());
    if (transfer.status !== 'pending') throw new Error('该所有权转移已经处理');
    if (decision === 'cancel' && transfer.fromOwnerUserId !== userId) {
      throw new Error('只有发起用户可以取消所有权转移');
    }
    if (decision === 'decline' && transfer.toOwnerUserId !== userId) {
      throw new Error('只有目标用户可以拒绝接收所有权');
    }
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      transferId: transfer.id,
      envelopeTaskId: transfer.envelopeTaskId,
      expectedAccessGeneration: transfer.expectedAccessGeneration,
      decision,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'vault.ownership-transfer.cancel',
        userId,
        { vaultId: transfer.vaultId },
        unsigned,
      ),
    };
  }

  async rekeyMaterialIntent(userId: string, vaultId: string, taskId: string): Promise<RekeyMaterialQuery> {
    const device = this.requireDevice(this.requireAccount());
    const unsigned = { taskId, actorDeviceId: device.deviceId };
    return {
      ...unsigned,
      signature: await this.signCommand('vault.rekey.material', userId, { vaultId }, unsigned),
    };
  }

  async prepareVaultRekey(
    userId: string,
    vaultId: string,
    profile: UserCryptoProfile,
    material: RekeyMaterial,
  ): Promise<RekeyVaultCommitRequest> {
    await this.abortVaultRekey(vaultId);
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const currentKeys = this.requireFullVaultKeys(vaultId);
    if (
      profile.userId !== userId ||
      material.state.vaultId !== vaultId ||
      material.task.fromEpoch !== currentKeys.keyEpoch ||
      material.task.toEpoch !== currentKeys.keyEpoch + 1 ||
      material.header.vaultId !== vaultId ||
      material.header.keyEpoch !== currentKeys.keyEpoch ||
      (material.recoveryKey !== null && material.recoveryKey.status !== 'active')
    ) {
      throw new Error('密码库安全更新数据与当前状态不一致，请刷新后重试');
    }
    const nextKeys = await createVaultKeys(material.task.toEpoch);
    try {
      const headerPayload = await decryptVaultMetadata(currentKeys.metadataKey, {
        vaultId,
        version: material.header.version,
        keyEpoch: material.header.keyEpoch,
        blob: material.header.blob,
      });
      const encryptedHeader = await encryptVaultMetadata(nextKeys.metadataKey, {
        vaultId,
        version: material.header.version + 1,
        keyEpoch: nextKeys.keyEpoch,
      }, headerPayload);
      const itemKinds = new Map<string, ItemMetadataPayload['kind']>();
      const reencryptedMetadata = await Promise.all(material.metadata.map(async (record) => {
        const payload = await decryptItemMetadata(currentKeys.metadataKey, encryptedRecord(record));
        const normalizedPayload = itemPayload(parseItemMetadataPayload(payload));
        itemKinds.set(record.itemId, normalizedPayload.kind);
        const plaintext = encodeJson(normalizedPayload as unknown as JsonValue);
        try {
          return {
            itemId: record.itemId,
            version: record.version,
            blob: await encryptBytes(nextKeys.metadataKey, plaintext, {
              blobType: 'item-metadata',
              vaultId,
              itemId: record.itemId,
              recordVersion: record.version,
              secretVersion: record.secretVersion,
              keyEpoch: nextKeys.keyEpoch,
            }),
          };
        } finally {
          plaintext.fill(0);
        }
      }));
      const rewrappedSecrets = await Promise.all(material.keyWraps.map(async (wrap) => {
        const placeholder = wrap.wrappedDek;
        const itemKind = itemKinds.get(wrap.itemId);
        if (!itemKind) throw new Error('密码库安全更新缺少条目信息，请刷新后重试');
        const rewrapped = await rewrapItemContentKey(currentKeys.contentKey, nextKeys.contentKey, {
          vaultId,
          itemId: wrap.itemId,
          itemKind,
          version: wrap.recordVersion,
          secretVersion: wrap.secretVersion,
          keyEpoch: wrap.keyEpoch,
          metadata: placeholder,
          encryptedValue: placeholder,
          wrappedDek: wrap.wrappedDek,
        }, nextKeys.keyEpoch);
        return { itemId: wrap.itemId, secretVersion: wrap.secretVersion, wrappedDek: rewrapped.wrappedDek };
      }));
      const userEnvelopes = await Promise.all(material.recipients.map((recipient) => createVaultKeyGrant(
        nextKeys,
        recipient.encryptionPublicKey,
        account.signingKeyPair.privateKey,
        {
          vaultId,
          recipientKind: 'user',
          recipientId: recipient.userId,
          recipientKeyVersion: recipient.keyVersion,
          capability: recipient.capability,
          signerUserId: userId,
          signerKeyVersion: profile.keyVersion,
        },
      )));
      const deviceEnvelopes = await Promise.all((material.devices ?? []).map((recipient) => createVaultKeyGrant(
        nextKeys,
        recipient.encryptionPublicKey,
        account.signingKeyPair.privateKey,
        {
          vaultId,
          recipientKind: 'device',
          recipientId: recipient.deviceId,
          recipientKeyVersion: recipient.keyVersion,
          capability: recipient.capability,
          signerUserId: userId,
          signerKeyVersion: profile.keyVersion,
        },
      )));
      const recoveryEnvelope = material.recoveryKey
        ? await createVaultKeyGrant(
            nextKeys,
            material.recoveryKey.publicEncryptionKey,
            account.signingKeyPair.privateKey,
            {
              vaultId,
              recipientKind: 'recovery',
              recipientId: material.recoveryKey.id,
              recipientKeyVersion: 1,
              capability: 'recovery',
              signerUserId: userId,
              signerKeyVersion: profile.keyVersion,
            },
          )
        : null;
      const unsigned = {
        idempotencyKey: crypto.randomUUID(),
        metadataFormatVersion: ITEM_METADATA_FORMAT_VERSION,
        headerFormatVersion: VAULT_HEADER_FORMAT_VERSION,
        expectedEpoch: material.task.fromEpoch,
        newEpoch: material.task.toEpoch,
        keyPossessionPublicKey: await vaultKeyPossessionPublicKey(nextKeys, {
          vaultId,
          keyEpoch: material.task.toEpoch,
        }),
        reason: rekeyRequestReason(material.task.reason),
        header: {
          vaultId,
          version: encryptedHeader.version,
          keyEpoch: encryptedHeader.keyEpoch,
          blob: encryptedHeader.blob,
        },
        envelopes: [
          ...userEnvelopes,
          ...deviceEnvelopes,
          ...(recoveryEnvelope ? [recoveryEnvelope] : []),
        ],
        rewrappedSecrets,
        reencryptedMetadata,
        actorDeviceId: device.deviceId,
      };
      const request = {
        ...unsigned,
        manifestSignature: await this.signCommand('vault.rekey', userId, { vaultId }, unsigned),
      };
      this.pendingVaultRekeys.set(vaultId, nextKeys);
      return request;
    } catch (error) {
      await destroyVaultKeys(nextKeys);
      throw error;
    }
  }

  async commitVaultRekey(vaultId: string): Promise<void> {
    const next = this.pendingVaultRekeys.get(vaultId);
    if (!next) throw new Error('没有待提交的密码库安全更新');
    const previous = this.vaultKeys.get(vaultId);
    this.pendingVaultRekeys.delete(vaultId);
    this.vaultKeys.set(vaultId, next);
    this.generation += 1;
    if (previous) await destroyVaultKeys(previous);
  }

  async abortVaultRekey(vaultId: string): Promise<void> {
    const pending = this.pendingVaultRekeys.get(vaultId);
    this.pendingVaultRekeys.delete(vaultId);
    if (pending) await destroyVaultKeys(pending);
  }

  async encryptMetadataUpdate(
    userId: string,
    item: DecryptedItemMeta,
    payload: ItemMetadataPayload,
  ): Promise<UpdateEncryptedItemRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const keys = this.requireVaultKeys(item.vaultId);
    const nextVersion = item.version + 1;
    const normalizedPayload = itemPayload(parseItemMetadataPayload(payload));
    const plaintext = encodeJson(normalizedPayload as unknown as JsonValue);
    let metadata: CipherBlob;
    try {
      metadata = await encryptBytes(keys.metadataKey, plaintext, {
        blobType: 'item-metadata',
        vaultId: item.vaultId,
        itemId: item.id,
        recordVersion: nextVersion,
        secretVersion: item.secretVersion,
        keyEpoch: keys.keyEpoch,
      });
    } finally {
      plaintext.fill(0);
    }
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedVersion: item.version,
      metadataFormatVersion: ITEM_METADATA_FORMAT_VERSION,
      keyEpoch: keys.keyEpoch,
      metadata,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'item.update_metadata',
        userId,
        { vaultId: item.vaultId, itemId: item.id },
        unsigned,
      ),
    };
  }

  async encryptRotation(
    userId: string,
    item: DecryptedItemMeta,
    secretValue: string,
  ): Promise<RotateEncryptedSecretRequest> {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const keys = this.requireFullVaultKeys(item.vaultId);
    const nextVersion = item.version + 1;
    if (secretValue.length === 0) throw new Error('请输入要保存的密码或敏感内容');
    const metadata = itemPayload(parseItemMetadataPayload({
      ...itemPayload(item),
      secretState: 'present',
    }));
    const encrypted = await encryptItemVersion(keys, {
      vaultId: item.vaultId,
      itemId: item.id,
      itemKind: item.kind,
      version: nextVersion,
      secretVersion: nextVersion,
      keyEpoch: keys.keyEpoch,
    }, { metadata: metadata as unknown as JsonValue, content: { value: secretValue } });
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedVersion: item.version,
      metadataFormatVersion: ITEM_METADATA_FORMAT_VERSION,
      keyEpoch: keys.keyEpoch,
      metadata: encrypted.metadata,
      encryptedValue: encrypted.encryptedValue,
      wrappedDek: encrypted.wrappedDek,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'item.rotate_secret',
        userId,
        { vaultId: item.vaultId, itemId: item.id },
        unsigned,
      ),
    };
  }

  async contentIntent(
    userId: string,
    item: ItemMeta,
    purpose: 'view' | 'copy' | 'fill',
    secretVersion?: number,
  ) {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const unsigned = { purpose, secretVersion, deviceId: device.deviceId };
    const normalized = secretVersion === undefined ? { purpose, deviceId: device.deviceId } : unsigned;
    return {
      ...normalized,
      intentSignature: await this.signCommand(
        'item.content.request',
        userId,
        { vaultId: item.vaultId, itemId: item.id },
        normalized,
      ),
    };
  }

  async encryptDelete(userId: string, item: ItemMeta) {
    const account = this.requireAccount();
    const device = this.requireDevice(account);
    const keys = this.requireVaultKeys(item.vaultId);
    const plaintext = encodeJson({ deleted: true });
    let metadata: CipherBlob;
    try {
      metadata = await encryptBytes(keys.metadataKey, plaintext, {
        blobType: 'item-metadata',
        vaultId: item.vaultId,
        itemId: item.id,
        recordVersion: item.version + 1,
        secretVersion: item.secretVersion,
        keyEpoch: keys.keyEpoch,
      });
    } finally {
      plaintext.fill(0);
    }
    const unsigned = {
      idempotencyKey: crypto.randomUUID(),
      expectedVersion: item.version,
      keyEpoch: keys.keyEpoch,
      metadata,
      actorDeviceId: device.deviceId,
    };
    return {
      ...unsigned,
      signature: await this.signCommand(
        'item.delete',
        userId,
        { vaultId: item.vaultId, itemId: item.id },
        unsigned,
      ),
    };
  }

  async encryptOfflineSnapshot(snapshot: EncryptedOfflineSnapshot): Promise<CipherBlob> {
    const account = this.requireAccount();
    const plaintext = encodeJson(snapshot as unknown as JsonValue);
    try {
      return await encryptBytes(
        account.accountKey,
        plaintext,
        cacheAad(account.accountId, this.requireDevice(account).deviceId),
      );
    } finally {
      plaintext.fill(0);
    }
  }

  async decryptOfflineSnapshot(blob: CipherBlob): Promise<EncryptedOfflineSnapshot> {
    const account = this.requireAccount();
    const plaintext = await decryptBytes(
      account.accountKey,
      blob,
      cacheAad(account.accountId, this.requireDevice(account).deviceId),
    );
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) as EncryptedOfflineSnapshot;
    } finally {
      plaintext.fill(0);
    }
  }

  async lock(): Promise<void> {
    const account = this.account;
    this.account = null;
    const pendingIdentityRotation = this.pendingIdentityRotation;
    this.pendingIdentityRotation = null;
    const pendingAccountCryptoReset = this.pendingAccountCryptoReset;
    this.pendingAccountCryptoReset = null;
    const vaults = [...this.vaultKeys.values()];
    this.vaultKeys.clear();
    this.vaultDirectories.clear();
    const pendingVaultRekeys = [...this.pendingVaultRekeys.values()];
    this.pendingVaultRekeys.clear();
    const pendingLegacyMigrations = [...this.pendingLegacyMigrations.values()];
    this.pendingLegacyMigrations.clear();
    this.generation += 1;
    await Promise.all(vaults.map((keys) => destroyVaultKeys(keys)));
    await Promise.all(pendingVaultRekeys.map((keys) => destroyVaultKeys(keys)));
    await Promise.all(pendingLegacyMigrations.map((pending) => destroyVaultKeys(pending.keys)));
    if (account) await destroyUnlockedAccount(account);
    if (pendingIdentityRotation) await destroyUnlockedAccount(pendingIdentityRotation);
    if (pendingAccountCryptoReset) await destroyUnlockedAccount(pendingAccountCryptoReset);
  }

  async dropVault(vaultId: string): Promise<void> {
    const keys = this.vaultKeys.get(vaultId);
    this.vaultKeys.delete(vaultId);
    this.vaultDirectories.delete(vaultId);
    if (keys) await destroyVaultKeys(keys);
  }

  private async signCommand(
    kind: string,
    userId: string,
    scope: { vaultId?: string; itemId?: string },
    request: object,
  ): Promise<string> {
    const device = this.requireDevice(this.requireAccount());
    return this.signCommandWith(device.signingKeyPair.privateKey, kind, userId, scope, request);
  }

  private async signCommandWith(
    privateKey: Uint8Array,
    kind: string,
    userId: string,
    scope: { vaultId?: string; itemId?: string },
    request: object,
  ): Promise<string> {
    const json: Record<string, JsonValue> = {
      itemId: scope.itemId ?? null,
      kind,
      protocol: E2EE_PROTOCOL,
      userId,
      request: request as unknown as JsonValue,
      vaultId: scope.vaultId ?? null,
    };
    const bytes = utf8(canonicalJson(json));
    try {
      return await signBytes(bytes, privateKey);
    } finally {
      bytes.fill(0);
    }
  }

  private requireAccount(): UnlockedAccount {
    if (!this.account) throw new Error('工作台已锁定');
    return this.account;
  }

  private requireDevice(account: UnlockedAccount) {
    if (!account.device) throw new Error('当前设备尚未获得授权');
    return account.device;
  }

  private requireVaultKeys(vaultId: string): VaultKeys {
    const keys = this.vaultKeys.get(vaultId);
    if (!keys) throw new Error('系统正在自动准备团队访问，请稍后重试');
    return keys;
  }

  private requireFullVaultKeys(vaultId: string): Required<VaultKeys> {
    const keys = this.requireVaultKeys(vaultId);
    if (!keys.contentKey) throw new Error('当前权限不能修改密码或敏感内容');
    return { ...keys, contentKey: keys.contentKey };
  }
}

export type E2eeKeyringPort = Pick<E2eeKeyring,
  | 'isUnlocked'
  | 'deviceId'
  | 'currentGeneration'
  | 'setup'
  | 'unlock'
  | 'enrollWebDevice'
  | 'prepareAccountCryptoReset'
  | 'unlockPendingAccountCryptoReset'
  | 'prepareAccountCryptoResetActivation'
  | 'commitAccountCryptoReset'
  | 'abortAccountCryptoReset'
  | 'prepareIdentityRotation'
  | 'commitIdentityRotation'
  | 'abortIdentityRotation'
  | 'migrationStartIntent'
  | 'migrationExportClaimIntent'
  | 'prepareLegacyMigration'
  | 'migrationVerificationIntent'
  | 'migrationActionIntent'
  | 'createLegacyKeyRetirementIntent'
  | 'approveLegacyKeyRetirementIntent'
  | 'completeLegacyKeyRetirementIntent'
  | 'commitLegacyMigration'
  | 'abortLegacyMigration'
  | 'signServerChallenge'
  | 'prepareMasterPasswordChange'
  | 'decryptBootstrap'
  | 'decryptMetadataRecord'
  | 'decryptContent'
  | 'initializeVault'
  | 'prepareVaultCreation'
  | 'encryptVaultRename'
  | 'encryptVaultDetails'
  | 'encryptVaultDirectories'
  | 'prepareEnterpriseRecoveryEnvelope'
  | 'completeRecovery'
  | 'approveExtensionEnrollment'
  | 'prepareExtensionTrustedUnlock'
  | 'prepareExtensionSessionResume'
  | 'revokeDevice'
  | 'prepareMembershipSet'
  | 'prepareMembershipRemoval'
  | 'prepareVaultDeletion'
  | 'prepareUninitializedVaultDeletion'
  | 'prepareEnvelopeTaskCompletion'
  | 'prepareOwnershipTransfer'
  | 'prepareOwnershipTransferAcceptance'
  | 'prepareOwnershipTransferCancellation'
  | 'rekeyMaterialIntent'
  | 'prepareVaultRekey'
  | 'commitVaultRekey'
  | 'abortVaultRekey'
  | 'encryptCreate'
  | 'encryptMetadataUpdate'
  | 'encryptRotation'
  | 'contentIntent'
  | 'encryptDelete'
  | 'encryptOfflineSnapshot'
  | 'decryptOfflineSnapshot'
  | 'lock'
  | 'dropVault'
> & {
  onFatal?(listener: (error: Error) => void): () => void;
};

function encryptedRecord(record: EncryptedItemMetadata) {
  return {
    vaultId: record.vaultId,
    itemId: record.itemId,
    version: record.version,
    secretVersion: record.secretVersion,
    keyEpoch: record.keyEpoch,
    metadata: record.blob,
    wrappedDek: record.blob,
    encryptedValue: record.blob,
  };
}

function recordToItem(record: EncryptedItemMetadata, payload: ItemMetadataPayload): DecryptedItemMeta {
  return {
    id: record.itemId,
    vaultId: record.vaultId,
    ...payload,
    version: record.version,
    secretVersion: record.secretVersion,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    updatedBy: record.updatedBy,
  };
}

function cacheAad(accountId: string, deviceId: string) {
  return {
    blobType: 'offline-cache' as const,
    accountId,
    deviceId,
    recordVersion: CACHE_RECORD_VERSION,
  };
}

function rekeyRequestReason(
  reason: RekeyMaterial['task']['reason'],
): RekeyVaultRequest['reason'] {
  if (reason === 'device_compromise') return 'device_compromised';
  if (reason === 'manual' || reason === 'ownership_transfer') return 'manual_rotation';
  return 'member_removed';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const LEGACY_EXPORT_FORMAT = 'mima-legacy-export-v1';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

interface LegacySealedPayload {
  format: typeof LEGACY_EXPORT_FORMAT;
  jobId: string;
  sourceDigest: string;
  recipient: { userId: string; keyVersion: number };
  vault: {
    vaultId: string;
    kind: 'personal' | 'team';
    name: string;
    ownerUserId: string | null;
    createdAt: string;
    updatedAt: string;
    items: LegacySealedItem[];
  };
  sourceAudit: { eventCount: number; headHash: string | null };
}

interface LegacySealedItem {
  metadata: {
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
  };
  metadataSourceDigest: string;
  secretVersions: LegacySealedSecret[];
}

interface LegacySealedSecret {
  id: string;
  itemId: string;
  vaultId: string;
  itemKind: 'login' | 'api_token' | 'secure_note';
  secretVersion: number;
  sourceDigest: string;
  value: string;
  createdAt: string;
  createdBy: string;
}

interface LegacyTargetDigestRecord {
  sourceKind: 'vault_header' | 'item_metadata' | 'item_secret';
  sourceId: string;
  sourceVersion: number;
  targetDigest: Uint8Array;
}

function parseLegacySealedPayload(bytes: Uint8Array): LegacySealedPayload {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('迁移导出不是有效的加密数据包');
  }
  if (!isRecord(value) || value.format !== LEGACY_EXPORT_FORMAT) {
    throw new Error('迁移导出格式不受支持');
  }
  if (!isUuid(value.jobId) || !isDigest(value.sourceDigest) || !isRecord(value.recipient)) {
    throw new Error('迁移导出的任务绑定不完整');
  }
  if (typeof value.recipient.userId !== 'string' || !isPositiveInteger(value.recipient.keyVersion)) {
    throw new Error('迁移导出的接收账号绑定无效');
  }
  if (!isRecord(value.vault) || !isRecord(value.sourceAudit) || !Array.isArray(value.vault.items)) {
    throw new Error('迁移导出的密码库结构不完整');
  }
  if (
    !isUuid(value.vault.vaultId) ||
    (value.vault.kind !== 'personal' && value.vault.kind !== 'team') ||
    typeof value.vault.name !== 'string' || value.vault.name.length === 0 || value.vault.name.length > 120 ||
    (value.vault.ownerUserId !== null && typeof value.vault.ownerUserId !== 'string') ||
    !isDateString(value.vault.createdAt) || !isDateString(value.vault.updatedAt) ||
    !isNonNegativeInteger(value.sourceAudit.eventCount) ||
    (value.sourceAudit.headHash !== null && typeof value.sourceAudit.headHash !== 'string') ||
    value.vault.items.length > 100_000
  ) {
    throw new Error('迁移导出的密码库信息无效');
  }

  let previousItemId = '';
  const seenItems = new Set<string>();
  for (const candidate of value.vault.items) {
    if (!isRecord(candidate) || !isRecord(candidate.metadata) || !Array.isArray(candidate.secretVersions)) {
      throw new Error('迁移导出的条目结构不完整');
    }
    const metadata = candidate.metadata;
    if (
      !isUuid(metadata.id) || metadata.vaultId !== value.vault.vaultId ||
      !isItemKind(metadata.kind) || typeof metadata.title !== 'string' || metadata.title.length === 0 || metadata.title.length > 200 ||
      !isNullableString(metadata.username, 200) || !isNullableString(metadata.origin, 300) ||
      !Array.isArray(metadata.tags) || metadata.tags.length > 20 || metadata.tags.some((tag) => typeof tag !== 'string' || tag.length === 0 || tag.length > 40) ||
      typeof metadata.favorite !== 'boolean' || !isSensitivity(metadata.sensitivity) ||
      !isPositiveInteger(metadata.version) || !isPositiveInteger(metadata.secretVersion) ||
      typeof metadata.deleted !== 'boolean' || !isDateString(metadata.createdAt) || !isDateString(metadata.updatedAt) ||
      typeof metadata.updatedBy !== 'string' || !isDigest(candidate.metadataSourceDigest) ||
      candidate.secretVersions.length > 100_000 || seenItems.has(metadata.id) ||
      (previousItemId !== '' && metadata.id < previousItemId)
    ) {
      throw new Error('迁移导出的条目信息无效');
    }
    seenItems.add(metadata.id);
    previousItemId = metadata.id;
    let previousSecretVersion = 0;
    const seenSecretIds = new Set<string>();
    for (const secret of candidate.secretVersions) {
      if (
        !isRecord(secret) || !isUuid(secret.id) || seenSecretIds.has(secret.id) ||
        secret.itemId !== metadata.id || secret.vaultId !== value.vault.vaultId ||
        secret.itemKind !== metadata.kind || !isPositiveInteger(secret.secretVersion) ||
        secret.secretVersion <= previousSecretVersion || !isDigest(secret.sourceDigest) ||
        typeof secret.value !== 'string' || secret.value.length > 1_000_000 ||
        !isDateString(secret.createdAt) || typeof secret.createdBy !== 'string'
      ) {
        throw new Error('迁移导出的历史版本信息无效');
      }
      seenSecretIds.add(secret.id);
      previousSecretVersion = secret.secretVersion;
    }
    if (
      candidate.secretVersions.length > 0 &&
      candidate.secretVersions[candidate.secretVersions.length - 1]!.secretVersion !== metadata.secretVersion
    ) {
      throw new Error('迁移导出的当前内容版本与历史记录不一致');
    }
  }
  return value as unknown as LegacySealedPayload;
}

function assertLegacyPayloadBinding(
  payload: LegacySealedPayload,
  expected: {
    userId: string;
    keyVersion: number;
    vaultId: string;
    jobId: string;
    sourceDigest: string;
    itemCount: number;
    metadataCount: number;
    secretCount: number;
  },
): void {
  const secretCount = payload.vault.items.reduce((count, item) => count + item.secretVersions.length, 0);
  const ownerBindingValid = payload.vault.kind === 'personal'
    ? payload.vault.ownerUserId === expected.userId
    : payload.vault.ownerUserId === null || payload.vault.ownerUserId === expected.userId;
  if (
    payload.jobId !== expected.jobId ||
    payload.sourceDigest !== expected.sourceDigest ||
    payload.recipient.userId !== expected.userId ||
    payload.recipient.keyVersion !== expected.keyVersion ||
    payload.vault.vaultId !== expected.vaultId ||
    !ownerBindingValid ||
    payload.vault.items.length !== expected.itemCount ||
    payload.vault.items.length !== expected.metadataCount ||
    secretCount !== expected.secretCount
  ) {
    throw new Error('迁移导出的任务、来源摘要、接收账号或记录数量不匹配');
  }
}

async function validateLegacyRecordDigests(payload: LegacySealedPayload): Promise<void> {
  const sodium = await sodiumReady();
  for (const item of payload.vault.items) {
    const declaredMetadataDigest = await fromBase64Url(item.metadataSourceDigest, 32);
    const metadataBytes = utf8(canonicalJson(item.metadata as unknown as JsonValue));
    const computedMetadataDigest = await hashBytes(metadataBytes);
    try {
      if (!sodium.memcmp(declaredMetadataDigest, computedMetadataDigest)) {
        throw new Error('迁移导出的条目元数据摘要不匹配');
      }
    } finally {
      sodium.memzero(declaredMetadataDigest);
      sodium.memzero(metadataBytes);
      sodium.memzero(computedMetadataDigest);
    }
    for (const secret of item.secretVersions) {
      const digest = await fromBase64Url(secret.sourceDigest, 32);
      sodium.memzero(digest);
    }
  }
}

async function encryptLegacySecret(
  keys: Required<VaultKeys>,
  secret: LegacySealedSecret,
): Promise<{ encryptedValue: CipherBlob; wrappedDek: CipherBlob }> {
  const sodium = await sodiumReady();
  const itemContentKey = sodium.randombytes_buf(32);
  const plaintext = encodeJson({
    value: secret.value,
    itemKind: secret.itemKind,
    itemId: secret.itemId,
    secretVersion: secret.secretVersion,
  });
  const kindBinding = `item-kind:${secret.itemKind}`;
  try {
    const [encryptedValue, wrappedDek] = await Promise.all([
      encryptBytes(itemContentKey, plaintext, {
        blobType: 'item-content',
        vaultId: secret.vaultId,
        itemId: secret.itemId,
        recipientId: kindBinding,
        recordVersion: secret.secretVersion,
        secretVersion: secret.secretVersion,
      }),
      encryptBytes(keys.contentKey, itemContentKey, {
        blobType: 'item-content-key-wrap',
        vaultId: secret.vaultId,
        itemId: secret.itemId,
        recipientId: kindBinding,
        recordVersion: secret.secretVersion,
        secretVersion: secret.secretVersion,
        keyEpoch: keys.keyEpoch,
      }),
    ]);
    const wrapContext = {
      blobType: 'item-content-key-wrap' as const,
      vaultId: secret.vaultId,
      itemId: secret.itemId,
      recipientId: kindBinding,
      recordVersion: secret.secretVersion,
      secretVersion: secret.secretVersion,
      keyEpoch: keys.keyEpoch,
    };
    const unwrappedItemContentKey = await decryptBytes(keys.contentKey, wrappedDek, wrapContext);
    try {
      if (!sodium.memcmp(unwrappedItemContentKey, itemContentKey)) {
        throw new Error('迁移生成的条目密钥包装回解校验失败');
      }
      await assertEncryptedBytesRoundTrip(
        unwrappedItemContentKey,
        encryptedValue,
        {
          blobType: 'item-content',
          vaultId: secret.vaultId,
          itemId: secret.itemId,
          recipientId: kindBinding,
          recordVersion: secret.secretVersion,
          secretVersion: secret.secretVersion,
        },
        plaintext,
      );
    } finally {
      sodium.memzero(unwrappedItemContentKey);
    }
    return { encryptedValue, wrappedDek };
  } finally {
    sodium.memzero(itemContentKey);
    sodium.memzero(plaintext);
  }
}

async function assertEncryptedBytesRoundTrip(
  key: Uint8Array,
  blob: CipherBlob,
  context: Parameters<typeof decryptBytes>[2],
  expectedPlaintext: Uint8Array,
): Promise<void> {
  const sodium = await sodiumReady();
  const decrypted = await decryptBytes(key, blob, context);
  try {
    if (!sodium.memcmp(decrypted, expectedPlaintext)) {
      throw new Error('迁移生成的目标密文回解校验失败');
    }
  } finally {
    sodium.memzero(decrypted);
  }
}

async function digestCipherBlob(blob: CipherBlob): Promise<Uint8Array> {
  const [nonce, ciphertext] = await Promise.all([
    fromBase64Url(blob.nonce, 24),
    fromBase64Url(blob.ciphertext),
  ]);
  try {
    if (ciphertext.byteLength < 17 || ciphertext.byteLength > 150_000) {
      throw new Error('迁移生成的密文长度无效');
    }
    return await hashBytes(nonce, ciphertext);
  } finally {
    nonce.fill(0);
    ciphertext.fill(0);
  }
}

async function hashBytes(...parts: Uint8Array[]): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  const length = parts.reduce((size, part) => size + part.byteLength, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  try {
    return sodium.crypto_hash_sha256(joined);
  } finally {
    sodium.memzero(joined);
  }
}

async function migrationTargetDigest(records: LegacyTargetDigestRecord[]): Promise<string> {
  try {
    const lines = await Promise.all(records.map(async (record) =>
      `${record.sourceKind}:${record.sourceId}:${record.sourceVersion}:${await toBase64Url(record.targetDigest)}`));
    lines.sort();
    const encoded = utf8(lines.join('\n'));
    try {
      const digest = await hashBytes(encoded);
      try {
        return await toBase64Url(digest);
      } finally {
        digest.fill(0);
      }
    } finally {
      encoded.fill(0);
    }
  } finally {
    for (const record of records) record.targetDigest.fill(0);
  }
}

function clearLegacyPayload(payload: LegacySealedPayload): void {
  payload.vault.name = '';
  for (const item of payload.vault.items) {
    item.metadata.title = '';
    item.metadata.username = null;
    item.metadata.origin = null;
    item.metadata.tags.fill('');
    item.metadata.tags.length = 0;
    for (const secret of item.secretVersions) secret.value = '';
    item.secretVersions.length = 0;
  }
  payload.vault.items.length = 0;
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

function sameCipherBlob(left: CipherBlob, right: CipherBlob): boolean {
  return left.suite === right.suite
    && left.aadVersion === right.aadVersion
    && left.nonce === right.nonce
    && left.ciphertext === right.ciphertext;
}

function isDigest(value: unknown): value is string {
  return typeof value === 'string' && value.length === 43 && BASE64URL_PATTERN.test(value);
}

function isDateString(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isNullableString(value: unknown, maxLength: number): value is string | null {
  return value === null || (typeof value === 'string' && value.length <= maxLength);
}

function isItemKind(value: unknown): value is ItemMetadataPayload['kind'] {
  return value === 'login' || value === 'api_token' || value === 'secure_note';
}

function isSensitivity(value: unknown): value is ItemMetadataPayload['sensitivity'] {
  return value === 'low' || value === 'medium' || value === 'high';
}

async function extensionDeviceFingerprint(input: {
  deviceId: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
}): Promise<string> {
  const crypto = await sodiumReady();
  const bytes = utf8(canonicalJson({
    deviceId: input.deviceId,
    encryptionPublicKey: input.encryptionPublicKey,
    kind: 'extension-device-fingerprint',
    protocol: E2EE_PROTOCOL,
    signingPublicKey: input.signingPublicKey,
  }));
  try {
    const digest = crypto.crypto_hash_sha256(bytes);
    try {
      const hex = [...digest.subarray(0, 16)]
        .map((value) => value.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
      return hex.match(/.{4}/g)!.join(' ');
    } finally {
      crypto.memzero(digest);
    }
  } finally {
    bytes.fill(0);
  }
}

function normalizeFingerprint(value: string): string {
  return value.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
}
