import type {
  CipherBlob,
  CompleteCryptoUnlockRequest,
  CreateEncryptedItemRequest,
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  EncryptedItemMetadata,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
  CompleteEnterpriseRecoveryRequest,
  EncryptedVaultHeader,
  InitializeVaultCryptoRequest,
  ItemMeta,
  RekeyMaterial,
  RekeyMaterialQuery,
  RotateEncryptedSecretRequest,
  UnlockChallenge,
  UpdateEncryptedItemRequest,
  UpdateEncryptedVaultHeaderRequest,
  UserCryptoProfile,
} from '@mima/contracts';
import {
  type E2eeKeyring,
  type CreateItemInput,
  type DecryptedBootstrapProjection,
  type DecryptedItemMeta,
  type ApproveExtensionEnrollmentRequest,
  type E2eeKeyringPort,
  type EncryptedOfflineSnapshot,
  type ItemMetadataPayload,
  type OfflineRecoveryResult,
  type SetupAccountResult,
  type EnrollWebDeviceResult,
  type PreparedIdentityRotationResult,
  type PreparedAccountCryptoResetResult,
  type PreparedAccountCryptoResetActivation,
  type SignerPublicKeys,
  type ExtensionEnrollment,
  type RekeyVaultCommitRequest,
  type LegacyMigrationActionRequest,
  type LegacyMigrationExportClaimRequest,
  type LegacyMigrationExportResponse,
  type LegacyMigrationJob,
  type LegacyMigrationMaterials,
  type LegacyMigrationStartRequest,
  type LegacyMigrationVerifyRequest,
  type PreparedLegacyMigration,
  type ResumeExtensionSessionRequest,
} from '@mima/client-core';
import type { AccountBundle, DeviceKeyBundle } from '@mima/e2ee';
import type { VaultDirectoryEntry } from '@mima/domain';
import type {
  ExtensionTrustedUnlockRequest,
  ExtensionTrustedUnlockResponse,
} from '@mima/e2ee';
import type { WebCryptoWorkerMethod, WebCryptoWorkerResponse } from './crypto-worker-protocol.ts';

export type CryptoWorkerFactory = () => Worker;

export class WorkerKeyring implements E2eeKeyringPort {
  private worker: Worker | null = null;
  private sequence = 0;
  private pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  private unlocked = false;
  private activeDeviceId: string | null = null;
  private generation = 0;
  private pendingResetDeviceId: string | null = null;
  private fatalListeners = new Set<(error: Error) => void>();

  constructor(private readonly workerFactory?: CryptoWorkerFactory) {}

  get isUnlocked(): boolean {
    return this.unlocked;
  }

  get deviceId(): string | null {
    return this.activeDeviceId;
  }

  get currentGeneration(): number {
    return this.generation;
  }

  onFatal(listener: (error: Error) => void): () => void {
    this.fatalListeners.add(listener);
    return () => this.fatalListeners.delete(listener);
  }

  async setup(mainPassword: string, input: Parameters<E2eeKeyring['setup']>[1]): Promise<SetupAccountResult> {
    const generation = this.generation;
    const result = await this.call<SetupAccountResult>('setup', [mainPassword, input]);
    this.assertActiveGeneration(generation);
    this.unlocked = true;
    this.activeDeviceId = result.deviceId;
    return result;
  }

  async unlock(
    mainPassword: string,
    profile: UserCryptoProfile,
    device: CryptoDevice,
    deviceBundle: DeviceKeyBundle,
  ): Promise<void> {
    const generation = this.generation;
    await this.call('unlock', [mainPassword, profile, device, deviceBundle]);
    this.assertActiveGeneration(generation);
    this.unlocked = true;
    this.activeDeviceId = device.id;
  }

  async enrollWebDevice(
    mainPassword: string,
    profile: UserCryptoProfile,
    deviceId: string,
  ): Promise<EnrollWebDeviceResult> {
    const generation = this.generation;
    const result = await this.call<EnrollWebDeviceResult>('enrollWebDevice', [mainPassword, profile, deviceId]);
    this.assertActiveGeneration(generation);
    this.unlocked = true;
    this.activeDeviceId = deviceId;
    return result;
  }

  async prepareAccountCryptoReset(
    mainPassword: string,
    profile: UserCryptoProfile,
    deviceId: string,
  ): Promise<PreparedAccountCryptoResetResult> {
    const generation = this.generation;
    const result = await this.forward<PreparedAccountCryptoResetResult>(
      'prepareAccountCryptoReset',
      [mainPassword, profile, deviceId],
    );
    this.assertActiveGeneration(generation);
    this.pendingResetDeviceId = deviceId;
    return result;
  }

  async unlockPendingAccountCryptoReset(
    mainPassword: string,
    accountBundle: AccountBundle,
    deviceBundle: DeviceKeyBundle,
  ): Promise<void> {
    const generation = this.generation;
    await this.forward('unlockPendingAccountCryptoReset', [mainPassword, accountBundle, deviceBundle]);
    this.assertActiveGeneration(generation);
    this.pendingResetDeviceId = deviceBundle.deviceId;
  }

  prepareAccountCryptoResetActivation(
    userId: string,
    reset: Parameters<E2eeKeyring['prepareAccountCryptoResetActivation']>[1],
    idempotencyKey?: string,
  ): Promise<PreparedAccountCryptoResetActivation> {
    return this.forward('prepareAccountCryptoResetActivation', [userId, reset, idempotencyKey]);
  }

  async commitAccountCryptoReset(): Promise<void> {
    const generation = this.generation;
    await this.forward('commitAccountCryptoReset', []);
    this.assertActiveGeneration(generation);
    this.unlocked = true;
    this.activeDeviceId = this.pendingResetDeviceId;
    this.generation += 1;
    this.pendingResetDeviceId = null;
  }

  async abortAccountCryptoReset(): Promise<void> {
    await this.forward('abortAccountCryptoReset', []);
    this.pendingResetDeviceId = null;
  }

  signServerChallenge(challenge: UnlockChallenge): Promise<CompleteCryptoUnlockRequest> {
    return this.forward('signServerChallenge', [challenge]);
  }

  prepareMasterPasswordChange(
    currentPassword: string,
    newPassword: string,
    profile: UserCryptoProfile,
  ): ReturnType<E2eeKeyring['prepareMasterPasswordChange']> {
    return this.forward('prepareMasterPasswordChange', [currentPassword, newPassword, profile]);
  }

  prepareIdentityRotation(
    mainPassword: string,
    profile: UserCryptoProfile,
    currentDevice: CryptoDevice,
  ): Promise<PreparedIdentityRotationResult> {
    return this.forward('prepareIdentityRotation', [mainPassword, profile, currentDevice]);
  }

  async commitIdentityRotation(): Promise<void> {
    await this.call('commitIdentityRotation', []);
    this.generation += 1;
  }

  async abortIdentityRotation(): Promise<void> {
    if (!this.worker) return;
    await this.call('abortIdentityRotation', []);
  }

  migrationStartIntent(userId: string, vaultId: string): Promise<LegacyMigrationStartRequest> {
    return this.forward('migrationStartIntent', [userId, vaultId]);
  }

  createLegacyKeyRetirementIntent(
    ...args: Parameters<E2eeKeyring['createLegacyKeyRetirementIntent']>
  ): ReturnType<E2eeKeyring['createLegacyKeyRetirementIntent']> {
    return this.forward('createLegacyKeyRetirementIntent', args);
  }

  approveLegacyKeyRetirementIntent(
    ...args: Parameters<E2eeKeyring['approveLegacyKeyRetirementIntent']>
  ): ReturnType<E2eeKeyring['approveLegacyKeyRetirementIntent']> {
    return this.forward('approveLegacyKeyRetirementIntent', args);
  }

  completeLegacyKeyRetirementIntent(
    ...args: Parameters<E2eeKeyring['completeLegacyKeyRetirementIntent']>
  ): ReturnType<E2eeKeyring['completeLegacyKeyRetirementIntent']> {
    return this.forward('completeLegacyKeyRetirementIntent', args);
  }

  migrationExportClaimIntent(userId: string, vaultId: string): Promise<LegacyMigrationExportClaimRequest> {
    return this.forward('migrationExportClaimIntent', [userId, vaultId]);
  }

  prepareLegacyMigration(
    userId: string,
    profile: UserCryptoProfile,
    job: LegacyMigrationJob,
    materials: LegacyMigrationMaterials,
    migrationExport: LegacyMigrationExportResponse,
  ): Promise<PreparedLegacyMigration> {
    return this.forward('prepareLegacyMigration', [userId, profile, job, materials, migrationExport]);
  }

  migrationVerificationIntent(
    userId: string,
    vaultId: string,
    jobId: string,
  ): Promise<LegacyMigrationVerifyRequest> {
    return this.forward('migrationVerificationIntent', [userId, vaultId, jobId]);
  }

  migrationActionIntent(
    userId: string,
    vaultId: string,
    jobId: string,
    action: 'cutover' | 'rollback',
  ): Promise<LegacyMigrationActionRequest> {
    return this.forward('migrationActionIntent', [userId, vaultId, jobId, action]);
  }

  async commitLegacyMigration(vaultId: string, jobId: string): Promise<void> {
    await this.forward('commitLegacyMigration', [vaultId, jobId]);
    this.generation += 1;
  }

  abortLegacyMigration(vaultId: string, jobId?: string): Promise<void> {
    return this.forward('abortLegacyMigration', [vaultId, jobId]);
  }

  decryptBootstrap(bootstrap: EncryptedBootstrapResponse, signers?: SignerPublicKeys): Promise<DecryptedBootstrapProjection> {
    return this.forward('decryptBootstrap', [bootstrap, signers]);
  }

  decryptMetadataRecord(record: EncryptedItemMetadata): Promise<DecryptedItemMeta> {
    return this.forward('decryptMetadataRecord', [record]);
  }

  decryptContent(response: EncryptedContentResponse): Promise<string> {
    return this.forward('decryptContent', [response]);
  }

  initializeVault(
    userId: string,
    vaultId: string,
    name: string,
    profile: UserCryptoProfile,
    recoveryKey: EnterpriseRecoveryKey | null,
    expectedStatus?: 'legacy' | 'preparing',
    devices?: CryptoDevice[],
    materials?: LegacyMigrationMaterials,
    vaultGroupName?: string | null,
  ): Promise<InitializeVaultCryptoRequest> {
    return this.forward('initializeVault', [
      userId,
      vaultId,
      name,
      profile,
      recoveryKey,
      expectedStatus,
      devices,
      materials,
      vaultGroupName,
    ]);
  }

  prepareVaultCreation(
    ...args: Parameters<E2eeKeyring['prepareVaultCreation']>
  ): ReturnType<E2eeKeyring['prepareVaultCreation']> {
    return this.forward('prepareVaultCreation', args);
  }

  encryptVaultRename(
    userId: string,
    vaultId: string,
    name: string,
    currentHeader: EncryptedVaultHeader,
  ): Promise<UpdateEncryptedVaultHeaderRequest> {
    return this.forward('encryptVaultRename', [userId, vaultId, name, currentHeader]);
  }

  encryptVaultDetails(
    ...args: Parameters<E2eeKeyring['encryptVaultDetails']>
  ): ReturnType<E2eeKeyring['encryptVaultDetails']> {
    return this.forward('encryptVaultDetails', args);
  }

  encryptVaultDirectories(
    userId: string,
    vaultId: string,
    directories: VaultDirectoryEntry[],
    currentHeader: EncryptedVaultHeader,
  ): Promise<UpdateEncryptedVaultHeaderRequest> {
    return this.forward('encryptVaultDirectories', [userId, vaultId, directories, currentHeader]);
  }

  prepareEnterpriseRecoveryEnvelope(
    ...args: Parameters<E2eeKeyring['prepareEnterpriseRecoveryEnvelope']>
  ): ReturnType<E2eeKeyring['prepareEnterpriseRecoveryEnvelope']> {
    return this.forward('prepareEnterpriseRecoveryEnvelope', args);
  }

  completeRecovery(
    userId: string,
    request: EnterpriseRecoveryRequest,
    recoveryKey: EnterpriseRecoveryKey,
    header: EncryptedVaultHeader,
    offlineResult: OfflineRecoveryResult,
  ): Promise<CompleteEnterpriseRecoveryRequest> {
    return this.forward('completeRecovery', [userId, request, recoveryKey, header, offlineResult]);
  }

  approveExtensionEnrollment(
    userId: string,
    profile: UserCryptoProfile,
    enrollment: ExtensionEnrollment,
  ): Promise<ApproveExtensionEnrollmentRequest> {
    return this.forward('approveExtensionEnrollment', [userId, profile, enrollment]);
  }

  prepareExtensionTrustedUnlock(
    profile: UserCryptoProfile,
    request: ExtensionTrustedUnlockRequest,
  ): Promise<ExtensionTrustedUnlockResponse> {
    return this.forward('prepareExtensionTrustedUnlock', [profile, request]);
  }

  prepareExtensionSessionResume(
    userId: string,
    request: ExtensionTrustedUnlockRequest,
  ): Promise<ResumeExtensionSessionRequest> {
    return this.forward('prepareExtensionSessionResume', [userId, request]);
  }

  revokeDevice(
    userId: string,
    targetDeviceId: string,
    expectedKeyVersion: number,
  ): ReturnType<E2eeKeyring['revokeDevice']> {
    return this.forward('revokeDevice', [userId, targetDeviceId, expectedKeyVersion]);
  }

  prepareMembershipSet(
    ...args: Parameters<E2eeKeyring['prepareMembershipSet']>
  ): ReturnType<E2eeKeyring['prepareMembershipSet']> {
    return this.forward('prepareMembershipSet', args);
  }

  prepareMembershipRemoval(
    ...args: Parameters<E2eeKeyring['prepareMembershipRemoval']>
  ): ReturnType<E2eeKeyring['prepareMembershipRemoval']> {
    return this.forward('prepareMembershipRemoval', args);
  }

  prepareVaultDeletion(
    ...args: Parameters<E2eeKeyring['prepareVaultDeletion']>
  ): ReturnType<E2eeKeyring['prepareVaultDeletion']> {
    return this.forward('prepareVaultDeletion', args);
  }

  prepareUninitializedVaultDeletion(
    ...args: Parameters<E2eeKeyring['prepareUninitializedVaultDeletion']>
  ): ReturnType<E2eeKeyring['prepareUninitializedVaultDeletion']> {
    return this.forward('prepareUninitializedVaultDeletion', args);
  }

  prepareEnvelopeTaskCompletion(
    ...args: Parameters<E2eeKeyring['prepareEnvelopeTaskCompletion']>
  ): ReturnType<E2eeKeyring['prepareEnvelopeTaskCompletion']> {
    return this.forward('prepareEnvelopeTaskCompletion', args);
  }

  prepareOwnershipTransfer(
    ...args: Parameters<E2eeKeyring['prepareOwnershipTransfer']>
  ): ReturnType<E2eeKeyring['prepareOwnershipTransfer']> {
    return this.forward('prepareOwnershipTransfer', args);
  }

  prepareOwnershipTransferAcceptance(
    ...args: Parameters<E2eeKeyring['prepareOwnershipTransferAcceptance']>
  ): ReturnType<E2eeKeyring['prepareOwnershipTransferAcceptance']> {
    return this.forward('prepareOwnershipTransferAcceptance', args);
  }

  prepareOwnershipTransferCancellation(
    ...args: Parameters<E2eeKeyring['prepareOwnershipTransferCancellation']>
  ): ReturnType<E2eeKeyring['prepareOwnershipTransferCancellation']> {
    return this.forward('prepareOwnershipTransferCancellation', args);
  }

  rekeyMaterialIntent(userId: string, vaultId: string, taskId: string): Promise<RekeyMaterialQuery> {
    return this.forward('rekeyMaterialIntent', [userId, vaultId, taskId]);
  }

  prepareVaultRekey(
    userId: string,
    vaultId: string,
    profile: UserCryptoProfile,
    material: RekeyMaterial,
  ): Promise<RekeyVaultCommitRequest> {
    return this.forward('prepareVaultRekey', [userId, vaultId, profile, material]);
  }

  async commitVaultRekey(vaultId: string): Promise<void> {
    await this.forward('commitVaultRekey', [vaultId]);
    this.generation += 1;
  }

  abortVaultRekey(vaultId: string): Promise<void> {
    return this.forward('abortVaultRekey', [vaultId]);
  }

  encryptCreate(
    userId: string,
    vaultId: string,
    input: CreateItemInput,
  ): Promise<CreateEncryptedItemRequest> {
    return this.forward('encryptCreate', [userId, vaultId, input]);
  }

  encryptMetadataUpdate(
    userId: string,
    item: DecryptedItemMeta,
    payload: ItemMetadataPayload,
  ): Promise<UpdateEncryptedItemRequest> {
    return this.forward('encryptMetadataUpdate', [userId, item, payload]);
  }

  encryptRotation(userId: string, item: DecryptedItemMeta, secretValue: string): Promise<RotateEncryptedSecretRequest> {
    return this.forward('encryptRotation', [userId, item, secretValue]);
  }

  contentIntent(
    userId: string,
    item: ItemMeta,
    purpose: 'view' | 'copy' | 'fill',
    secretVersion?: number,
  ) {
    return this.forward<Awaited<ReturnType<E2eeKeyring['contentIntent']>>>(
      'contentIntent',
      [userId, item, purpose, secretVersion],
    );
  }

  encryptDelete(userId: string, item: ItemMeta): ReturnType<E2eeKeyring['encryptDelete']> {
    return this.forward('encryptDelete', [userId, item]);
  }

  encryptOfflineSnapshot(snapshot: EncryptedOfflineSnapshot): Promise<CipherBlob> {
    return this.forward('encryptOfflineSnapshot', [snapshot]);
  }

  decryptOfflineSnapshot(blob: CipherBlob): Promise<EncryptedOfflineSnapshot> {
    return this.forward('decryptOfflineSnapshot', [blob]);
  }

  async lock(): Promise<void> {
    const worker = this.worker;
    this.worker = null;
    this.unlocked = false;
    this.activeDeviceId = null;
    this.pendingResetDeviceId = null;
    this.generation += 1;
    if (!worker) return;
    worker.terminate();
    const error = new Error('工作台已锁定');
    this.pending.forEach(({ reject }) => reject(error));
    this.pending.clear();
  }

  dropVault(vaultId: string): Promise<void> {
    return this.forward('dropVault', [vaultId]);
  }

  private forward<T>(method: WebCryptoWorkerMethod, args: unknown[]): Promise<T> {
    return this.call(method, args);
  }

  private call<T = void>(method: WebCryptoWorkerMethod, args: unknown[]): Promise<T> {
    const worker = this.ensureWorker();
    const id = ++this.sequence;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
      });
      try {
        worker.postMessage({ id, method, args });
      } catch (error) {
        this.onWorkerFailure(worker, asError(error, '浏览器安全模块暂时不可用，请重新加载页面'));
      }
    });
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    if (!this.workerFactory && typeof Worker === 'undefined') {
      throw new Error('当前浏览器不支持密码库所需的安全功能，请升级浏览器后重试');
    }
    const worker = this.workerFactory
      ? this.workerFactory()
      : new Worker(new URL('./crypto.worker.ts', import.meta.url), { type: 'module', name: 'mima-crypto' });
    worker.onmessage = (event: MessageEvent<WebCryptoWorkerResponse>) => {
      const pending = this.pending.get(event.data.id);
      if (!pending) return;
      this.pending.delete(event.data.id);
      if (event.data.ok) pending.resolve(event.data.result);
      else {
        const error = new Error(event.data.error.message) as Error & { code?: string };
        error.code = event.data.error.code;
        pending.reject(error);
      }
    };
    worker.onerror = () => this.onWorkerFailure(worker, new Error('浏览器安全模块运行失败，请重新加载页面'));
    worker.onmessageerror = () => this.onWorkerFailure(worker, new Error('浏览器安全模块返回异常，请重新加载页面'));
    this.worker = worker;
    return worker;
  }

  private onWorkerFailure(worker: Worker, error: Error): void {
    if (this.worker !== worker) return;
    this.worker = null;
    this.unlocked = false;
    this.activeDeviceId = null;
    this.pendingResetDeviceId = null;
    this.generation += 1;
    worker.terminate();
    this.pending.forEach(({ reject }) => reject(error));
    this.pending.clear();
    for (const listener of this.fatalListeners) {
      try {
        listener(error);
      } catch (listenerError) {
        void listenerError;
      }
    }
  }

  private assertActiveGeneration(generation: number): void {
    if (generation !== this.generation || !this.worker) throw new Error('工作台已锁定');
  }
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}
