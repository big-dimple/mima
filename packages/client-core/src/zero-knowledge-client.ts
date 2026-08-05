import type {
  AccountCryptoResetRequest,
  AtomicCreateEncryptedVaultRequest,
  CryptoDevice,
  CreateEncryptedProjectRequest,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  EncryptedItemMetadata,
  EncryptedSyncEvent,
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryCase,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
  ExtensionSessionResponse,
  ItemMeta,
  MembershipRole,
  RemoveEncryptedMembershipResponse,
  RewrapCryptoProfileRequest,
  SetEncryptedMembershipResponse,
  SubjectKind,
  SessionInfo,
  UserCryptoProfile,
  VaultCryptoState,
  VaultEnvelopeTask,
  VaultOwnershipTransfer,
  LegacyKeyRetirementResponse,
  LegacyKeyRetirementReason,
} from '@mima/contracts';
import {
  assertExtensionTrustedUnlockRequest,
  type DeviceKeyBundle,
  type ExtensionTrustedUnlockRequest,
  type ExtensionTrustedUnlockResponse,
} from '@mima/e2ee';
import { normalizeVaultGroupName, type VaultDirectoryEntry } from '@mima/domain';
import { ApiRequestError } from './api-client.ts';
import type { ZeroKnowledgeApi } from './zero-knowledge-api-client.ts';
import {
  parseOfflineRecoveryResult,
  type E2eeKeyringPort,
  type EncryptedOfflineSnapshot,
  type OfflineRecoveryResult,
} from './e2ee-keyring.ts';
import type { ExtensionEnrollment } from './e2ee-keyring.ts';
import type { EncryptedSyncClient } from './encrypted-sync.ts';
import type {
  CreateItemInput,
  DecryptedItemMeta,
  ItemMetadataPayload,
  SecurityPhase,
} from './e2ee-model.ts';
import type { EncryptedCommandOutbox } from './encrypted-outbox.ts';
import type { EncryptedStorageBackend, PersistedEncryptedCommand } from './encrypted-storage.ts';
import type { MetaStore } from './meta-store.ts';
import type { SecretLeaseStore } from './secret-lease.ts';
import type {
  LegacyMigrationJob,
  LegacyMigrationStatusResponse,
} from './legacy-migration.ts';

export interface ZeroKnowledgeClientOptions {
  api: ZeroKnowledgeApi;
  store: MetaStore;
  leases: SecretLeaseStore;
  keyring: E2eeKeyringPort;
  storage: EncryptedStorageBackend;
  outbox: EncryptedCommandOutbox;
  onKeyringFatal?: (error: Error) => void;
  onDeviceRevoked?: (deviceId: string) => void;
}

function isDefinitiveVaultCreationFailure(error: unknown): boolean {
  if (!(error instanceof ApiRequestError)) return false;
  return error.status >= 400 && error.status < 500 && ![408, 425, 429].includes(error.status);
}

function isRetryableUnlockTransportFailure(error: unknown): boolean {
  return error instanceof ApiRequestError && [0, 502, 503, 504].includes(error.status);
}

function isRetryableVaultInitializationFailure(error: unknown): boolean {
  return error instanceof ApiRequestError && [0, 408, 425, 429, 502, 503, 504].includes(error.status);
}

function isConvergentVaultInitializationFailure(error: unknown): boolean {
  return error instanceof ApiRequestError && [404, 409].includes(error.status);
}

const DEFAULT_PERSONAL_VAULT_NAME = '我的密码库';

export interface IdentityRotationOutcome {
  revokedDeviceCount: number;
  rekeyTaskCount: number;
  localCachePersisted: boolean;
}

export interface MainPasswordChangeOutcome {
  localCachePersisted: boolean;
}

export interface ExtensionTrustedUnlockResult {
  response: ExtensionTrustedUnlockResponse;
  session?: ExtensionSessionResponse;
}

export class ZeroKnowledgeClient {
  private api: ZeroKnowledgeApi;
  private store: MetaStore;
  private leases: SecretLeaseStore;
  private keyring: E2eeKeyringPort;
  private storage: EncryptedStorageBackend;
  private outbox: EncryptedCommandOutbox;
  private bootstrap: EncryptedBootstrapResponse | null = null;
  private profile: UserCryptoProfile | null = null;
  private device: CryptoDevice | null = null;
  private deviceBundle: DeviceKeyBundle | null = null;
  private contents: Record<string, EncryptedContentResponse> = {};
  private rekeyTasks = new Map<string, string>();
  private preparedLegacyMigrations = new Map<string, string>();
  private online = true;
  private sync: EncryptedSyncClient | null = null;
  private refreshInFlight: Promise<void> | null = null;
  private automaticEnvelopeGeneration = 0;
  private automaticEnvelopeRequests = new Set<string>();
  private automaticEnvelopeWorkers = new Map<string, Promise<void>>();
  private automaticRecoveryCoverageRequested = false;
  private automaticRecoveryCoverageWorker: Promise<void> | null = null;
  private automaticRecoveryCaseRequested = false;
  private automaticRecoveryCaseWorker: Promise<void> | null = null;
  private readonly onDeviceRevoked?: (deviceId: string) => void;

  constructor(options: ZeroKnowledgeClientOptions) {
    this.api = options.api;
    this.store = options.store;
    this.leases = options.leases;
    this.keyring = options.keyring;
    this.storage = options.storage;
    this.outbox = options.outbox;
    this.onDeviceRevoked = options.onDeviceRevoked;
    this.keyring.onFatal?.((error) => {
      this.handleKeyringFatal();
      options.onKeyringFatal?.(error);
    });
    this.outbox.onError(() => {
      this.contents = {};
      this.leases.revokeAll();
    });
    let previousSize = this.outbox.size;
    this.outbox.subscribe(() => {
      const size = this.outbox.size;
      if (previousSize > 0 && size === 0 && this.online && this.keyring.isUnlocked) {
        void this.refresh();
      }
      previousSize = size;
    });
  }

  get phase(): SecurityPhase {
    return this.store.getState().securityPhase;
  }

  get isUnlocked(): boolean {
    return this.keyring.isUnlocked;
  }

  get currentDeviceId(): string | null {
    return this.keyring.deviceId;
  }

  rekeyTaskId(vaultId: string): string | null {
    return this.rekeyTasks.get(vaultId) ?? null;
  }

  hasPreparedLegacyMigration(vaultId: string, jobId?: string): boolean {
    const preparedJobId = this.preparedLegacyMigrations.get(vaultId);
    return preparedJobId !== undefined && (jobId === undefined || preparedJobId === jobId);
  }

  attachSync(sync: EncryptedSyncClient): void {
    this.sync = sync;
  }

  private handleKeyringFatal(): void {
    this.invalidateAutomaticEnvelopeDelivery();
    this.sync?.stop();
    this.outbox.setOnline(false);
    this.leases.revokeAll();
    this.preparedLegacyMigrations.clear();
    this.rekeyTasks.clear();
    this.bootstrap = null;
    this.contents = {};
    this.store.getState().lockProjection();
  }

  async prepare(session: SessionInfo): Promise<SecurityPhase> {
    this.invalidateAutomaticEnvelopeDelivery();
    this.api.setCsrfToken(session.csrfToken);
    this.store.getState().setUser(session.user);
    this.online = true;
    this.store.getState().setConnection('connecting');
    try {
      const bootstrap = session.locked ? null : await this.api.encryptedBootstrap();
      const [lockedProfile, lockedDevices] = session.locked
        ? await Promise.all([this.api.cryptoProfile(), this.api.cryptoDevices()])
        : [null, []];
      this.bootstrap = bootstrap;
      this.profile = bootstrap?.profile ?? lockedProfile;
      if (!this.profile) {
        return this.setPhase('setup-required');
      }
      const activeReset = (await this.api.accountCryptoResetRequests())
        .find((request) => request.targetUserId === session.user.id
          && (request.status === 'pending' || request.status === 'approved'));
      this.device = await this.selectDevice(this.profile, bootstrap?.devices ?? lockedDevices);
      const cached = await this.storage.getAccount(session.user.id);
      this.deviceBundle = cached?.deviceBundle ?? null;
      await this.outbox.restore(session.user.id);
      this.outbox.setOnline(false);
      if (activeReset) return this.setPhase('account-reset');
      return this.setPhase('authenticated-locked');
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) throw error;
      const cached = await this.storage.getAccount(session.user.id);
      if (!cached) throw error;
      this.online = false;
      this.profile = cached.profile;
      this.device = cached.device;
      this.deviceBundle = cached.deviceBundle;
      this.store.getState().setConnection('offline');
      await this.outbox.restore(session.user.id);
      this.outbox.setOnline(false);
      return this.setPhase('authenticated-locked');
    }
  }

  async prepareOffline(): Promise<boolean> {
    const cached = await this.storage.getLatestAccount();
    if (!cached?.encryptedBootstrap) return false;
    this.online = false;
    this.profile = cached.profile;
    this.device = cached.device;
    this.deviceBundle = cached.deviceBundle;
    this.store.getState().setConnection('offline');
    await this.outbox.restore(cached.accountId);
    this.outbox.setOnline(false);
    this.setPhase('authenticated-locked');
    return true;
  }

  async setup(mainPassword: string, confirmation: string): Promise<void> {
    const user = this.store.getState().user;
    if (!user) throw new Error('登录状态已经失效');
    if (mainPassword !== confirmation) throw new Error('两次输入的主密码不一致');
    validateMainPassword(mainPassword);
    this.setPhase('unlocking');
    try {
      const deviceId = crypto.randomUUID();
      const setup = await this.keyring.setup(mainPassword, {
        accountId: user.id,
        deviceId,
        deviceName: browserDeviceName(),
        platform: browserPlatform(),
      });
      this.deviceBundle = setup.deviceBundle;
      this.profile = await this.api.createCryptoProfile(setup.request);
      const devices = await this.api.cryptoDevices();
      this.device = devices.find((device) => device.id === deviceId) ?? null;
      if (!this.device) throw new Error('设备资料创建失败');
      await this.storage.putAccount({
        accountId: user.id,
        profile: this.profile,
        device: this.device,
        deviceBundle: setup.deviceBundle,
        encryptedBootstrap: null,
        cachedAt: new Date().toISOString(),
      });
      await this.finishServerUnlock();
      this.bootstrap = await this.loadUnlockedBootstrap();
      await this.applyUnlockedBootstrap(this.bootstrap);
    } catch (error) {
      await this.keyring.lock();
      this.setPhase(this.profile ? 'authenticated-locked' : 'setup-required');
      throw error;
    }
  }

  accountCryptoResetRequests(): Promise<AccountCryptoResetRequest[]> {
    return this.api.accountCryptoResetRequests();
  }

  async startAccountCryptoReset(mainPassword: string, confirmation: string): Promise<AccountCryptoResetRequest> {
    const created = await this.prepareAccountCryptoResetCandidate(mainPassword, confirmation, null);
    this.outbox.setOnline(false);
    this.setPhase('account-reset');
    return created;
  }

  async startForgotPasswordRecoveryCase(
    caseId: string,
    mainPassword: string,
    confirmation: string,
  ): Promise<EnterpriseRecoveryCase> {
    const created = await this.prepareAccountCryptoResetCandidate(mainPassword, confirmation, caseId);
    const user = this.requireUser();
    try {
      const pending = await this.storage.getPendingAccountCryptoReset(user.id);
      if (!pending || pending.request.id !== created.id || !pending.activationRequest) {
        throw new Error('新主密码的自动启用信息没有保存成功');
      }
      const recoveryCase = await this.api.finalizeRecoveryCase(caseId, {
        idempotencyKey: crypto.randomUUID(),
        kind: 'forgot_password',
        accountResetRequestId: created.id,
        activation: pending.activationRequest,
      });
      await this.storage.putPendingAccountCryptoReset({
        ...pending,
        request: { ...pending.request, caseId },
        recoveryCaseId: caseId,
      });
      this.outbox.setOnline(false);
      this.setPhase('account-reset');
      return recoveryCase;
    } catch (error) {
      await this.api.cancelAccountCryptoReset(created.id, {
        idempotencyKey: crypto.randomUUID(),
        requestDigest: created.requestDigest,
      }).catch(() => undefined);
      await this.keyring.abortAccountCryptoReset();
      await this.storage.deletePendingAccountCryptoReset(user.id);
      throw error;
    }
  }

  private async prepareAccountCryptoResetCandidate(
    mainPassword: string,
    confirmation: string,
    recoveryCaseId: string | null,
  ): Promise<AccountCryptoResetRequest> {
    if (!this.online) throw new Error('提交解锁重置申请需要联网，请检查网络后重试');
    const user = this.requireUser();
    const profile = this.profile;
    if (!profile) throw new Error('当前账号没有可重置的解锁信息');
    if (mainPassword !== confirmation) throw new Error('两次输入的新主密码不一致');
    validateMainPassword(mainPassword);
    const prepared = await this.keyring.prepareAccountCryptoReset(
      mainPassword,
      profile,
      crypto.randomUUID(),
    );
    let created: AccountCryptoResetRequest;
    try {
      created = await this.api.createAccountCryptoReset(prepared.request);
      const activation = await this.keyring.prepareAccountCryptoResetActivation(user.id, created);
      await this.storage.putPendingAccountCryptoReset({
        accountId: user.id,
        request: created,
        recoveryCaseId,
        activationRequest: activation.request,
        accountBundle: prepared.accountBundle,
        deviceBundle: prepared.deviceBundle,
        cachedAt: new Date().toISOString(),
      });
    } catch (error) {
      await this.keyring.abortAccountCryptoReset();
      throw error;
    }
    return created;
  }

  async approveAccountCryptoReset(request: AccountCryptoResetRequest): Promise<AccountCryptoResetRequest> {
    if (!this.online) throw new Error('审批解锁重置申请需要联网，请检查网络后重试');
    return this.api.approveAccountCryptoReset(request.id, {
      idempotencyKey: crypto.randomUUID(),
      requestDigest: request.requestDigest,
    });
  }

  async cancelAccountCryptoReset(request: AccountCryptoResetRequest): Promise<void> {
    if (!this.online) throw new Error('取消解锁重置申请需要联网，请检查网络后重试');
    const user = this.requireUser();
    await this.api.cancelAccountCryptoReset(request.id, {
      idempotencyKey: crypto.randomUUID(),
      requestDigest: request.requestDigest,
    });
    await this.keyring.abortAccountCryptoReset();
    await this.storage.deletePendingAccountCryptoReset(user.id);
    this.setPhase('authenticated-locked');
  }

  async activateAccountCryptoReset(
    request: AccountCryptoResetRequest,
    mainPassword: string,
  ): Promise<void> {
    if (!this.online) throw new Error('完成解锁重置需要联网，请检查网络后重试');
    if (request.status !== 'approved') throw new Error('解锁重置申请尚未通过两名管理员审批');
    const user = this.requireUser();
    const pending = await this.storage.getPendingAccountCryptoReset(user.id);
    if (!pending || pending.request.id !== request.id || pending.request.requestDigest !== request.requestDigest) {
      throw new Error('这次主密码重置的准备信息已失效，请重新设置新主密码');
    }
    await this.keyring.unlockPendingAccountCryptoReset(
      mainPassword,
      pending.accountBundle,
      pending.deviceBundle,
    );
    if (!pending.activationRequest) {
      const activation = await this.keyring.prepareAccountCryptoResetActivation(user.id, request);
      await this.storage.putPendingAccountCryptoReset({
        ...pending,
        activationRequest: activation.request,
      });
    }
    await this.activatePreparedAccountCryptoReset(request);
  }

  async activatePreparedAccountCryptoReset(request: AccountCryptoResetRequest): Promise<void> {
    if (!this.online) throw new Error('完成主密码重置需要联网，请检查网络后重试');
    if (request.status !== 'approved') throw new Error('正在等待两位管理员确认');
    const user = this.requireUser();
    const pending = await this.storage.getPendingAccountCryptoReset(user.id);
    if (!pending || pending.request.id !== request.id || pending.request.requestDigest !== request.requestDigest) {
      throw new Error('恢复准备信息已失效，请重新设置新主密码');
    }
    if (!pending.activationRequest) {
      throw new Error('这次恢复来自旧版本，请刷新后重新设置新主密码');
    }
    let response;
    try {
      response = await this.api.activateAccountCryptoReset(request.id, pending.activationRequest);
    } catch (error) {
      throw friendlyUnlockError(error);
    }
    let remainsUnlocked = true;
    try {
      await this.keyring.commitAccountCryptoReset();
    } catch {
      remainsUnlocked = false;
      await this.keyring.lock();
    }
    this.profile = response.profile;
    this.device = response.device;
    this.deviceBundle = pending.deviceBundle;
    this.bootstrap = null;
    this.contents = {};
    this.rekeyTasks = new Map(response.rekeyTasks.map((task) => [task.vaultId, task.taskId]));
    await this.outbox.clear(false);
    await this.storage.activatePendingAccountCryptoReset({
      accountId: user.id,
      profile: response.profile,
      device: response.device,
      deviceBundle: pending.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    });
    if (remainsUnlocked) {
      this.bootstrap = await this.api.encryptedBootstrap();
      await this.applyUnlockedBootstrap(this.bootstrap);
    } else {
      this.setPhase('authenticated-locked');
    }
  }

  async unlock(mainPassword: string): Promise<void> {
    if (!this.profile && this.online) {
      await this.refreshLockedCryptoContext();
    }
    if (!this.profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    this.setPhase('unlocking');
    try {
      if (this.device && this.deviceBundle) {
        try {
          await this.keyring.unlock(mainPassword, this.profile, this.device, this.deviceBundle);
        } catch (error) {
          throw friendlyUnlockError(error);
        }
      } else {
        if (!this.online) throw new Error('这是此浏览器首次使用，请联网完成设备授权');
        let enrolled;
        try {
          enrolled = await this.keyring.enrollWebDevice(mainPassword, this.profile, crypto.randomUUID());
        } catch (error) {
          throw friendlyUnlockError(error);
        }
        this.device = await this.api.registerCryptoDevice(enrolled.request);
        this.deviceBundle = enrolled.deviceBundle;
        await this.storage.putAccount({
          accountId: this.profile.userId,
          profile: this.profile,
          device: this.device,
          deviceBundle: enrolled.deviceBundle,
          encryptedBootstrap: null,
          cachedAt: new Date().toISOString(),
        });
      }
      if (this.online) {
        await this.finishServerUnlock();
        this.bootstrap = await this.loadUnlockedBootstrap();
        this.contents = {};
      } else {
        const cached = await this.storage.getAccount(this.profile.userId);
        if (!cached?.encryptedBootstrap) throw new Error('此浏览器没有可用的离线数据，请联网后解锁');
        const snapshot = await this.keyring.decryptOfflineSnapshot(cached.encryptedBootstrap);
        this.bootstrap = snapshot.bootstrap;
        this.contents = snapshot.contents;
      }
      await this.applyUnlockedBootstrap(this.requireBootstrap());
    } catch (error) {
      await this.keyring.lock();
      this.leases.revokeAll();
      this.store.getState().lockProjection();
      this.setPhase('authenticated-locked');
      throw error instanceof Error ? error : new Error('解锁失败');
    }
  }

  async refresh(scheduleAutomaticEnvelopeDelivery = true): Promise<void> {
    if (!this.online || !this.keyring.isUnlocked) return;
    if (this.refreshInFlight) {
      await this.refreshInFlight;
      if (scheduleAutomaticEnvelopeDelivery) {
        this.scheduleAutomaticEnvelopeDelivery();
        this.scheduleAutomaticRecoveryCoverage();
        this.scheduleAutomaticRecoveryCaseCompletion();
      }
      return;
    }
    const refresh = (async () => {
      const bootstrap = await this.loadUnlockedBootstrap();
      this.adoptCompatibleProfile(bootstrap.profile);
      const normalizedBootstrap = this.profile
        && bootstrap.profile?.userId === this.profile.userId
        && this.profile.profileVersion >= bootstrap.profile.profileVersion
        ? { ...bootstrap, profile: this.profile }
        : bootstrap;
      this.bootstrap = normalizedBootstrap;
      await this.applyUnlockedBootstrap(normalizedBootstrap, scheduleAutomaticEnvelopeDelivery);
    })();
    this.refreshInFlight = refresh;
    try {
      await refresh;
    } finally {
      if (this.refreshInFlight === refresh) this.refreshInFlight = null;
    }
  }

  async lock(notifyRemoteServer = true): Promise<void> {
    const notifyServer = notifyRemoteServer && this.online && this.store.getState().user !== null;
    this.invalidateAutomaticEnvelopeDelivery();
    this.sync?.stop();
    this.outbox.setOnline(false);
    this.leases.revokeAll();
    await this.keyring.lock();
    this.preparedLegacyMigrations.clear();
    this.bootstrap = null;
    this.contents = {};
    this.store.getState().lockProjection();
    if (notifyServer) await this.api.lock().catch(() => undefined);
  }

  async logout(): Promise<void> {
    await this.lock();
    await this.outbox.clear(false);
    try {
      if (this.online) await this.api.logout();
    } finally {
      this.api.setCsrfToken(null);
      this.profile = null;
      this.device = null;
      this.deviceBundle = null;
      this.store.getState().reset();
    }
  }

  async handleSessionGone(): Promise<void> {
    this.invalidateAutomaticEnvelopeDelivery();
    this.sync?.stop();
    this.outbox.setOnline(false);
    this.leases.revokeAll();
    await this.keyring.lock();
    await this.outbox.clear(false);
    this.api.setCsrfToken(null);
    this.bootstrap = null;
    this.contents = {};
    this.store.getState().reset();
  }

  setOnline(online: boolean): void {
    if (!online) {
      this.invalidateAutomaticEnvelopeDelivery();
      this.online = false;
      this.outbox.setOnline(false);
      this.sync?.stop();
      this.store.getState().setConnection('offline');
      if (this.keyring.isUnlocked) this.setPhase('unlocked-offline');
      return;
    }
    this.store.getState().setConnection('connecting');
    if (!this.keyring.isUnlocked) {
      void this.api.session().then((session) => {
        this.api.setCsrfToken(session.csrfToken);
        this.online = true;
        this.store.getState().setConnection('online');
      }).catch(() => {
        this.online = false;
        this.store.getState().setConnection('offline');
      });
      return;
    }
    this.online = true;
    void this.refresh().then(() => {
      this.online = true;
    }).catch(() => {
      this.online = false;
      this.outbox.setOnline(false);
      this.store.getState().setConnection('offline');
      this.setPhase('unlocked-offline');
    });
  }

  async createItem(
    vaultId: string,
    input: CreateItemInput,
  ): Promise<string> {
    const user = this.requireUser();
    const request = await this.keyring.encryptCreate(user.id, vaultId, input);
    const path = `/api/v2/vaults/${vaultId}/items`;
    if (!this.online) {
      const now = new Date().toISOString();
      const record: EncryptedItemMetadata = {
        itemId: request.itemId,
        vaultId,
        version: 1,
        secretVersion: 1,
        keyEpoch: request.keyEpoch,
        deleted: false,
        blob: request.metadata,
        createdAt: now,
        updatedAt: now,
        updatedBy: user.id,
      };
      this.cacheEncryptedItem(record);
      this.cacheOptimisticContent(record, request.encryptedValue, request.wrappedDek, user.id, 1, 1, now);
      this.store.getState().upsertItemOptimistic({
        id: request.itemId,
        vaultId,
        kind: input.kind,
        secretState: input.kind === 'login' && input.secretValue === null ? 'absent' : 'present',
        title: input.title,
        username: input.username,
        origin: input.origin,
        loginUrl: input.loginUrl,
        loginUrls: input.loginUrls ?? [],
        folderPath: input.folderPath ?? null,
        description: input.kind === 'secure_note' ? null : (input.description ?? null),
        linkedLoginItemId: input.kind === 'api_token' ? (input.linkedLoginItemId ?? null) : null,
        tags: input.tags,
        favorite: input.favorite,
        sensitivity: input.sensitivity,
        version: 1,
        secretVersion: 1,
        createdAt: now,
        updatedAt: now,
        updatedBy: user.id,
      });
      await this.enqueue('item.create', 'POST', path, request);
      await this.persistSnapshot();
      return request.itemId;
    }
    try {
      const record = await this.api.createEncryptedItem(vaultId, request);
      await this.applyEncryptedItem(record);
      return record.itemId;
    } catch (error) {
      if (await this.retainVersionConflict('item.create', 'POST', path, request, error)) return request.itemId;
      throw error;
    }
  }

  async createVault(name: string): Promise<string> {
    if (!this.online) throw new Error('新建密码库需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const normalizedName = name.trim();
    const profile = this.profile;
    if (!normalizedName) throw new Error('密码库名称不能为空');
    if (!profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    if (!this.keyring.isUnlocked) throw new Error('请先在当前浏览器输入主密码');
    const recoveryKey = bootstrap.recoveryKey?.status === 'active' ? bootstrap.recoveryKey : null;
    const vaultId = crypto.randomUUID();
    const request = await this.keyring.prepareVaultCreation(
      user.id,
      vaultId,
      normalizedName,
      profile,
      recoveryKey,
      bootstrap.devices,
    ) as AtomicCreateEncryptedVaultRequest;
    await this.submitVaultCreation(vaultId, () => this.api.createEncryptedVault(request));
    await this.refresh();
    return vaultId;
  }

  async createProject(parentVaultId: string, name: string): Promise<string> {
    if (!this.online) throw new Error('新建项目需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const profile = this.profile;
    const parent = bootstrap.vaults.find((vault) => vault.id === parentVaultId);
    const normalizedName = name.trim();
    if (!normalizedName) throw new Error('项目名称不能为空');
    if (!profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    if (!parent || parent.kind !== 'team' || parent.projectContext?.kind === 'project') {
      throw new Error('只能在上级团队密码库下新建项目');
    }
    if (!this.keyring.isUnlocked) throw new Error('请先输入主密码');
    const recoveryKey = bootstrap.recoveryKey?.status === 'active' ? bootstrap.recoveryKey : null;
    const vaultId = crypto.randomUUID();
    const request = await this.keyring.prepareVaultCreation(
      user.id,
      vaultId,
      normalizedName,
      profile,
      recoveryKey,
      bootstrap.devices,
      {
        parentVaultId,
        expectedParentAccessGeneration: this.requireAccessGeneration(parentVaultId),
      },
    ) as CreateEncryptedProjectRequest;
    await this.submitVaultCreation(
      vaultId,
      () => this.api.createEncryptedProject(parentVaultId, request),
    );
    await this.refresh();
    return vaultId;
  }

  async initializePendingVault(vaultId: string, name: string): Promise<void> {
    if (!this.online) throw new Error('初始化密码库需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    if (!this.profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
    if (!vault) throw new Error('密码库不存在或当前账号无权访问');
    const migration = await this.api.legacyMigrationStatus(vaultId);
    const recoveryKey = bootstrap.recoveryKey?.status === 'active' ? bootstrap.recoveryKey : null;
    if (!migration.materials) throw new Error('密码库初始化材料暂不可用，请重新检查后再试');
    if (!name.trim()) throw new Error('密码库名称不能为空');
    const request = await this.keyring.initializeVault(
      user.id,
      vaultId,
      name.trim(),
      this.profile,
      recoveryKey,
      vault.crypto.status === 'legacy'
        ? 'legacy'
        : 'preparing',
      bootstrap.devices,
      migration.materials,
    );
    await this.api.initializeVaultCrypto(vaultId, request);
    await this.refresh();
  }

  private async loadUnlockedBootstrap(): Promise<EncryptedBootstrapResponse> {
    const bootstrap = await this.api.encryptedBootstrap();
    return this.initializeDefaultPersonalVault(bootstrap);
  }

  private async initializeDefaultPersonalVault(
    bootstrap: EncryptedBootstrapResponse,
  ): Promise<EncryptedBootstrapResponse> {
    if (!this.online || !this.keyring.isUnlocked || !this.profile) return bootstrap;
    const user = this.requireUser();
    const personalVault = bootstrap.vaults.find((vault) =>
      vault.kind === 'personal'
      && vault.ownerUserId === user.id
      && (vault.crypto.status === 'legacy' || vault.crypto.status === 'preparing'));
    if (!personalVault) return bootstrap;

    const migration = await this.api.legacyMigrationStatus(personalVault.id);
    if (migration.status !== 'pending' || !migration.emptyVaultInitializationAllowed || !migration.materials) {
      return bootstrap;
    }

    const recoveryKey = bootstrap.recoveryKey?.status === 'active' ? bootstrap.recoveryKey : null;
    const request = await this.keyring.initializeVault(
      user.id,
      personalVault.id,
      DEFAULT_PERSONAL_VAULT_NAME,
      this.profile,
      recoveryKey,
      personalVault.crypto.status === 'legacy' ? 'legacy' : 'preparing',
      bootstrap.devices,
      migration.materials,
    );

    let failure: unknown = null;
    let reconcile = false;
    try {
      await this.api.initializeVaultCrypto(personalVault.id, request);
    } catch (error) {
      failure = error;
      reconcile = isConvergentVaultInitializationFailure(error);
      if (isRetryableVaultInitializationFailure(error)) {
        reconcile = true;
        try {
          await this.api.initializeVaultCrypto(personalVault.id, request);
          failure = null;
        } catch (retryError) {
          failure = retryError;
        }
      }
    }

    if (failure === null) return this.api.encryptedBootstrap();
    await this.keyring.dropVault(personalVault.id);
    if (reconcile || isConvergentVaultInitializationFailure(failure)) {
      const latest = await this.api.encryptedBootstrap();
      const completed = latest.vaults.some((vault) =>
        vault.id === personalVault.id && vault.crypto.status === 'e2ee');
      if (completed) return latest;
    }
    throw failure;
  }

  async deleteUninitializedVault(vaultId: string): Promise<void> {
    if (!this.online) throw new Error('清理未初始化密码库需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
    if (!vault || vault.kind !== 'team' || vault.crypto.status === 'e2ee') {
      throw new Error('只能清理自己拥有的未初始化团队密码库');
    }
    const request = await this.keyring.prepareUninitializedVaultDeletion(
      user.id,
      vaultId,
      this.requireAccessGeneration(vaultId),
    );
    await this.api.deleteUninitializedVault(vaultId, request);
    await this.keyring.dropVault(vaultId);
    await this.refresh();
  }

  async renameVault(vaultId: string, name: string): Promise<void> {
    if (!this.online) throw new Error('修改密码库名称需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const normalizedName = name.trim();
    if (!normalizedName) throw new Error('密码库名称不能为空');
    const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
    const header = bootstrap.headers
      .filter((candidate) => candidate.vaultId === vaultId && candidate.keyEpoch === vault?.crypto.activeEpoch)
      .sort((left, right) => right.version - left.version)[0];
    if (!vault || vault.crypto.status !== 'e2ee' || !header) {
      throw new Error('密码库尚未完成加密初始化，请刷新后重试');
    }
    if (!this.api.updateEncryptedVaultHeader) throw new Error('当前服务版本不支持修改密码库名称');
    const request = await this.keyring.encryptVaultRename(
      user.id,
      vaultId,
      normalizedName,
      header,
    );
    await this.api.updateEncryptedVaultHeader(vaultId, request);
    await this.refresh();
  }

  async updateVaultDetails(
    vaultId: string,
    details: { name: string; vaultGroupName: string | null },
  ): Promise<void> {
    if (!this.online) throw new Error('修改密码库设置需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const normalizedName = details.name.trim();
    const normalizedGroupName = normalizeVaultGroupName(details.vaultGroupName);
    if (!normalizedName) throw new Error('密码库名称不能为空');
    if (details.vaultGroupName?.trim() && normalizedGroupName === null) {
      throw new Error('密码库旧版设置格式不正确');
    }
    const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
    const header = bootstrap.headers
      .filter((candidate) => candidate.vaultId === vaultId && candidate.keyEpoch === vault?.crypto.activeEpoch)
      .sort((left, right) => right.version - left.version)[0];
    if (!vault || vault.kind !== 'team' || vault.crypto.status !== 'e2ee' || !header) {
      throw new Error('团队密码库尚未完成加密初始化，请刷新后重试');
    }
    if (!this.api.updateEncryptedVaultHeader) throw new Error('当前服务版本不支持修改密码库设置');
    const request = await this.keyring.encryptVaultDetails(user.id, vaultId, {
      name: normalizedName,
      vaultGroupName: normalizedGroupName,
    }, header);
    await this.api.updateEncryptedVaultHeader(vaultId, request);
    await this.refresh();
  }

  async updateVaultDirectories(vaultId: string, directories: VaultDirectoryEntry[]): Promise<void> {
    if (!this.online) throw new Error('管理目录需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
    const header = bootstrap.headers
      .filter((candidate) => candidate.vaultId === vaultId && candidate.keyEpoch === vault?.crypto.activeEpoch)
      .sort((left, right) => right.version - left.version)[0];
    if (!vault || vault.crypto.status !== 'e2ee' || !header) {
      throw new Error('密码库尚未完成加密初始化，请刷新后重试');
    }
    if (!this.api.updateEncryptedVaultHeader) throw new Error('当前服务版本不支持管理目录');
    const request = await this.keyring.encryptVaultDirectories(user.id, vaultId, directories, header);
    await this.api.updateEncryptedVaultHeader(vaultId, request);
    await this.refresh();
  }

  async deleteVault(vaultId: string): Promise<void> {
    if (!this.online) throw new Error('删除密码库需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const vault = bootstrap.vaults.find((candidate) => candidate.id === vaultId);
    const header = bootstrap.headers
      .filter((candidate) => candidate.vaultId === vaultId && candidate.keyEpoch === vault?.crypto.activeEpoch)
      .sort((left, right) => right.version - left.version)[0];
    if (!vault || vault.kind !== 'team' || !header) throw new Error('只能删除自己拥有的团队密码库');
    const request = await this.keyring.prepareVaultDeletion(
      user.id,
      vaultId,
      this.requireAccessGeneration(vaultId),
      header,
    );
    await this.api.deleteEncryptedVault(vaultId, request);
    await this.keyring.dropVault(vaultId);
    await this.refresh();
  }

  async setVaultMembership(
    vaultId: string,
    subjectKind: SubjectKind,
    subjectId: string,
    role: MembershipRole,
    mode: 'replace' | 'grant_or_upgrade' = 'replace',
    refreshAfter = true,
  ): Promise<SetEncryptedMembershipResponse> {
    if (!this.online) throw new Error('成员授权需要连接服务器');
    const user = this.requireUser();
    if (!this.profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    const expectedAccessGeneration = this.requireAccessGeneration(vaultId);
    const recipientProfile = subjectKind === 'user' && role !== 'auditor'
      ? (await this.api.cryptoPublicProfiles([subjectId])).find((profile) => profile.userId === subjectId)
      : undefined;
    const request = await this.keyring.prepareMembershipSet(user.id, vaultId, {
      subjectKind,
      subjectId,
      role,
      mode,
      expectedAccessGeneration,
      distribution: recipientProfile ? {
        signerKeyVersion: this.profile.keyVersion,
        recipientProfile,
      } : undefined,
    });
    const result = await this.api.setEncryptedMembership(vaultId, request);
    if (refreshAfter) await this.refresh();
    else this.scheduleAutomaticEnvelopeDelivery([vaultId]);
    return result;
  }

  private async submitVaultCreation(
    vaultId: string,
    submit: () => Promise<unknown>,
  ): Promise<void> {
    try {
      await submit();
      return;
    } catch (firstError) {
      if (isDefinitiveVaultCreationFailure(firstError)) {
        await this.keyring.dropVault(vaultId);
        throw firstError;
      }
      try {
        await submit();
        return;
      } catch (retryError) {
        try {
          await this.refresh();
          if (this.bootstrap?.vaults.some((vault) => vault.id === vaultId)) return;
        } catch {
          throw new Error('创建结果暂时无法确认。请恢复网络并刷新工作台，不要重复创建', {
            cause: retryError,
          });
        }
        await this.keyring.dropVault(vaultId);
        throw retryError;
      }
    }
  }

  async removeVaultMembership(
    vaultId: string,
    subjectKind: SubjectKind,
    subjectId: string,
  ): Promise<RemoveEncryptedMembershipResponse> {
    if (!this.online) throw new Error('撤销成员需要连接服务器');
    const user = this.requireUser();
    const expectedAccessGeneration = this.requireAccessGeneration(vaultId);
    const request = await this.keyring.prepareMembershipRemoval(user.id, vaultId, {
      subjectKind,
      subjectId,
      expectedAccessGeneration,
    });
    const result = await this.api.removeEncryptedMembership(vaultId, request);
    await this.refresh();
    return result;
  }

  listEnvelopeTasks(vaultId: string): Promise<VaultEnvelopeTask[]> {
    if (!this.online) throw new Error('查看团队访问准备状态需要联网，请检查网络后重试');
    return this.api.vaultEnvelopeTasks(vaultId);
  }

  async completeEnvelopeTask(
    task: VaultEnvelopeTask,
    refreshAfter = true,
    expectedAutomaticGeneration?: number,
  ): Promise<void> {
    if (!this.online) throw new Error('自动准备团队访问需要联网，请检查网络后重试');
    const user = this.requireUser();
    if (!this.profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    const request = await this.keyring.prepareEnvelopeTaskCompletion(user.id, this.profile, task);
    if (
      expectedAutomaticGeneration !== undefined &&
      (expectedAutomaticGeneration !== this.automaticEnvelopeGeneration || !this.keyring.isUnlocked)
    ) return;
    await this.api.completeVaultEnvelopeTask(task, request);
    if (refreshAfter) await this.refresh();
  }

  async transferVaultOwnership(vaultId: string, newOwnerUserId: string): Promise<VaultOwnershipTransfer> {
    if (!this.online) throw new Error('所有权转移需要连接服务器');
    await this.waitForAutomaticEnvelopeDelivery(vaultId);
    const user = this.requireUser();
    const request = await this.keyring.prepareOwnershipTransfer(
      user.id,
      vaultId,
      newOwnerUserId,
      this.requireAccessGeneration(vaultId),
    );
    const transfer = await this.api.createOwnershipTransfer(vaultId, request);
    await this.refresh();
    return transfer;
  }

  getVaultOwnershipTransfer(vaultId: string): Promise<VaultOwnershipTransfer | null> {
    if (!this.online) throw new Error('所有权转移状态需要连接服务器');
    return this.api.ownershipTransfer(vaultId);
  }

  async acceptVaultOwnershipTransfer(transfer: VaultOwnershipTransfer): Promise<VaultOwnershipTransfer> {
    if (!this.online) throw new Error('确认接收所有权需要连接服务器');
    const user = this.requireUser();
    await this.refresh();
    const request = await this.keyring.prepareOwnershipTransferAcceptance(user.id, transfer);
    const accepted = await this.api.acceptOwnershipTransfer(transfer.vaultId, request);
    await this.refresh();
    return accepted;
  }

  async cancelVaultOwnershipTransfer(
    transfer: VaultOwnershipTransfer,
    decision: 'cancel' | 'decline',
  ): Promise<VaultOwnershipTransfer> {
    if (!this.online) throw new Error('处理所有权转移需要连接服务器');
    const user = this.requireUser();
    const request = await this.keyring.prepareOwnershipTransferCancellation(user.id, transfer, decision);
    const cancelled = await this.api.cancelOwnershipTransfer(transfer.vaultId, request);
    await this.refresh();
    return cancelled;
  }

  legacyMigrationStatus(vaultId: string): Promise<LegacyMigrationStatusResponse> {
    if (!this.online) throw new Error('旧密码库迁移需要连接服务器');
    return this.api.legacyMigrationStatus(vaultId);
  }

  legacyKeyRetirementStatus(): Promise<LegacyKeyRetirementResponse> {
    if (!this.online) throw new Error('旧密钥退役状态需要连接服务器');
    return this.api.legacyKeyRetirementStatus();
  }

  async createLegacyKeyRetirement(input: {
    reasonCode: LegacyKeyRetirementReason;
    retireBy: string | null;
    copyInventoryDigest: string;
    copyManifestDigest: string;
    kekFingerprintDigest: string | null;
  }): Promise<LegacyKeyRetirementResponse> {
    if (!this.online) throw new Error('登记旧密钥退役计划需要连接服务器');
    const user = this.requireUser();
    if (!this.keyring.isUnlocked) throw new Error('请先解锁当前管理员设备');
    const request = await this.keyring.createLegacyKeyRetirementIntent(user.id, input);
    return this.api.createLegacyKeyRetirement(request);
  }

  async approveLegacyKeyRetirement(
    planDigest: string,
    evidenceDigest: string,
  ): Promise<LegacyKeyRetirementResponse> {
    if (!this.online) throw new Error('审批旧密钥退役需要连接服务器');
    const user = this.requireUser();
    if (!this.keyring.isUnlocked) throw new Error('请先解锁当前管理员设备');
    const request = await this.keyring.approveLegacyKeyRetirementIntent(user.id, planDigest, evidenceDigest);
    return this.api.approveLegacyKeyRetirement(request);
  }

  async completeLegacyKeyRetirement(
    planDigest: string,
    completionEvidenceDigest: string,
  ): Promise<LegacyKeyRetirementResponse> {
    if (!this.online) throw new Error('完成旧密钥退役需要连接服务器');
    const user = this.requireUser();
    if (!this.keyring.isUnlocked) throw new Error('请先解锁当前管理员设备');
    const request = await this.keyring.completeLegacyKeyRetirementIntent(
      user.id,
      planDigest,
      completionEvidenceDigest,
    );
    return this.api.completeLegacyKeyRetirement(request);
  }

  async startLegacyMigration(vaultId: string): Promise<LegacyMigrationStatusResponse> {
    if (!this.online) throw new Error('开始迁移需要连接服务器');
    const user = this.requireUser();
    if (!this.keyring.isUnlocked) throw new Error('请先输入主密码');
    const request = await this.keyring.migrationStartIntent(user.id, vaultId);
    await this.api.startLegacyMigration(vaultId, request);
    await this.refresh();
    return this.api.legacyMigrationStatus(vaultId);
  }

  async convertLegacyMigration(vaultId: string): Promise<LegacyMigrationStatusResponse> {
    if (!this.online) throw new Error('领取和转换迁移数据需要连接服务器');
    const user = this.requireUser();
    const profile = this.profile;
    if (!profile || !this.keyring.isUnlocked) throw new Error('请先解锁当前设备');
    const status = await this.api.legacyMigrationStatus(vaultId);
    const job = requireMigrationJob(status, 'encrypting');
    if (!status.materials) {
      throw new Error('有效成员尚未全部设置主密码，或企业恢复公钥不可用，暂时不能生成完整密钥分发');
    }
    if (this.hasPreparedLegacyMigration(vaultId, job.id)) return status;

    const claimIntent = await this.keyring.migrationExportClaimIntent(user.id, vaultId);
    const migrationExport = await this.api.claimLegacyMigrationExport(vaultId, claimIntent);
    try {
      const prepared = await this.keyring.prepareLegacyMigration(
        user.id,
        profile,
        job,
        status.materials,
        migrationExport,
      );
      this.preparedLegacyMigrations.set(vaultId, job.id);
      await this.api.submitLegacyMigrationTarget(vaultId, prepared.target);
      for (const batch of prepared.recordBatches) {
        await this.api.uploadLegacyMigrationRecords(vaultId, batch);
      }
      return await this.api.legacyMigrationStatus(vaultId);
    } catch (error) {
      throw await this.rollbackAfterMigrationFailure(vaultId, job, error);
    }
  }

  async verifyLegacyMigration(vaultId: string): Promise<LegacyMigrationStatusResponse> {
    if (!this.online) throw new Error('迁移核对需要连接服务器');
    const user = this.requireUser();
    const status = await this.api.legacyMigrationStatus(vaultId);
    const job = requireMigrationJob(status, 'encrypting');
    if (!this.hasPreparedLegacyMigration(vaultId, job.id)) {
      throw new Error('本页没有领取时生成的迁移密文。请回滚后重新开始，不能重复领取旧数据');
    }
    try {
      const request = await this.keyring.migrationVerificationIntent(user.id, vaultId, job.id);
      return await this.api.verifyLegacyMigration(vaultId, request);
    } catch (error) {
      throw await this.rollbackAfterMigrationFailure(vaultId, job, error);
    }
  }

  async cutoverLegacyMigration(vaultId: string): Promise<void> {
    if (!this.online) throw new Error('迁移切换需要连接服务器');
    const user = this.requireUser();
    const status = await this.api.legacyMigrationStatus(vaultId);
    const job = requireMigrationJob(status, 'verifying');
    if (!this.hasPreparedLegacyMigration(vaultId, job.id)) {
      throw new Error('本页没有待提交的迁移密钥。请回滚后重新开始');
    }
    const request = await this.keyring.migrationActionIntent(user.id, vaultId, job.id, 'cutover');
    try {
      await this.api.cutoverLegacyMigration(vaultId, request);
      await this.keyring.commitLegacyMigration(vaultId, job.id);
      this.preparedLegacyMigrations.delete(vaultId);
      await this.refresh();
    } catch (error) {
      const latest = await this.api.legacyMigrationStatus(vaultId).catch(() => null);
      if (latest?.status === 'complete' && latest.job?.id === job.id) {
        await this.keyring.commitLegacyMigration(vaultId, job.id);
        this.preparedLegacyMigrations.delete(vaultId);
        await this.refresh();
        return;
      }
      throw await this.rollbackAfterMigrationFailure(vaultId, job, error);
    }
  }

  async rollbackLegacyMigration(vaultId: string): Promise<void> {
    if (!this.online) throw new Error('迁移回滚需要连接服务器');
    const user = this.requireUser();
    const status = await this.api.legacyMigrationStatus(vaultId);
    const job = status.job;
    if (!job || !['frozen', 'encrypting', 'verifying'].includes(job.status)) {
      await this.keyring.abortLegacyMigration(vaultId);
      this.preparedLegacyMigrations.delete(vaultId);
      throw new Error('当前迁移状态不允许回滚');
    }
    const request = await this.keyring.migrationActionIntent(user.id, vaultId, job.id, 'rollback');
    try {
      await this.api.rollbackLegacyMigration(vaultId, request);
    } finally {
      await this.keyring.abortLegacyMigration(vaultId, job.id);
      this.preparedLegacyMigrations.delete(vaultId);
    }
    await this.refresh();
  }

  async completeRecovery(
    request: EnterpriseRecoveryRequest,
    offlineResult: OfflineRecoveryResult,
  ): Promise<void> {
    if (!this.online) throw new Error('提交企业恢复结果需要连接服务器');
    const user = this.requireUser();
    const bootstrap = this.requireBootstrap();
    const header = bootstrap.headers.find((entry) => entry.vaultId === request.vaultId);
    if (!header) throw new Error('当前设备没有收到该密码库的加密头');
    if (!bootstrap.recoveryKey) throw new Error('当前企业恢复公钥不可用');
    const completeRequest = await this.keyring.prepareRecovery(
      user.id,
      request,
      bootstrap.recoveryKey,
      header,
      offlineResult,
    );
    try {
      await this.api.completeRecovery(request.id, completeRequest);
      await this.keyring.commitRecovery(request.id);
    } catch (error) {
      await this.keyring.abortRecovery(request.id);
      throw error;
    }
    await this.refresh();
    if (request.targetCapability === 'full') {
      this.store.getState().setSecurityPhase('rekey-blocked');
    }
  }

  async continueInterruptedHandoffRecoveryCase(
    recoveryCase: EnterpriseRecoveryCase,
  ): Promise<EnterpriseRecoveryCase> {
    if (!this.online) throw new Error('继续恢复原有访问需要连接服务器');
    if (!this.keyring.isUnlocked) throw new Error('请先输入主密码');
    if (recoveryCase.kind !== 'interrupted_handoff' || recoveryCase.status !== 'waiting_for_target') {
      throw new Error('这次恢复协助已经进入下一步或已经结束');
    }
    const user = this.requireUser();
    const profile = this.profile;
    if (!profile) throw new Error('当前账号安全信息不可用，请重新登录');
    const request = await this.keyring.prepareInterruptedHandoffRecoveryCase(
      user.id,
      recoveryCase.id,
      profile,
    );
    const finalized = await this.api.finalizeRecoveryCase(recoveryCase.id, request);
    this.scheduleAutomaticRecoveryCaseCompletion();
    return finalized;
  }

  async distributeEnterpriseRecoveryEnvelope(
    recoveryKey: EnterpriseRecoveryKey,
    vault: EnterpriseRecoveryCoverage['vaults'][number],
    signal?: AbortSignal,
  ): Promise<{ alreadyCovered: boolean }> {
    if (!this.online) throw new Error('添加公司恢复保护需要连接服务器');
    if (!this.profile || !this.keyring.isUnlocked) throw new Error('请先解锁当前设备');
    if (vault.covered) return { alreadyCovered: true };
    if (!vault.canManage) throw new Error('只有密码库拥有者可以添加公司恢复保护');
    if (vault.epoch === null) throw new Error('密码库尚未完成零知识加密初始化');
    throwIfAborted(signal);
    const user = this.requireUser();
    const generation = this.keyring.currentGeneration;
    const request = await this.keyring.prepareEnterpriseRecoveryEnvelope(
      user.id,
      this.profile,
      recoveryKey,
      vault.vaultId,
      vault.epoch,
    );
    throwIfAborted(signal);
    if (generation !== this.keyring.currentGeneration) {
      throw new Error('工作台状态已变化，本次恢复保护任务已取消');
    }
    const response = await this.api.distributeRecoveryEnvelope(
      recoveryKey.id,
      vault.vaultId,
      request,
      signal,
    );
    return { alreadyCovered: response.alreadyCovered };
  }

  async approveExtensionEnrollment(enrollment: ExtensionEnrollment): Promise<void> {
    if (!this.online) throw new Error('批准扩展设备需要连接服务器');
    const user = this.requireUser();
    if (!this.profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    const approval = await this.keyring.approveExtensionEnrollment(user.id, this.profile, enrollment);
    await this.api.approveExtensionEnrollment(enrollment.id, approval);
    await this.refresh();
  }

  async prepareExtensionTrustedUnlock(
    request: ExtensionTrustedUnlockRequest,
    needsSession = true,
  ): Promise<ExtensionTrustedUnlockResult> {
    assertExtensionTrustedUnlockRequest(request);
    const user = this.requireUser();
    const profile = this.profile;
    if (!profile || !this.keyring.isUnlocked || request.accountId !== user.id) {
      throw new Error('密码库尚未解锁，不能确认扩展');
    }
    let device = this.bootstrap?.devices.find((entry) => entry.id === request.deviceId);
    if (!device && this.online) {
      await this.refresh();
      device = this.bootstrap?.devices.find((entry) => entry.id === request.deviceId);
    }
    if (
      !device ||
      device.revokedAt ||
      device.userId !== user.id ||
      device.deviceType !== 'extension' ||
      device.keyVersion !== request.accountKeyVersion ||
      device.encryptionPublicKey !== request.deviceEncryptionPublicKey ||
      device.signingPublicKey !== request.deviceSigningPublicKey
    ) {
      throw new Error('扩展设备未获得当前账号授权');
    }
    const response = await this.keyring.prepareExtensionTrustedUnlock(profile, request);
    if (!needsSession) return { response };
    const resumeRequest = await this.keyring.prepareExtensionSessionResume(user.id, request);
    const session = await this.api.resumeExtensionSession(resumeRequest);
    return { response, session };
  }

  listDevices(): Promise<CryptoDevice[]> {
    return this.api.cryptoDevices();
  }

  async changeMainPassword(
    currentPassword: string,
    newPassword: string,
    confirmation: string,
  ): Promise<MainPasswordChangeOutcome> {
    if (!this.online) throw new Error('修改主密码需要连接服务器');
    if (!this.keyring.isUnlocked) throw new Error('当前设备尚未解锁');
    if (!this.profile || !this.device || !this.deviceBundle) {
      throw new Error('当前账号或设备授权信息不完整，请重新登录');
    }
    if (newPassword !== confirmation) throw new Error('两次输入的新主密码不一致');
    if (currentPassword === newPassword) throw new Error('新主密码不能与当前主密码相同');
    validateMainPassword(newPassword);

    const previousProfile = this.profile;
    let request: RewrapCryptoProfileRequest;
    try {
      request = await this.keyring.prepareMasterPasswordChange(
        currentPassword,
        newPassword,
        previousProfile,
      );
    } catch (error) {
      throw friendlyUnlockError(error);
    }
    const updatedProfile = await this.commitMainPasswordChange(previousProfile, request);
    this.profile = updatedProfile;
    if (this.bootstrap) this.bootstrap = { ...this.bootstrap, profile: updatedProfile };

    const localCachePersisted = await this.persistMainPasswordChangeCache();
    return { localCachePersisted };
  }

  async revokeDevice(device: CryptoDevice): Promise<void> {
    if (!this.online) throw new Error('撤销设备需要连接服务器');
    const user = this.requireUser();
    const request = await this.keyring.revokeDevice(user.id, device.id, device.keyVersion);
    const current = device.id === this.keyring.deviceId;
    await this.api.revokeCryptoDevice(device.id, request);
    this.onDeviceRevoked?.(device.id);
    if (current) {
      await this.storage.deleteAccount(user.id);
      await this.handleSessionGone();
      return;
    }
    await this.refresh();
  }

  async rotateIdentity(mainPassword: string): Promise<IdentityRotationOutcome> {
    if (!this.online) throw new Error('轮换身份密钥需要连接服务器');
    if (!mainPassword) throw new Error('请输入主密码');
    const profile = this.profile;
    const device = this.device;
    if (!profile || !device || !this.keyring.isUnlocked) throw new Error('当前设备尚未解锁');
    this.sync?.stop();
    this.outbox.setOnline(false);
    this.leases.revokeAll();
    this.setPhase('rotating-identity');

    let prepared: Awaited<ReturnType<E2eeKeyringPort['prepareIdentityRotation']>>;
    try {
      prepared = await this.keyring.prepareIdentityRotation(mainPassword, profile, device);
    } catch (error) {
      this.setPhase('unlocked-online');
      this.sync?.start();
      throw friendlyUnlockError(error);
    }

    let response: Awaited<ReturnType<ZeroKnowledgeApi['rotateCryptoProfile']>>;
    try {
      response = await this.api.rotateCryptoProfile(prepared.request);
    } catch (error) {
      await this.keyring.abortIdentityRotation();
      this.setPhase('unlocked-online');
      this.sync?.start();
      throw error;
    }

    await this.keyring.commitIdentityRotation();
    this.profile = response.profile;
    this.device = response.device;
    this.deviceBundle = prepared.deviceBundle;
    this.bootstrap = null;
    this.contents = {};
    this.rekeyTasks = new Map(response.rekeyTasks.map((task) => [task.vaultId, task.taskId]));
    await this.outbox.clear(false);

    const nextCache = {
      accountId: response.profile.userId,
      profile: response.profile,
      device: response.device,
      deviceBundle: prepared.deviceBundle,
      encryptedBootstrap: null,
      cachedAt: new Date().toISOString(),
    };
    let localCachePersisted = true;
    try {
      await this.storage.replaceAccountAfterIdentityRotation(nextCache);
    } catch {
      localCachePersisted = false;
      await this.storage.deleteAccount(response.profile.userId).catch(() => undefined);
    }

    this.store.getState().lockProjection();
    for (const task of response.rekeyTasks) {
      this.store.getState().setVaultCryptoState({
        vaultId: task.vaultId,
        status: 'rekey_required',
        activeEpoch: task.fromEpoch,
        pendingEpoch: task.toEpoch,
        rekeyTaskId: task.taskId,
        encryptedHeader: null,
        migrationJobId: null,
        updatedAt: new Date().toISOString(),
      });
    }
    this.store.getState().setConnection('online');
    this.setPhase('rekey-blocked');
    return {
      revokedDeviceCount: response.revokedDeviceCount,
      rekeyTaskCount: response.rekeyTasks.length,
      localCachePersisted,
    };
  }

  async completeVaultRekey(vaultId: string): Promise<void> {
    if (!this.online) throw new Error('完成密码库安全更新需要联网，请检查网络后重试');
    const user = this.requireUser();
    const profile = this.profile;
    const taskId = this.rekeyTasks.get(vaultId);
    if (!profile || !taskId) throw new Error('当前没有可继续的安全更新，请先刷新状态');
    const intent = await this.keyring.rekeyMaterialIntent(user.id, vaultId, taskId);
    const material = await this.api.rekeyMaterial(vaultId, intent);
    let committedState: VaultCryptoState;
    try {
      const request = await this.keyring.prepareVaultRekey(user.id, vaultId, profile, material);
      committedState = await this.api.commitVaultRekey(vaultId, request);
      await this.keyring.commitVaultRekey(vaultId);
    } catch (error) {
      await this.keyring.abortVaultRekey(vaultId);
      throw error;
    }
    this.rekeyTasks.delete(vaultId);
    this.store.getState().setVaultCryptoState(committedState);
    this.reconcileSecurityPhaseFromProjection();
    await this.refresh().catch(() => undefined);
  }

  async updateItem(item: DecryptedItemMeta, payload: ItemMetadataPayload): Promise<void> {
    const user = this.requireUser();
    const request = await this.keyring.encryptMetadataUpdate(user.id, item, payload);
    const path = `/api/v2/items/${item.id}`;
    if (!this.online) {
      const now = new Date().toISOString();
      this.cacheEncryptedItem({
        itemId: item.id,
        vaultId: item.vaultId,
        version: item.version + 1,
        secretVersion: item.secretVersion,
        keyEpoch: request.keyEpoch,
        deleted: false,
        blob: request.metadata,
        createdAt: item.createdAt,
        updatedAt: now,
        updatedBy: user.id,
      });
      this.store.getState().upsertItemOptimistic({
        ...item,
        ...payload,
        version: item.version + 1,
        updatedAt: now,
        updatedBy: user.id,
      });
      await this.enqueue('item.update', 'PATCH', path, request);
      await this.persistSnapshot();
      return;
    }
    try {
      const record = await this.api.updateEncryptedItem(item.id, request);
      await this.applyEncryptedItem(record);
    } catch (error) {
      if (await this.retainVersionConflict('item.update', 'PATCH', path, request, error)) return;
      throw error;
    }
  }

  async rotateItem(item: DecryptedItemMeta, secretValue: string): Promise<void> {
    const user = this.requireUser();
    const request = await this.keyring.encryptRotation(user.id, item, secretValue);
    const path = `/api/v2/items/${item.id}/secret`;
    delete this.contents[item.id];
    this.leases.revoke(item.id);
    if (!this.online) {
      const now = new Date().toISOString();
      const nextVersion = item.version + 1;
      const record: EncryptedItemMetadata = {
        itemId: item.id,
        vaultId: item.vaultId,
        version: nextVersion,
        secretVersion: nextVersion,
        keyEpoch: request.keyEpoch,
        deleted: false,
        blob: request.metadata,
        createdAt: item.createdAt,
        updatedAt: now,
        updatedBy: user.id,
      };
      this.cacheEncryptedItem(record);
      this.cacheOptimisticContent(
        record,
        request.encryptedValue,
        request.wrappedDek,
        user.id,
        nextVersion,
        nextVersion,
        now,
      );
      this.store.getState().upsertItemOptimistic({
        ...item,
        secretState: 'present',
        version: item.version + 1,
        secretVersion: item.version + 1,
        updatedAt: now,
        updatedBy: user.id,
      });
      await this.enqueue('item.rotate', 'PUT', path, request);
      await this.persistSnapshot();
      return;
    }
    try {
      const record = await this.api.rotateEncryptedSecret(item.id, request);
      await this.applyEncryptedItem(record);
      await this.persistSnapshot();
    } catch (error) {
      if (await this.retainVersionConflict('item.rotate', 'PUT', path, request, error)) return;
      throw error;
    }
  }

  async reveal(
    itemId: string,
    purpose: 'view' | 'copy' | 'fill',
    secretVersion?: number,
  ): Promise<{ itemId: string; secretVersion: number; value: string }> {
    const user = this.requireUser();
    const item = this.store.getState().items[itemId];
    if (!item) throw new Error('条目不存在');
    const generation = this.keyring.currentGeneration;
    const requestedVersion = secretVersion ?? item.secretVersion;
    let response = this.contents[contentCacheKey(itemId, requestedVersion)] ?? this.contents[itemId];
    if (this.online) {
      const intent = await this.keyring.contentIntent(user.id, item, purpose, secretVersion);
      response = await this.api.encryptedContent(itemId, intent);
      this.contents[contentCacheKey(itemId, response.secret.secretVersion)] = response;
      await this.persistSnapshot();
    }
    if (!response || (secretVersion !== undefined && response.secret.secretVersion !== secretVersion)) {
      throw new Error('离线缓存中没有这个版本的敏感内容');
    }
    const value = await this.keyring.decryptContent(response);
    if (generation !== this.keyring.currentGeneration) throw new Error('工作台状态已变化，本次查看结果已清除');
    return { itemId, secretVersion: response.secret.secretVersion, value };
  }

  async deleteItem(item: ItemMeta): Promise<void> {
    const user = this.requireUser();
    const request = await this.keyring.encryptDelete(user.id, item);
    const path = `/api/v2/items/${item.id}`;
    this.deleteCachedContents(item.id);
    this.leases.revoke(item.id);
    if (!this.online) {
      const now = new Date().toISOString();
      this.cacheEncryptedItem({
        itemId: item.id,
        vaultId: item.vaultId,
        version: item.version + 1,
        secretVersion: item.secretVersion,
        keyEpoch: request.keyEpoch,
        deleted: true,
        blob: request.metadata,
        createdAt: item.createdAt,
        updatedAt: now,
        updatedBy: user.id,
      });
      const state = this.store.getState();
      state.applyEvent({ type: 'item.deleted', cursor: state.cursor, vaultId: item.vaultId, itemId: item.id });
      await this.enqueue('item.delete', 'DELETE', path, request);
      await this.persistSnapshot();
      return;
    }
    try {
      await this.api.deleteEncryptedItem(item.id, request);
      const state = this.store.getState();
      state.applyEvent({ type: 'item.deleted', cursor: state.cursor, vaultId: item.vaultId, itemId: item.id });
      await this.persistSnapshot();
    } catch (error) {
      if (await this.retainVersionConflict('item.delete', 'DELETE', path, request, error)) return;
      throw error;
    }
  }

  async applyEncryptedSyncEvent(event: EncryptedSyncEvent): Promise<void> {
    if (!this.keyring.isUnlocked) return;
    const state = this.store.getState();
    if (
      event.cursor < state.cursor
      || (event.cursor === state.cursor && event.type !== 'sync.ready')
    ) return;
    switch (event.type) {
      case 'item.encrypted_upserted': {
        this.cacheEncryptedItem(event.item);
        const item = await this.keyring.decryptMetadataRecord(event.item);
        state.applyEvent({ type: 'item.upserted', cursor: event.cursor, item });
        await this.persistSnapshot();
        return;
      }
      case 'item.deleted': {
        if (this.bootstrap) {
          this.bootstrap = {
            ...this.bootstrap,
            cursor: Math.max(this.bootstrap.cursor, event.cursor),
            items: this.bootstrap.items.filter((item) => item.itemId !== event.itemId),
          };
        }
        this.deleteCachedContents(event.itemId);
        state.applyEvent(event);
        await this.persistSnapshot();
        return;
      }
      case 'vault.crypto_changed': {
        const pendingTeamAccess = Boolean(state.pendingVaultAccessIds[event.state.vaultId]);
        state.advanceCursor(event.cursor);
        state.setVaultCryptoState(event.state);
        if (this.bootstrap) {
          this.bootstrap = {
            ...this.bootstrap,
            cursor: Math.max(this.bootstrap.cursor, event.cursor),
            vaults: this.bootstrap.vaults.map((vault) =>
              vault.id === event.state.vaultId ? { ...vault, crypto: event.state } : vault),
            headers: event.header
              ? [...this.bootstrap.headers.filter((header) => header.vaultId !== event.state.vaultId), event.header]
              : this.bootstrap.headers.filter((header) => header.vaultId !== event.state.vaultId),
          };
        }
        if (event.state.status === 'rekey_required' && !pendingTeamAccess) {
          this.setPhase('rekey-blocked');
          this.outbox.setOnline(false);
          return;
        }
        await this.refresh();
        return;
      }
      case 'vault.rekey_required': {
        const taskId = (event as EncryptedSyncEvent & { taskId?: string }).taskId;
        if (taskId) this.rekeyTasks.set(event.vaultId, taskId);
        const current = state.vaultCrypto[event.vaultId];
        if (current) {
          state.setVaultCryptoState({
            ...current,
            status: 'rekey_required',
            pendingEpoch: event.pendingEpoch,
            updatedAt: new Date().toISOString(),
          });
        }
        state.advanceCursor(event.cursor);
        this.setPhase('rekey-blocked');
        this.outbox.setOnline(false);
        return;
      }
      case 'vault.revoked': {
        await this.keyring.dropVault(event.vaultId);
        if (this.bootstrap) {
          this.bootstrap = {
            ...this.bootstrap,
            cursor: Math.max(this.bootstrap.cursor, event.cursor),
            vaults: this.bootstrap.vaults.filter((vault) => vault.id !== event.vaultId),
            memberships: this.bootstrap.memberships.filter((membership) => membership.vaultId !== event.vaultId),
            envelopes: this.bootstrap.envelopes.filter((envelope) => envelope.vaultId !== event.vaultId),
            headers: this.bootstrap.headers.filter((header) => header.vaultId !== event.vaultId),
            items: this.bootstrap.items.filter((item) => item.vaultId !== event.vaultId),
          };
        }
        for (const [cacheKey, content] of Object.entries(this.contents)) {
          if (content.metadata.vaultId === event.vaultId) delete this.contents[cacheKey];
        }
        state.applyEvent(event);
        await this.persistSnapshot();
        return;
      }
      case 'crypto.profile_rewrapped': {
        state.advanceCursor(event.cursor);
        const currentProfile = this.profile;
        const actorIsCurrentDevice = event.actorDeviceId === (this.keyring.deviceId ?? this.device?.id);
        if (actorIsCurrentDevice || (currentProfile && event.profileVersion <= currentProfile.profileVersion)) {
          return;
        }
        const accountId = currentProfile?.userId ?? state.user?.id;
        const currentDevice = this.device;
        const currentDeviceBundle = this.deviceBundle;
        await this.lock(false);
        if (!accountId) return;

        const cached = await this.storage.getAccount(accountId).catch(() => null);
        await this.storage.deleteAccountLocator(accountId).catch(() => undefined);
        try {
          const latest = await this.api.cryptoProfile();
          if (!latest || latest.userId !== accountId || latest.profileVersion < event.profileVersion) {
            throw new Error('服务器尚未返回最新的账号安全信息，请稍后重试');
          }
          if (currentProfile && !sameCryptoIdentity(latest, currentProfile)) {
            throw new Error('账号安全信息已更新，请重新登录并解锁');
          }
          this.profile = latest;
          if (cached && sameCryptoIdentity(cached.profile, latest)) {
            await this.storage.putAccount({
              ...cached,
              profile: latest,
              cachedAt: new Date().toISOString(),
            });
          } else if (currentDevice && currentDeviceBundle) {
            await this.storage.putAccount({
              accountId,
              profile: latest,
              device: currentDevice,
              deviceBundle: currentDeviceBundle,
              encryptedBootstrap: null,
              cachedAt: new Date().toISOString(),
            });
          }
        } catch {
          this.profile = null;
          this.device = null;
          this.deviceBundle = null;
          await this.storage.deleteAccountLocator(accountId).catch(() => undefined);
        }
        return;
      }
      case 'device.revoked': {
        state.advanceCursor(event.cursor);
        this.onDeviceRevoked?.(event.deviceId);
        if (event.deviceId === this.keyring.deviceId) {
          const userId = state.user?.id;
          if (userId) await this.storage.deleteAccount(userId);
          await this.handleSessionGone();
        }
        return;
      }
      case 'sync.cursor':
        state.advanceCursor(event.cursor);
        if (this.bootstrap) this.bootstrap = { ...this.bootstrap, cursor: Math.max(this.bootstrap.cursor, event.cursor) };
        return;
      case 'sync.ready': {
        state.applyEvent(event);
        if (this.bootstrap) {
          const allowed = new Set(event.vaultIds);
          this.bootstrap = {
            ...this.bootstrap,
            cursor: Math.max(this.bootstrap.cursor, event.cursor),
            vaults: this.bootstrap.vaults.filter((vault) => allowed.has(vault.id)),
            memberships: this.bootstrap.memberships.filter((membership) => allowed.has(membership.vaultId)),
            envelopes: this.bootstrap.envelopes.filter((envelope) => allowed.has(envelope.vaultId)),
            headers: this.bootstrap.headers.filter((header) => allowed.has(header.vaultId)),
            items: this.bootstrap.items.filter((item) => allowed.has(item.vaultId)),
          };
        }
        const currentState = this.store.getState();
        const phases = Object.entries(currentState.vaultCrypto)
          .filter(([vaultId]) => !currentState.pendingVaultAccessIds[vaultId])
          .map(([, crypto]) => crypto);
        currentState.setConnection('online');
        if (phases.some((crypto) => crypto.status === 'rekey_required')) {
          this.setPhase('rekey-blocked');
          this.outbox.setOnline(false);
        } else if (phases.some((crypto) => crypto.status !== 'e2ee')) {
          this.setPhase('migration-required');
          this.outbox.setOnline(false);
        } else {
          this.setPhase('unlocked-online');
          this.outbox.setOnline(true);
        }
        await this.persistSnapshot();
        this.scheduleAutomaticEnvelopeDelivery();
      }
    }
  }

  private async finishServerUnlock(): Promise<void> {
    const deviceId = this.keyring.deviceId;
    if (!deviceId) throw new Error('当前设备尚未初始化');
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const challenge = await this.api.createUnlockChallenge(deviceId);
        await this.api.completeCryptoUnlock(await this.keyring.signServerChallenge(challenge));
        return;
      } catch (error) {
        if (attempt === 0 && isRetryableUnlockTransportFailure(error)) continue;
        throw error;
      }
    }
  }

  private async refreshLockedCryptoContext(): Promise<void> {
    const profile = await this.api.cryptoProfile();
    if (!profile) throw new Error('当前账号安全信息不完整，请刷新后重试');
    const devices = await this.api.cryptoDevices();
    this.profile = profile;
    this.device = await this.selectDevice(profile, devices);
    const cached = await this.storage.getAccount(profile.userId);
    this.deviceBundle = this.device && cached?.device.id === this.device.id
      ? cached.deviceBundle
      : null;
  }

  private async applyUnlockedBootstrap(
    bootstrap: EncryptedBootstrapResponse,
    scheduleAutomaticEnvelopeDelivery = true,
  ): Promise<void> {
    const signerIds = [...new Set(bootstrap.envelopes.map((envelope) => envelope.signerUserId))];
    const embeddedProfiles = (bootstrap as EncryptedBootstrapResponse & {
      signerProfiles?: Array<{ userId: string; keyVersion: number; signingPublicKey: string }>;
    }).signerProfiles ?? [];
    const profiles = signerIds.length > 0 && this.online && embeddedProfiles.length === 0
      ? await this.api.cryptoPublicProfiles(signerIds)
      : embeddedProfiles;
    const projection = await this.keyring.decryptBootstrap(
      bootstrap,
      Object.fromEntries(profiles.map((profile) => [
        `${profile.userId}:${profile.keyVersion}`,
        profile.signingPublicKey,
      ])),
    );
    for (const state of Object.values(projection.vaultCrypto)) {
      if (projection.pendingVaultAccessIds?.[state.vaultId]) continue;
      const taskId = (state as typeof state & { rekeyTaskId?: string | null }).rekeyTaskId;
      if (taskId) this.rekeyTasks.set(state.vaultId, taskId);
    }
    this.store.getState().applyDecryptedBootstrap(projection);
    this.outbox.replayConflicts();
    const states = Object.entries(projection.vaultCrypto)
      .filter(([vaultId]) => !projection.pendingVaultAccessIds?.[vaultId])
      .map(([, state]) => state);
    const phase = states.some((state) => state.recoveryRequired || state.status === 'rekey_required')
      ? 'rekey-blocked'
      : states.some((state) => state.status !== 'e2ee')
        ? 'migration-required'
        : this.online
          ? 'unlocked-online'
          : 'unlocked-offline';
    this.store.getState().setConnection(this.online && this.sync ? 'connecting' : this.online ? 'online' : 'offline');
    this.outbox.setOnline(this.online && !this.sync);
    this.setPhase(phase);
    if (this.online) await this.persistSnapshot();
    if (this.online && this.sync) {
      this.sync.stop();
      this.sync.start();
    }
    if (this.online && scheduleAutomaticEnvelopeDelivery) {
      this.scheduleAutomaticEnvelopeDelivery();
      this.scheduleAutomaticRecoveryCoverage();
      this.scheduleAutomaticRecoveryCaseCompletion();
    }
  }

  private invalidateAutomaticEnvelopeDelivery(): void {
    this.automaticEnvelopeGeneration += 1;
    this.automaticEnvelopeRequests.clear();
    this.automaticRecoveryCoverageRequested = false;
    this.automaticRecoveryCaseRequested = false;
  }

  private automaticEnvelopeVaultIds(requestedVaultIds?: Iterable<string>): string[] {
    const bootstrap = this.bootstrap;
    const user = this.store.getState().user;
    if (!bootstrap || !user || !this.online || !this.keyring.isUnlocked) return [];
    const requested = requestedVaultIds ? new Set(requestedVaultIds) : null;
    return bootstrap.vaults
      .filter((vault) => vault.kind === 'team' && (!requested || requested.has(vault.id)))
      .filter((vault) => bootstrap.memberships.some((membership) =>
        membership.vaultId === vault.id &&
        membership.subjectKind === 'user' &&
        membership.subjectId === user.id &&
        membership.role === 'owner'))
      .filter((vault) => bootstrap.envelopes.some((envelope) =>
        envelope.vaultId === vault.id && envelope.capability === 'full'))
      .map((vault) => vault.id);
  }

  private scheduleAutomaticEnvelopeDelivery(requestedVaultIds?: Iterable<string>): void {
    for (const vaultId of this.automaticEnvelopeVaultIds(requestedVaultIds)) {
      this.automaticEnvelopeRequests.add(vaultId);
      if (this.automaticEnvelopeWorkers.has(vaultId)) continue;
      this.startAutomaticEnvelopeWorker(vaultId);
    }
  }

  private scheduleAutomaticRecoveryCoverage(): void {
    if (!this.online || !this.keyring.isUnlocked) return;
    this.automaticRecoveryCoverageRequested = true;
    if (this.automaticRecoveryCoverageWorker) return;
    const generation = this.automaticEnvelopeGeneration;
    const worker = this.runAutomaticRecoveryCoverage(generation)
      .catch(() => undefined)
      .finally(() => {
        if (this.automaticRecoveryCoverageWorker !== worker) return;
        this.automaticRecoveryCoverageWorker = null;
        if (
          this.automaticRecoveryCoverageRequested
          && generation === this.automaticEnvelopeGeneration
          && this.online
          && this.keyring.isUnlocked
        ) this.scheduleAutomaticRecoveryCoverage();
      });
    this.automaticRecoveryCoverageWorker = worker;
  }

  private async runAutomaticRecoveryCoverage(generation: number): Promise<void> {
    while (
      this.automaticRecoveryCoverageRequested
      && generation === this.automaticEnvelopeGeneration
      && this.online
      && this.keyring.isUnlocked
    ) {
      this.automaticRecoveryCoverageRequested = false;
      const keys = await this.api.recoveryKeys();
      const recoveryKey = keys.find((entry) => entry.status === 'staged')
        ?? keys.find((entry) => entry.status === 'active');
      if (!recoveryKey) return;
      const coverage = await this.api.recoveryCoverage(recoveryKey.id);
      let refreshRequired = false;
      for (const vault of coverage.vaults) {
        if (
          generation !== this.automaticEnvelopeGeneration
          || !this.online
          || !this.keyring.isUnlocked
        ) return;
        if (vault.covered || !vault.canManage || vault.epoch === null) continue;
        try {
          await this.distributeEnterpriseRecoveryEnvelope(recoveryKey, vault);
          refreshRequired = true;
        } catch (error) {
          if (error instanceof ApiRequestError && (error.status === 404 || error.status === 409)) {
            refreshRequired = true;
            continue;
          }
          return;
        }
      }
      if (refreshRequired) {
        await this.refresh(false).catch(() => undefined);
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new Event('mima:recovery-coverage-updated'));
        }
      }
    }
  }

  private scheduleAutomaticRecoveryCaseCompletion(): void {
    if (!this.online || !this.keyring.isUnlocked) return;
    this.automaticRecoveryCaseRequested = true;
    if (this.automaticRecoveryCaseWorker) return;
    const generation = this.automaticEnvelopeGeneration;
    const worker = this.runAutomaticRecoveryCaseCompletion(generation)
      .catch(() => undefined)
      .finally(() => {
        if (this.automaticRecoveryCaseWorker !== worker) return;
        this.automaticRecoveryCaseWorker = null;
        if (
          this.automaticRecoveryCaseRequested
          && generation === this.automaticEnvelopeGeneration
          && this.online
          && this.keyring.isUnlocked
        ) this.scheduleAutomaticRecoveryCaseCompletion();
      });
    this.automaticRecoveryCaseWorker = worker;
  }

  private async runAutomaticRecoveryCaseCompletion(generation: number): Promise<void> {
    this.automaticRecoveryCaseRequested = false;
    const user = this.requireUser();
    let cases = await this.api.recoveryCases();
    let refreshCases = false;
    let retryWaitingCase = false;
    for (const recoveryCase of cases.filter((entry) => (
      entry.targetUserId === user.id
      && entry.kind === 'interrupted_handoff'
      && entry.status === 'waiting_for_target'
    ))) {
      if (generation !== this.automaticEnvelopeGeneration || !this.online || !this.keyring.isUnlocked) return;
      try {
        await this.continueInterruptedHandoffRecoveryCase(recoveryCase);
        refreshCases = true;
      } catch (error) {
        if (error instanceof ApiRequestError && (error.status === 404 || error.status === 409)) {
          refreshCases = true;
        } else {
          retryWaitingCase = true;
        }
      }
    }
    if (refreshCases) cases = await this.api.recoveryCases();
    const activeCases = cases.filter((entry) => (
      entry.targetUserId === user.id
      && (entry.status === 'approved' || entry.status === 'processing')
    ));
    const shouldPollAgain = retryWaitingCase || cases.some((entry) => (
      entry.targetUserId === user.id
      && entry.kind === 'interrupted_handoff'
      && ['pending_approval', 'approved', 'processing'].includes(entry.status)
    ));
    for (const recoveryCase of activeCases) {
      if (generation !== this.automaticEnvelopeGeneration || !this.online || !this.keyring.isUnlocked) return;
      if (!recoveryCase.hasOfflineResult) continue;
      const transfer = await this.api.recoveryCaseTransfer(recoveryCase.id);
      if (!transfer) continue;
      const bootstrap = this.requireBootstrap();
      const recoveryKey = bootstrap.recoveryKey;
      if (!recoveryKey || recoveryKey.id !== recoveryCase.recoveryKeyId || recoveryKey.status !== 'active') continue;
      const approvedItems = recoveryCase.items.filter((item) => item.status === 'approved');
      const resultByRequestId = new Map(transfer.results.map((result) => [result.requestId, result]));
      const prepared: Array<{
        request: EnterpriseRecoveryRequest;
        completeRequest: Awaited<ReturnType<E2eeKeyringPort['prepareRecovery']>>;
      }> = [];
      try {
        for (const request of approvedItems) {
          const rawResult = resultByRequestId.get(request.id);
          const header = bootstrap.headers.find((entry) => entry.vaultId === request.vaultId);
          if (!rawResult || !header) throw new Error('恢复结果不完整');
          const completeRequest = await this.keyring.prepareRecovery(
            user.id,
            request,
            recoveryKey,
            header,
            parseOfflineRecoveryResult(rawResult),
            `rc-${recoveryCase.id}-${request.id}`,
          );
          prepared.push({ request, completeRequest });
        }
      } catch {
        await Promise.all(prepared.map(({ request }) => this.keyring.abortRecovery(request.id)));
        continue;
      }
      for (const { request, completeRequest } of prepared) {
        if (generation !== this.automaticEnvelopeGeneration || !this.online || !this.keyring.isUnlocked) {
          await Promise.all(prepared.map(({ request: pending }) => this.keyring.abortRecovery(pending.id)));
          return;
        }
        try {
          await this.api.completeRecovery(request.id, completeRequest);
          await this.keyring.commitRecovery(request.id);
        } catch {
          const latest = await this.api.recoveryCase(recoveryCase.id).catch(() => null);
          const latestItem = latest?.items.find((item) => item.id === request.id);
          if (latestItem?.status === 'completed') await this.keyring.commitRecovery(request.id);
          else await this.keyring.abortRecovery(request.id);
        }
      }
      await this.refresh(false).catch(() => undefined);
    }
    if (shouldPollAgain && generation === this.automaticEnvelopeGeneration) {
      setTimeout(() => {
        if (generation === this.automaticEnvelopeGeneration) this.scheduleAutomaticRecoveryCaseCompletion();
      }, 10_000);
    }
  }

  private startAutomaticEnvelopeWorker(vaultId: string): void {
    const generation = this.automaticEnvelopeGeneration;
    const worker = this.runAutomaticEnvelopeWorker(vaultId, generation)
      .catch(() => undefined)
      .finally(() => {
        if (this.automaticEnvelopeWorkers.get(vaultId) !== worker) return;
        this.automaticEnvelopeWorkers.delete(vaultId);
        if (
          this.automaticEnvelopeRequests.has(vaultId) &&
          this.automaticEnvelopeVaultIds([vaultId]).length > 0
        ) this.startAutomaticEnvelopeWorker(vaultId);
      });
    this.automaticEnvelopeWorkers.set(vaultId, worker);
  }

  private async runAutomaticEnvelopeWorker(vaultId: string, generation: number): Promise<void> {
    while (
      generation === this.automaticEnvelopeGeneration &&
      this.online &&
      this.keyring.isUnlocked &&
      this.automaticEnvelopeRequests.delete(vaultId)
    ) {
      const continueImmediately = await this.deliverPendingVaultEnvelopes(vaultId, generation);
      if (!continueImmediately) {
        if (generation === this.automaticEnvelopeGeneration) {
          this.automaticEnvelopeRequests.delete(vaultId);
        }
        return;
      }
    }
  }

  private async deliverPendingVaultEnvelopes(vaultId: string, generation: number): Promise<boolean> {
    let refreshRequired = false;
    try {
      const [tasks, transfer] = await Promise.all([
        this.api.vaultEnvelopeTasks(vaultId),
        this.api.ownershipTransfer(vaultId),
      ]);
      for (const task of tasks) {
        if (
          generation !== this.automaticEnvelopeGeneration ||
          !this.online ||
          !this.keyring.isUnlocked
        ) return false;
        if (
          task.status !== 'pending' ||
          !task.recipientProfile ||
          task.expectedProfileGeneration !== task.recipientProfile.keyVersion ||
          transfer?.envelopeTaskId === task.id
        ) continue;
        try {
          await this.completeEnvelopeTask(task, false, generation);
          refreshRequired = true;
        } catch (error) {
          if (error instanceof ApiRequestError && (error.status === 404 || error.status === 409)) {
            refreshRequired = true;
          }
          if (refreshRequired) await this.refresh(false).catch(() => undefined);
          return false;
        }
      }
      if (refreshRequired) await this.refresh(false);
      return true;
    } catch {
      if (refreshRequired) await this.refresh(false).catch(() => undefined);
      return false;
    }
  }

  private async waitForAutomaticEnvelopeDelivery(vaultId: string): Promise<void> {
    this.scheduleAutomaticEnvelopeDelivery([vaultId]);
    const worker = this.automaticEnvelopeWorkers.get(vaultId);
    if (worker) await worker;
  }

  private async persistSnapshot(): Promise<void> {
    if (!this.profile || !this.device || !this.deviceBundle || !this.bootstrap || !this.keyring.isUnlocked) return;
    const snapshot: EncryptedOfflineSnapshot = { bootstrap: this.bootstrap, contents: this.contents };
    const encryptedBootstrap = await this.keyring.encryptOfflineSnapshot(snapshot);
    await this.storage.putAccount({
      accountId: this.profile.userId,
      profile: this.profile,
      device: this.device,
      deviceBundle: this.deviceBundle,
      encryptedBootstrap,
      cachedAt: new Date().toISOString(),
    });
  }

  private async commitMainPasswordChange(
    previousProfile: UserCryptoProfile,
    request: RewrapCryptoProfileRequest,
  ): Promise<UserCryptoProfile> {
    try {
      const updated = await this.api.rewrapCryptoProfile(request);
      if (!matchesMainPasswordChange(updated, previousProfile, request)) {
        await this.storage.deleteAccountLocator(previousProfile.userId).catch(() => undefined);
        throw new Error(mainPasswordChangeUncertainMessage());
      }
      return updated;
    } catch (error) {
      if (!shouldReconcileMainPasswordChange(error)) throw error;

      let observed: UserCryptoProfile | null | undefined;
      try {
        observed = await this.api.cryptoProfile();
      } catch {
        observed = undefined;
      }
      if (observed && matchesMainPasswordChange(observed, previousProfile, request)) return observed;
      if (observed && sameCryptoProfile(observed, previousProfile)) throw error;
      if (error instanceof ApiRequestError && error.status === 409) throw error;

      await this.storage.deleteAccountLocator(previousProfile.userId).catch(() => undefined);
      throw new Error(mainPasswordChangeUncertainMessage());
    }
  }

  private async persistMainPasswordChangeCache(): Promise<boolean> {
    if (this.bootstrap) {
      try {
        await this.persistSnapshot();
        return true;
      } catch {
        // Fall through to a small online-only locator so a large snapshot cannot
        // strand the new main-password wrap or erase pending encrypted commands.
      }
    }
    const profile = this.profile;
    const device = this.device;
    const deviceBundle = this.deviceBundle;
    if (!profile || !device || !deviceBundle) return false;
    try {
      await this.storage.putAccount({
        accountId: profile.userId,
        profile,
        device,
        deviceBundle,
        encryptedBootstrap: null,
        cachedAt: new Date().toISOString(),
      });
    } catch {
      await this.storage.deleteAccountLocator(profile.userId).catch(() => undefined);
    }
    return false;
  }

  private adoptCompatibleProfile(profile: UserCryptoProfile | null): void {
    const current = this.profile;
    if (!profile || !current || profile.profileVersion < current.profileVersion) return;
    if (!sameCryptoIdentity(profile, current)) {
      throw new Error('账号安全信息已更新，请重新登录并解锁');
    }
    if (profile.profileVersion === current.profileVersion && !sameCryptoProfile(profile, current)) {
      throw new Error('账号安全信息出现冲突，请重新登录后再试');
    }
    this.profile = profile;
  }

  private async applyEncryptedItem(record: EncryptedItemMetadata): Promise<void> {
    this.cacheEncryptedItem(record);
    const item = await this.keyring.decryptMetadataRecord(record);
    const state = this.store.getState();
    state.applyEvent({ type: 'item.upserted', cursor: state.cursor, item });
    await this.persistSnapshot();
  }

  private cacheEncryptedItem(record: EncryptedItemMetadata): void {
    if (!this.bootstrap) return;
    this.bootstrap = {
      ...this.bootstrap,
      items: [
        ...this.bootstrap.items.filter((item) => item.itemId !== record.itemId),
        record,
      ],
    };
  }

  private cacheOptimisticContent(
    metadata: EncryptedItemMetadata,
    encryptedValue: import('@mima/contracts').CipherBlob,
    wrappedDek: import('@mima/contracts').CipherBlob,
    createdBy: string,
    recordVersion: number,
    secretVersion: number,
    createdAt: string,
  ): void {
    const response = {
      metadata,
      secret: {
        itemId: metadata.itemId,
        vaultId: metadata.vaultId,
        secretVersion,
        recordVersion,
        encryptedValue,
        createdAt,
        createdBy,
      },
      keyWrap: {
        itemId: metadata.itemId,
        vaultId: metadata.vaultId,
        secretVersion,
        keyEpoch: metadata.keyEpoch,
        wrappedDek,
        createdAt,
        createdBy,
      },
    } as EncryptedContentResponse;
    this.contents[contentCacheKey(metadata.itemId, secretVersion)] = response;
  }

  private deleteCachedContents(itemId: string): void {
    delete this.contents[itemId];
    for (const cacheKey of Object.keys(this.contents)) {
      if (cacheKey.startsWith(`${itemId}:`)) delete this.contents[cacheKey];
    }
  }

  private async selectDevice(
    profile: UserCryptoProfile,
    devices: CryptoDevice[],
  ): Promise<CryptoDevice | null> {
    const cached = await this.storage.getAccount(profile.userId);
    const cachedDevice = cached && devices.find(
      (device) =>
        device.id === cached.device.id &&
        device.revokedAt === null &&
        device.encryptionPublicKey === cached.deviceBundle.encryptionPublicKey &&
        device.signingPublicKey === cached.deviceBundle.signingPublicKey,
    );
    return cachedDevice ?? null;
  }

  private async enqueue(
    kind: PersistedEncryptedCommand['kind'],
    method: PersistedEncryptedCommand['method'],
    path: string,
    body: { idempotencyKey: string },
  ): Promise<void> {
    const accountId = this.requireUser().id;
    await this.outbox.enqueue({
      id: body.idempotencyKey,
      accountId,
      kind,
      method,
      path,
      body,
      createdAt: new Date().toISOString(),
    });
  }

  private async retainVersionConflict(
    kind: PersistedEncryptedCommand['kind'],
    method: PersistedEncryptedCommand['method'],
    path: string,
    body: { idempotencyKey: string },
    error: unknown,
  ): Promise<boolean> {
    if ((error as { status?: number }).status !== 409) return false;
    await this.outbox.retainConflict({
      id: body.idempotencyKey,
      accountId: this.requireUser().id,
      kind,
      method,
      path,
      body,
      createdAt: new Date().toISOString(),
    }, error);
    return true;
  }

  private async rollbackAfterMigrationFailure(
    vaultId: string,
    job: LegacyMigrationJob,
    error: unknown,
  ): Promise<Error> {
    const message = error instanceof Error ? error.message : '迁移处理失败';
    let rolledBack = false;
    try {
      const user = this.requireUser();
      const request = await this.keyring.migrationActionIntent(user.id, vaultId, job.id, 'rollback');
      await this.api.rollbackLegacyMigration(vaultId, request);
      rolledBack = true;
    } catch {
      rolledBack = false;
    } finally {
      await this.keyring.abortLegacyMigration(vaultId, job.id);
      this.preparedLegacyMigrations.delete(vaultId);
    }
    if (rolledBack) {
      await this.refresh().catch(() => undefined);
      return new Error(`${message}。服务器已恢复旧格式写入，待提交密钥已销毁`);
    }
    return new Error(`${message}。本地待提交密钥已销毁，但服务器可能仍处于冻结状态，请刷新后执行回滚`);
  }

  private setPhase(phase: SecurityPhase): SecurityPhase {
    this.store.getState().setSecurityPhase(phase);
    return phase;
  }

  private reconcileSecurityPhaseFromProjection(): void {
    const currentState = this.store.getState();
    const states = Object.entries(currentState.vaultCrypto)
      .filter(([vaultId]) => !currentState.pendingVaultAccessIds[vaultId])
      .map(([, state]) => state);
    if (states.some((state) => state.recoveryRequired || state.status === 'rekey_required')) {
      this.setPhase('rekey-blocked');
      return;
    }
    if (states.some((state) => state.status !== 'e2ee')) {
      this.setPhase('migration-required');
      return;
    }
    this.setPhase(this.online ? 'unlocked-online' : 'unlocked-offline');
  }

  private requireBootstrap(): EncryptedBootstrapResponse {
    if (!this.bootstrap) throw new Error('没有可用的密码库数据，请刷新后重试');
    return this.bootstrap;
  }

  private requireUser() {
    const user = this.store.getState().user;
    if (!user) throw new Error('登录状态已经失效');
    return user;
  }

  private requireAccessGeneration(vaultId: string): number {
    const generation = this.store.getState().vaultCrypto[vaultId]?.accessGeneration;
    if (generation === undefined) throw new Error('密码库成员版本缺失，请刷新后重试');
    return generation;
  }
}

function validateMainPassword(password: string): void {
  if (password.length < 12) throw new Error('主密码至少需要 12 个字符');
  if (password.length > 256) throw new Error('主密码不能超过 256 个字符');
}

function friendlyUnlockError(error: unknown): Error {
  if (error instanceof ApiRequestError) return error;
  const code = (error as { code?: string }).code;
  if (code === 'authentication_failed') return new Error('主密码不正确');
  return error instanceof Error ? error : new Error('解锁失败');
}

function shouldReconcileMainPasswordChange(error: unknown): boolean {
  return error instanceof ApiRequestError
    && (error.status === 0 || error.status === 409 || error.status >= 500);
}

function matchesMainPasswordChange(
  profile: UserCryptoProfile,
  previous: UserCryptoProfile,
  request: RewrapCryptoProfileRequest,
): boolean {
  return profile.profileVersion === request.expectedProfileVersion + 1
    && sameCryptoIdentity(profile, previous)
    && sameKdf(profile.kdf, request.kdf)
    && sameCipherBlob(profile.encryptedAccountBundle, request.encryptedAccountBundle);
}

function sameCryptoProfile(left: UserCryptoProfile, right: UserCryptoProfile): boolean {
  return left.profileVersion === right.profileVersion
    && sameCryptoIdentity(left, right)
    && sameKdf(left.kdf, right.kdf)
    && sameCipherBlob(left.encryptedAccountBundle, right.encryptedAccountBundle);
}

function sameCryptoIdentity(left: UserCryptoProfile, right: UserCryptoProfile): boolean {
  return left.userId === right.userId
    && left.keyVersion === right.keyVersion
    && left.suite === right.suite
    && left.encryptionPublicKey === right.encryptionPublicKey
    && left.signingPublicKey === right.signingPublicKey
    && left.recoveryEnabled === right.recoveryEnabled;
}

function sameKdf(
  left: UserCryptoProfile['kdf'],
  right: UserCryptoProfile['kdf'],
): boolean {
  return left.algorithm === right.algorithm
    && left.memoryKiB === right.memoryKiB
    && left.iterations === right.iterations
    && left.parallelism === right.parallelism
    && left.salt === right.salt
    && left.outputBytes === right.outputBytes;
}

function sameCipherBlob(
  left: UserCryptoProfile['encryptedAccountBundle'],
  right: UserCryptoProfile['encryptedAccountBundle'],
): boolean {
  return left.suite === right.suite
    && left.aadVersion === right.aadVersion
    && left.nonce === right.nonce
    && left.ciphertext === right.ciphertext;
}

function mainPasswordChangeUncertainMessage(): string {
  return '服务器可能已经接受主密码更新，但当前无法确认。请不要重复提交；恢复连接后重新打开页面，并先用新主密码解锁。';
}

function throwIfAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw signal.reason instanceof Error ? signal.reason : new Error('操作已取消');
}

function requireMigrationJob(
  status: LegacyMigrationStatusResponse,
  expectedStatus: LegacyMigrationJob['status'],
): LegacyMigrationJob {
  if (!status.job || status.status !== expectedStatus || status.job.status !== expectedStatus) {
    throw new Error(`迁移任务当前处于“${migrationStatusLabel(status.status)}”，不能执行这一步`);
  }
  return status.job;
}

function migrationStatusLabel(status: LegacyMigrationStatusResponse['status']): string {
  const labels: Record<LegacyMigrationStatusResponse['status'], string> = {
    pending: '尚未开始',
    preparing: '正在准备',
    frozen: '等待隔离迁移程序',
    encrypting: '等待浏览器转换',
    verifying: '核对完成，等待切换',
    cutover: '正在切换',
    complete: '已完成',
    failed: '失败',
  };
  return labels[status];
}

function browserDeviceName(): string {
  if (typeof navigator === 'undefined') return 'Web 浏览器';
  const platform = navigatorPlatform();
  return `${platform} 浏览器`;
}

function browserPlatform(): string {
  if (typeof navigator === 'undefined') return 'web';
  return `web:${navigatorPlatform()}`;
}

function contentCacheKey(itemId: string, secretVersion: number): string {
  return `${itemId}:${secretVersion}`;
}

function navigatorPlatform(): string {
  const data = navigator as Navigator & { userAgentData?: { platform?: string } };
  return data.userAgentData?.platform ?? navigator.platform ?? 'unknown';
}
