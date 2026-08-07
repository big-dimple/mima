import type {
  ApiError,
  AuthConfig,
  BootstrapResponse,
  CreateItemRequest,
  DeleteItemRequest,
  ExtensionSessionResponse,
  ItemMeta,
  LoginRequest,
  Membership,
  PairingCodeResponse,
  RevealPurpose,
  RevealResponse,
  RotateSecretRequest,
  SecretVersionInfo,
  SessionInfo,
  SetMembershipRequest,
  RemoveMembershipRequest,
  UpdateItemMetaRequest,
  Vault,
  AuditEvent,
  AccountCryptoResetRequest,
  AtomicCreateEncryptedVaultRequest,
  AcceptVaultOwnershipTransferRequest,
  CancelVaultOwnershipTransferRequest,
  ActivateAccountCryptoResetRequest,
  ActivateAccountCryptoResetResponse,
  ActivateEnterpriseRecoveryKeyRequest,
  ApproveAccountCryptoResetRequest,
  ApproveEnterpriseRecoveryKeyRequest,
  ApproveEnterpriseRecoveryCaseRequest,
  CancelAccountCryptoResetRequest,
  CancelEnterpriseRecoveryKeyRequest,
  CancelEnterpriseRecoveryCaseRequest,
  CancelEnterpriseRecoveryRequest,
  CreateAccountCryptoResetRequest,
  DirectoryResponse,
  UserSearchResponse,
  CustomGroup,
  CustomGroupDetail,
  CompleteCryptoUnlockRequest,
  CreateCryptoProfileRequest,
  CreateEncryptedProjectRequest,
  CreatedEncryptedVault,
  CreateEncryptedItemRequest,
  DeleteEncryptedVaultRequest,
  DeleteEncryptedVaultResponse,
  DeleteUninitializedVaultRequest,
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  EncryptedItemMetadata,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryCase,
  EnterpriseRecoveryCasePackage,
  EnterpriseRecoveryCaseApprovalMaterial,
  EnterpriseRecoveryCaseTransfer,
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryReadiness,
  EnterpriseRecoveryCustodyShare,
  EnterpriseRecoveryRequest,
  EnterpriseRecoveryWorkspace,
  FinalizeEnterpriseRecoveryCaseRequest,
  CreateEnterpriseRecoveryRequest,
  CreateEnterpriseRecoveryCaseRequest,
  DistributeEnterpriseRecoveryEnvelopeRequest,
  DistributeEnterpriseRecoveryEnvelopeResponse,
  ApproveEnterpriseRecoveryRequest,
  CompleteEnterpriseRecoveryRequest,
  InitializeVaultCryptoRequest,
  RotateEncryptedSecretRequest,
  RotateCryptoProfileRequest,
  RotateCryptoProfileResponse,
  RegisterCryptoDeviceRequest,
  RegisterEnterpriseRecoveryKeyRequest,
  RegisterManagedEnterpriseRecoveryKeyRequest,
  UploadEnterpriseRecoveryCaseTransferRequest,
  RewrapCryptoProfileRequest,
  RekeyMaterial,
  RekeyMaterialQuery,
  RevokeCryptoDeviceRequest,
  UnlockChallenge,
  UpdateEncryptedItemRequest,
  UserCryptoProfile,
  VaultCryptoState,
  VaultEnvelopeTask,
  CompleteVaultEnvelopeTaskRequest,
  SetEncryptedMembershipRequest,
  SetEncryptedMembershipResponse,
  RemoveEncryptedMembershipRequest,
  RemoveEncryptedMembershipResponse,
  CreateVaultOwnershipTransferRequest,
  VaultOwnershipTransfer,
  ApproveLegacyKeyRetirementRequest,
  CompleteLegacyKeyRetirementRequest,
  CreateLegacyKeyRetirementRequest,
  LegacyKeyRetirementResponse,
} from '@mima/contracts';
import { CSRF_HEADER } from '@mima/contracts';
import type {
  ApproveExtensionEnrollmentRequest,
  ExtensionEnrollment,
  ExtensionPairingEnrollmentStatus,
  RekeyVaultCommitRequest,
  ResumeExtensionSessionRequest,
} from './e2ee-keyring.ts';
import type {
  LegacyMigrationActionRequest,
  LegacyMigrationCutoverResponse,
  LegacyMigrationExportClaimRequest,
  LegacyMigrationExportResponse,
  LegacyMigrationJob,
  LegacyMigrationStartRequest,
  LegacyMigrationStatusResponse,
  LegacyMigrationTargetRequest,
  LegacyMigrationUploadRequest,
  LegacyMigrationUploadResponse,
  LegacyMigrationVerifyRequest,
} from './legacy-migration.ts';

export class ApiRequestError extends Error {
  constructor(
    public status: number,
    public body: Partial<ApiError>,
  ) {
    super(body.message ?? `HTTP ${status}`);
  }
}

export function isConflict(err: unknown): err is ApiRequestError & { status: 409 } {
  return err instanceof ApiRequestError && err.status === 409;
}

/**
 * 基于 fetch 的 API 客户端。Cookie 会话 + CSRF 头；
 * 密码、Token 等敏感内容只短暂出现在 reveal() 的返回值中，不得写入状态或持久化缓存。
 */
export class ApiClient {
  private csrfToken: string | null = null;
  private unauthorizedHandler: (() => void) | null = null;
  private directoryCache: { value: DirectoryResponse; expiresAt: number } | null = null;
  private directoryInFlight: Promise<DirectoryResponse> | null = null;

  constructor(private baseUrl = '') {}

  setCsrfToken(token: string | null): void {
    this.csrfToken = token;
    if (token === null) this.clearSessionCaches();
  }

  clearSessionCaches(): void {
    this.directoryCache = null;
    this.directoryInFlight = null;
  }

  /** 任意请求返回 401（会话过期/被撤销）时回调。登录/解锁密码错误除外。 */
  setUnauthorizedHandler(handler: (() => void) | null): void {
    this.unauthorizedHandler = handler;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.csrfToken && method !== 'GET') headers[CSRF_HEADER] = this.csrfToken;
    let res: Response | undefined;
    const attempts = method === 'GET' ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        res = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers,
          credentials: 'include',
          body: body === undefined ? undefined : JSON.stringify(body),
        });
      } catch (err) {
        if (attempt + 1 < attempts) continue;
        throw new ApiRequestError(0, { message: err instanceof Error ? err.message : '网络错误' });
      }
      if (attempt + 1 < attempts && [502, 503, 504].includes(res.status)) continue;
      break;
    }
    if (!res) throw new ApiRequestError(0, { message: '网络错误' });
    if (!res.ok) {
      let parsed: Partial<ApiError> = {};
      try {
        parsed = (await res.json()) as Partial<ApiError>;
      } catch {
        /* 非 JSON 错误体 */
      }
      const credentialCheck =
        (method === 'POST' && path === '/api/session') ||
        path === '/api/session/unlock' ||
        path === '/api/v2/session/crypto-unlock';
      const sessionProbe = method === 'GET' && path === '/api/session';
      if (res.status === 401 && !credentialCheck && !sessionProbe) {
        this.unauthorizedHandler?.();
      }
      throw new ApiRequestError(res.status, parsed);
    }
    return (await res.json()) as T;
  }

  sendEncryptedCommand<T>(
    method: 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    path: string,
    body: unknown,
  ): Promise<T> {
    if (!path.startsWith('/api/v2/')) throw new Error('密文命令只能发送到 v2 API');
    return this.request(method, path, body);
  }

  // --- 会话 ---
  login(req: LoginRequest): Promise<SessionInfo> {
    return this.request('POST', '/api/session', req);
  }
  authConfig(): Promise<AuthConfig> {
    return this.request('GET', '/api/auth/config');
  }
  session(): Promise<SessionInfo> {
    return this.request('GET', '/api/session');
  }
  logout(): Promise<{ ok: boolean }> {
    return this.request('DELETE', '/api/session');
  }
  lock(): Promise<{ ok: boolean }> {
    return this.request('POST', '/api/session/lock');
  }
  unlock(password: string): Promise<{ ok: boolean }> {
    return this.request('POST', '/api/session/unlock', { password });
  }

  cryptoProfile(): Promise<UserCryptoProfile | null> {
    return this.request('GET', '/api/v2/crypto/profile');
  }
  accountCryptoResetRequests(query: { status?: string; targetUserId?: string } = {}): Promise<AccountCryptoResetRequest[]> {
    const params = new URLSearchParams();
    if (query.status) params.set('status', query.status);
    if (query.targetUserId) params.set('targetUserId', query.targetUserId);
    const suffix = params.size ? `?${params.toString()}` : '';
    return this.request('GET', `/api/v2/account-crypto-resets${suffix}`);
  }
  accountCryptoResetRequest(requestId: string): Promise<AccountCryptoResetRequest> {
    return this.request('GET', `/api/v2/account-crypto-resets/${requestId}`);
  }
  createAccountCryptoReset(request: CreateAccountCryptoResetRequest): Promise<AccountCryptoResetRequest> {
    return this.request('POST', '/api/v2/account-crypto-resets', request);
  }
  approveAccountCryptoReset(
    requestId: string,
    request: ApproveAccountCryptoResetRequest,
  ): Promise<AccountCryptoResetRequest> {
    return this.request('POST', `/api/v2/account-crypto-resets/${requestId}/approve`, request);
  }
  activateAccountCryptoReset(
    requestId: string,
    request: ActivateAccountCryptoResetRequest,
  ): Promise<ActivateAccountCryptoResetResponse> {
    return this.request('POST', `/api/v2/account-crypto-resets/${requestId}/activate`, request);
  }
  cancelAccountCryptoReset(
    requestId: string,
    request: CancelAccountCryptoResetRequest,
  ): Promise<AccountCryptoResetRequest> {
    return this.request('POST', `/api/v2/account-crypto-resets/${requestId}/cancel`, request);
  }
  createCryptoProfile(request: CreateCryptoProfileRequest): Promise<UserCryptoProfile> {
    return this.request('POST', '/api/v2/crypto/profile', request);
  }
  rewrapCryptoProfile(request: RewrapCryptoProfileRequest): Promise<UserCryptoProfile> {
    return this.request('PUT', '/api/v2/crypto/profile', request);
  }
  rotateCryptoProfile(request: RotateCryptoProfileRequest): Promise<RotateCryptoProfileResponse> {
    return this.request('POST', '/api/v2/crypto/profile/rotate', request);
  }
  cryptoDevices(): Promise<CryptoDevice[]> {
    return this.request('GET', '/api/v2/devices');
  }
  registerCryptoDevice(request: RegisterCryptoDeviceRequest): Promise<CryptoDevice> {
    return this.request('POST', '/api/v2/devices', request);
  }
  revokeCryptoDevice(
    deviceId: string,
    request: RevokeCryptoDeviceRequest,
  ): Promise<{ ok: true; rekeyVaultIds: string[] }> {
    return this.request('POST', `/api/v2/devices/${deviceId}/revoke`, request);
  }
  rekeyMaterial(vaultId: string, query: RekeyMaterialQuery): Promise<RekeyMaterial> {
    const params = new URLSearchParams({
      taskId: query.taskId,
      actorDeviceId: query.actorDeviceId,
      signature: query.signature,
    });
    return this.request('GET', `/api/v2/vaults/${vaultId}/rekey-material?${params.toString()}`);
  }
  commitVaultRekey(vaultId: string, request: RekeyVaultCommitRequest): Promise<VaultCryptoState> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/rekey`, request);
  }
  cryptoPublicProfiles(userIds: string[]): Promise<PublicCryptoProfile[]> {
    return this.request('POST', '/api/v2/crypto/public-profiles', { userIds });
  }
  vaultEnvelopeTasks(
    vaultId: string,
    status: 'pending' | 'completed' | 'cancelled' | 'all' = 'pending',
  ): Promise<VaultEnvelopeTask[]> {
    return this.request('GET', `/api/v2/vaults/${vaultId}/envelope-tasks?status=${status}`);
  }
  myEnvelopeTasks(
    status: 'pending' | 'completed' | 'cancelled' | 'all' = 'pending',
  ): Promise<VaultEnvelopeTask[]> {
    return this.request('GET', `/api/v2/envelope-tasks/mine?status=${status}`);
  }
  completeVaultEnvelopeTask(
    task: VaultEnvelopeTask,
    request: CompleteVaultEnvelopeTaskRequest,
  ): Promise<VaultEnvelopeTask> {
    return this.request(
      'POST',
      `/api/v2/vaults/${task.vaultId}/envelope-tasks/${task.id}/complete`,
      request,
    );
  }
  setEncryptedMembership(
    vaultId: string,
    request: SetEncryptedMembershipRequest,
  ): Promise<SetEncryptedMembershipResponse> {
    return this.request('PUT', `/api/v2/vaults/${vaultId}/members`, request);
  }
  removeEncryptedMembership(
    vaultId: string,
    request: RemoveEncryptedMembershipRequest,
  ): Promise<RemoveEncryptedMembershipResponse> {
    return this.request('DELETE', `/api/v2/vaults/${vaultId}/members`, request);
  }

  deleteEncryptedVault(
    vaultId: string,
    request: DeleteEncryptedVaultRequest,
  ): Promise<DeleteEncryptedVaultResponse> {
    return this.request('DELETE', `/api/v2/vaults/${vaultId}`, request);
  }
  ownershipTransfer(vaultId: string): Promise<VaultOwnershipTransfer | null> {
    return this.request('GET', `/api/v2/vaults/${vaultId}/ownership-transfer`);
  }
  createOwnershipTransfer(
    vaultId: string,
    request: CreateVaultOwnershipTransferRequest,
  ): Promise<VaultOwnershipTransfer> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/ownership-transfer`, request);
  }
  acceptOwnershipTransfer(
    vaultId: string,
    request: AcceptVaultOwnershipTransferRequest,
  ): Promise<VaultOwnershipTransfer> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/ownership-transfer/accept`, request);
  }
  cancelOwnershipTransfer(
    vaultId: string,
    request: CancelVaultOwnershipTransferRequest,
  ): Promise<VaultOwnershipTransfer> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/ownership-transfer/cancel`, request);
  }
  recoveryRequests(): Promise<EnterpriseRecoveryRequest[]> {
    return this.request('GET', '/api/v2/recovery/requests');
  }
  recoveryCases(): Promise<EnterpriseRecoveryCase[]> {
    return this.request('GET', '/api/v2/recovery/cases');
  }
  recoveryCase(caseId: string): Promise<EnterpriseRecoveryCase> {
    return this.request('GET', `/api/v2/recovery/cases/${caseId}`);
  }
  createRecoveryCase(request: CreateEnterpriseRecoveryCaseRequest): Promise<EnterpriseRecoveryCase> {
    return this.request('POST', '/api/v2/recovery/cases', request);
  }
  finalizeRecoveryCase(
    caseId: string,
    request: FinalizeEnterpriseRecoveryCaseRequest,
  ): Promise<EnterpriseRecoveryCase> {
    return this.request('POST', `/api/v2/recovery/cases/${caseId}/target`, request);
  }
  approveRecoveryCase(
    caseId: string,
    request: ApproveEnterpriseRecoveryCaseRequest,
  ): Promise<EnterpriseRecoveryCase> {
    return this.request('POST', `/api/v2/recovery/cases/${caseId}/approve`, request);
  }
  cancelRecoveryCase(
    caseId: string,
    request: CancelEnterpriseRecoveryCaseRequest,
  ): Promise<EnterpriseRecoveryCase> {
    return this.request('POST', `/api/v2/recovery/cases/${caseId}/cancel`, request);
  }
  recoveryCasePackage(caseId: string): Promise<EnterpriseRecoveryCasePackage> {
    return this.request('GET', `/api/v2/recovery/cases/${caseId}/package`);
  }
  recoveryCaseApprovalMaterial(caseId: string): Promise<EnterpriseRecoveryCaseApprovalMaterial> {
    return this.request('GET', `/api/v2/recovery/cases/${caseId}/approval-material`);
  }
  uploadRecoveryCaseTransfer(
    caseId: string,
    request: UploadEnterpriseRecoveryCaseTransferRequest,
  ): Promise<EnterpriseRecoveryCase> {
    return this.request('POST', `/api/v2/recovery/cases/${caseId}/transfers`, request);
  }
  recoveryCaseTransfer(caseId: string): Promise<EnterpriseRecoveryCaseTransfer | null> {
    return this.request('GET', `/api/v2/recovery/cases/${caseId}/transfer`);
  }
  recoveryWorkspace(): Promise<EnterpriseRecoveryWorkspace> {
    return this.request('GET', '/api/v2/recovery/workspace');
  }
  recoveryKey(): Promise<EnterpriseRecoveryKey | null> {
    return this.request('GET', '/api/v2/recovery/key');
  }
  recoveryKeys(): Promise<EnterpriseRecoveryKey[]> {
    return this.request('GET', '/api/v2/recovery/keys');
  }
  recoveryReadiness(): Promise<EnterpriseRecoveryReadiness> {
    return this.request('GET', '/api/v2/recovery/readiness');
  }
  recoveryCoverage(keyId: string): Promise<EnterpriseRecoveryCoverage> {
    return this.request('GET', `/api/v2/recovery/keys/${keyId}/coverage`);
  }
  registerRecoveryKey(request: RegisterEnterpriseRecoveryKeyRequest): Promise<EnterpriseRecoveryKey> {
    return this.request('POST', '/api/v2/recovery/key', request);
  }
  registerManagedRecoveryKey(
    request: RegisterManagedEnterpriseRecoveryKeyRequest,
  ): Promise<EnterpriseRecoveryKey> {
    return this.request('POST', '/api/v2/recovery/custody', request);
  }
  recoveryCustodyShare(keyId: string): Promise<EnterpriseRecoveryCustodyShare> {
    return this.request('GET', `/api/v2/recovery/keys/${keyId}/custody/share`);
  }
  approveRecoveryKey(
    keyId: string,
    request: ApproveEnterpriseRecoveryKeyRequest,
  ): Promise<EnterpriseRecoveryKey> {
    return this.request('POST', `/api/v2/recovery/keys/${keyId}/approve`, request);
  }
  activateRecoveryKey(
    keyId: string,
    request: ActivateEnterpriseRecoveryKeyRequest,
  ): Promise<EnterpriseRecoveryKey> {
    return this.request('POST', `/api/v2/recovery/keys/${keyId}/activate`, request);
  }
  cancelRecoveryKey(
    keyId: string,
    request: CancelEnterpriseRecoveryKeyRequest,
  ): Promise<EnterpriseRecoveryKey> {
    return this.request('POST', `/api/v2/recovery/keys/${keyId}/cancel`, request);
  }
  distributeRecoveryEnvelope(
    keyId: string,
    vaultId: string,
    request: DistributeEnterpriseRecoveryEnvelopeRequest,
  ): Promise<DistributeEnterpriseRecoveryEnvelopeResponse> {
    return this.request('POST', `/api/v2/recovery/keys/${keyId}/vaults/${vaultId}/envelope`, request);
  }
  recoveryPackage(requestId: string): Promise<unknown> {
    return this.request('GET', `/api/v2/recovery/requests/${requestId}/package`);
  }
  createRecoveryRequest(request: CreateEnterpriseRecoveryRequest): Promise<EnterpriseRecoveryRequest> {
    return this.request('POST', '/api/v2/recovery/requests', request);
  }
  approveRecoveryRequest(
    requestId: string,
    request: ApproveEnterpriseRecoveryRequest,
  ): Promise<EnterpriseRecoveryRequest> {
    return this.request('POST', `/api/v2/recovery/requests/${requestId}/approve`, request);
  }
  cancelRecoveryRequest(
    requestId: string,
    request: CancelEnterpriseRecoveryRequest,
  ): Promise<EnterpriseRecoveryRequest> {
    return this.request('POST', `/api/v2/recovery/requests/${requestId}/cancel`, request);
  }
  completeRecovery(
    requestId: string,
    request: CompleteEnterpriseRecoveryRequest,
  ): Promise<EnterpriseRecoveryRequest> {
    return this.request('POST', `/api/v2/recovery/requests/${requestId}/complete`, request);
  }
  createUnlockChallenge(deviceId: string): Promise<UnlockChallenge> {
    return this.request('POST', '/api/v2/session/unlock-challenge', { deviceId });
  }
  completeCryptoUnlock(request: CompleteCryptoUnlockRequest): Promise<{ ok: true; deviceId: string }> {
    return this.request('POST', '/api/v2/session/crypto-unlock', request);
  }
  beginOidcReauthentication(): Promise<{ redirectUrl: string }> {
    return this.request('POST', '/api/session/reauth');
  }
  devUsers(): Promise<{ mode: string; users: { username: string; displayName: string }[] }> {
    return this.request('GET', '/api/auth/dev-users');
  }
  async directory(): Promise<DirectoryResponse> {
    if (this.directoryCache && this.directoryCache.expiresAt > Date.now()) {
      return this.directoryCache.value;
    }
    if (this.directoryInFlight) return this.directoryInFlight;

    const pending = this.request<DirectoryResponse>('GET', '/api/directory');
    this.directoryInFlight = pending;
    try {
      const value = await pending;
      this.directoryCache = { value, expiresAt: Date.now() + 60_000 };
      return value;
    } finally {
      if (this.directoryInFlight === pending) this.directoryInFlight = null;
    }
  }
  searchUsers(query: string, includeIds: string[] = [], limit = 50): Promise<UserSearchResponse> {
    const params = new URLSearchParams({ q: query, limit: String(limit) });
    if (includeIds.length > 0) params.set('includeIds', includeIds.join(','));
    return this.request('GET', `/api/users/search?${params.toString()}`);
  }
  groups(scope: 'owned' | 'joined', query = '', limit = 50): Promise<CustomGroup[]> {
    const params = new URLSearchParams({ scope, q: query, limit: String(limit) });
    return this.request('GET', `/api/groups?${params.toString()}`);
  }
  group(groupId: string): Promise<CustomGroupDetail> {
    return this.request('GET', `/api/groups/${groupId}`);
  }
  createGroup(name: string, memberUserIds: string[], idempotencyKey: string): Promise<CustomGroupDetail> {
    return this.request('POST', '/api/groups', { name, memberUserIds, idempotencyKey });
  }
  updateGroup(
    groupId: string,
    expectedRevision: string,
    name: string,
    memberUserIds: string[],
    idempotencyKey: string,
  ): Promise<CustomGroupDetail> {
    return this.request('PUT', `/api/groups/${groupId}`, {
      expectedRevision, name, memberUserIds, idempotencyKey,
    });
  }
  renameGroup(groupId: string, expectedRevision: string, name: string, idempotencyKey: string): Promise<{ ok: boolean }> {
    return this.request('PATCH', `/api/groups/${groupId}`, { expectedRevision, name, idempotencyKey });
  }
  setGroupMembers(groupId: string, expectedRevision: string, memberUserIds: string[], idempotencyKey: string): Promise<{ ok: boolean }> {
    return this.request('PUT', `/api/groups/${groupId}/members`, { expectedRevision, memberUserIds, idempotencyKey });
  }
  transferGroup(groupId: string, expectedRevision: string, newOwnerUserId: string, idempotencyKey: string): Promise<{ ok: boolean }> {
    return this.request('POST', `/api/groups/${groupId}/transfer`, { expectedRevision, newOwnerUserId, idempotencyKey });
  }
  deleteGroup(groupId: string, expectedRevision: string, idempotencyKey: string): Promise<{ ok: boolean }> {
    return this.request('DELETE', `/api/groups/${groupId}`, { expectedRevision, idempotencyKey });
  }

  // --- 数据 ---
  bootstrap(): Promise<BootstrapResponse> {
    return this.request('GET', '/api/bootstrap');
  }
  encryptedBootstrap(): Promise<EncryptedBootstrapResponse> {
    return this.request('GET', '/api/v2/bootstrap');
  }
  legacyKeyRetirementStatus(): Promise<LegacyKeyRetirementResponse> {
    return this.request('GET', '/api/v2/legacy-key-retirement');
  }
  createLegacyKeyRetirement(
    request: CreateLegacyKeyRetirementRequest,
  ): Promise<LegacyKeyRetirementResponse> {
    return this.request('POST', '/api/v2/legacy-key-retirement', request);
  }
  approveLegacyKeyRetirement(
    request: ApproveLegacyKeyRetirementRequest,
  ): Promise<LegacyKeyRetirementResponse> {
    return this.request('POST', '/api/v2/legacy-key-retirement/approve', request);
  }
  completeLegacyKeyRetirement(
    request: CompleteLegacyKeyRetirementRequest,
  ): Promise<LegacyKeyRetirementResponse> {
    return this.request('POST', '/api/v2/legacy-key-retirement/complete', request);
  }
  createEncryptedVault(request: AtomicCreateEncryptedVaultRequest): Promise<CreatedEncryptedVault> {
    return this.request('POST', '/api/v2/vaults', request);
  }
  createEncryptedProject(
    parentVaultId: string,
    request: CreateEncryptedProjectRequest,
  ): Promise<CreatedEncryptedVault> {
    return this.request('POST', `/api/v2/vaults/${parentVaultId}/projects`, request);
  }
  deleteUninitializedVault(
    vaultId: string,
    request: DeleteUninitializedVaultRequest,
  ): Promise<DeleteEncryptedVaultResponse> {
    return this.request('DELETE', `/api/v2/vaults/${vaultId}/uninitialized`, request);
  }
  initializeVaultCrypto(
    vaultId: string,
    request: InitializeVaultCryptoRequest,
  ): Promise<import('@mima/contracts').VaultCryptoState> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/initialize`, request);
  }
  legacyMigrationStatus(vaultId: string): Promise<LegacyMigrationStatusResponse> {
    return this.request('GET', `/api/v2/vaults/${vaultId}/migration`);
  }
  startLegacyMigration(vaultId: string, request: LegacyMigrationStartRequest): Promise<LegacyMigrationJob> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/start`, request);
  }
  claimLegacyMigrationExport(
    vaultId: string,
    request: LegacyMigrationExportClaimRequest,
  ): Promise<LegacyMigrationExportResponse> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/export`, request);
  }
  submitLegacyMigrationTarget(
    vaultId: string,
    request: LegacyMigrationTargetRequest,
  ): Promise<{ ok: true; jobId: string }> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/target`, request);
  }
  uploadLegacyMigrationRecords(
    vaultId: string,
    request: LegacyMigrationUploadRequest,
  ): Promise<LegacyMigrationUploadResponse> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/records`, request);
  }
  verifyLegacyMigration(
    vaultId: string,
    request: LegacyMigrationVerifyRequest,
  ): Promise<LegacyMigrationStatusResponse> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/verify`, request);
  }
  cutoverLegacyMigration(
    vaultId: string,
    request: LegacyMigrationActionRequest,
  ): Promise<LegacyMigrationCutoverResponse> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/cutover`, request);
  }
  rollbackLegacyMigration(
    vaultId: string,
    request: LegacyMigrationActionRequest,
  ): Promise<{ ok: true }> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/migration/rollback`, request);
  }
  createEncryptedItem(vaultId: string, request: CreateEncryptedItemRequest): Promise<EncryptedItemMetadata> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/items`, request);
  }
  updateEncryptedItem(itemId: string, request: UpdateEncryptedItemRequest): Promise<EncryptedItemMetadata> {
    return this.request('PATCH', `/api/v2/items/${itemId}`, request);
  }
  rotateEncryptedSecret(itemId: string, request: RotateEncryptedSecretRequest): Promise<EncryptedItemMetadata> {
    return this.request('PUT', `/api/v2/items/${itemId}/secret`, request);
  }
  deleteEncryptedItem(itemId: string, request: EncryptedDeleteItemRequest): Promise<EncryptedItemMetadata> {
    return this.request('DELETE', `/api/v2/items/${itemId}`, request);
  }
  encryptedContent(
    itemId: string,
    request: {
      purpose: RevealPurpose;
      secretVersion?: number;
      deviceId: string;
      intentSignature: string;
    },
  ): Promise<EncryptedContentResponse> {
    return this.request('POST', `/api/v2/items/${itemId}/content`, request);
  }
  createVault(name: string, idempotencyKey: string): Promise<Vault> {
    return this.request('POST', '/api/vaults', { name, idempotencyKey });
  }
  renameVault(vaultId: string, name: string, idempotencyKey: string): Promise<Vault> {
    return this.request('PATCH', `/api/vaults/${vaultId}`, { name, idempotencyKey });
  }
  deleteVault(vaultId: string, idempotencyKey: string): Promise<{ ok: boolean }> {
    return this.request('DELETE', `/api/vaults/${vaultId}`, { idempotencyKey });
  }
  vaultMembers(vaultId: string): Promise<Membership[]> {
    return this.request('GET', `/api/vaults/${vaultId}/members`);
  }
  setMembership(vaultId: string, req: SetMembershipRequest): Promise<{ ok: boolean }> {
    return this.request('PUT', `/api/vaults/${vaultId}/members`, req);
  }
  removeMembership(vaultId: string, req: RemoveMembershipRequest): Promise<{ ok: boolean }> {
    return this.request('DELETE', `/api/vaults/${vaultId}/members`, req);
  }
  /** 原子转移所有权：新 owner 设为直接用户 owner，调用者（原 owner）降为 editor。 */
  transferOwnership(vaultId: string, newOwnerUserId: string, idempotencyKey: string): Promise<{ ok: boolean }> {
    return this.request('POST', `/api/vaults/${vaultId}/transfer`, { newOwnerUserId, idempotencyKey });
  }
  vaultAudit(vaultId: string): Promise<AuditEvent[]> {
    return this.request('GET', `/api/vaults/${vaultId}/audit`);
  }
  createItem(vaultId: string, req: CreateItemRequest): Promise<ItemMeta> {
    return this.request('POST', `/api/vaults/${vaultId}/items`, req);
  }
  updateItemMeta(itemId: string, req: UpdateItemMetaRequest): Promise<ItemMeta> {
    return this.request('PATCH', `/api/items/${itemId}`, req);
  }
  rotateSecret(itemId: string, req: RotateSecretRequest): Promise<ItemMeta> {
    return this.request('PUT', `/api/items/${itemId}/secret`, req);
  }
  deleteItem(itemId: string, req: DeleteItemRequest): Promise<{ ok: boolean }> {
    return this.request('DELETE', `/api/items/${itemId}`, req);
  }
  itemVersions(itemId: string): Promise<SecretVersionInfo[]> {
    return this.request<EncryptedVersionInfo[]>('GET', `/api/v2/items/${itemId}/versions`).then(
      (versions) => versions.map((version) => ({
        itemId: version.itemId,
        secretVersion: version.secretVersion,
        keyVersion: `record-${version.recordVersion}`,
        createdAt: version.createdAt,
        createdBy: version.createdByDeviceId,
      })),
    );
  }
  reveal(itemId: string, purpose: RevealPurpose, secretVersion?: number): Promise<RevealResponse> {
    return this.request('POST', `/api/items/${itemId}/reveal`, { purpose, secretVersion });
  }

  // --- 扩展配对 ---
  createPairingCode(): Promise<PairingCodeResponse> {
    return this.request('POST', '/api/v2/extension/pairing');
  }
  extensionPairingStatus(code: string): Promise<ExtensionPairingEnrollmentStatus> {
    return this.request<unknown>('POST', '/api/v2/extension/pairing/status', { code }).then(
      normalizeExtensionPairingStatus,
    );
  }
  extensionEnrollments(): Promise<ExtensionEnrollment[]> {
    return this.request<unknown[]>('GET', '/api/v2/extension/enrollments').then(
      (values) => values.map(normalizeExtensionEnrollment),
    );
  }
  approveExtensionEnrollment(
    enrollmentId: string,
    request: ApproveExtensionEnrollmentRequest,
  ): Promise<{ ok: true; status: 'approved' }> {
    return this.request('POST', `/api/v2/extension/enrollments/${enrollmentId}/approve`, request);
  }
  resumeExtensionSession(request: ResumeExtensionSessionRequest): Promise<ExtensionSessionResponse> {
    return this.request('POST', '/api/v2/extension/session/resume', request);
  }
  claimPairingCode(code: string): Promise<ExtensionSessionResponse> {
    return this.request('POST', '/api/extension/sessions', { code });
  }
}

export interface PublicCryptoProfile {
  userId: string;
  keyVersion: number;
  encryptionPublicKey: string;
  signingPublicKey: string;
}

export interface EncryptedDeleteItemRequest {
  idempotencyKey: string;
  expectedVersion: number;
  keyEpoch: number;
  metadata: import('@mima/contracts').CipherBlob;
  actorDeviceId: string;
  signature: string;
}

interface EncryptedVersionInfo {
  itemId: string;
  secretVersion: number;
  recordVersion: number;
  createdAt: string;
  createdByDeviceId: string;
}

function normalizeExtensionEnrollment(value: unknown): ExtensionEnrollment {
  if (typeof value !== 'object' || value === null) throw new Error('扩展配对请求格式不正确');
  const record = value as Record<string, unknown>;
  const device = typeof record.device === 'object' && record.device !== null
    ? record.device as Record<string, unknown>
    : record;
  const id = stringField(record, 'id', 'enrollmentId');
  return {
    id,
    deviceId: stringField(device, 'id', 'deviceId'),
    encryptionPublicKey: stringField(device, 'encryptionPublicKey'),
    signingPublicKey: stringField(device, 'signingPublicKey'),
    fingerprint: stringField(device, 'fingerprint'),
    joinChannelPublicKey: stringField(record, 'joinChannelPublicKey'),
    status: stringField(record, 'status') as ExtensionEnrollment['status'],
    expiresAt: stringField(record, 'expiresAt'),
  };
}

function normalizeExtensionPairingStatus(value: unknown): ExtensionPairingEnrollmentStatus {
  if (typeof value !== 'object' || value === null) throw new Error('扩展配对状态格式不正确');
  const record = value as Record<string, unknown>;
  const status = stringField(record, 'status');
  if (status !== 'waiting' && status !== 'claimed' && status !== 'expired') {
    throw new Error('扩展配对状态不受支持');
  }
  return {
    status,
    enrollment: record.enrollment === null ? null : normalizeExtensionEnrollment(record.enrollment),
  };
}

function stringField(record: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    if (typeof record[key] === 'string') return record[key] as string;
  }
  throw new Error(`扩展配对请求缺少字段：${keys[0]}`);
}
