import type {
  AccountCryptoResetRequest,
  AtomicCreateEncryptedVaultRequest,
  AcceptVaultOwnershipTransferRequest,
  CancelVaultOwnershipTransferRequest,
  ActivateAccountCryptoResetRequest,
  ActivateAccountCryptoResetResponse,
  ApproveAccountCryptoResetRequest,
  ApproveEnterpriseRecoveryKeyRequest,
  ApproveEnterpriseRecoveryRequest,
  ApproveLegacyKeyRetirementRequest,
  AuthConfig,
  CancelAccountCryptoResetRequest,
  CompleteCryptoUnlockRequest,
  CompleteEnterpriseRecoveryRequest,
  CompleteLegacyKeyRetirementRequest,
  CompleteVaultEnvelopeTaskRequest,
  CreateAccountCryptoResetRequest,
  CreateCryptoProfileRequest,
  CreateEncryptedProjectRequest,
  CreatedEncryptedVault,
  DeleteEncryptedVaultRequest,
  DeleteEncryptedVaultResponse,
  DeleteUninitializedVaultRequest,
  CreateEncryptedItemRequest,
  CreateEnterpriseRecoveryRequest,
  DistributeEnterpriseRecoveryEnvelopeRequest,
  DistributeEnterpriseRecoveryEnvelopeResponse,
  CreateLegacyKeyRetirementRequest,
  CreateVaultOwnershipTransferRequest,
  CryptoDevice,
  CustomGroup,
  CustomGroupDetail,
  DirectoryResponse,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  EncryptedItemMetadata,
  EnterpriseRecoveryCandidate,
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
  EnterpriseRecoveryRequest,
  ExtensionSessionResponse,
  InitializeVaultCryptoRequest,
  LegacyKeyRetirementResponse,
  LoginRequest,
  PairingCodeResponse,
  RegisterEnterpriseRecoveryKeyRequest,
  RegisterCryptoDeviceRequest,
  RekeyMaterial,
  RekeyMaterialQuery,
  RemoveEncryptedMembershipRequest,
  RemoveEncryptedMembershipResponse,
  RevealPurpose,
  RevokeCryptoDeviceRequest,
  RewrapCryptoProfileRequest,
  RotateCryptoProfileRequest,
  RotateCryptoProfileResponse,
  RotateEncryptedSecretRequest,
  ActivateEnterpriseRecoveryKeyRequest,
  SecretVersionInfo,
  SessionInfo,
  SetEncryptedMembershipRequest,
  SetEncryptedMembershipResponse,
  UnlockChallenge,
  UpdateEncryptedItemRequest,
  UpdateEncryptedVaultHeaderRequest,
  UserCryptoProfile,
  UserSearchResponse,
  VaultCryptoState,
  VaultEnvelopeTask,
  VaultOwnershipTransfer,
  ZeroKnowledgeApiError,
  ZeroKnowledgeAuditEvent,
} from '@mima/contracts';
import { CSRF_HEADER, ZeroKnowledgeApiErrorSchema } from '@mima/contracts';
import { ApiRequestError } from './api-client.ts';
import type {
  ApproveExtensionEnrollmentRequest,
  ExtensionEnrollment,
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
import type { EncryptedDeleteItemRequest, PublicCryptoProfile } from './api-client.ts';

export class ZeroKnowledgeApiClient {
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

  setUnauthorizedHandler(handler: (() => void) | null): void {
    this.unauthorizedHandler = handler;
  }

  private async request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.csrfToken && method !== 'GET') headers[CSRF_HEADER] = this.csrfToken;
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        credentials: 'include',
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      });
    } catch (error) {
      if (signal?.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error('操作已取消');
      }
      throw new ApiRequestError(0, {
        message: error instanceof Error ? error.message : '网络错误',
      });
    }
    if (!response.ok) {
      let parsed: Partial<ZeroKnowledgeApiError> = {};
      try {
        const candidate = ZeroKnowledgeApiErrorSchema.partial().safeParse(await response.json());
        if (candidate.success) parsed = candidate.data;
      } catch {
        // Non-JSON proxy errors have no trusted response body.
      }
      const credentialCheck = (method === 'POST' && path === '/api/session')
        || path === '/api/v2/session/crypto-unlock';
      const sessionProbe = method === 'GET' && path === '/api/session';
      if (response.status === 401 && !credentialCheck && !sessionProbe) {
        this.unauthorizedHandler?.();
      }
      throw new ApiRequestError(response.status, parsed);
    }
    return (await response.json()) as T;
  }

  sendEncryptedCommand<T>(
    method: 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    path: string,
    body: unknown,
  ): Promise<T> {
    if (!path.startsWith('/api/v2/')) throw new Error('密文命令只能发送到 v2 API');
    return this.request(method, path, body);
  }

  login(request: LoginRequest): Promise<SessionInfo> {
    return this.request('POST', '/api/session', request);
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

  cryptoProfile(): Promise<UserCryptoProfile | null> {
    return this.request('GET', '/api/v2/crypto/profile');
  }

  accountCryptoResetRequests(
    query: { status?: string; targetUserId?: string } = {},
  ): Promise<AccountCryptoResetRequest[]> {
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

  distributeRecoveryEnvelope(
    keyId: string,
    vaultId: string,
    request: DistributeEnterpriseRecoveryEnvelopeRequest,
    signal?: AbortSignal,
  ): Promise<DistributeEnterpriseRecoveryEnvelopeResponse> {
    return this.request(
      'POST',
      `/api/v2/recovery/keys/${keyId}/vaults/${vaultId}/envelope`,
      request,
      signal,
    );
  }

  recoveryCandidates(): Promise<EnterpriseRecoveryCandidate[]> {
    return this.request('GET', '/api/v2/recovery/candidates');
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
  ): Promise<VaultCryptoState> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/initialize`, request);
  }

  updateEncryptedVaultHeader(
    vaultId: string,
    request: UpdateEncryptedVaultHeaderRequest,
  ): Promise<import('@mima/contracts').EncryptedVaultHeader> {
    return this.request('PATCH', `/api/v2/vaults/${vaultId}/header`, request);
  }

  legacyMigrationStatus(vaultId: string): Promise<LegacyMigrationStatusResponse> {
    return this.request('GET', `/api/v2/vaults/${vaultId}/migration`);
  }

  startLegacyMigration(
    vaultId: string,
    request: LegacyMigrationStartRequest,
  ): Promise<LegacyMigrationJob> {
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

  createEncryptedItem(
    vaultId: string,
    request: CreateEncryptedItemRequest,
  ): Promise<EncryptedItemMetadata> {
    return this.request('POST', `/api/v2/vaults/${vaultId}/items`, request);
  }

  updateEncryptedItem(
    itemId: string,
    request: UpdateEncryptedItemRequest,
  ): Promise<EncryptedItemMetadata> {
    return this.request('PATCH', `/api/v2/items/${itemId}`, request);
  }

  rotateEncryptedSecret(
    itemId: string,
    request: RotateEncryptedSecretRequest,
  ): Promise<EncryptedItemMetadata> {
    return this.request('PUT', `/api/v2/items/${itemId}/secret`, request);
  }

  deleteEncryptedItem(
    itemId: string,
    request: EncryptedDeleteItemRequest,
  ): Promise<EncryptedItemMetadata> {
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

  vaultAudit(vaultId: string): Promise<ZeroKnowledgeAuditEvent[]> {
    return this.request('GET', `/api/vaults/${vaultId}/audit`);
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

  createPairingCode(): Promise<PairingCodeResponse> {
    return this.request('POST', '/api/v2/extension/pairing');
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

  resumeExtensionSession(
    request: ResumeExtensionSessionRequest,
  ): Promise<ExtensionSessionResponse> {
    return this.request('POST', '/api/v2/extension/session/resume', request);
  }
}

type ZeroKnowledgeApiMethods = {
  [Key in keyof ZeroKnowledgeApiClient]: ZeroKnowledgeApiClient[Key];
};

export type ZeroKnowledgeApi = Omit<
  ZeroKnowledgeApiMethods,
  'recoveryCandidates' | 'updateEncryptedVaultHeader'
> & Partial<Pick<
  ZeroKnowledgeApiMethods,
  'recoveryCandidates' | 'updateEncryptedVaultHeader'
>>;

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
  return {
    id: stringField(record, 'id', 'enrollmentId'),
    deviceId: stringField(device, 'id', 'deviceId'),
    encryptionPublicKey: stringField(device, 'encryptionPublicKey'),
    signingPublicKey: stringField(device, 'signingPublicKey'),
    fingerprint: stringField(device, 'fingerprint'),
    joinChannelPublicKey: stringField(record, 'joinChannelPublicKey'),
    status: stringField(record, 'status') as ExtensionEnrollment['status'],
    expiresAt: stringField(record, 'expiresAt'),
  };
}

function stringField(record: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    if (typeof record[key] === 'string') return record[key] as string;
  }
  throw new Error(`扩展配对请求缺少字段：${keys[0]}`);
}
