import { z } from 'zod';

// ---------------------------------------------------------------------------
// 基础枚举
// ---------------------------------------------------------------------------

/** 库内成员角色。platform-admin 是数据库直授的系统角色，不是库角色。 */
export const MembershipRoleSchema = z.enum(['viewer', 'editor', 'owner', 'auditor']);
export type MembershipRole = z.infer<typeof MembershipRoleSchema>;

/** 全局展示用角色集合（含 platform-admin）。 */
export const RoleSchema = z.enum(['viewer', 'editor', 'owner', 'auditor', 'platform-admin']);
export type Role = z.infer<typeof RoleSchema>;

export const VaultKindSchema = z.enum(['personal', 'team']);
export type VaultKind = z.infer<typeof VaultKindSchema>;

export const ItemKindSchema = z.enum(['login', 'api_token', 'secure_note']);
export type ItemKind = z.infer<typeof ItemKindSchema>;

export const SensitivitySchema = z.enum(['low', 'medium', 'high']);
export type Sensitivity = z.infer<typeof SensitivitySchema>;

export const SubjectKindSchema = z.enum(['user', 'group', 'custom_group']);
export type SubjectKind = z.infer<typeof SubjectKindSchema>;

export const RevealPurposeSchema = z.enum(['view', 'copy', 'fill']);
export type RevealPurpose = z.infer<typeof RevealPurposeSchema>;

export const E2EE_SUITE = 'lm-e2ee-v1' as const;
export const E2EESuiteSchema = z.literal(E2EE_SUITE);
export type E2EESuite = z.infer<typeof E2EESuiteSchema>;

export const Base64UrlSchema = z
  .string()
  .min(1)
  .max(200_000)
  .regex(/^[A-Za-z0-9_-]+$/, 'must be unpadded base64url');

export const Argon2idParamsSchema = z.object({
  algorithm: z.literal('argon2id13'),
  memoryKiB: z.literal(65_536),
  iterations: z.literal(3),
  parallelism: z.literal(1),
  salt: Base64UrlSchema,
  outputBytes: z.literal(32),
});
export type Argon2idParams = z.infer<typeof Argon2idParamsSchema>;

export const CipherBlobSchema = z.object({
  suite: E2EESuiteSchema,
  aadVersion: z.literal(1),
  nonce: Base64UrlSchema,
  ciphertext: Base64UrlSchema,
});
export type CipherBlob = z.infer<typeof CipherBlobSchema>;

export const CryptoCapabilitySchema = z.enum(['metadata', 'full', 'recovery']);
export type CryptoCapability = z.infer<typeof CryptoCapabilitySchema>;

export const VaultCryptoStatusSchema = z.enum([
  'legacy',
  'preparing',
  'frozen',
  'encrypting',
  'verifying',
  'e2ee',
  'rekey_required',
]);
export type VaultCryptoStatus = z.infer<typeof VaultCryptoStatusSchema>;

// ---------------------------------------------------------------------------
// 核心实体（全部不含敏感内容正文）
// ---------------------------------------------------------------------------

export const SessionUserSchema = z.object({
  id: z.string(),
  username: z.string(),
  displayName: z.string(),
  email: z.string(),
  groups: z.array(z.string()),
  isPlatformAdmin: z.boolean(),
  isLocalPlatformAdmin: z.boolean().optional(),
});
export type SessionUser = z.infer<typeof SessionUserSchema>;

export const VAULT_HEADER_FORMAT_VERSION = 3 as const;
const VaultHeaderFormatVersionSchema = z.union([
  z.literal(2),
  z.literal(VAULT_HEADER_FORMAT_VERSION),
]);

export const VaultProjectContextSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('root') }),
  z.object({
    kind: z.literal('project'),
    visibleParentVaultId: z.string().uuid().nullable(),
  }),
]);
export type VaultProjectContext = z.infer<typeof VaultProjectContextSchema>;

export const VaultSchema = z.object({
  id: z.string().uuid(),
  kind: VaultKindSchema,
  name: z.string().min(1).max(120),
  ownerUserId: z.string().nullable(),
  /** 旧服务可能暂不返回；新服务对团队库始终返回访问范围内的项目上下文。 */
  projectContext: VaultProjectContextSchema.optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type Vault = z.infer<typeof VaultSchema>;

export const MembershipSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  subjectKind: SubjectKindSchema,
  subjectId: z.string().min(1),
  role: MembershipRoleSchema,
  createdAt: z.string(),
});
export type Membership = z.infer<typeof MembershipSchema>;

/** 凭证条目元数据。敏感内容正文永远单独通过 Reveal 获取。 */
export const ItemMetaSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  kind: ItemKindSchema,
  title: z.string().min(1).max(200),
  /** 登录用户名 / Token 标签，纯元数据。 */
  username: z.string().max(200).nullable(),
  /** 网站地址 Origin（scheme://host[:port]），仅 login 类型使用。 */
  origin: z.string().max(300).nullable(),
  tags: z.array(z.string().min(1).max(40)).max(20),
  favorite: z.boolean(),
  sensitivity: SensitivitySchema,
  /** 条目乐观并发版本，任何写操作 +1。 */
  version: z.number().int().positive(),
  /** 当前内容版本号（= 最近一次敏感内容写入时的条目版本）。 */
  secretVersion: z.number().int().positive(),
  createdAt: z.string(),
  updatedAt: z.string(),
  updatedBy: z.string(),
});
export type ItemMeta = z.infer<typeof ItemMetaSchema>;

export const SecretVersionInfoSchema = z.object({
  itemId: z.string().uuid(),
  secretVersion: z.number().int().positive(),
  keyVersion: z.string(),
  createdAt: z.string(),
  createdBy: z.string(),
});
export type SecretVersionInfo = z.infer<typeof SecretVersionInfoSchema>;

export const AuditEventSchema = z.object({
  id: z.number().int(),
  ts: z.string(),
  actorUserId: z.string().nullable(),
  action: z.string(),
  vaultId: z.string().nullable(),
  itemId: z.string().nullable(),
  success: z.boolean(),
  details: z.record(z.unknown()),
  prevHash: z.string(),
  hash: z.string(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

export const ZeroKnowledgeAuditEventSchema = AuditEventSchema.extend({
  details: z.object({}).strict(),
});
export type ZeroKnowledgeAuditEvent = z.infer<typeof ZeroKnowledgeAuditEventSchema>;

// ---------------------------------------------------------------------------
// 零知识加密实体。服务端只保存密文、公钥、签名和路由元数据。
// ---------------------------------------------------------------------------

export const UserCryptoProfileSchema = z.object({
  userId: z.string(),
  profileVersion: z.number().int().positive(),
  keyVersion: z.number().int().positive(),
  suite: E2EESuiteSchema,
  kdf: Argon2idParamsSchema,
  encryptedAccountBundle: CipherBlobSchema,
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  recoveryEnabled: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type UserCryptoProfile = z.infer<typeof UserCryptoProfileSchema>;

export const CryptoDeviceSchema = z.object({
  id: z.string().uuid(),
  userId: z.string(),
  deviceType: z.enum(['web', 'extension', 'desktop', 'mobile']),
  encryptedLabel: CipherBlobSchema.nullable(),
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  certificate: Base64UrlSchema,
  certificateSignature: Base64UrlSchema,
  keyVersion: z.number().int().positive(),
  trustedAt: z.string(),
  lastSeenAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
});
export type CryptoDevice = z.infer<typeof CryptoDeviceSchema>;

export const EnterpriseRecoveryKeySchema = z.object({
  id: z.string().uuid(),
  ceremonyId: z.string().min(1).max(200),
  keyFingerprint: Base64UrlSchema,
  publicEncryptionKey: Base64UrlSchema,
  threshold: z.literal(2),
  shareCount: z.literal(3),
  status: z.enum(['pending', 'staged', 'active', 'retired', 'compromised', 'cancelled']),
  ceremonyEvidenceDigest: Base64UrlSchema,
  approvalUserIds: z.array(z.string()).max(2),
  createdAt: z.string(),
  retiredAt: z.string().nullable(),
  cancelledAt: z.string().nullable().optional(),
});
export type EnterpriseRecoveryKey = z.infer<typeof EnterpriseRecoveryKeySchema>;

export const EnterpriseRecoveryAdministratorSchema = z.object({
  userId: z.string(),
  username: z.string(),
  displayName: z.string(),
  identitySource: z.enum(['dev', 'oidc', 'ldap', 'feishu']),
  active: z.boolean(),
  hasCryptoProfile: z.boolean(),
  activeDeviceCount: z.number().int().nonnegative(),
  ready: z.boolean(),
});
export type EnterpriseRecoveryAdministrator = z.infer<
  typeof EnterpriseRecoveryAdministratorSchema
>;

export const EnterpriseRecoveryReadinessSchema = z.object({
  requiredAdministratorCount: z.literal(3),
  administratorCount: z.number().int().nonnegative(),
  readyAdministratorCount: z.number().int().nonnegative(),
  ready: z.boolean(),
  administrators: z.array(EnterpriseRecoveryAdministratorSchema),
});
export type EnterpriseRecoveryReadiness = z.infer<typeof EnterpriseRecoveryReadinessSchema>;

export const EnterpriseRecoveryVaultCoverageSchema = z.object({
  vaultId: z.string().uuid(),
  epoch: z.number().int().positive().nullable(),
  covered: z.boolean(),
  canManage: z.boolean(),
  ownerUserIds: z.array(z.string()),
});
export type EnterpriseRecoveryVaultCoverage = z.infer<
  typeof EnterpriseRecoveryVaultCoverageSchema
>;

export const EnterpriseRecoveryCoverageSchema = z.object({
  keyId: z.string().uuid(),
  totalVaultCount: z.number().int().nonnegative(),
  coveredVaultCount: z.number().int().nonnegative(),
  complete: z.boolean(),
  vaults: z.array(EnterpriseRecoveryVaultCoverageSchema),
});
export type EnterpriseRecoveryCoverage = z.infer<typeof EnterpriseRecoveryCoverageSchema>;

export const EnterpriseRecoveryRequestSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  recoveryKeyId: z.string().uuid(),
  keyEpoch: z.number().int().positive(),
  targetUserId: z.string(),
  targetDeviceId: z.string().uuid(),
  targetEncryptionPublicKey: Base64UrlSchema,
  targetKeyVersion: z.number().int().positive(),
  targetCapability: z.enum(['metadata', 'full']),
  accountResetRequestId: z.string().uuid().nullable(),
  requestDigest: Base64UrlSchema,
  status: z.enum(['pending', 'approved', 'completed', 'cancelled', 'expired', 'failed']),
  approvalUserIds: z.array(z.string()).max(2),
  createdAt: z.string(),
  expiresAt: z.string(),
  completedAt: z.string().nullable(),
  cancelledAt: z.string().nullable().optional(),
  expiredAt: z.string().nullable().optional(),
  lastErrorCode: z.string().nullable().optional(),
});
export type EnterpriseRecoveryRequest = z.infer<typeof EnterpriseRecoveryRequestSchema>;

export const EnterpriseRecoveryCandidateSchema = z.object({
  vaultId: z.string().uuid(),
  targetUserId: z.string(),
  targetDisplayName: z.string(),
  targetUsername: z.string(),
  targetDeviceId: z.string().uuid(),
  targetEncryptionPublicKey: Base64UrlSchema,
  targetKeyVersion: z.number().int().positive(),
  targetCapability: z.literal('full'),
  reason: z.literal('personal_owner_missing_current_full_envelope'),
});
export type EnterpriseRecoveryCandidate = z.infer<typeof EnterpriseRecoveryCandidateSchema>;

export const EnterpriseRecoveryWorkspaceSchema = z.object({
  refreshedAt: z.string(),
  keys: z.array(EnterpriseRecoveryKeySchema),
  readiness: EnterpriseRecoveryReadinessSchema.nullable(),
  coverage: EnterpriseRecoveryCoverageSchema.nullable(),
  requests: z.array(EnterpriseRecoveryRequestSchema),
  candidates: z.array(EnterpriseRecoveryCandidateSchema),
});
export type EnterpriseRecoveryWorkspace = z.infer<typeof EnterpriseRecoveryWorkspaceSchema>;

export const VaultCryptoStateSchema = z.object({
  vaultId: z.string().uuid(),
  status: VaultCryptoStatusSchema,
  activeEpoch: z.number().int().nonnegative(),
  accessGeneration: z.number().int().nonnegative().optional(),
  pendingEpoch: z.number().int().positive().nullable(),
  rekeyTaskId: z.string().uuid().nullable(),
  encryptedHeader: CipherBlobSchema.nullable(),
  migrationJobId: z.string().uuid().nullable(),
  recoveryRequired: z.boolean().optional(),
  recoveryReason: z.enum(['missing_current_full_envelope']).nullable().optional(),
  updatedAt: z.string(),
});
export type VaultCryptoState = z.infer<typeof VaultCryptoStateSchema>;

export const VaultKeyEnvelopeSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  epoch: z.number().int().positive(),
  recipientKind: z.enum(['user', 'device', 'recovery']),
  recipientId: z.string().min(1).max(200),
  recipientKeyVersion: z.number().int().positive(),
  capability: CryptoCapabilitySchema,
  sealedKeyBundle: Base64UrlSchema,
  signerUserId: z.string(),
  signerKeyVersion: z.number().int().positive(),
  signature: Base64UrlSchema,
  createdAt: z.string(),
});
export type VaultKeyEnvelope = z.infer<typeof VaultKeyEnvelopeSchema>;

export const VaultEnvelopeTaskAuthorizationKindSchema = z.enum([
  'direct',
  'custom_group',
  'directory_group',
]);
export const VaultEnvelopeTaskStatusSchema = z.enum(['pending', 'completed', 'cancelled']);
export const VaultEnvelopeTaskSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  keyEpoch: z.number().int().positive(),
  authorizationKind: VaultEnvelopeTaskAuthorizationKindSchema,
  authorizationRef: z.string().min(1).max(200),
  recipientUserId: z.string().min(1).max(200),
  capability: z.enum(['metadata', 'full']),
  expectedProfileGeneration: z.number().int().positive().nullable(),
  status: VaultEnvelopeTaskStatusSchema,
  completedEnvelopeId: z.string().uuid().nullable(),
  recipientProfile: z.object({
    keyVersion: z.number().int().positive(),
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
  }).nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
  completedAt: z.string().nullable(),
  cancelledAt: z.string().nullable(),
});
export type VaultEnvelopeTask = z.infer<typeof VaultEnvelopeTaskSchema>;

export const CompleteVaultEnvelopeTaskRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  actorDeviceId: z.string().uuid(),
  envelope: VaultKeyEnvelopeSchema.omit({ id: true, createdAt: true }),
  signature: Base64UrlSchema,
});
export type CompleteVaultEnvelopeTaskRequest = z.infer<typeof CompleteVaultEnvelopeTaskRequestSchema>;

export const CreateVaultOwnershipTransferRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  newOwnerUserId: z.string().min(1).max(200),
  expectedAccessGeneration: z.number().int().nonnegative(),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type CreateVaultOwnershipTransferRequest = z.infer<
  typeof CreateVaultOwnershipTransferRequestSchema
>;

export const AcceptVaultOwnershipTransferRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  transferId: z.string().uuid(),
  envelopeTaskId: z.string().uuid(),
  expectedAccessGeneration: z.number().int().nonnegative(),
  acceptanceDigest: Base64UrlSchema,
  keyPossessionSignature: Base64UrlSchema,
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type AcceptVaultOwnershipTransferRequest = z.infer<
  typeof AcceptVaultOwnershipTransferRequestSchema
>;

export const CancelVaultOwnershipTransferRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  transferId: z.string().uuid(),
  envelopeTaskId: z.string().uuid(),
  expectedAccessGeneration: z.number().int().nonnegative(),
  decision: z.enum(['cancel', 'decline']),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type CancelVaultOwnershipTransferRequest = z.infer<
  typeof CancelVaultOwnershipTransferRequestSchema
>;

export const VaultOwnershipTransferSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  fromOwnerUserId: z.string(),
  toOwnerUserId: z.string(),
  envelopeTaskId: z.string().uuid(),
  keyEpoch: z.number().int().positive(),
  envelopeReady: z.boolean(),
  completedEnvelopeId: z.string().uuid().nullable(),
  envelopeCiphertextDigest: Base64UrlSchema.nullable(),
  keyPossessionProofAvailable: z.boolean(),
  expectedAccessGeneration: z.number().int().nonnegative(),
  status: z.enum(['pending', 'completed', 'cancelled']),
  acceptanceRequired: z.boolean(),
  acceptanceStatus: z.enum(['waiting', 'accepted', 'cancelled', 'legacy_completed']),
  acceptedByDeviceId: z.string().uuid().nullable(),
  acceptanceDigest: Base64UrlSchema.nullable(),
  acceptanceSignature: Base64UrlSchema.nullable(),
  acceptedAt: z.string().nullable(),
  rekeyTask: z.object({
    id: z.string().uuid(),
    fromEpoch: z.number().int().positive(),
    toEpoch: z.number().int().positive(),
  }).nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
  completedAt: z.string().nullable(),
  cancelledAt: z.string().nullable(),
});
export type VaultOwnershipTransfer = z.infer<typeof VaultOwnershipTransferSchema>;

export const EncryptedVaultHeaderSchema = z.object({
  vaultId: z.string().uuid(),
  version: z.number().int().positive(),
  keyEpoch: z.number().int().positive(),
  blob: CipherBlobSchema,
  updatedAt: z.string(),
  updatedBy: z.string(),
});
export type EncryptedVaultHeader = z.infer<typeof EncryptedVaultHeaderSchema>;

export const EncryptedItemMetadataSchema = z.object({
  itemId: z.string().uuid(),
  vaultId: z.string().uuid(),
  version: z.number().int().positive(),
  secretVersion: z.number().int().positive(),
  keyEpoch: z.number().int().positive(),
  deleted: z.boolean(),
  blob: CipherBlobSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  updatedBy: z.string(),
});
export type EncryptedItemMetadata = z.infer<typeof EncryptedItemMetadataSchema>;

export const EncryptedSecretVersionSchema = z.object({
  itemId: z.string().uuid(),
  vaultId: z.string().uuid(),
  /** 条目记录版本；历史内容的 AAD 不能用当前 metadata version 代替。 */
  recordVersion: z.number().int().positive(),
  secretVersion: z.number().int().positive(),
  encryptedValue: CipherBlobSchema,
  createdAt: z.string(),
  createdBy: z.string(),
});
export type EncryptedSecretVersion = z.infer<typeof EncryptedSecretVersionSchema>;

export const EncryptedItemKeyWrapSchema = z.object({
  itemId: z.string().uuid(),
  vaultId: z.string().uuid(),
  secretVersion: z.number().int().positive(),
  keyEpoch: z.number().int().positive(),
  wrappedDek: CipherBlobSchema,
  createdAt: z.string(),
  createdBy: z.string(),
});
export type EncryptedItemKeyWrap = z.infer<typeof EncryptedItemKeyWrapSchema>;

// ---------------------------------------------------------------------------
// 同步事件（SSE），永远不携带敏感内容明文
// ---------------------------------------------------------------------------

export const SyncEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('item.upserted'),
    cursor: z.number().int(),
    item: ItemMetaSchema,
  }),
  z.object({
    type: z.literal('item.deleted'),
    cursor: z.number().int(),
    vaultId: z.string().uuid(),
    itemId: z.string().uuid(),
  }),
  z.object({
    type: z.literal('vault.upserted'),
    cursor: z.number().int(),
    vault: VaultSchema,
    memberships: z.array(MembershipSchema),
    /** 新获得访问权时附带条目快照。 */
    items: z.array(ItemMetaSchema).optional(),
  }),
  z.object({
    type: z.literal('vault.revoked'),
    cursor: z.number().int(),
    vaultId: z.string().uuid(),
  }),
  /** 事件被服务端过滤（无权访问）时仅推进 cursor，不携带任何 vault/item 标识。 */
  z.object({
    type: z.literal('sync.cursor'),
    cursor: z.number().int(),
  }),
  /** backlog 回放完毕：客户端此后才可标记在线并冲刷 Outbox。
   * vaultIds 是服务端此刻的权威可访问库列表——客户端据此删除
   * 离线期间被撤权或删除的本地缓存（最终一致）。 */
  z.object({
    type: z.literal('sync.ready'),
    cursor: z.number().int(),
    vaultIds: z.array(z.string().uuid()),
  }),
]);
export type SyncEvent = z.infer<typeof SyncEventSchema>;

export const EncryptedSyncEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('item.encrypted_upserted'),
    cursor: z.number().int(),
    item: EncryptedItemMetadataSchema,
  }),
  z.object({
    type: z.literal('item.deleted'),
    cursor: z.number().int(),
    vaultId: z.string().uuid(),
    itemId: z.string().uuid(),
  }),
  z.object({
    type: z.literal('vault.crypto_changed'),
    cursor: z.number().int(),
    state: VaultCryptoStateSchema,
    header: EncryptedVaultHeaderSchema.nullable(),
  }),
  z.object({
    type: z.literal('vault.rekey_required'),
    cursor: z.number().int(),
    vaultId: z.string().uuid(),
    pendingEpoch: z.number().int().positive(),
    taskId: z.string().uuid(),
  }),
  z.object({
    type: z.literal('vault.revoked'),
    cursor: z.number().int(),
    vaultId: z.string().uuid(),
  }),
  z.object({
    type: z.literal('crypto.profile_rewrapped'),
    cursor: z.number().int(),
    actorDeviceId: z.string().uuid(),
    profileVersion: z.number().int().positive(),
  }),
  z.object({ type: z.literal('device.revoked'), cursor: z.number().int(), deviceId: z.string().uuid() }),
  z.object({ type: z.literal('sync.cursor'), cursor: z.number().int() }),
  z.object({
    type: z.literal('sync.ready'),
    cursor: z.number().int(),
    vaultIds: z.array(z.string().uuid()),
  }),
]);
export type EncryptedSyncEvent = z.infer<typeof EncryptedSyncEventSchema>;

// ---------------------------------------------------------------------------
// 请求 / 响应契约
// ---------------------------------------------------------------------------

export const LoginRequestSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});
export type LoginRequest = z.infer<typeof LoginRequestSchema>;

export const AuthConfigSchema = z.object({
  mode: z.enum(['dev', 'feishu', 'ldap', 'oidc']),
  loginProvider: z.enum(['dev', 'feishu', 'ldap', 'oidc']),
  reauthProvider: z.enum(['none', 'dev', 'ldap', 'oidc']),
  directoryProvider: z.enum(['dev', 'ldap', 'authentik']),
  loginMethod: z.enum(['password', 'oidc', 'feishu']),
  reauthMethod: z.enum(['none', 'password', 'oidc']),
  providerLabel: z.string(),
});
export type AuthConfig = z.infer<typeof AuthConfigSchema>;

export const DirectoryResponseSchema = z.object({
  users: z.array(z.object({
    id: z.string(),
    username: z.string(),
    displayName: z.string(),
  })),
  groups: z.array(z.string()),
  syncedAt: z.string().nullable(),
});
export type DirectoryResponse = z.infer<typeof DirectoryResponseSchema>;

export const UserSearchResultSchema = z.object({
  id: z.string(),
  username: z.string(),
  displayName: z.string(),
});
export type UserSearchResult = z.infer<typeof UserSearchResultSchema>;

export const UserSearchResponseSchema = z.object({
  users: z.array(UserSearchResultSchema),
  syncedAt: z.string().nullable(),
});
export type UserSearchResponse = z.infer<typeof UserSearchResponseSchema>;

export const CustomGroupSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(120),
  ownerUserId: z.string(),
  ownerDisplayName: z.string(),
  memberCount: z.number().int().nonnegative(),
  pendingEnvelopeCount: z.number().int().nonnegative().optional(),
  isOwner: z.boolean(),
  isMember: z.boolean(),
  frozen: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type CustomGroup = z.infer<typeof CustomGroupSchema>;

export const CustomGroupDetailSchema = CustomGroupSchema.extend({
  members: z.array(UserSearchResultSchema),
  revision: z.string().min(16).max(128),
});
export type CustomGroupDetail = z.infer<typeof CustomGroupDetailSchema>;

const CustomGroupRevisionSchema = z.string().min(16).max(128);

export const CreateCustomGroupRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  name: z.string().trim().min(1).max(120),
  memberUserIds: z.array(z.string().min(1)).max(500).default([]),
});
export const RenameCustomGroupRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedRevision: CustomGroupRevisionSchema.optional(),
  name: z.string().trim().min(1).max(120),
});
export const SetCustomGroupMembersRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedRevision: CustomGroupRevisionSchema.optional(),
  memberUserIds: z.array(z.string().min(1)).max(500),
});
export const UpdateCustomGroupRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedRevision: CustomGroupRevisionSchema,
  name: z.string().trim().min(1).max(120),
  memberUserIds: z.array(z.string().min(1)).max(500),
});
export const TransferCustomGroupRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedRevision: CustomGroupRevisionSchema.optional(),
  newOwnerUserId: z.string().min(1),
});
export const DeleteCustomGroupRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedRevision: CustomGroupRevisionSchema.optional(),
});

export const SessionInfoSchema = z.object({
  user: SessionUserSchema,
  csrfToken: z.string(),
  locked: z.boolean(),
  cryptoProfileInitialized: z.boolean().optional(),
  cryptoDeviceId: z.string().uuid().nullable().optional(),
});
export type SessionInfo = z.infer<typeof SessionInfoSchema>;

export const BootstrapResponseSchema = z.object({
  user: SessionUserSchema,
  vaults: z.array(VaultSchema),
  memberships: z.array(MembershipSchema),
  items: z.array(ItemMetaSchema),
  cursor: z.number().int(),
});
export type BootstrapResponse = z.infer<typeof BootstrapResponseSchema>;

export const EncryptedBootstrapResponseSchema = z.object({
  user: SessionUserSchema,
  profile: UserCryptoProfileSchema.nullable(),
  recoveryKey: EnterpriseRecoveryKeySchema.nullable(),
  devices: z.array(CryptoDeviceSchema),
  vaults: z.array(VaultSchema.omit({ name: true }).extend({ crypto: VaultCryptoStateSchema })),
  memberships: z.array(MembershipSchema),
  envelopes: z.array(VaultKeyEnvelopeSchema),
  signerProfiles: z.array(z.object({
    userId: z.string(),
    keyVersion: z.number().int().positive(),
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
  })),
  headers: z.array(EncryptedVaultHeaderSchema),
  items: z.array(EncryptedItemMetadataSchema),
  cursor: z.number().int(),
});
export type EncryptedBootstrapResponse = z.infer<typeof EncryptedBootstrapResponseSchema>;

export const CreateCryptoProfileRequestSchema = z.object({
  profileVersion: z.literal(1),
  keyVersion: z.literal(1),
  suite: E2EESuiteSchema,
  kdf: Argon2idParamsSchema,
  encryptedAccountBundle: CipherBlobSchema,
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  recoveryEnabled: z.literal(true),
  device: z.object({
    id: z.string().uuid(),
    deviceType: z.enum(['web', 'extension', 'desktop', 'mobile']),
    encryptedLabel: CipherBlobSchema.nullable(),
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
    certificate: Base64UrlSchema,
    certificateSignature: Base64UrlSchema,
  }),
});
export type CreateCryptoProfileRequest = z.infer<typeof CreateCryptoProfileRequestSchema>;

export const RewrapCryptoProfileRequestSchema = z.object({
  expectedProfileVersion: z.number().int().positive(),
  kdf: Argon2idParamsSchema,
  encryptedAccountBundle: CipherBlobSchema,
  deviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type RewrapCryptoProfileRequest = z.infer<typeof RewrapCryptoProfileRequestSchema>;

export const RotateCryptoProfileRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedProfileVersion: z.number().int().positive(),
  expectedKeyVersion: z.number().int().positive(),
  newKeyVersion: z.number().int().positive(),
  encryptedAccountBundle: CipherBlobSchema,
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  actorDeviceId: z.string().uuid(),
  actorDevice: z.object({
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
    certificate: Base64UrlSchema,
    certificateSignature: Base64UrlSchema,
  }),
  newSigningKeyProof: Base64UrlSchema,
  actorSignature: Base64UrlSchema,
});
export type RotateCryptoProfileRequest = z.infer<typeof RotateCryptoProfileRequestSchema>;

export const RotateCryptoProfileResponseSchema = z.object({
  profile: UserCryptoProfileSchema,
  device: CryptoDeviceSchema,
  revokedDeviceCount: z.number().int().nonnegative(),
  rekeyTasks: z.array(z.object({
    vaultId: z.string().uuid(),
    taskId: z.string().uuid(),
    fromEpoch: z.number().int().positive(),
    toEpoch: z.number().int().positive(),
  })),
});
export type RotateCryptoProfileResponse = z.infer<typeof RotateCryptoProfileResponseSchema>;

export const AccountCryptoResetStatusSchema = z.enum([
  'pending',
  'approved',
  'activated',
  'cancelled',
  'expired',
  'failed',
]);
export type AccountCryptoResetStatus = z.infer<typeof AccountCryptoResetStatusSchema>;

export const AccountCryptoResetCandidateDeviceSchema = z.object({
  id: z.string().uuid(),
  deviceType: z.enum(['web', 'extension', 'desktop', 'mobile']),
  encryptedLabel: CipherBlobSchema.nullable(),
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  certificate: Base64UrlSchema,
  certificateSignature: Base64UrlSchema,
});
export type AccountCryptoResetCandidateDevice = z.infer<
  typeof AccountCryptoResetCandidateDeviceSchema
>;

export const AccountCryptoResetRequestSchema = z.object({
  id: z.string().uuid(),
  targetUserId: z.string(),
  expectedProfileVersion: z.number().int().positive(),
  expectedKeyVersion: z.number().int().positive(),
  newKeyVersion: z.number().int().positive(),
  suite: E2EESuiteSchema,
  kdf: Argon2idParamsSchema,
  encryptedAccountBundle: CipherBlobSchema,
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  candidateDevice: AccountCryptoResetCandidateDeviceSchema,
  requestDigest: Base64UrlSchema,
  status: AccountCryptoResetStatusSchema,
  approvalUserIds: z.array(z.string()).max(2),
  affectedVaultIds: z.array(z.string().uuid()),
  createdAt: z.string(),
  expiresAt: z.string(),
  approvedAt: z.string().nullable(),
  activatedAt: z.string().nullable(),
  cancelledAt: z.string().nullable(),
  expiredAt: z.string().nullable().optional(),
  lastErrorCode: z.string().nullable().optional(),
});
export type AccountCryptoResetRequest = z.infer<typeof AccountCryptoResetRequestSchema>;

export const LegacyKeyRetirementReasonSchema = z.enum([
  'post_cutover',
  'rollback_window',
  'regulatory_hold',
  'fresh_install',
]);
export type LegacyKeyRetirementReason = z.infer<typeof LegacyKeyRetirementReasonSchema>;

export const LegacyKeyRetirementStatusSchema = z.enum([
  'unplanned',
  'planned',
  'approved',
  'completed',
  'not_applicable',
]);
export type LegacyKeyRetirementStatus = z.infer<typeof LegacyKeyRetirementStatusSchema>;

export const LegacyKeyRetirementResponseSchema = z.object({
  deploymentId: z.string().min(1).max(128),
  status: LegacyKeyRetirementStatusSchema,
  reasonCode: LegacyKeyRetirementReasonSchema.nullable(),
  retireBy: z.string().nullable(),
  copyInventoryDigest: Base64UrlSchema.nullable(),
  copyManifestDigest: Base64UrlSchema.nullable(),
  kekFingerprintDigest: Base64UrlSchema.nullable(),
  planDigest: Base64UrlSchema.nullable(),
  approvalCount: z.number().int().nonnegative(),
  approvalUserIds: z.array(z.string()),
  approvalEvidenceDigest: Base64UrlSchema.nullable(),
  migratedJobCount: z.number().int().nonnegative(),
  evidenceJobCount: z.number().int().nonnegative(),
  legacyKeyState: z.enum(['unknown', 'retained', 'retired', 'not_applicable']),
  overdue: z.boolean(),
  createdAt: z.string().nullable(),
  approvedAt: z.string().nullable(),
  completedAt: z.string().nullable(),
});
export type LegacyKeyRetirementResponse = z.infer<typeof LegacyKeyRetirementResponseSchema>;

export const CreateLegacyKeyRetirementRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  reasonCode: LegacyKeyRetirementReasonSchema,
  retireBy: z.string().datetime().nullable(),
  copyInventoryDigest: Base64UrlSchema,
  copyManifestDigest: Base64UrlSchema,
  kekFingerprintDigest: Base64UrlSchema.nullable(),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
}).superRefine((value, ctx) => {
  if (value.reasonCode === 'fresh_install') {
    if (value.retireBy !== null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['retireBy'], message: 'fresh install must not have a retirement deadline' });
    }
    if (value.kekFingerprintDigest !== null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['kekFingerprintDigest'], message: 'fresh install must not have a legacy KEK fingerprint' });
    }
  } else {
    if (value.retireBy === null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['retireBy'], message: 'retirement deadline is required' });
    }
    if (value.kekFingerprintDigest === null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['kekFingerprintDigest'], message: 'legacy KEK fingerprint digest is required' });
    }
  }
});
export type CreateLegacyKeyRetirementRequest = z.infer<typeof CreateLegacyKeyRetirementRequestSchema>;

export const ApproveLegacyKeyRetirementRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  planDigest: Base64UrlSchema,
  evidenceDigest: Base64UrlSchema,
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type ApproveLegacyKeyRetirementRequest = z.infer<typeof ApproveLegacyKeyRetirementRequestSchema>;

export const CompleteLegacyKeyRetirementRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  planDigest: Base64UrlSchema,
  completionEvidenceDigest: Base64UrlSchema,
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type CompleteLegacyKeyRetirementRequest = z.infer<typeof CompleteLegacyKeyRetirementRequestSchema>;

export const CreateAccountCryptoResetRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedProfileVersion: z.number().int().positive(),
  expectedKeyVersion: z.number().int().positive(),
  newKeyVersion: z.number().int().positive(),
  suite: E2EESuiteSchema,
  kdf: Argon2idParamsSchema,
  encryptedAccountBundle: CipherBlobSchema,
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  candidateDevice: AccountCryptoResetCandidateDeviceSchema,
  candidateUserProof: Base64UrlSchema,
});
export type CreateAccountCryptoResetRequest = z.infer<
  typeof CreateAccountCryptoResetRequestSchema
>;

export const ListAccountCryptoResetRequestsQuerySchema = z.object({
  status: AccountCryptoResetStatusSchema.optional(),
  targetUserId: z.string().min(1).optional(),
});
export type ListAccountCryptoResetRequestsQuery = z.infer<
  typeof ListAccountCryptoResetRequestsQuerySchema
>;

export const ApproveAccountCryptoResetRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  requestDigest: Base64UrlSchema,
});
export type ApproveAccountCryptoResetRequest = z.infer<
  typeof ApproveAccountCryptoResetRequestSchema
>;

export const ActivateAccountCryptoResetRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  requestDigest: Base64UrlSchema,
  candidateDevicePossessionSignature: Base64UrlSchema,
  candidateUserSignature: Base64UrlSchema,
});
export type ActivateAccountCryptoResetRequest = z.infer<
  typeof ActivateAccountCryptoResetRequestSchema
>;

export const CancelAccountCryptoResetRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  requestDigest: Base64UrlSchema,
});
export type CancelAccountCryptoResetRequest = z.infer<
  typeof CancelAccountCryptoResetRequestSchema
>;

export const ActivateAccountCryptoResetResponseSchema = z.object({
  request: AccountCryptoResetRequestSchema,
  profile: UserCryptoProfileSchema,
  device: CryptoDeviceSchema,
  revokedDeviceCount: z.number().int().nonnegative(),
  affectedVaultIds: z.array(z.string().uuid()),
  rekeyTasks: z.array(z.object({
    vaultId: z.string().uuid(),
    taskId: z.string().uuid(),
    fromEpoch: z.number().int().positive(),
    toEpoch: z.number().int().positive(),
  })),
});
export type ActivateAccountCryptoResetResponse = z.infer<
  typeof ActivateAccountCryptoResetResponseSchema
>;

export const CreateUnlockChallengeRequestSchema = z.object({ deviceId: z.string().uuid() });
export const UnlockChallengeSchema = z.object({
  id: z.string().uuid(),
  challenge: Base64UrlSchema,
  expiresAt: z.string(),
});
export type UnlockChallenge = z.infer<typeof UnlockChallengeSchema>;

export const CompleteCryptoUnlockRequestSchema = z.object({
  challengeId: z.string().uuid(),
  deviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type CompleteCryptoUnlockRequest = z.infer<typeof CompleteCryptoUnlockRequestSchema>;

export const RegisterCryptoDeviceRequestSchema = z.object({
  id: z.string().uuid(),
  deviceType: z.enum(['web', 'extension', 'desktop', 'mobile']),
  encryptedLabel: CipherBlobSchema.nullable(),
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
  certificate: Base64UrlSchema,
  certificateSignature: Base64UrlSchema,
  approvalDeviceId: z.string().uuid().optional(),
  approvalSignature: Base64UrlSchema,
});
export type RegisterCryptoDeviceRequest = z.infer<typeof RegisterCryptoDeviceRequestSchema>;

export const RevokeCryptoDeviceRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedKeyVersion: z.number().int().positive(),
  signature: Base64UrlSchema,
});
export type RevokeCryptoDeviceRequest = z.infer<typeof RevokeCryptoDeviceRequestSchema>;

export const RegisterEnterpriseRecoveryKeyRequestSchema = z.object({
  ceremonyId: z.string().min(1).max(200),
  publicEncryptionKey: Base64UrlSchema,
  keyFingerprint: Base64UrlSchema,
  threshold: z.literal(2),
  shareCount: z.literal(3),
  ceremonyEvidenceDigest: Base64UrlSchema,
});
export type RegisterEnterpriseRecoveryKeyRequest = z.infer<
  typeof RegisterEnterpriseRecoveryKeyRequestSchema
>;

export const ApproveEnterpriseRecoveryKeyRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  ceremonyEvidenceDigest: Base64UrlSchema,
});
export type ApproveEnterpriseRecoveryKeyRequest = z.infer<
  typeof ApproveEnterpriseRecoveryKeyRequestSchema
>;

export const ActivateEnterpriseRecoveryKeyRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  ceremonyEvidenceDigest: Base64UrlSchema,
});
export type ActivateEnterpriseRecoveryKeyRequest = z.infer<
  typeof ActivateEnterpriseRecoveryKeyRequestSchema
>;

export const CancelEnterpriseRecoveryKeyRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  ceremonyEvidenceDigest: Base64UrlSchema,
});
export type CancelEnterpriseRecoveryKeyRequest = z.infer<
  typeof CancelEnterpriseRecoveryKeyRequestSchema
>;

export const CreateEnterpriseRecoveryRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  vaultId: z.string().uuid(),
  targetUserId: z.string(),
  targetDeviceId: z.string().uuid(),
  targetEncryptionPublicKey: Base64UrlSchema,
  targetKeyVersion: z.number().int().positive(),
  reason: z.enum(['lost_all_devices', 'suspected_compromise', 'account_reset']),
  accountResetRequestId: z.string().uuid().optional(),
}).superRefine((value, ctx) => {
  if (value.reason === 'account_reset' && !value.accountResetRequestId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['accountResetRequestId'], message: 'account reset provenance is required' });
  }
  if (value.reason !== 'account_reset' && value.accountResetRequestId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['accountResetRequestId'], message: 'account reset provenance is not allowed' });
  }
});
export type CreateEnterpriseRecoveryRequest = z.infer<
  typeof CreateEnterpriseRecoveryRequestSchema
>;

export const ApproveEnterpriseRecoveryRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  requestDigest: Base64UrlSchema,
});
export type ApproveEnterpriseRecoveryRequest = z.infer<
  typeof ApproveEnterpriseRecoveryRequestSchema
>;

export const CancelEnterpriseRecoveryRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  requestDigest: Base64UrlSchema,
});
export type CancelEnterpriseRecoveryRequest = z.infer<
  typeof CancelEnterpriseRecoveryRequestSchema
>;

export const CompleteEnterpriseRecoveryRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  requestDigest: Base64UrlSchema,
  recoveredEnvelope: VaultKeyEnvelopeSchema.omit({ id: true, createdAt: true }),
  actorDeviceId: z.string().uuid(),
  targetConfirmationSignature: Base64UrlSchema,
  toolEvidenceDigest: Base64UrlSchema,
});
export type CompleteEnterpriseRecoveryRequest = z.infer<
  typeof CompleteEnterpriseRecoveryRequestSchema
>;

export const VaultKeyEnvelopeInputSchema = VaultKeyEnvelopeSchema.omit({ id: true, createdAt: true });
export type VaultKeyEnvelopeInput = z.infer<typeof VaultKeyEnvelopeInputSchema>;

export const DistributeEnterpriseRecoveryEnvelopeRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  actorDeviceId: z.string().uuid(),
  envelope: VaultKeyEnvelopeInputSchema,
  signature: Base64UrlSchema,
});
export type DistributeEnterpriseRecoveryEnvelopeRequest = z.infer<
  typeof DistributeEnterpriseRecoveryEnvelopeRequestSchema
>;

export const DistributeEnterpriseRecoveryEnvelopeResponseSchema = z.object({
  ok: z.literal(true),
  alreadyCovered: z.boolean(),
});
export type DistributeEnterpriseRecoveryEnvelopeResponse = z.infer<
  typeof DistributeEnterpriseRecoveryEnvelopeResponseSchema
>;

export const InitializeVaultCryptoRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedStatus: z.enum(['legacy', 'preparing']),
  epoch: z.literal(1),
  headerFormatVersion: VaultHeaderFormatVersionSchema.optional(),
  keyPossessionPublicKey: Base64UrlSchema,
  header: EncryptedVaultHeaderSchema.omit({ updatedAt: true, updatedBy: true }),
  envelopes: z.array(VaultKeyEnvelopeInputSchema).min(1).max(1000),
  actorDeviceId: z.string().uuid(),
  manifestSignature: Base64UrlSchema,
});
export type InitializeVaultCryptoRequest = z.infer<typeof InitializeVaultCryptoRequestSchema>;

export const UpdateEncryptedVaultHeaderRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedHeaderVersion: z.number().int().positive(),
  headerFormatVersion: VaultHeaderFormatVersionSchema,
  operation: z.enum(['rename', 'details', 'directories']),
  header: EncryptedVaultHeaderSchema.omit({ updatedAt: true, updatedBy: true }),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type UpdateEncryptedVaultHeaderRequest = z.infer<
  typeof UpdateEncryptedVaultHeaderRequestSchema
>;

export const CreateEncryptedItemRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  itemId: z.string().uuid(),
  keyEpoch: z.number().int().positive(),
  metadata: CipherBlobSchema,
  encryptedValue: CipherBlobSchema,
  wrappedDek: CipherBlobSchema,
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type CreateEncryptedItemRequest = z.infer<typeof CreateEncryptedItemRequestSchema>;

const ItemMetadataFormatVersionSchema = z.union([z.literal(2), z.literal(3), z.literal(4), z.literal(5)]);

export const UpdateEncryptedItemRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedVersion: z.number().int().positive(),
  metadataFormatVersion: ItemMetadataFormatVersionSchema.optional(),
  keyEpoch: z.number().int().positive(),
  metadata: CipherBlobSchema,
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type UpdateEncryptedItemRequest = z.infer<typeof UpdateEncryptedItemRequestSchema>;

export const RotateEncryptedSecretRequestSchema = UpdateEncryptedItemRequestSchema.extend({
  encryptedValue: CipherBlobSchema,
  wrappedDek: CipherBlobSchema,
});
export type RotateEncryptedSecretRequest = z.infer<typeof RotateEncryptedSecretRequestSchema>;

export const EncryptedContentRequestSchema = z.object({
  purpose: RevealPurposeSchema,
  secretVersion: z.number().int().positive().optional(),
  deviceId: z.string().uuid(),
  intentSignature: Base64UrlSchema,
});
export const EncryptedContentResponseSchema = z.object({
  metadata: EncryptedItemMetadataSchema,
  secret: EncryptedSecretVersionSchema,
  keyWrap: EncryptedItemKeyWrapSchema,
});
export type EncryptedContentResponse = z.infer<typeof EncryptedContentResponseSchema>;

export const RekeyVaultRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  metadataFormatVersion: ItemMetadataFormatVersionSchema.optional(),
  headerFormatVersion: VaultHeaderFormatVersionSchema.optional(),
  expectedEpoch: z.number().int().positive(),
  newEpoch: z.number().int().positive(),
  keyPossessionPublicKey: Base64UrlSchema,
  reason: z.enum(['member_removed', 'role_reduced', 'device_compromised', 'manual_rotation', 'ownership_transfer']),
  envelopes: z.array(VaultKeyEnvelopeInputSchema).min(1).max(1000),
  rewrappedSecrets: z.array(z.object({
    itemId: z.string().uuid(),
    secretVersion: z.number().int().positive(),
    wrappedDek: CipherBlobSchema,
  })).max(100_000),
  reencryptedMetadata: z.array(z.object({
    itemId: z.string().uuid(),
    version: z.number().int().positive(),
    blob: CipherBlobSchema,
  })).max(100_000),
  actorDeviceId: z.string().uuid(),
  manifestSignature: Base64UrlSchema,
});
export type RekeyVaultRequest = z.infer<typeof RekeyVaultRequestSchema>;

export const RekeyMaterialQuerySchema = z.object({
  taskId: z.string().uuid(),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type RekeyMaterialQuery = z.infer<typeof RekeyMaterialQuerySchema>;

export const RekeyMaterialSchema = z.object({
  task: z.object({
    id: z.string().uuid(),
    fromEpoch: z.number().int().positive(),
    toEpoch: z.number().int().positive(),
    reason: z.enum(['membership_change', 'device_compromise', 'manual', 'ownership_transfer']),
    freezeGeneration: z.number().int().nonnegative(),
  }),
  state: VaultCryptoStateSchema,
  header: EncryptedVaultHeaderSchema.extend({ signature: Base64UrlSchema }),
  metadata: z.array(EncryptedItemMetadataSchema.extend({ signature: Base64UrlSchema })),
  keyWraps: z.array(EncryptedItemKeyWrapSchema.extend({
    recordVersion: z.number().int().positive(),
    signature: Base64UrlSchema,
  })),
  recipients: z.array(z.object({
    userId: z.string(),
    role: MembershipRoleSchema,
    capability: z.enum(['metadata', 'full']),
    keyVersion: z.number().int().positive(),
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
  })),
  devices: z.array(z.object({
    deviceId: z.string().uuid(),
    userId: z.string(),
    capability: z.enum(['metadata', 'full']),
    keyVersion: z.number().int().positive(),
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
  })).optional(),
  recoveryKey: EnterpriseRecoveryKeySchema.nullable(),
});
export type RekeyMaterial = z.infer<typeof RekeyMaterialSchema>;

export const MigrationStatusSchema = z.enum([
  'pending',
  'preparing',
  'frozen',
  'encrypting',
  'verifying',
  'cutover',
  'complete',
  'failed',
]);
export type LegacyMigrationStatus = z.infer<typeof MigrationStatusSchema>;

export const LegacyMigrationJobSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  attempt: z.number().int().positive(),
  status: MigrationStatusSchema,
  targetEpoch: z.number().int().positive(),
  expectedItemCount: z.number().int().nonnegative(),
  expectedMetadataVersionCount: z.number().int().nonnegative(),
  expectedSecretVersionCount: z.number().int().nonnegative(),
  expectedRecipientCount: z.number().int().nonnegative(),
  verifiedItemCount: z.number().int().nonnegative(),
  verifiedMetadataVersionCount: z.number().int().nonnegative(),
  verifiedSecretVersionCount: z.number().int().nonnegative(),
  verifiedRecipientCount: z.number().int().nonnegative(),
  sourceDigest: Base64UrlSchema.nullable(),
  lastErrorCode: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
  completedAt: z.string().nullable(),
  rolledBackAt: z.string().nullable(),
});
export type LegacyMigrationJob = z.infer<typeof LegacyMigrationJobSchema>;

export const LegacyMigrationRecipientSchema = z.object({
  userId: z.string(),
  role: MembershipRoleSchema,
  capability: CryptoCapabilitySchema,
  keyVersion: z.number().int().positive(),
  encryptionPublicKey: Base64UrlSchema,
  signingPublicKey: Base64UrlSchema,
});
export type LegacyMigrationRecipient = z.infer<typeof LegacyMigrationRecipientSchema>;

export const LegacyMigrationMaterialsSchema = z.object({
  recipients: z.array(LegacyMigrationRecipientSchema),
  devices: z.array(z.object({
    deviceId: z.string().uuid(),
    userId: z.string(),
    capability: CryptoCapabilitySchema,
    keyVersion: z.number().int().positive(),
    encryptionPublicKey: Base64UrlSchema,
    signingPublicKey: Base64UrlSchema,
  })).optional(),
  recoveryKey: EnterpriseRecoveryKeySchema.nullable(),
});
export type LegacyMigrationMaterials = z.infer<typeof LegacyMigrationMaterialsSchema>;

export const LegacyMigrationStatusResponseSchema = z.object({
  status: MigrationStatusSchema,
  job: LegacyMigrationJobSchema.nullable(),
  materials: LegacyMigrationMaterialsSchema.nullable(),
  emptyVaultInitializationAllowed: z.boolean().describe(
    '服务端确认密码库仍可写、没有旧条目且没有非空旧审计内容时为 true',
  ),
});
export type LegacyMigrationStatusResponse = z.infer<typeof LegacyMigrationStatusResponseSchema>;

export const LegacyMigrationManifestSchema = z.object({
  vaultId: z.string().uuid(),
  legacyItemCount: z.number().int().nonnegative(),
  legacySecretVersionCount: z.number().int().nonnegative(),
  encryptedItemCount: z.number().int().nonnegative(),
  encryptedSecretVersionCount: z.number().int().nonnegative(),
  legacyDigest: Base64UrlSchema,
  encryptedDigest: Base64UrlSchema,
  envelopeRecipientIds: z.array(z.string()),
  toolRevision: z.string().min(1).max(120),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type LegacyMigrationManifest = z.infer<typeof LegacyMigrationManifestSchema>;

export const LegacyMigrationExportClaimRequestSchema = z.object({
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type LegacyMigrationExportClaimRequest = z.infer<
  typeof LegacyMigrationExportClaimRequestSchema
>;

export const LegacyMigrationExportResponseSchema = z.object({
  sealedExport: Base64UrlSchema,
  recipientKeyVersion: z.number().int().positive(),
  sourceDigest: Base64UrlSchema,
});
export type LegacyMigrationExportResponse = z.infer<
  typeof LegacyMigrationExportResponseSchema
>;

const IdempotencyKeySchema = z.string().min(8).max(80);

const DeprecatedInitialOwnerUserIdSchema = z.string().min(1).max(200).optional().describe(
  '已废弃：仅兼容旧客户端，若提供必须等于当前登录用户；所有权变更请使用所有权转移流程',
);

export const DeprecatedCreateEncryptedVaultRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  initialOwnerUserId: DeprecatedInitialOwnerUserIdSchema,
}).strict();
export type DeprecatedCreateEncryptedVaultRequest = z.infer<
  typeof DeprecatedCreateEncryptedVaultRequestSchema
>;

const AtomicEncryptedVaultCreationFieldsSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  vaultId: z.string().uuid(),
  epoch: z.literal(1),
  headerFormatVersion: z.literal(VAULT_HEADER_FORMAT_VERSION),
  keyPossessionPublicKey: Base64UrlSchema,
  header: EncryptedVaultHeaderSchema.omit({ updatedAt: true, updatedBy: true }),
  envelopes: z.array(VaultKeyEnvelopeInputSchema).min(1).max(1000),
  actorDeviceId: z.string().uuid(),
  manifestSignature: Base64UrlSchema,
});

export const AtomicCreateEncryptedVaultRequestSchema = AtomicEncryptedVaultCreationFieldsSchema;
export type AtomicCreateEncryptedVaultRequest = z.infer<
  typeof AtomicCreateEncryptedVaultRequestSchema
>;

export const CreateEncryptedProjectRequestSchema = AtomicEncryptedVaultCreationFieldsSchema.extend({
  expectedParentAccessGeneration: z.number().int().nonnegative(),
});
export type CreateEncryptedProjectRequest = z.infer<
  typeof CreateEncryptedProjectRequestSchema
>;

export const CreateEncryptedVaultRequestSchema = z.union([
  AtomicCreateEncryptedVaultRequestSchema,
  DeprecatedCreateEncryptedVaultRequestSchema,
]);
export type CreateEncryptedVaultRequest = z.infer<typeof CreateEncryptedVaultRequestSchema>;

export const CreatedEncryptedVaultSchema = VaultSchema.omit({ name: true }).extend({
  kind: z.literal('team'),
  ownerUserId: z.null(),
  projectContext: VaultProjectContextSchema,
  crypto: VaultCryptoStateSchema,
});
export type CreatedEncryptedVault = z.infer<typeof CreatedEncryptedVaultSchema>;

export const CreateVaultRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  name: z.string().min(1).max(120),
  initialOwnerUserId: DeprecatedInitialOwnerUserIdSchema,
});
export type CreateVaultRequest = z.infer<typeof CreateVaultRequestSchema>;

export const RenameVaultRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  name: z.string().min(1).max(120),
});

/** 原子转移所有权：新 owner 设为直接用户 owner，原 owner（若为直接用户成员）降为 editor。 */
export const TransferOwnershipRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  newOwnerUserId: z.string().min(1).max(200),
});
export type TransferOwnershipRequest = z.infer<typeof TransferOwnershipRequestSchema>;

export const SetMembershipRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  subjectKind: SubjectKindSchema,
  subjectId: z.string().min(1).max(200),
  role: MembershipRoleSchema,
});
export type SetMembershipRequest = z.infer<typeof SetMembershipRequestSchema>;

export const RemoveMembershipRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  subjectKind: SubjectKindSchema,
  subjectId: z.string().min(1).max(200),
});
export type RemoveMembershipRequest = z.infer<typeof RemoveMembershipRequestSchema>;

export const SetEncryptedMembershipRequestSchema = SetMembershipRequestSchema.extend({
  mode: z.enum(['replace', 'grant_or_upgrade']).optional(),
  expectedAccessGeneration: z.number().int().nonnegative(),
  actorDeviceId: z.string().uuid(),
  envelopes: z.array(VaultKeyEnvelopeInputSchema).max(1000),
  signature: Base64UrlSchema,
});
export type SetEncryptedMembershipRequest = z.infer<typeof SetEncryptedMembershipRequestSchema>;

const EncryptedMembershipMutationResultSchema = z.object({
  ok: z.literal(true),
  accessGeneration: z.number().int().nonnegative(),
  rekeyRequired: z.boolean(),
  retainedAccess: z.boolean(),
  rekeyTask: z.object({
    id: z.string().uuid(),
    fromEpoch: z.number().int().positive(),
    toEpoch: z.number().int().positive(),
  }).nullable(),
});

export const SetEncryptedMembershipResponseSchema = EncryptedMembershipMutationResultSchema.extend({
  envelopeTasks: z.object({
    pending: z.number().int().nonnegative(),
    completed: z.number().int().nonnegative(),
    withoutProfile: z.number().int().nonnegative(),
  }).nullable(),
});
export type SetEncryptedMembershipResponse = z.infer<typeof SetEncryptedMembershipResponseSchema>;

export const RemoveEncryptedMembershipRequestSchema = RemoveMembershipRequestSchema.extend({
  expectedAccessGeneration: z.number().int().nonnegative(),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type RemoveEncryptedMembershipRequest = z.infer<typeof RemoveEncryptedMembershipRequestSchema>;

export const RemoveEncryptedMembershipResponseSchema = EncryptedMembershipMutationResultSchema;
export type RemoveEncryptedMembershipResponse = z.infer<typeof RemoveEncryptedMembershipResponseSchema>;

export const DeleteEncryptedVaultRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  expectedAccessGeneration: z.number().int().nonnegative(),
  expectedHeaderVersion: z.number().int().positive().optional(),
  directoryCount: z.number().int().nonnegative().max(500).optional(),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type DeleteEncryptedVaultRequest = z.infer<typeof DeleteEncryptedVaultRequestSchema>;

export const DeleteEncryptedVaultResponseSchema = z.object({ ok: z.literal(true) });
export type DeleteEncryptedVaultResponse = z.infer<typeof DeleteEncryptedVaultResponseSchema>;

export const DeleteUninitializedVaultRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  expectedAccessGeneration: z.number().int().nonnegative(),
  actorDeviceId: z.string().uuid(),
  signature: Base64UrlSchema,
});
export type DeleteUninitializedVaultRequest = z.infer<
  typeof DeleteUninitializedVaultRequestSchema
>;

export const ItemMetaPatchSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  username: z.string().max(200).nullable().optional(),
  origin: z.string().max(300).nullable().optional(),
  tags: z.array(z.string().min(1).max(40)).max(20).optional(),
  favorite: z.boolean().optional(),
  sensitivity: SensitivitySchema.optional(),
});
export type ItemMetaPatch = z.infer<typeof ItemMetaPatchSchema>;

export const CreateItemRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  kind: ItemKindSchema,
  title: z.string().min(1).max(200),
  username: z.string().max(200).nullable().default(null),
  origin: z.string().max(300).nullable().default(null),
  tags: z.array(z.string().min(1).max(40)).max(20).default([]),
  favorite: z.boolean().default(false),
  sensitivity: SensitivitySchema.default('medium'),
  /** 敏感内容正文：密码 / Token / 备注正文。服务端加密后即丢弃明文。 */
  secretValue: z.string().min(1).max(20000),
});
export type CreateItemRequest = z.infer<typeof CreateItemRequestSchema>;

export const UpdateItemMetaRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  expectedVersion: z.number().int().positive(),
  patch: ItemMetaPatchSchema,
});
export type UpdateItemMetaRequest = z.infer<typeof UpdateItemMetaRequestSchema>;

export const RotateSecretRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  expectedVersion: z.number().int().positive(),
  secretValue: z.string().min(1).max(20000),
});
export type RotateSecretRequest = z.infer<typeof RotateSecretRequestSchema>;

export const DeleteItemRequestSchema = z.object({
  idempotencyKey: IdempotencyKeySchema,
  expectedVersion: z.number().int().positive(),
});
export type DeleteItemRequest = z.infer<typeof DeleteItemRequestSchema>;

export const RevealRequestSchema = z.object({
  purpose: RevealPurposeSchema,
  /** 缺省读取当前版本；显式给出可读取历史版本。 */
  secretVersion: z.number().int().positive().optional(),
});
export type RevealRequest = z.infer<typeof RevealRequestSchema>;

export const RevealResponseSchema = z.object({
  itemId: z.string().uuid(),
  secretVersion: z.number().int().positive(),
  value: z.string(),
});
export type RevealResponse = z.infer<typeof RevealResponseSchema>;

export const PairingCodeResponseSchema = z.object({
  code: z.string(),
  expiresAt: z.string(),
});
export type PairingCodeResponse = z.infer<typeof PairingCodeResponseSchema>;

export const ExtensionSessionRequestSchema = z.object({
  code: z.string().min(6).max(12),
});
/** 扩展读取请求：fill 必须携带当前标签页 Origin 与本地缓存的条目 version，服务端按最新条目再校验。 */
export const ExtensionRevealRequestSchema = z.object({
  purpose: z.enum(['copy', 'fill']),
  origin: z.string().max(300).optional(),
  itemVersion: z.number().int().positive().optional(),
});
export type ExtensionRevealRequest = z.infer<typeof ExtensionRevealRequestSchema>;
export const ExtensionSessionResponseSchema = z.object({
  token: z.string(),
  expiresAt: z.string(),
  user: SessionUserSchema,
});
export type ExtensionSessionResponse = z.infer<typeof ExtensionSessionResponseSchema>;

export const ApiErrorSchema = z.object({
  statusCode: z.number().int(),
  error: z.string(),
  message: z.string(),
  code: z.string().optional(),
  /** 409 冲突时返回服务端当前版本，客户端不得自动合并敏感内容。 */
  currentVersion: z.number().int().optional(),
  currentItem: ItemMetaSchema.optional(),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;

export const ZeroKnowledgeApiErrorSchema = ApiErrorSchema.omit({ currentItem: true });
export type ZeroKnowledgeApiError = z.infer<typeof ZeroKnowledgeApiErrorSchema>;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

export const SECRET_LEASE_TTL_MS = 60_000;
export const CLIPBOARD_CLEAR_MS = 30_000;
export const PAIRING_CODE_TTL_MS = 120_000;
export const EXTENSION_SESSION_TTL_MS = 100 * 365 * 24 * 60 * 60 * 1000;
export const CSRF_HEADER = 'x-mima-csrf';
export const ITEM_METADATA_FORMAT_VERSION = 5 as const;
export const ITEM_METADATA_FORMAT_HEADER = 'x-mima-item-metadata-format';
export const WEB_ORIGIN = 'http://localhost:4173';
export const API_PORT = 4174;
export const WEB_PORT = 4173;
