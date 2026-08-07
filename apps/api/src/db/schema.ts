import {
  pgTable,
  text,
  uuid,
  boolean,
  integer,
  bigint,
  bigserial,
  timestamp,
  jsonb,
  customType,
  uniqueIndex,
  index,
  primaryKey,
  foreignKey,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => 'bytea',
});

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  username: text('username').notNull().unique(),
  displayName: text('display_name').notNull(),
  email: text('email').notNull(),
  groups: jsonb('groups').$type<string[]>().notNull().default([]),
  source: text('source').$type<'dev' | 'oidc' | 'ldap' | 'feishu'>().notNull().default('dev'),
  active: boolean('active').notNull().default(true),
  directoryProvider: text('directory_provider'),
  directoryDn: text('directory_dn'),
  directoryStableId: text('directory_stable_id'),
  directorySyncedAt: timestamp('directory_synced_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const userIdentities = pgTable(
  'user_identities',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    provider: text('provider').notNull(),
    issuer: text('issuer').notNull(),
    subject: text('subject').notNull(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('user_identities_provider_issuer_subject_uq').on(t.provider, t.issuer, t.subject),
    uniqueIndex('user_identities_provider_user_uq').on(t.provider, t.userId),
  ],
);

export const directoryGroups = pgTable('directory_groups', {
  id: text('id').primaryKey(),
  provider: text('provider').notNull(),
  providerGroupId: text('provider_group_id').notNull(),
  displayName: text('display_name').notNull(),
  active: boolean('active').notNull().default(true),
  syncedAt: timestamp('synced_at', { withTimezone: true }).notNull(),
});

export const directorySyncState = pgTable('directory_sync_state', {
  provider: text('provider').primaryKey(),
  lastAttemptAt: timestamp('last_attempt_at', { withTimezone: true }).notNull(),
  lastSuccessAt: timestamp('last_success_at', { withTimezone: true }),
  lastError: text('last_error'),
  userCount: integer('user_count').notNull().default(0),
  groupCount: integer('group_count').notNull().default(0),
});

export const vaults = pgTable(
  'vaults',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    kind: text('kind').$type<'personal' | 'team'>().notNull(),
    name: text('name').notNull(),
    ownerUserId: text('owner_user_id'),
    parentVaultId: uuid('parent_vault_id'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('vaults_parent_vault_idx')
      .on(t.parentVaultId)
      .where(sql`${t.parentVaultId} IS NOT NULL`),
    foreignKey({
      columns: [t.parentVaultId],
      foreignColumns: [t.id],
      name: 'vaults_parent_vault_fk',
    }).onDelete('restrict'),
    check('vaults_project_kind_check', sql`${t.parentVaultId} IS NULL OR ${t.kind} = 'team'`),
  ],
);

export const vaultMemberships = pgTable(
  'vault_memberships',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    subjectKind: text('subject_kind').$type<'user' | 'group'>().notNull(),
    subjectId: text('subject_id').notNull(),
    role: text('role').$type<'viewer' | 'editor' | 'owner' | 'auditor'>().notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('vault_memberships_subject_uq').on(t.vaultId, t.subjectKind, t.subjectId)],
);

export const items = pgTable(
  'items',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    kind: text('kind').$type<'login' | 'api_token' | 'secure_note'>().notNull(),
    title: text('title').notNull(),
    username: text('username'),
    origin: text('origin'),
    tags: jsonb('tags').$type<string[]>().notNull().default([]),
    favorite: boolean('favorite').notNull().default(false),
    sensitivity: text('sensitivity').$type<'low' | 'medium' | 'high'>().notNull().default('medium'),
    version: integer('version').notNull().default(1),
    secretVersion: integer('secret_version').notNull().default(1),
    deleted: boolean('deleted').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    updatedBy: text('updated_by').notNull(),
  },
  (t) => [
    index('items_vault_idx').on(t.vaultId),
    uniqueIndex('items_id_vault_uq').on(t.id, t.vaultId),
  ],
);

/** 追加式密文表：同一 (item_id, secret_version) 永不覆盖。 */
export const itemSecretVersions = pgTable(
  'item_secret_versions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    itemId: uuid('item_id')
      .notNull()
      .references(() => items.id, { onDelete: 'cascade' }),
    vaultId: uuid('vault_id').notNull(),
    itemKind: text('item_kind').notNull(),
    secretVersion: integer('secret_version').notNull(),
    ciphertext: bytea('ciphertext').notNull(),
    iv: bytea('iv').notNull(),
    authTag: bytea('auth_tag').notNull(),
    wrappedDek: bytea('wrapped_dek').notNull(),
    keyVersion: text('key_version').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    createdBy: text('created_by').notNull(),
  },
  (t) => [uniqueIndex('item_secret_versions_uq').on(t.itemId, t.secretVersion)],
);

export const syncEvents = pgTable(
  'sync_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    type: text('type').notNull(),
    vaultId: uuid('vault_id').notNull(),
    itemId: uuid('item_id'),
    payload: jsonb('payload').$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('sync_events_vault_idx').on(t.vaultId)],
);

export const auditEvents = pgTable('audit_events', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  ts: timestamp('ts', { withTimezone: true }).notNull().defaultNow(),
  actorUserId: text('actor_user_id'),
  action: text('action').notNull(),
  vaultId: uuid('vault_id'),
  itemId: uuid('item_id'),
  success: boolean('success').notNull(),
  details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
  prevHash: text('prev_hash').notNull(),
  hash: text('hash').notNull(),
});

export const sessions = pgTable('sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  tokenHash: text('token_hash').notNull().unique(),
  userId: text('user_id').notNull(),
  csrfToken: text('csrf_token').notNull(),
  locked: boolean('locked').notNull().default(false),
  authMethod: text('auth_method').$type<'password' | 'oidc' | 'feishu'>().notNull().default('password'),
  authProvider: text('auth_provider').$type<'dev' | 'ldap' | 'oidc' | 'feishu'>().notNull().default('dev'),
  authenticatedAt: timestamp('authenticated_at', { withTimezone: true }).notNull().defaultNow(),
  externalNamespace: text('external_namespace'),
  externalSubject: text('external_subject'),
  externalSessionId: text('external_session_id'),
  oidcIssuer: text('oidc_issuer'),
  oidcSubject: text('oidc_subject'),
  oidcSid: text('oidc_sid'),
  unlockGeneration: integer('unlock_generation').notNull().default(0),
  unlockedDeviceId: uuid('unlocked_device_id'),
  unlockedAt: timestamp('unlocked_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

export const oidcTransactions = pgTable('oidc_transactions', {
  stateHash: text('state_hash').primaryKey(),
  purpose: text('purpose').$type<'login' | 'reauth'>().notNull(),
  ciphertext: bytea('ciphertext').notNull(),
  iv: bytea('iv').notNull(),
  authTag: bytea('auth_tag').notNull(),
  keyVersion: text('key_version').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

export const authTransactions = pgTable('auth_transactions', {
  stateHash: text('state_hash').primaryKey(),
  provider: text('provider').$type<'feishu'>().notNull(),
  purpose: text('purpose').$type<'login' | 'reauth'>().notNull(),
  ciphertext: bytea('ciphertext').notNull(),
  iv: bytea('iv').notNull(),
  authTag: bytea('auth_tag').notNull(),
  keyVersion: text('key_version').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

export const systemRoleAssignments = pgTable(
  'system_role_assignments',
  {
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').$type<'platform-admin'>().notNull(),
    assignedBy: text('assigned_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.role] })],
);

export const customGroups = pgTable(
  'custom_groups',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    ownerUserId: text('owner_user_id')
      .notNull()
      .references(() => users.id),
    name: text('name').notNull(),
    frozen: boolean('frozen').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
);

export const customGroupMembers = pgTable(
  'custom_group_members',
  {
    groupId: uuid('group_id')
      .notNull()
      .references(() => customGroups.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    addedBy: text('added_by').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.groupId, t.userId] }),
    index('custom_group_members_user_idx').on(t.userId),
  ],
);

export const vaultCustomGroupRoles = pgTable(
  'vault_custom_group_roles',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    groupId: uuid('group_id')
      .notNull()
      .references(() => customGroups.id, { onDelete: 'restrict' }),
    role: text('role').$type<'viewer' | 'editor' | 'auditor'>().notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('vault_custom_group_roles_vault_group_uq').on(t.vaultId, t.groupId),
    index('vault_custom_group_roles_group_idx').on(t.groupId),
  ],
);

export const oidcLogoutTokens = pgTable('oidc_logout_tokens', {
  jtiHash: text('jti_hash').primaryKey(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const extensionPairingCodes = pgTable('extension_pairing_codes', {
  code: text('code').primaryKey(),
  userId: text('user_id').notNull(),
  /** 生成配对码的 Web 会话 id：来源会话被锁定/删除后配对码不可领取。 */
  sessionId: uuid('session_id'),
  enrollmentRequestId: uuid('enrollment_request_id'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
});

export const extensionSessions = pgTable('extension_sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  tokenHash: text('token_hash').notNull().unique(),
  userId: text('user_id').notNull(),
  deviceId: uuid('device_id'),
  securityGeneration: integer('security_generation').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

export const commandDedup = pgTable(
  'command_dedup',
  {
    idempotencyKey: text('idempotency_key').notNull(),
    userId: text('user_id').notNull(),
    commandName: text('command_name').notNull().default('legacy'),
    requestDigest: bytea('request_digest'),
    statusCode: integer('status_code').notNull(),
    response: jsonb('response').$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('command_dedup_uq').on(t.idempotencyKey, t.userId, t.commandName)],
);

export const authAttempts = pgTable(
  'auth_attempts',
  {
    scope: text('scope').notNull(),
    keyHash: text('key_hash').notNull(),
    windowStartedAt: timestamp('window_started_at', { withTimezone: true }).notNull(),
    windowExpiresAt: timestamp('window_expires_at', { withTimezone: true }).notNull(),
    failureCount: integer('failure_count').notNull().default(0),
    blockedUntil: timestamp('blocked_until', { withTimezone: true }),
    lastAttemptAt: timestamp('last_attempt_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.scope, t.keyHash] }),
    index('auth_attempts_cleanup_idx').on(t.windowExpiresAt, t.blockedUntil),
  ],
);

export const enterpriseRecoveryKeys = pgTable(
  'enterprise_recovery_keys',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    ceremonyId: text('ceremony_id').notNull(),
    keyFingerprint: text('key_fingerprint').notNull(),
    publicEncryptionKey: bytea('public_encryption_key').notNull(),
    threshold: integer('threshold').notNull().default(2),
    shareCount: integer('share_count').notNull().default(3),
    custodyMode: text('custody_mode')
      .$type<'legacy_offline' | 'administrator_accounts'>()
      .notNull()
      .default('legacy_offline'),
    status: text('status')
      .$type<'pending' | 'staged' | 'active' | 'retired' | 'compromised' | 'cancelled'>()
      .notNull()
      .default('pending'),
    ceremonyEvidenceDigest: bytea('ceremony_evidence_digest').notNull(),
    createdByUserId: text('created_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    retiredAt: timestamp('retired_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('enterprise_recovery_keys_ceremony_uq').on(t.ceremonyId),
    uniqueIndex('enterprise_recovery_keys_fingerprint_uq').on(t.keyFingerprint),
    uniqueIndex('enterprise_recovery_keys_active_uq').on(t.status).where(sql`${t.status} = 'active'`),
    uniqueIndex('enterprise_recovery_keys_draft_uq')
      .on(sql`(true)`)
      .where(sql`${t.status} IN ('pending', 'staged')`),
  ],
);

export const enterpriseRecoveryKeyApprovals = pgTable(
  'enterprise_recovery_key_approvals',
  {
    recoveryKeyId: uuid('recovery_key_id')
      .notNull()
      .references(() => enterpriseRecoveryKeys.id, { onDelete: 'restrict' }),
    approverUserId: text('approver_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    ceremonyEvidenceDigest: bytea('ceremony_evidence_digest').notNull(),
    actorDeviceId: uuid('actor_device_id').references(() => userDevices.id, { onDelete: 'restrict' }),
    sealedShareDigest: bytea('sealed_share_digest'),
    approvalSignature: bytea('approval_signature'),
    approvedAt: timestamp('approved_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.recoveryKeyId, t.approverUserId] })],
);

export const enterpriseRecoveryCustodyShares = pgTable(
  'enterprise_recovery_custody_shares',
  {
    recoveryKeyId: uuid('recovery_key_id')
      .notNull()
      .references(() => enterpriseRecoveryKeys.id, { onDelete: 'restrict' }),
    administratorUserId: text('administrator_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    administratorKeyVersion: integer('administrator_key_version').notNull(),
    administratorEncryptionPublicKey: bytea('administrator_encryption_public_key').notNull(),
    shareIndex: integer('share_index').notNull(),
    sealedShareCiphertext: bytea('sealed_share_ciphertext').notNull(),
    sealedShareDigest: bytea('sealed_share_digest').notNull(),
    registeredByUserId: text('registered_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.recoveryKeyId, t.administratorUserId] }),
    uniqueIndex('enterprise_recovery_custody_shares_index_uq')
      .on(t.recoveryKeyId, t.shareIndex),
  ],
);

export const userCryptoProfiles = pgTable(
  'user_crypto_profiles',
  {
    userId: text('user_id')
      .primaryKey()
      .references(() => users.id, { onDelete: 'cascade' }),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    profileVersion: integer('profile_version').notNull().default(1),
    cryptoGeneration: integer('crypto_generation').notNull().default(1),
    kdfAlgorithm: text('kdf_algorithm').$type<'argon2id13'>().notNull().default('argon2id13'),
    kdfMemoryKib: integer('kdf_memory_kib').notNull().default(65536),
    kdfIterations: integer('kdf_iterations').notNull().default(3),
    kdfParallelism: integer('kdf_parallelism').notNull().default(1),
    kdfSalt: bytea('kdf_salt').notNull(),
    wrappedAccountKeyCiphertext: bytea('wrapped_account_key_ciphertext').notNull(),
    wrappedAccountKeyNonce: bytea('wrapped_account_key_nonce').notNull(),
    encryptedPrivateKeyBundle: bytea('encrypted_private_key_bundle'),
    privateKeyBundleNonce: bytea('private_key_bundle_nonce'),
    publicEncryptionKey: bytea('public_encryption_key').notNull(),
    publicSigningKey: bytea('public_signing_key').notNull(),
    signingKeyFingerprint: text('signing_key_fingerprint').notNull().unique(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
);

export const userDevices = pgTable(
  'user_devices',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    deviceType: text('device_type').$type<'web' | 'extension' | 'desktop' | 'mobile'>().notNull(),
    status: text('status').$type<'pending' | 'active' | 'revoked'>().notNull().default('pending'),
    trustMethod: text('trust_method')
      .$type<'master_password' | 'device_approval' | 'passkey_prf' | 'recovery'>()
      .notNull(),
    deviceGeneration: integer('device_generation').notNull().default(1),
    keyFingerprint: text('key_fingerprint').notNull(),
    publicEncryptionKey: bytea('public_encryption_key').notNull(),
    publicSigningKey: bytea('public_signing_key').notNull(),
    encryptedPrivateKeyBundle: bytea('encrypted_private_key_bundle'),
    privateKeyBundleNonce: bytea('private_key_bundle_nonce'),
    encryptedLabel: bytea('encrypted_label'),
    labelNonce: bytea('label_nonce'),
    certificatePayload: bytea('certificate_payload').notNull(),
    certificateSignature: bytea('certificate_signature').notNull(),
    approvedByDeviceId: uuid('approved_by_device_id'),
    webauthnCredentialId: bytea('webauthn_credential_id'),
    webauthnPublicKey: bytea('webauthn_public_key'),
    webauthnPrfSalt: bytea('webauthn_prf_salt'),
    webauthnSignCount: integer('webauthn_sign_count').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    activatedAt: timestamp('activated_at', { withTimezone: true }),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedByUserId: text('revoked_by_user_id').references(() => users.id, { onDelete: 'set null' }),
    revocationReason: text('revocation_reason'),
  },
  (t) => [
    uniqueIndex('user_devices_id_user_uq').on(t.id, t.userId),
    uniqueIndex('user_devices_user_fingerprint_uq').on(t.userId, t.keyFingerprint),
    uniqueIndex('user_devices_webauthn_credential_uq')
      .on(t.webauthnCredentialId)
      .where(sql`${t.webauthnCredentialId} IS NOT NULL`),
    index('user_devices_user_status_idx').on(t.userId, t.status),
    foreignKey({
      columns: [t.approvedByDeviceId],
      foreignColumns: [t.id],
      name: 'user_devices_approved_by_device_fk',
    }).onDelete('set null'),
  ],
);

export const sessionUnlockChallenges = pgTable(
  'session_unlock_challenges',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    sessionId: uuid('session_id')
      .references(() => sessions.id, { onDelete: 'cascade' }),
    extensionSessionId: uuid('extension_session_id')
      .references(() => extensionSessions.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'cascade' }),
    purpose: text('purpose')
      .$type<'unlock' | 'device_activation' | 'sensitive_command' | 'recovery'>()
      .notNull(),
    challengeHash: bytea('challenge_hash').notNull(),
    challengeNonce: bytea('challenge_nonce').notNull(),
    sessionGeneration: integer('session_generation').notNull(),
    profileVersion: integer('profile_version').notNull(),
    deviceGeneration: integer('device_generation').notNull(),
    failedAttempts: integer('failed_attempts').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    verifiedAt: timestamp('verified_at', { withTimezone: true }),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('session_unlock_challenges_hash_uq').on(t.challengeHash),
    index('session_unlock_challenges_session_idx').on(t.sessionId, t.expiresAt),
    index('session_unlock_challenges_extension_session_idx').on(t.extensionSessionId, t.expiresAt),
    index('session_unlock_challenges_cleanup_idx').on(t.expiresAt, t.consumedAt),
    check(
      'session_unlock_challenges_session_source_ck',
      sql`num_nonnulls(${t.sessionId}, ${t.extensionSessionId}) = 1`,
    ),
  ],
);

export const deviceEnrollmentRequests = pgTable(
  'device_enrollment_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    requestedBySessionId: uuid('requested_by_session_id')
      .notNull()
      .references(() => sessions.id, { onDelete: 'cascade' }),
    requestedDeviceId: uuid('requested_device_id').notNull(),
    deviceType: text('device_type').$type<'web' | 'extension' | 'desktop' | 'mobile'>().notNull(),
    requestingKeyFingerprint: text('requesting_key_fingerprint').notNull(),
    requestingEncryptionPublicKey: bytea('requesting_encryption_public_key').notNull(),
    requestingSigningPublicKey: bytea('requesting_signing_public_key').notNull(),
    joinChannelPublicKey: bytea('join_channel_public_key').notNull(),
    encryptedLabel: bytea('encrypted_label'),
    labelNonce: bytea('label_nonce'),
    challengeHash: bytea('challenge_hash').notNull(),
    status: text('status')
      .$type<'pending' | 'approved' | 'claimed' | 'rejected' | 'expired'>()
      .notNull()
      .default('pending'),
    approvedByDeviceId: uuid('approved_by_device_id').references(() => userDevices.id, {
      onDelete: 'set null',
    }),
    approvalCiphertext: bytea('approval_ciphertext'),
    approvalNonce: bytea('approval_nonce'),
    approvalAlgorithm: text('approval_algorithm').$type<'x25519-sealed-box'>(),
    approvalSignature: bytea('approval_signature'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    claimedAt: timestamp('claimed_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('device_enrollment_requests_challenge_uq').on(t.challengeHash),
    index('device_enrollment_requests_user_status_idx').on(t.userId, t.status, t.expiresAt),
  ],
);

export const vaultKeyEpochs = pgTable(
  'vault_key_epochs',
  {
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    epoch: integer('epoch').notNull(),
    previousEpoch: integer('previous_epoch'),
    status: text('status')
      .$type<'preparing' | 'active' | 'retired' | 'compromised'>()
      .notNull()
      .default('preparing'),
    reason: text('reason')
      .$type<'initial' | 'migration' | 'membership_change' | 'device_compromise' | 'manual' | 'ownership_transfer'>()
      .notNull(),
    metadataKeyCommitment: bytea('metadata_key_commitment').notNull(),
    contentKeyCommitment: bytea('content_key_commitment').notNull(),
    recipientSetDigest: bytea('recipient_set_digest').notNull(),
    keyPossessionPublicKey: bytea('key_possession_public_key'),
    createdByUserId: text('created_by_user_id').references(() => users.id, { onDelete: 'set null' }),
    createdByDeviceId: uuid('created_by_device_id').references(() => userDevices.id, { onDelete: 'set null' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    activatedAt: timestamp('activated_at', { withTimezone: true }),
    retiredAt: timestamp('retired_at', { withTimezone: true }),
  },
  (t) => [
    primaryKey({ columns: [t.vaultId, t.epoch] }),
    foreignKey({
      columns: [t.vaultId, t.previousEpoch],
      foreignColumns: [t.vaultId, t.epoch],
      name: 'vault_key_epochs_previous_fk',
    }),
    uniqueIndex('vault_key_epochs_active_uq').on(t.vaultId).where(sql`${t.status} = 'active'`),
  ],
);

export const vaultCryptoStates = pgTable(
  'vault_crypto_states',
  {
    vaultId: uuid('vault_id')
      .primaryKey()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    storageMode: text('storage_mode').$type<'legacy' | 'e2ee'>().notNull().default('legacy'),
    writeState: text('write_state').$type<'open' | 'frozen' | 'rekeying'>().notNull().default('open'),
    activeEpoch: integer('active_epoch'),
    activeHeaderVersion: integer('active_header_version').notNull().default(0),
    accessGeneration: integer('access_generation').notNull().default(0),
    rowVersion: integer('row_version').notNull().default(1),
    cutoverAt: timestamp('cutover_at', { withTimezone: true }),
    legacyReadDisabledAt: timestamp('legacy_read_disabled_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      columns: [t.vaultId, t.activeEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'vault_crypto_states_active_epoch_fk',
    }),
    foreignKey({
      columns: [t.vaultId, t.activeHeaderVersion, t.activeEpoch],
      foreignColumns: [
        encryptedVaultHeaders.vaultId,
        encryptedVaultHeaders.headerVersion,
        encryptedVaultHeaders.keyEpoch,
      ],
      name: 'vault_crypto_states_active_header_fk',
    }),
  ],
);

export const legacyMigrationJobs = pgTable(
  'legacy_migration_jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'restrict' }),
    attempt: integer('attempt').notNull().default(1),
    state: text('state')
      .$type<'legacy' | 'preparing' | 'frozen' | 'encrypting' | 'verifying' | 'cutover' | 'e2ee' | 'failed'>()
      .notNull()
      .default('legacy'),
    sourceFormat: text('source_format').notNull().default('server-envelope-v1'),
    targetProtocol: text('target_protocol').notNull().default('lm-e2ee-v1'),
    targetEpoch: integer('target_epoch').notNull(),
    sourceSnapshotHash: bytea('source_snapshot_hash'),
    sourceAuditHeadHash: text('source_audit_head_hash'),
    expectedItemCount: integer('expected_item_count').notNull().default(0),
    expectedMetadataVersionCount: integer('expected_metadata_version_count').notNull().default(0),
    expectedSecretVersionCount: integer('expected_secret_version_count').notNull().default(0),
    expectedRecipientCount: integer('expected_recipient_count').notNull().default(0),
    expectedAuditEventCount: integer('expected_audit_event_count').notNull().default(0),
    verifiedItemCount: integer('verified_item_count').notNull().default(0),
    verifiedMetadataVersionCount: integer('verified_metadata_version_count').notNull().default(0),
    verifiedSecretVersionCount: integer('verified_secret_version_count').notNull().default(0),
    verifiedRecipientCount: integer('verified_recipient_count').notNull().default(0),
    verifiedAuditEventCount: integer('verified_audit_event_count').notNull().default(0),
    startedByUserId: text('started_by_user_id').references(() => users.id, { onDelete: 'set null' }),
    startedByDeviceId: uuid('started_by_device_id').references(() => userDevices.id, { onDelete: 'set null' }),
    lastErrorCode: text('last_error_code'),
    lastErrorDetailCiphertext: bytea('last_error_detail_ciphertext'),
    lastErrorDetailNonce: bytea('last_error_detail_nonce'),
    exportRecipientUserId: text('export_recipient_user_id').references(() => users.id, {
      onDelete: 'restrict',
    }),
    exportRecipientKeyVersion: integer('export_recipient_key_version'),
    exportRecipientKeyDigest: bytea('export_recipient_key_digest'),
    exportExpiresAt: timestamp('export_expires_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    startedAt: timestamp('started_at', { withTimezone: true }),
    frozenAt: timestamp('frozen_at', { withTimezone: true }),
    verifiedAt: timestamp('verified_at', { withTimezone: true }),
    cutoverAt: timestamp('cutover_at', { withTimezone: true }),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    rolledBackAt: timestamp('rolled_back_at', { withTimezone: true }),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('legacy_migration_jobs_vault_attempt_uq').on(t.vaultId, t.attempt),
    uniqueIndex('legacy_migration_jobs_active_uq')
      .on(t.vaultId)
      .where(sql`${t.state} IN ('preparing', 'frozen', 'encrypting', 'verifying', 'cutover')`),
    foreignKey({
      columns: [t.vaultId, t.targetEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'legacy_migration_jobs_target_epoch_fk',
    }),
  ],
);

export const legacyMigrationExports = pgTable(
  'legacy_migration_exports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    jobId: uuid('job_id')
      .notNull()
      .unique()
      .references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'restrict' }),
    recipientUserId: text('recipient_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    recipientKeyVersion: integer('recipient_key_version').notNull(),
    recipientKeyDigest: bytea('recipient_key_digest').notNull(),
    sourceDigest: bytea('source_digest').notNull(),
    exportFormat: text('export_format')
      .$type<'mima-legacy-export-v1'>()
      .notNull()
      .default('mima-legacy-export-v1'),
    algorithm: text('algorithm')
      .$type<'x25519-xsalsa20-poly1305-sealed-box'>()
      .notNull()
      .default('x25519-xsalsa20-poly1305-sealed-box'),
    sealedExport: bytea('sealed_export').notNull(),
    sealedExportDigest: bytea('sealed_export_digest').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    claimedAt: timestamp('claimed_at', { withTimezone: true }),
    claimedByDeviceId: uuid('claimed_by_device_id').references(() => userDevices.id, {
      onDelete: 'restrict',
    }),
  },
  (t) => [
    index('legacy_migration_exports_available_idx')
      .on(t.recipientUserId, t.vaultId, t.expiresAt)
      .where(sql`${t.claimedAt} IS NULL`),
  ],
);

export const auditChainRewriteTransitions = pgTable('audit_chain_rewrite_transitions', {
  migrationJobId: uuid('migration_job_id')
    .primaryKey()
    .references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
  previousHeadId: bigint('previous_head_id', { mode: 'number' }).notNull(),
  previousHeadHash: text('previous_head_hash').notNull(),
  rewrittenHeadId: bigint('rewritten_head_id', { mode: 'number' }).notNull(),
  rewrittenHeadHash: text('rewritten_head_hash').notNull(),
  transitionDigest: bytea('transition_digest').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const vaultKeyEnvelopes = pgTable(
  'vault_key_envelopes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    keyEpoch: integer('key_epoch').notNull(),
    recipientKind: text('recipient_kind').$type<'user' | 'device' | 'enterprise_recovery'>().notNull(),
    accessScope: text('access_scope').$type<'metadata' | 'full' | 'recovery'>().notNull(),
    recipientUserId: text('recipient_user_id').references(() => users.id, { onDelete: 'cascade' }),
    recipientDeviceId: uuid('recipient_device_id').references(() => userDevices.id, { onDelete: 'cascade' }),
    recipientRecoveryKeyId: uuid('recipient_recovery_key_id').references(() => enterpriseRecoveryKeys.id, {
      onDelete: 'restrict',
    }),
    recipientKeyFingerprint: text('recipient_key_fingerprint').notNull(),
    authorizationKind: text('authorization_kind')
      .$type<'direct' | 'custom_group' | 'directory_group' | 'owner' | 'recovery' | 'migration'>()
      .notNull(),
    authorizationRef: text('authorization_ref'),
    algorithm: text('algorithm').notNull().default('x25519-sealed-box'),
    envelopeVersion: integer('envelope_version').notNull().default(1),
    ciphertext: bytea('ciphertext').notNull(),
    ciphertextDigest: bytea('ciphertext_digest').notNull(),
    senderDeviceId: uuid('sender_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    signerUserId: text('signer_user_id').references(() => users.id, { onDelete: 'restrict' }),
    signerKeyVersion: integer('signer_key_version'),
    signerPublicKey: bytea('signer_public_key'),
    signature: bytea('signature').notNull(),
    status: text('status').$type<'pending' | 'active' | 'revoked' | 'superseded'>().notNull().default('pending'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    activatedAt: timestamp('activated_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revocationReason: text('revocation_reason'),
  },
  (t) => [
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'vault_key_envelopes_epoch_fk',
    }).onDelete('cascade'),
    uniqueIndex('vault_key_envelopes_recipient_authorization_uq').on(
      t.vaultId,
      t.keyEpoch,
      t.recipientKind,
      t.recipientKeyFingerprint,
      t.accessScope,
      t.authorizationKind,
      sql`coalesce(${t.authorizationRef}, '')`,
    ),
    index('vault_key_envelopes_recipient_user_idx').on(t.recipientUserId, t.status, t.vaultId),
    index('vault_key_envelopes_recipient_device_idx').on(t.recipientDeviceId, t.status, t.vaultId),
    index('vault_key_envelopes_epoch_idx').on(t.vaultId, t.keyEpoch, t.status),
  ],
);

export const vaultEnvelopeTasks = pgTable(
  'vault_envelope_tasks',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    keyEpoch: integer('key_epoch').notNull(),
    authorizationKind: text('authorization_kind')
      .$type<'direct' | 'custom_group' | 'directory_group'>()
      .notNull(),
    authorizationRef: text('authorization_ref').notNull(),
    recipientUserId: text('recipient_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    capability: text('capability').$type<'metadata' | 'full'>().notNull(),
    expectedProfileGeneration: integer('expected_profile_generation'),
    status: text('status').$type<'pending' | 'completed' | 'cancelled'>().notNull().default('pending'),
    completedEnvelopeId: uuid('completed_envelope_id').references(() => vaultKeyEnvelopes.id, {
      onDelete: 'cascade',
    }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
  },
  (t) => [
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'vault_envelope_tasks_epoch_fk',
    }).onDelete('cascade'),
    uniqueIndex('vault_envelope_tasks_pending_uq')
      .on(
        t.vaultId,
        t.keyEpoch,
        t.authorizationKind,
        t.authorizationRef,
        t.recipientUserId,
        t.capability,
      )
      .where(sql`${t.status} = 'pending'`),
    index('vault_envelope_tasks_owner_idx').on(t.vaultId, t.keyEpoch, t.status, t.createdAt),
    index('vault_envelope_tasks_recipient_idx').on(t.recipientUserId, t.status, t.updatedAt),
    index('vault_envelope_tasks_authorization_idx').on(t.authorizationKind, t.authorizationRef, t.status),
  ],
);

export const vaultOwnershipTransferRequests = pgTable(
  'vault_ownership_transfer_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    fromOwnerUserId: text('from_owner_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    toOwnerUserId: text('to_owner_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    envelopeTaskId: uuid('envelope_task_id')
      .notNull()
      .references(() => vaultEnvelopeTasks.id, { onDelete: 'cascade' }),
    expectedAccessGeneration: integer('expected_access_generation').notNull(),
    status: text('status').$type<'pending' | 'completed' | 'cancelled'>().notNull().default('pending'),
    acceptanceRequired: boolean('acceptance_required').notNull().default(true),
    acceptanceIdempotencyKey: text('acceptance_idempotency_key'),
    acceptedByDeviceId: uuid('accepted_by_device_id')
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    acceptanceDigest: bytea('acceptance_digest'),
    acceptanceSignature: bytea('acceptance_signature'),
    keyPossessionSignature: bytea('key_possession_signature'),
    acceptedKeyEpoch: integer('accepted_key_epoch'),
    acceptedAt: timestamp('accepted_at', { withTimezone: true }),
    requestedByDeviceId: uuid('requested_by_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('vault_ownership_transfer_requests_active_uq')
      .on(t.vaultId)
      .where(sql`${t.status} = 'pending'`),
    uniqueIndex('vault_ownership_transfer_requests_pending_task_uq')
      .on(t.envelopeTaskId)
      .where(sql`${t.status} = 'pending'`),
    index('vault_ownership_transfer_requests_target_idx').on(t.toOwnerUserId, t.status, t.createdAt),
    index('vault_ownership_transfer_acceptance_device_idx')
      .on(t.acceptedByDeviceId, t.acceptedAt)
      .where(sql`${t.acceptedByDeviceId} IS NOT NULL`),
    foreignKey({
      columns: [t.vaultId, t.acceptedKeyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'vault_ownership_transfer_accepted_epoch_fk',
    }).onDelete('restrict'),
  ],
);

export const encryptedVaultHeaders = pgTable(
  'encrypted_vault_headers',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    headerVersion: integer('header_version').notNull(),
    keyEpoch: integer('key_epoch').notNull(),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    schemaVersion: integer('schema_version').notNull().default(1),
    ciphertext: bytea('ciphertext').notNull(),
    nonce: bytea('nonce').notNull(),
    ciphertextDigest: bytea('ciphertext_digest').notNull(),
    createdByDeviceId: uuid('created_by_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    signature: bytea('signature').notNull(),
    migrationJobId: uuid('migration_job_id').references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'encrypted_vault_headers_epoch_fk',
    }).onDelete('cascade'),
    uniqueIndex('encrypted_vault_headers_version_epoch_uq').on(t.vaultId, t.headerVersion, t.keyEpoch),
    index('encrypted_vault_headers_current_idx').on(t.vaultId, t.keyEpoch, t.headerVersion),
  ],
);

export const encryptedItemMetadataVersions = pgTable(
  'encrypted_item_metadata_versions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    itemId: uuid('item_id')
      .notNull()
      .references(() => items.id, { onDelete: 'cascade' }),
    vaultId: uuid('vault_id').notNull(),
    recordVersion: integer('record_version').notNull(),
    keyEpoch: integer('key_epoch').notNull(),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    schemaVersion: integer('schema_version').notNull().default(1),
    ciphertext: bytea('ciphertext').notNull(),
    nonce: bytea('nonce').notNull(),
    ciphertextDigest: bytea('ciphertext_digest').notNull(),
    createdByDeviceId: uuid('created_by_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    signature: bytea('signature').notNull(),
    migrationJobId: uuid('migration_job_id').references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      columns: [t.itemId, t.vaultId],
      foreignColumns: [items.id, items.vaultId],
      name: 'encrypted_item_metadata_versions_item_ctx_fk',
    }).onDelete('cascade'),
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'encrypted_item_metadata_versions_epoch_fk',
    }).onDelete('cascade'),
    uniqueIndex('encrypted_item_metadata_versions_record_epoch_uq').on(t.itemId, t.recordVersion, t.keyEpoch),
    index('encrypted_item_metadata_versions_vault_idx').on(t.vaultId, t.keyEpoch, t.itemId, t.recordVersion),
  ],
);

export const encryptedItemSecretVersions = pgTable(
  'encrypted_item_secret_versions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    itemId: uuid('item_id')
      .notNull()
      .references(() => items.id, { onDelete: 'cascade' }),
    vaultId: uuid('vault_id').notNull(),
    recordVersion: integer('record_version').notNull(),
    secretVersion: integer('secret_version').notNull(),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    schemaVersion: integer('schema_version').notNull().default(1),
    ciphertext: bytea('ciphertext').notNull(),
    nonce: bytea('nonce').notNull(),
    ciphertextDigest: bytea('ciphertext_digest').notNull(),
    createdByDeviceId: uuid('created_by_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    signature: bytea('signature').notNull(),
    legacySecretVersionId: uuid('legacy_secret_version_id').references(() => itemSecretVersions.id, {
      onDelete: 'restrict',
    }),
    migrationJobId: uuid('migration_job_id').references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      columns: [t.itemId, t.vaultId],
      foreignColumns: [items.id, items.vaultId],
      name: 'encrypted_item_secret_versions_item_ctx_fk',
    }).onDelete('cascade'),
    uniqueIndex('encrypted_item_secret_versions_item_secret_uq').on(t.itemId, t.secretVersion),
    uniqueIndex('encrypted_item_secret_versions_item_secret_vault_uq').on(
      t.itemId,
      t.secretVersion,
      t.vaultId,
    ),
    uniqueIndex('encrypted_item_secret_versions_legacy_source_uq').on(t.legacySecretVersionId),
    index('encrypted_item_secret_versions_vault_idx').on(t.vaultId, t.itemId, t.secretVersion),
  ],
);

export const encryptedItemKeyWraps = pgTable(
  'encrypted_item_key_wraps',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    itemId: uuid('item_id').notNull(),
    secretVersion: integer('secret_version').notNull(),
    vaultId: uuid('vault_id').notNull(),
    keyEpoch: integer('key_epoch').notNull(),
    wrappedDekCiphertext: bytea('wrapped_dek_ciphertext').notNull(),
    wrappedDekNonce: bytea('wrapped_dek_nonce').notNull(),
    ciphertextDigest: bytea('ciphertext_digest').notNull(),
    createdByDeviceId: uuid('created_by_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    signature: bytea('signature').notNull(),
    migrationJobId: uuid('migration_job_id').references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      columns: [t.itemId, t.secretVersion, t.vaultId],
      foreignColumns: [
        encryptedItemSecretVersions.itemId,
        encryptedItemSecretVersions.secretVersion,
        encryptedItemSecretVersions.vaultId,
      ],
      name: 'encrypted_item_key_wraps_secret_fk',
    }).onDelete('cascade'),
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'encrypted_item_key_wraps_epoch_fk',
    }).onDelete('cascade'),
    uniqueIndex('encrypted_item_key_wraps_version_epoch_uq').on(t.itemId, t.secretVersion, t.keyEpoch),
    index('encrypted_item_key_wraps_epoch_idx').on(t.vaultId, t.keyEpoch, t.itemId),
  ],
);

export const vaultRekeyJobs = pgTable(
  'vault_rekey_jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'restrict' }),
    fromEpoch: integer('from_epoch').notNull(),
    toEpoch: integer('to_epoch').notNull(),
    reason: text('reason')
      .$type<'membership_change' | 'device_compromise' | 'manual' | 'ownership_transfer'>()
      .notNull(),
    status: text('status')
      .$type<'pending' | 'distributing' | 'rewrapping' | 'verifying' | 'ready' | 'committed' | 'failed' | 'cancelled'>()
      .notNull()
      .default('pending'),
    freezeGeneration: integer('freeze_generation').notNull(),
    expectedRecipientCount: integer('expected_recipient_count').notNull().default(0),
    distributedRecipientCount: integer('distributed_recipient_count').notNull().default(0),
    expectedSecretVersionCount: integer('expected_secret_version_count').notNull().default(0),
    rewrappedSecretVersionCount: integer('rewrapped_secret_version_count').notNull().default(0),
    expectedMetadataVersionCount: integer('expected_metadata_version_count').notNull().default(0),
    reencryptedMetadataVersionCount: integer('reencrypted_metadata_version_count').notNull().default(0),
    checkpointCursor: text('checkpoint_cursor'),
    sourceDigest: bytea('source_digest'),
    resultDigest: bytea('result_digest'),
    verificationSignature: bytea('verification_signature'),
    initiatedByUserId: text('initiated_by_user_id').references(() => users.id, { onDelete: 'set null' }),
    initiatedByDeviceId: uuid('initiated_by_device_id').references(() => userDevices.id, { onDelete: 'set null' }),
    lastErrorCode: text('last_error_code'),
    lastErrorDetailCiphertext: bytea('last_error_detail_ciphertext'),
    lastErrorDetailNonce: bytea('last_error_detail_nonce'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    startedAt: timestamp('started_at', { withTimezone: true }),
    committedAt: timestamp('committed_at', { withTimezone: true }),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      columns: [t.vaultId, t.fromEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'vault_rekey_jobs_from_epoch_fk',
    }),
    foreignKey({
      columns: [t.vaultId, t.toEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'vault_rekey_jobs_to_epoch_fk',
    }),
    uniqueIndex('vault_rekey_jobs_vault_to_epoch_uq').on(t.vaultId, t.toEpoch),
    uniqueIndex('vault_rekey_jobs_active_uq')
      .on(t.vaultId)
      .where(sql`${t.status} IN ('pending', 'distributing', 'rewrapping', 'verifying', 'ready')`),
  ],
);

export const legacyMigrationCheckpoints = pgTable(
  'legacy_migration_checkpoints',
  {
    jobId: uuid('job_id')
      .notNull()
      .references(() => legacyMigrationJobs.id, { onDelete: 'cascade' }),
    stage: text('stage').$type<'preparing' | 'frozen' | 'encrypting' | 'verifying' | 'cutover'>().notNull(),
    cursorKind: text('cursor_kind'),
    cursorValue: text('cursor_value'),
    processedCount: integer('processed_count').notNull().default(0),
    succeededCount: integer('succeeded_count').notNull().default(0),
    failedCount: integer('failed_count').notNull().default(0),
    sourceDigest: bytea('source_digest'),
    targetDigest: bytea('target_digest'),
    checkpointHash: bytea('checkpoint_hash').notNull(),
    encryptedState: bytea('encrypted_state'),
    encryptedStateNonce: bytea('encrypted_state_nonce'),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.jobId, t.stage] })],
);

export const legacyMigrationRecords = pgTable(
  'legacy_migration_records',
  {
    jobId: uuid('job_id')
      .notNull()
      .references(() => legacyMigrationJobs.id, { onDelete: 'cascade' }),
    sourceKind: text('source_kind').$type<'vault_header' | 'item_metadata' | 'item_secret'>().notNull(),
    sourceId: text('source_id').notNull(),
    sourceVersion: integer('source_version').notNull().default(1),
    targetRecordId: uuid('target_record_id'),
    state: text('state').$type<'pending' | 'encrypted' | 'verified' | 'failed'>().notNull().default('pending'),
    sourceDigest: bytea('source_digest').notNull(),
    targetDigest: bytea('target_digest'),
    errorCode: text('error_code'),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.jobId, t.sourceKind, t.sourceId, t.sourceVersion] }),
    uniqueIndex('legacy_migration_records_target_uq').on(t.jobId, t.targetRecordId),
  ],
);

export const legacyMigrationEvidence = pgTable(
  'legacy_migration_evidence',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    jobId: uuid('job_id')
      .notNull()
      .references(() => legacyMigrationJobs.id, { onDelete: 'restrict' }),
    evidenceType: text('evidence_type')
      .$type<'source_snapshot' | 'record_counts' | 'ciphertext_digest' | 'recipient_coverage' | 'audit_chain_head' | 'cutover' | 'rollback' | 'legacy_key_retirement'>()
      .notNull(),
    stage: text('stage')
      .$type<'legacy' | 'preparing' | 'frozen' | 'encrypting' | 'verifying' | 'cutover' | 'e2ee' | 'failed'>()
      .notNull(),
    subjectKind: text('subject_kind').$type<'vault' | 'item' | 'secret_version' | 'recipient' | 'audit_chain' | 'deployment'>(),
    subjectId: text('subject_id'),
    recordCount: integer('record_count'),
    digest: bytea('digest').notNull(),
    retirementManifestDigest: bytea('retirement_manifest_digest'),
    encryptedPayload: bytea('encrypted_payload'),
    encryptedPayloadNonce: bytea('encrypted_payload_nonce'),
    signerDeviceId: uuid('signer_device_id').references(() => userDevices.id, { onDelete: 'set null' }),
    signature: bytea('signature'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('legacy_migration_evidence_job_idx').on(t.jobId, t.stage, t.evidenceType, t.createdAt)],
);

export const legacyKeyRetirementPlans = pgTable(
  'legacy_key_retirement_plans',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    deploymentId: text('deployment_id').notNull().unique(),
    status: text('status')
      .$type<'planned' | 'approved' | 'completed' | 'not_applicable'>()
      .notNull()
      .default('planned'),
    reasonCode: text('reason_code')
      .$type<'post_cutover' | 'rollback_window' | 'regulatory_hold' | 'fresh_install'>()
      .notNull(),
    retireBy: timestamp('retire_by', { withTimezone: true }),
    copyInventoryDigest: bytea('copy_inventory_digest').notNull(),
    copyManifestDigest: bytea('copy_manifest_digest').notNull(),
    kekFingerprintDigest: bytea('kek_fingerprint_digest'),
    planDigest: bytea('plan_digest').notNull().unique(),
    completionEvidenceDigest: bytea('completion_evidence_digest'),
    createdByUserId: text('created_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdByDeviceId: uuid('created_by_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    planSignature: bytea('plan_signature').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    completedAt: timestamp('completed_at', { withTimezone: true }),
  },
  (t) => [index('legacy_key_retirement_plans_status_idx').on(t.status, t.retireBy, t.createdAt)],
);

export const legacyKeyRetirementApprovals = pgTable(
  'legacy_key_retirement_approvals',
  {
    planId: uuid('plan_id')
      .notNull()
      .references(() => legacyKeyRetirementPlans.id, { onDelete: 'restrict' }),
    approverUserId: text('approver_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    approverDeviceId: uuid('approver_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    planDigest: bytea('plan_digest').notNull(),
    evidenceDigest: bytea('evidence_digest').notNull(),
    signature: bytea('signature').notNull(),
    approvedAt: timestamp('approved_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.planId, t.approverUserId] }),
  ],
);

export const encryptedClientCommands = pgTable(
  'encrypted_client_commands',
  {
    id: uuid('id').primaryKey(),
    idempotencyKey: text('idempotency_key').notNull(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'cascade' }),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'cascade' }),
    itemId: uuid('item_id').references(() => items.id, { onDelete: 'cascade' }),
    commandType: text('command_type').notNull(),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    keyEpoch: integer('key_epoch').notNull(),
    expectedRecordVersion: integer('expected_record_version'),
    expectedSecretVersion: integer('expected_secret_version'),
    payloadCiphertext: bytea('payload_ciphertext').notNull(),
    payloadNonce: bytea('payload_nonce').notNull(),
    payloadDigest: bytea('payload_digest').notNull(),
    signature: bytea('signature').notNull(),
    status: text('status')
      .$type<'accepted' | 'committed' | 'conflict' | 'rejected' | 'expired'>()
      .notNull()
      .default('accepted'),
    resultCode: text('result_code'),
    serverSequence: bigint('server_sequence', { mode: 'number' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    committedAt: timestamp('committed_at', { withTimezone: true }),
  },
  (t) => [
    foreignKey({
      columns: [t.itemId, t.vaultId],
      foreignColumns: [items.id, items.vaultId],
      name: 'encrypted_client_commands_item_ctx_fk',
    }).onDelete('cascade'),
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'encrypted_client_commands_epoch_fk',
    }),
    uniqueIndex('encrypted_client_commands_user_idempotency_uq').on(t.userId, t.idempotencyKey),
    index('encrypted_client_commands_pending_idx').on(t.deviceId, t.status, t.createdAt),
    index('encrypted_client_commands_expiry_idx').on(t.expiresAt),
  ],
);

export const accountCryptoResetRequests = pgTable(
  'account_crypto_reset_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    targetUserId: text('target_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    expectedProfileVersion: integer('expected_profile_version').notNull(),
    expectedCryptoGeneration: integer('expected_crypto_generation').notNull(),
    newCryptoGeneration: integer('new_crypto_generation').notNull(),
    protocolVersion: text('protocol_version').notNull().default('lm-e2ee-v1'),
    kdfAlgorithm: text('kdf_algorithm').$type<'argon2id13'>().notNull().default('argon2id13'),
    kdfMemoryKib: integer('kdf_memory_kib').notNull(),
    kdfIterations: integer('kdf_iterations').notNull(),
    kdfParallelism: integer('kdf_parallelism').notNull(),
    kdfSalt: bytea('kdf_salt').notNull(),
    wrappedAccountKeyCiphertext: bytea('wrapped_account_key_ciphertext').notNull(),
    wrappedAccountKeyNonce: bytea('wrapped_account_key_nonce').notNull(),
    publicEncryptionKey: bytea('public_encryption_key').notNull(),
    publicSigningKey: bytea('public_signing_key').notNull(),
    signingKeyFingerprint: text('signing_key_fingerprint').notNull(),
    candidateDeviceId: uuid('candidate_device_id').notNull(),
    candidateDeviceType: text('candidate_device_type')
      .$type<'web' | 'extension' | 'desktop' | 'mobile'>()
      .notNull(),
    candidateDeviceEncryptionPublicKey: bytea('candidate_device_encryption_public_key').notNull(),
    candidateDeviceSigningPublicKey: bytea('candidate_device_signing_public_key').notNull(),
    candidateDeviceKeyFingerprint: text('candidate_device_key_fingerprint').notNull(),
    candidateDeviceEncryptedLabel: bytea('candidate_device_encrypted_label'),
    candidateDeviceLabelNonce: bytea('candidate_device_label_nonce'),
    candidateDeviceCertificatePayload: bytea('candidate_device_certificate_payload').notNull(),
    candidateDeviceCertificateSignature: bytea('candidate_device_certificate_signature').notNull(),
    candidateUserProof: bytea('candidate_user_proof').notNull(),
    requestDigest: bytea('request_digest').notNull().unique(),
    caseId: uuid('case_id'),
    recoveryActivationIdempotencyKey: text('recovery_activation_idempotency_key'),
    recoveryActivationDeviceSignature: bytea('recovery_activation_device_signature'),
    recoveryActivationUserSignature: bytea('recovery_activation_user_signature'),
    status: text('status')
      .$type<'pending' | 'approved' | 'activated' | 'cancelled' | 'expired' | 'failed'>()
      .notNull()
      .default('pending'),
    createdByUserId: text('created_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    activatedAt: timestamp('activated_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
    expiredAt: timestamp('expired_at', { withTimezone: true }),
    failedAt: timestamp('failed_at', { withTimezone: true }),
    lastErrorCode: text('last_error_code'),
  },
  (t) => [
    uniqueIndex('account_crypto_reset_requests_active_uq')
      .on(t.targetUserId)
      .where(sql`${t.status} IN ('pending', 'approved')`),
    index('account_crypto_reset_requests_admin_idx').on(t.status, t.expiresAt, t.createdAt),
    uniqueIndex('account_crypto_reset_requests_candidate_device_uq')
      .on(t.candidateDeviceId)
      .where(sql`${t.status} IN ('pending', 'approved', 'activated')`),
    uniqueIndex('account_crypto_reset_requests_case_uq')
      .on(t.caseId)
      .where(sql`${t.caseId} IS NOT NULL`),
  ],
);

export const accountCryptoResetApprovals = pgTable(
  'account_crypto_reset_approvals',
  {
    requestId: uuid('request_id')
      .notNull()
      .references(() => accountCryptoResetRequests.id, { onDelete: 'restrict' }),
    approverUserId: text('approver_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    requestDigest: bytea('request_digest').notNull(),
    approvedAt: timestamp('approved_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.requestId, t.approverUserId] })],
);

export const accountCryptoResetVaults = pgTable(
  'account_crypto_reset_vaults',
  {
    requestId: uuid('request_id')
      .notNull()
      .references(() => accountCryptoResetRequests.id, { onDelete: 'restrict' }),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'restrict' }),
    rekeyJobId: uuid('rekey_job_id').references(() => vaultRekeyJobs.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.requestId, t.vaultId] }),
    index('account_crypto_reset_vaults_vault_idx').on(t.vaultId, t.requestId),
  ],
);

export const enterpriseRecoveryCases = pgTable(
  'enterprise_recovery_cases',
  {
    id: uuid('id').primaryKey(),
    kind: text('kind').$type<'forgot_password' | 'interrupted_handoff'>().notNull(),
    targetUserId: text('target_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    recoveryKeyId: uuid('recovery_key_id')
      .notNull()
      .references(() => enterpriseRecoveryKeys.id, { onDelete: 'restrict' }),
    status: text('status').$type<
      | 'waiting_for_target'
      | 'pending_approval'
      | 'approved'
      | 'processing'
      | 'completed'
      | 'completed_with_skips'
      | 'cancelled'
      | 'expired'
    >().notNull().default('waiting_for_target'),
    caseDigest: bytea('case_digest'),
    targetDeviceId: uuid('target_device_id'),
    targetEncryptionPublicKey: bytea('target_encryption_public_key'),
    targetKeyVersion: integer('target_key_version'),
    accountResetRequestId: uuid('account_reset_request_id').references(
      () => accountCryptoResetRequests.id,
      { onDelete: 'restrict' },
    ),
    resolutionKind: text('resolution_kind').$type<'recover_access' | 'replace_empty_personal'>()
      .notNull().default('recover_access'),
    abandonedVaultId: uuid('abandoned_vault_id'),
    replacementVaultId: uuid('replacement_vault_id'),
    emptyVaultWitnessDigest: bytea('empty_vault_witness_digest'),
    createdByUserId: text('created_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    finalizedAt: timestamp('finalized_at', { withTimezone: true }),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    processingAt: timestamp('processing_at', { withTimezone: true }),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
    expiredAt: timestamp('expired_at', { withTimezone: true }),
    lastErrorCode: text('last_error_code'),
  },
  (t) => [
    uniqueIndex('enterprise_recovery_cases_active_target_uq')
      .on(t.targetUserId)
      .where(sql`${t.status} IN ('waiting_for_target', 'pending_approval', 'approved', 'processing')`),
    index('enterprise_recovery_cases_admin_idx').on(t.status, t.expiresAt, t.createdAt),
  ],
);

export const enterpriseRecoveryCaseApprovals = pgTable(
  'enterprise_recovery_case_approvals',
  {
    caseId: uuid('case_id')
      .notNull()
      .references(() => enterpriseRecoveryCases.id, { onDelete: 'restrict' }),
    approverUserId: text('approver_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    caseDigest: bytea('case_digest').notNull(),
    actorDeviceId: uuid('actor_device_id').references(() => userDevices.id, { onDelete: 'restrict' }),
    approvalSignature: bytea('approval_signature'),
    approvedAt: timestamp('approved_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.caseId, t.approverUserId] })],
);

export const enterpriseRecoveryCaseShareRelays = pgTable(
  'enterprise_recovery_case_share_relays',
  {
    caseId: uuid('case_id')
      .notNull()
      .references(() => enterpriseRecoveryCases.id, { onDelete: 'restrict' }),
    fromUserId: text('from_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    toUserId: text('to_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    toKeyVersion: integer('to_key_version').notNull(),
    sealedShareCiphertext: bytea('sealed_share_ciphertext').notNull(),
    sealedShareDigest: bytea('sealed_share_digest').notNull(),
    caseDigest: bytea('case_digest').notNull(),
    actorDeviceId: uuid('actor_device_id')
      .notNull()
      .references(() => userDevices.id, { onDelete: 'restrict' }),
    relaySignature: bytea('relay_signature').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
  },
  (t) => [
    primaryKey({ columns: [t.caseId, t.fromUserId, t.toUserId] }),
    index('enterprise_recovery_case_share_relays_recipient_idx')
      .on(t.toUserId, t.expiresAt, t.consumedAt),
  ],
);

export const enterpriseRecoveryCaseTransfers = pgTable(
  'enterprise_recovery_case_transfers',
  {
    caseId: uuid('case_id')
      .primaryKey()
      .references(() => enterpriseRecoveryCases.id, { onDelete: 'restrict' }),
    caseDigest: bytea('case_digest').notNull(),
    transferDigest: bytea('transfer_digest').notNull(),
    transferPayload: jsonb('transfer_payload').$type<Record<string, unknown>>().notNull(),
    uploadedByUserId: text('uploaded_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    uploadedAt: timestamp('uploaded_at', { withTimezone: true }).notNull().defaultNow(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
  },
);

export const enterpriseRecoveryRequests = pgTable(
  'enterprise_recovery_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    vaultId: uuid('vault_id')
      .notNull()
      .references(() => vaults.id, { onDelete: 'restrict' }),
    recoveryKeyId: uuid('recovery_key_id')
      .notNull()
      .references(() => enterpriseRecoveryKeys.id, { onDelete: 'restrict' }),
    keyEpoch: integer('key_epoch').notNull(),
    targetUserId: text('target_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    targetDeviceId: uuid('target_device_id').notNull(),
    targetEncryptionPublicKey: bytea('target_encryption_public_key').notNull(),
    targetKeyFingerprint: text('target_key_fingerprint'),
    targetKeyVersion: integer('target_key_version').notNull(),
    targetCapability: text('target_capability').$type<'metadata' | 'full'>().notNull(),
    reason: text('reason')
      .$type<'lost_all_devices' | 'suspected_compromise' | 'account_reset'>()
      .notNull(),
    accountResetRequestId: uuid('account_reset_request_id').references(
      () => accountCryptoResetRequests.id,
      { onDelete: 'restrict' },
    ),
    caseId: uuid('case_id').references(() => enterpriseRecoveryCases.id, { onDelete: 'restrict' }),
    requestDigest: bytea('request_digest').notNull().unique(),
    status: text('status')
      .$type<'pending' | 'approved' | 'satisfied' | 'completed' | 'cancelled' | 'expired' | 'failed'>()
      .notNull()
      .default('pending'),
    createdByUserId: text('created_by_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    completedEnvelopeId: uuid('completed_envelope_id').references(() => vaultKeyEnvelopes.id, {
      onDelete: 'restrict',
    }),
    toolEvidenceDigest: bytea('tool_evidence_digest'),
    lastErrorCode: text('last_error_code'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
    expiredAt: timestamp('expired_at', { withTimezone: true }),
    failedAt: timestamp('failed_at', { withTimezone: true }),
  },
  (t) => [
    foreignKey({
      columns: [t.vaultId, t.keyEpoch],
      foreignColumns: [vaultKeyEpochs.vaultId, vaultKeyEpochs.epoch],
      name: 'enterprise_recovery_requests_epoch_fk',
    }).onDelete('restrict'),
    uniqueIndex('enterprise_recovery_requests_active_uq')
      .on(t.vaultId, t.targetUserId)
      .where(sql`${t.status} IN ('pending', 'approved')`),
    index('enterprise_recovery_requests_target_idx').on(t.targetUserId, t.status, t.expiresAt),
    index('enterprise_recovery_requests_case_idx')
      .on(t.caseId, t.status, t.vaultId)
      .where(sql`${t.caseId} IS NOT NULL`),
  ],
);

export const enterpriseRecoveryApprovals = pgTable(
  'enterprise_recovery_approvals',
  {
    requestId: uuid('request_id')
      .notNull()
      .references(() => enterpriseRecoveryRequests.id, { onDelete: 'restrict' }),
    approverUserId: text('approver_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    requestDigest: bytea('request_digest').notNull(),
    approvedAt: timestamp('approved_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.requestId, t.approverUserId] })],
);
