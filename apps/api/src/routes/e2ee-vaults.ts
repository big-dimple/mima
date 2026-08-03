import { and, asc, desc, eq, inArray, max, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import {
  ZeroKnowledgeApiErrorSchema,
  CipherBlobSchema,
  CreateEncryptedProjectRequestSchema,
  CreateEncryptedVaultRequestSchema,
  CreatedEncryptedVaultSchema,
  CreateEncryptedItemRequestSchema,
  DeleteEncryptedVaultRequestSchema,
  DeleteEncryptedVaultResponseSchema,
  DeleteUninitializedVaultRequestSchema,
  EncryptedContentRequestSchema,
  EncryptedBootstrapResponseSchema,
  EncryptedItemMetadataSchema,
  EncryptedVaultHeaderSchema,
  InitializeVaultCryptoRequestSchema,
  ITEM_METADATA_FORMAT_VERSION,
  VAULT_HEADER_FORMAT_VERSION,
  LegacyMigrationExportClaimRequestSchema,
  LegacyMigrationExportResponseSchema,
  LegacyMigrationManifestSchema,
  LegacyMigrationStatusResponseSchema,
  RemoveEncryptedMembershipRequestSchema,
  RemoveEncryptedMembershipResponseSchema,
  RekeyMaterialQuerySchema,
  RekeyMaterialSchema,
  RekeyVaultRequestSchema,
  RotateEncryptedSecretRequestSchema,
  SetEncryptedMembershipRequestSchema,
  SetEncryptedMembershipResponseSchema,
  UpdateEncryptedItemRequestSchema,
  UpdateEncryptedVaultHeaderRequestSchema,
  VaultCryptoStateSchema,
  VaultKeyEnvelopeInputSchema,
  type AtomicCreateEncryptedVaultRequest,
  type CreateEncryptedProjectRequest,
  type MembershipRole,
  type LegacyMigrationStatus,
  type RekeyVaultRequest,
  type VaultKeyEnvelopeInput,
} from '@mima/contracts';
import { canEditItems, canReveal, resolveEffectiveRole } from '@mima/domain';
import {
  AUDIT_CHAIN_GENESIS,
  computeAuditHash,
} from '@mima/crypto';
import { canonicalJson } from '@mima/e2ee';
import {
  accountCryptoResetVaults,
  auditEvents,
  auditChainRewriteTransitions,
  commandDedup,
  customGroupMembers,
  encryptedItemKeyWraps,
  encryptedItemMetadataVersions,
  encryptedItemSecretVersions,
  encryptedVaultHeaders,
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryKeys,
  enterpriseRecoveryRequests,
  itemSecretVersions,
  items,
  legacyMigrationCheckpoints,
  legacyMigrationEvidence,
  legacyMigrationExports,
  legacyMigrationJobs,
  legacyMigrationRecords,
  syncEvents,
  userCryptoProfiles,
  userDevices,
  users,
  vaultCryptoStates,
  vaultCustomGroupRoles,
  vaultKeyEnvelopes,
  vaultKeyEpochs,
  vaultMemberships,
  vaultRekeyJobs,
  vaults,
} from '../db/schema.ts';
import {
  buildLegacySourceManifest,
  legacySourceDigest,
  legacySourceRecords,
} from '../migration/legacy-source.ts';
import {
  getVaultAccess,
  listAccessibleVaults,
  listAuthorizedVaults,
  listPersonalVaultRecoveryCandidates,
  listVaultMemberships,
} from '../services/access.ts';
import { appendAudit, auditStandalone, recordAnchor, type DbOrTx } from '../services/audit.ts';
import { recordSyncEvent, runCommand } from '../services/commands.ts';
import {
  decodeBase64Url,
  decodeCipherBlob,
  digestBlob,
  encodeBase64Url,
  encodeCipherBlob,
  envelopeSignerProfiles,
  getActiveDevice,
  getCryptoProfile,
  publicKeyFingerprint,
  resolveEnvelopeRecipient,
  sha256,
  toEnvelopeDto,
  toCryptoDeviceDto,
  toCryptoProfileDto,
  verifyCommandSignature,
  verifyVaultEnvelope,
} from '../services/e2ee.ts';
import {
  cancelEnvelopeTasks,
  capabilityForRole,
  ensureEnvelopeTasks,
  resolveAuthorizedVaultCapability,
  revokeUsersAndRequireRekey,
  settleEnvelopeTasksAfterRekey,
} from '../services/vault-envelope-tasks.ts';
import { toMembershipDto } from '../services/mappers.ts';
import {
  lockEnterpriseRecoveryCoverage,
  lockRecipientSets,
} from '../services/recipient-set-lock.ts';

const VaultParams = z.object({ vaultId: z.string().uuid() });
const ItemParams = z.object({ itemId: z.string().uuid() });
const DeleteEncryptedItemRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  expectedVersion: z.number().int().positive(),
  keyEpoch: z.number().int().positive(),
  metadata: CipherBlobSchema,
  actorDeviceId: z.string().uuid(),
  signature: z.string().min(1),
});
type EncryptedItemWriteRequest = Pick<FastifyRequest, 'user' | 'sessionRow'> & {
  params: z.infer<typeof ItemParams>;
  body: z.infer<typeof UpdateEncryptedItemRequestSchema> & Partial<
    Pick<z.infer<typeof RotateEncryptedSecretRequestSchema>, 'encryptedValue' | 'wrappedDek'>
  >;
};
const RekeyWithHeaderRequestSchema = RekeyVaultRequestSchema.extend({
  header: EncryptedVaultHeaderSchema.omit({ updatedAt: true, updatedBy: true }),
});
const MigrationStartRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  actorDeviceId: z.string().uuid(),
  signature: z.string().min(1),
});
const MigrationPrepareTargetRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  jobId: z.string().uuid(),
  headerFormatVersion: z.union([z.literal(2), z.literal(VAULT_HEADER_FORMAT_VERSION)]).optional(),
  keyPossessionPublicKey: z.string().min(1),
  header: EncryptedVaultHeaderSchema.omit({ updatedAt: true, updatedBy: true }),
  envelopes: z.array(VaultKeyEnvelopeInputSchema).min(1).max(1000),
  actorDeviceId: z.string().uuid(),
  manifestSignature: z.string().min(1),
});
const MigrationRecordSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('metadata'),
    sourceId: z.string().uuid(),
    sourceVersion: z.number().int().positive(),
    sourceDigest: z.string().min(1),
    itemId: z.string().uuid(),
    version: z.number().int().positive(),
    blob: CipherBlobSchema,
  }),
  z.object({
    kind: z.literal('secret'),
    sourceId: z.string().uuid(),
    sourceVersion: z.number().int().positive(),
    sourceDigest: z.string().min(1),
    itemId: z.string().uuid(),
    recordVersion: z.number().int().positive(),
    secretVersion: z.number().int().positive(),
    encryptedValue: CipherBlobSchema,
    wrappedDek: CipherBlobSchema,
  }),
]);
const MigrationUploadRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  jobId: z.string().uuid(),
  actorDeviceId: z.string().uuid(),
  records: z.array(MigrationRecordSchema).min(1).max(100),
  signature: z.string().min(1),
});
const MigrationCutoverRequestSchema = z.object({
  idempotencyKey: z.string().min(8).max(80),
  jobId: z.string().uuid(),
  actorDeviceId: z.string().uuid(),
  signature: z.string().min(1),
});

class E2eeConflictError extends Error {
  constructor(public readonly currentVersion: number, message = 'version conflict') {
    super(message);
  }
}

class MembershipEnvelopeError extends Error {}
class MembershipGrantModeError extends Error {}
class VaultInitializationEnvelopeError extends Error {}
class OwnerInvariantError extends Error {
  constructor(message = '密码库必须保留至少一名直接用户拥有者') {
    super(message);
  }
}
class VaultDeletionForbiddenError extends Error {}
class VaultHasProjectsError extends Error {}
class AtomicVaultCreationError extends Error {}
class VaultNotEmptyError extends Error {
  constructor(
    public readonly itemCount: number,
    public readonly directoryCount: number,
  ) {
    super('vault is not empty');
  }
}
class VaultHeaderFormatOutdatedError extends Error {}
class VaultDeletionBlockedError extends Error {
  constructor(blockers: string[]) {
    super(`该密码库保留了${blockers.join('、')}，为避免破坏恢复与审计证据，暂时不能删除`);
  }
}

export function registerE2eeVaultRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const readGuard = [app.requireSession];
  const writeGuard = [app.requireSession, app.requireCsrf];

  async function createAtomicVault(
    req: Pick<FastifyRequest, 'user' | 'sessionRow'>,
    body: AtomicCreateEncryptedVaultRequest | CreateEncryptedProjectRequest,
    reply: FastifyReply,
    options: {
      action: 'vault.create' | 'vault.project.create';
      auditAction: 'vault.e2ee.create' | 'vault.project.create';
      parentVaultId: string | null;
      projectContext:
        | { kind: 'root' }
        | { kind: 'project'; visibleParentVaultId: string };
    },
  ) {
    if (
      body.header.vaultId !== body.vaultId || body.header.keyEpoch !== 1 ||
      body.header.version !== 1 || body.epoch !== 1
    ) return badRequest(reply, '加密头与新密码库上下文不一致');
    if (options.parentVaultId !== null && !('expectedParentAccessGeneration' in body)) {
      return badRequest(reply, '项目缺少上级密码库版本');
    }
    const expectedParentAccessGeneration = 'expectedParentAccessGeneration' in body
      ? body.expectedParentAccessGeneration
      : null;
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, body.actorDeviceId, reply);
    if (!actor) return;
    const unsigned = without(body, 'manifestSignature');
    const signatureVaultId = options.parentVaultId ?? body.vaultId;
    if (!await verifyCommandSignature(
      body.manifestSignature,
      encodeBase64Url(actor.publicSigningKey),
      options.action,
      { userId: req.user.id, vaultId: signatureVaultId, request: unsigned },
    )) return unauthorized(reply, '当前设备无法确认新建密码库，请刷新页面后重试');
    let keyPossessionPublicKey: Buffer;
    let header: ReturnType<typeof decodeCipherBlob>;
    let manifestSignature: Buffer;
    try {
      keyPossessionPublicKey = decodeBase64Url(body.keyPossessionPublicKey, { exact: 32 });
      header = decodeCipherBlob(body.header.blob);
      manifestSignature = decodeBase64Url(body.manifestSignature, { exact: 64 });
    } catch {
      return badRequest(reply, '密码库加密材料格式无效');
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, body.idempotencyKey, async (tx, collect) => {
        await lockEnterpriseRecoveryCoverage(tx);
        await lockRecipientSets(tx, [req.user.id]);
        if (options.parentVaultId !== null) {
          const parentState = (await tx.select().from(vaultCryptoStates)
            .where(eq(vaultCryptoStates.vaultId, options.parentVaultId)).for('update').limit(1))[0];
          const parent = (await tx.select().from(vaults)
            .where(eq(vaults.id, options.parentVaultId)).for('update').limit(1))[0];
          const directOwner = await directSubjectRole(tx, options.parentVaultId, 'user', req.user.id);
          if (
            !parent || parent.kind !== 'team' || parent.parentVaultId !== null || directOwner !== 'owner'
          ) throw new AtomicVaultCreationError('只有上级团队密码库的直接拥有者可以新建项目');
          if (
            !parentState || parentState.storageMode !== 'e2ee' || parentState.writeState !== 'open' ||
            parentState.accessGeneration !== expectedParentAccessGeneration
          ) throw new E2eeConflictError(parentState?.accessGeneration ?? 0);
        }
        const currentActor = await getActiveDevice(tx, req.user.id, actor.id);
        const currentProfile = await getCryptoProfile(tx, req.user.id);
        if (!currentActor || !currentProfile) {
          throw new AtomicVaultCreationError('当前设备或主密码资料刚发生变化，请刷新后重新创建');
        }
        const vault = (await tx.insert(vaults).values({
          id: body.vaultId,
          kind: 'team',
          name: '',
          ownerUserId: null,
          parentVaultId: options.parentVaultId,
        }).returning())[0]!;
        await tx.insert(vaultMemberships).values({
          vaultId: vault.id,
          subjectKind: 'user',
          subjectId: req.user.id,
          role: 'owner',
        });
        const state = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, vault.id)).for('update').limit(1))[0];
        if (!state || state.storageMode !== 'legacy' || state.writeState !== 'open') {
          throw new AtomicVaultCreationError('新密码库初始状态不正确，本次创建已撤销');
        }
        const checkedEnvelopes = await validateEnvelopes(tx, body.envelopes, {
          vaultId: vault.id,
          epoch: 1,
          signerUserId: req.user.id,
          signerKeyVersion: currentProfile.cryptoGeneration,
          signerPublicKey: encodeBase64Url(currentProfile.publicSigningKey),
        }).catch(() => null);
        const exactRecipients = checkedEnvelopes
          ? await envelopesMatchExpectedRecipients(tx, vault.id, body.envelopes).catch(() => false)
          : false;
        if (!checkedEnvelopes || !exactRecipients) {
          throw new AtomicVaultCreationError('成员、设备或恢复设置刚发生变化，请刷新后重新创建');
        }
        const commitments = envelopeCommitments(body.envelopes);
        await tx.insert(vaultKeyEpochs).values({
          vaultId: vault.id,
          epoch: 1,
          previousEpoch: null,
          status: 'active',
          reason: 'initial',
          ...commitments,
          keyPossessionPublicKey,
          createdByUserId: req.user.id,
          createdByDeviceId: currentActor.id,
          activatedAt: new Date(),
        });
        await insertEnvelopes(
          tx,
          body.envelopes,
          checkedEnvelopes,
          currentActor.id,
          currentProfile.publicSigningKey,
          'active',
        );
        const headerRow = (await tx.insert(encryptedVaultHeaders).values({
          vaultId: vault.id,
          headerVersion: 1,
          keyEpoch: 1,
          schemaVersion: body.headerFormatVersion,
          ciphertext: header.ciphertext,
          nonce: header.nonce,
          ciphertextDigest: digestBlob(body.header.blob),
          createdByDeviceId: currentActor.id,
          signature: manifestSignature,
        }).returning())[0]!;
        const now = new Date();
        const updated = (await tx.update(vaultCryptoStates).set({
          storageMode: 'e2ee',
          writeState: 'open',
          activeEpoch: 1,
          activeHeaderVersion: 1,
          accessGeneration: 1,
          rowVersion: state.rowVersion + 1,
          cutoverAt: now,
          legacyReadDisabledAt: now,
          updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, vault.id)).returning())[0]!;
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed',
          vaultId: vault.id,
          itemId: null,
          payload: { epoch: 1, headerVersion: 1 },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: options.auditAction,
          vaultId: vault.id,
          success: true,
          details: {},
        });
        return {
          statusCode: 201,
          response: {
            id: vault.id,
            kind: 'team' as const,
            ownerUserId: null,
            projectContext: options.projectContext,
            crypto: toVaultCryptoState(updated, headerRow, null, null),
            createdAt: vault.createdAt.toISOString(),
            updatedAt: now.toISOString(),
          },
        };
      });
      return reply.code(201).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, '上级密码库刚被其他人修改，请刷新后确认最新状态再创建项目');
      }
      if (error instanceof AtomicVaultCreationError) return conflict(reply, error.message);
      if (isUniqueViolation(error)) {
        return codedConflict(
          reply,
          'vault_create_reconcile_required',
          '相同密码库标识已经完成或正在创建，请刷新工作台确认结果，不要重复提交',
        );
      }
      if (isForeignKeyViolation(error)) {
        return conflict(reply, '上级密码库或接收者资料已经变化，请刷新后重新创建');
      }
      throw error;
    }
  }

  r.post('/api/v2/vaults', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      body: CreateEncryptedVaultRequestSchema,
      response: {
        201: CreatedEncryptedVaultSchema,
        '4xx': ZeroKnowledgeApiErrorSchema,
      },
    },
  }, async (req, reply) => {
    if (!('vaultId' in req.body)) {
      return codedConflict(
        reply,
        'client_upgrade_required',
        '当前页面版本较旧，不能安全创建密码库。请刷新页面后重新创建；本次没有写入任何数据',
      );
    }
    return createAtomicVault(req, req.body, reply, {
      action: 'vault.create',
      auditAction: 'vault.e2ee.create',
      parentVaultId: null,
      projectContext: { kind: 'root' },
    });
  });

  r.post('/api/v2/vaults/:vaultId/projects', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: CreateEncryptedProjectRequestSchema,
      response: { 201: CreatedEncryptedVaultSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => createAtomicVault(req, req.body, reply, {
    action: 'vault.project.create',
    auditAction: 'vault.project.create',
    parentVaultId: req.params.vaultId,
    projectContext: { kind: 'project', visibleParentVaultId: req.params.vaultId },
  }));

  r.delete('/api/v2/vaults/:vaultId', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: DeleteEncryptedVaultRequestSchema,
      response: { 200: DeleteEncryptedVaultResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind !== 'team' || access.role !== 'owner') {
      return forbidden(reply, '只有团队密码库拥有者可以删除密码库');
    }
    if (req.body.expectedHeaderVersion === undefined || req.body.directoryCount === undefined) {
      return codedConflict(
        reply,
        'header_format_outdated',
        '当前页面版本较旧，请刷新页面并确认密码库已经清空后再删除',
      );
    }
    const expectedHeaderVersion = req.body.expectedHeaderVersion;
    const directoryCount = req.body.directoryCount;
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'vault.delete', {
      userId: req.user.id, vaultId: req.params.vaultId, request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认删除密码库，请刷新页面后重试');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const state = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (!state || state.storageMode !== 'e2ee' ||
          state.accessGeneration !== req.body.expectedAccessGeneration ||
          state.activeHeaderVersion !== expectedHeaderVersion
        ) throw new E2eeConflictError(state?.accessGeneration ?? 0);
        const lockedVault = (await tx.select().from(vaults)
          .where(eq(vaults.id, req.params.vaultId)).for('update').limit(1))[0];
        if (!lockedVault || lockedVault.kind !== 'team') throw new VaultDeletionForbiddenError();
        const currentAccess = await getVaultAccess(tx, req.user, req.params.vaultId);
        if (!currentAccess || currentAccess.vault.kind !== 'team' || currentAccess.role !== 'owner') {
          throw new VaultDeletionForbiddenError();
        }
        const itemCountRows = await tx.select({ count: sql<number>`count(*)::int` }).from(items).where(and(
          eq(items.vaultId, state.vaultId),
          eq(items.deleted, false),
        ));
        const itemCount = itemCountRows[0]?.count ?? 0;
        if (itemCount > 0 || directoryCount > 0) {
          throw new VaultNotEmptyError(itemCount, directoryCount);
        }
        const project = await tx.select({ id: vaults.id }).from(vaults)
          .where(eq(vaults.parentVaultId, state.vaultId)).limit(1);
        if (project[0]) throw new VaultHasProjectsError();
        const blockers = await vaultDeletionBlockers(tx, state.vaultId);
        if (blockers.length > 0) throw new VaultDeletionBlockedError(blockers);
        await tx.delete(vaultRekeyJobs).where(eq(vaultRekeyJobs.vaultId, state.vaultId));
        collect(await recordSyncEvent(tx, {
          type: 'vault.deleted', vaultId: state.vaultId, itemId: null, payload: {},
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'vault.delete',
          vaultId: state.vaultId,
          success: true,
          details: {},
        });
        await tx.delete(vaults).where(eq(vaults.id, state.vaultId));
        return { statusCode: 200, response: { ok: true as const } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, '密码库刚被其他人修改，请刷新后确认最新状态再删除');
      }
      if (error instanceof VaultDeletionForbiddenError) {
        return forbidden(reply, '你的拥有者权限已经变化，请刷新后确认');
      }
      if (error instanceof VaultHasProjectsError) {
        return codedConflict(
          reply,
          'vault_has_projects',
          '该团队密码库下还有项目。请先逐个清空并删除项目，再删除上级密码库',
        );
      }
      if (error instanceof VaultNotEmptyError) {
        return codedConflict(
          reply,
          'vault_not_empty',
          `删除前必须先清空密码库。当前还有 ${error.itemCount} 个条目、${error.directoryCount} 个目录，请清理后重试`,
        );
      }
      if (error instanceof VaultDeletionBlockedError) return conflict(reply, error.message);
      if (isForeignKeyViolation(error)) {
        return conflict(reply, '密码库仍有关联项目、恢复或迁移记录，暂时不能删除；请先处理关联内容');
      }
      throw error;
    }
  });

  r.delete('/api/v2/vaults/:vaultId/uninitialized', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: DeleteUninitializedVaultRequestSchema,
      response: { 200: DeleteEncryptedVaultResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'vault.uninitialized.delete', {
      userId: req.user.id,
      vaultId: req.params.vaultId,
      request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认清理这个空密码库，请刷新页面后重试');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const state = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (
          !state || state.storageMode !== 'legacy' || state.writeState !== 'open' ||
          state.activeEpoch !== null || state.activeHeaderVersion !== 0 ||
          state.accessGeneration !== req.body.expectedAccessGeneration
        ) throw new E2eeConflictError(state?.rowVersion ?? 0);
        const vault = (await tx.select().from(vaults)
          .where(eq(vaults.id, req.params.vaultId)).for('update').limit(1))[0];
        if (!vault || vault.kind !== 'team') throw new VaultDeletionForbiddenError();
        const owner = await directSubjectRole(tx, vault.id, 'user', req.user.id);
        if (owner !== 'owner') throw new VaultDeletionForbiddenError();
        const item = await tx.select({ id: items.id }).from(items)
          .where(eq(items.vaultId, vault.id)).limit(1);
        const child = await tx.select({ id: vaults.id }).from(vaults)
          .where(eq(vaults.parentVaultId, vault.id)).limit(1);
        const epoch = await tx.select({ epoch: vaultKeyEpochs.epoch }).from(vaultKeyEpochs)
          .where(eq(vaultKeyEpochs.vaultId, vault.id)).limit(1);
        const header = await tx.select({ version: encryptedVaultHeaders.headerVersion }).from(encryptedVaultHeaders)
          .where(eq(encryptedVaultHeaders.vaultId, vault.id)).limit(1);
        if (item[0] || child[0] || epoch[0] || header[0]) throw new AtomicVaultCreationError();
        const blockers = await vaultDeletionBlockers(tx, vault.id);
        if (blockers.length > 0) throw new VaultDeletionBlockedError(blockers);
        collect(await recordSyncEvent(tx, {
          type: 'vault.deleted', vaultId: vault.id, itemId: null, payload: {},
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'vault.uninitialized.delete',
          vaultId: vault.id,
          success: true,
          details: {},
        });
        await tx.delete(vaults).where(eq(vaults.id, vault.id));
        return { statusCode: 200, response: { ok: true as const } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, '密码库状态已经变化，请刷新后再清理');
      }
      if (error instanceof VaultDeletionForbiddenError) {
        return forbidden(reply, '只有该团队密码库的直接拥有者可以清理');
      }
      if (error instanceof AtomicVaultCreationError) {
        return conflict(reply, '该密码库已经包含加密材料、项目或条目，不能按未初始化密码库清理');
      }
      if (error instanceof VaultDeletionBlockedError) return conflict(reply, error.message);
      throw error;
    }
  });

  r.get('/api/v2/bootstrap', {
    preHandler: readGuard,
    schema: {
      tags: ['e2ee'],
      response: { 200: EncryptedBootstrapResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    const [profile, accessible, authorized, recoveryCandidateRows] = await Promise.all([
      getCryptoProfile(db, req.user.id),
      listAccessibleVaults(db, req.user),
      listAuthorizedVaults(db, req.user),
      listPersonalVaultRecoveryCandidates(db, req.user.id),
    ]);
    const accessibleVaultIds = new Set(accessible.map((access) => access.vault.id));
    const pendingTeamAccess = authorized.filter((access) =>
      access.vault.kind === 'team' && !accessibleVaultIds.has(access.vault.id));
    const pendingTeamVaultIds = new Set(pendingTeamAccess.map((access) => access.vault.id));
    const recoveryCandidates = recoveryCandidateRows.filter((candidate) =>
      !accessibleVaultIds.has(candidate.vault.id));
    const recoveryByVault = new Map(recoveryCandidates.map((candidate) => [candidate.vault.id, candidate]));
    const visible = [
      ...accessible,
      ...pendingTeamAccess,
      ...recoveryCandidates.map((candidate) => ({ vault: candidate.vault, role: 'owner' as const })),
    ];
    const vaultIds = visible.map((access) => access.vault.id);
    const visibleVaultIds = new Set(vaultIds);
    const contentVaultIds = [...accessibleVaultIds];
    const headerVaultIds = [
      ...accessibleVaultIds,
      ...recoveryCandidates.map((candidate) => candidate.vault.id),
    ];
    const devices = await db.select().from(userDevices).where(eq(userDevices.userId, req.user.id));
    const activeDeviceIds = devices.filter((device) => device.status === 'active').map((device) => device.id);
    const [states, memberships, headers, currentItems, migrationJobs, rekeyJobs, cursorRows, recoveryRows] = await Promise.all([
      vaultIds.length ? db.select().from(vaultCryptoStates).where(inArray(vaultCryptoStates.vaultId, vaultIds)) : [],
      Promise.all(vaultIds.map((vaultId) => listVaultMemberships(db, vaultId))).then((rows) => rows.flat()),
      headerVaultIds.length
        ? db.select().from(encryptedVaultHeaders).where(inArray(encryptedVaultHeaders.vaultId, headerVaultIds))
        : [],
      contentVaultIds.length ? db.select({ item: items, metadata: encryptedItemMetadataVersions })
        .from(items)
        .innerJoin(encryptedItemMetadataVersions, and(
          eq(encryptedItemMetadataVersions.itemId, items.id),
          eq(encryptedItemMetadataVersions.recordVersion, items.version),
        ))
        .innerJoin(vaultCryptoStates, and(
          eq(vaultCryptoStates.vaultId, items.vaultId),
          eq(vaultCryptoStates.activeEpoch, encryptedItemMetadataVersions.keyEpoch),
        ))
        .where(inArray(items.vaultId, contentVaultIds)) : [],
      vaultIds.length ? db.select().from(legacyMigrationJobs).where(inArray(legacyMigrationJobs.vaultId, vaultIds)) : [],
      vaultIds.length ? db.select().from(vaultRekeyJobs).where(inArray(vaultRekeyJobs.vaultId, vaultIds)) : [],
      db.select({ cursor: max(syncEvents.id) }).from(syncEvents),
      db.select().from(enterpriseRecoveryKeys).where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1),
    ]);
    const envelopeRows = contentVaultIds.length ? await db
      .select({ envelope: vaultKeyEnvelopes, sender: userDevices, signer: userCryptoProfiles })
      .from(vaultKeyEnvelopes)
      .innerJoin(userDevices, eq(userDevices.id, vaultKeyEnvelopes.senderDeviceId))
      .innerJoin(userCryptoProfiles, eq(userCryptoProfiles.userId, userDevices.userId))
      .where(and(
        inArray(vaultKeyEnvelopes.vaultId, contentVaultIds),
        eq(vaultKeyEnvelopes.status, 'active'),
      )) : [];
    const stateByVault = new Map(states.map((state) => [state.vaultId, state]));
    const capabilityByVault = new Map(accessible.map(({ vault, role }) => [
      vault.id,
      capabilityForRole(role!),
    ]));
    const ownEnvelopes = envelopeRows.filter(({ envelope }) => {
      const state = stateByVault.get(envelope.vaultId);
      return state?.activeEpoch === envelope.keyEpoch &&
        capabilityByVault.get(envelope.vaultId) === envelope.accessScope &&
        (
          envelope.recipientUserId === req.user.id ||
          (envelope.recipientDeviceId !== null && activeDeviceIds.includes(envelope.recipientDeviceId))
        );
    });
    const activeHeaders = headers.filter((header) => {
      const state = stateByVault.get(header.vaultId);
      return state?.activeEpoch === header.keyEpoch && state.activeHeaderVersion === header.headerVersion;
    });
    const signerProfiles = envelopeSignerProfiles(ownEnvelopes);
    const activeHeaderByVault = new Map(activeHeaders.map((header) => [header.vaultId, header]));
    return {
      user: req.user,
      profile: profile ? toCryptoProfileDto(profile) : null,
      recoveryKey: recoveryRows[0] ? await enterpriseRecoveryKeyDto(db, recoveryRows[0]) : null,
      devices: devices.map(toCryptoDeviceDto),
      vaults: visible.map(({ vault }) => {
        const state = states.find((row) => row.vaultId === vault.id)!;
        const migration = latestMigration(migrationJobs.filter((job) => job.vaultId === vault.id));
        const rekey = activeRekey(rekeyJobs.filter((job) => job.vaultId === vault.id));
        const header = activeHeaderByVault.get(vault.id) ?? null;
        const crypto = toVaultCryptoState(state, header, migration, rekey, recoveryByVault.has(vault.id));
        return {
          id: vault.id,
          kind: vault.kind,
          ownerUserId: vault.ownerUserId,
          ...(vault.kind === 'team' ? {
            projectContext: vault.parentVaultId === null
              ? { kind: 'root' as const }
              : {
                  kind: 'project' as const,
                  visibleParentVaultId: visibleVaultIds.has(vault.parentVaultId)
                    ? vault.parentVaultId
                    : null,
                },
          } : {}),
          createdAt: vault.createdAt.toISOString(),
          updatedAt: vault.updatedAt.toISOString(),
          crypto: pendingTeamVaultIds.has(vault.id)
            ? { ...crypto, rekeyTaskId: null, encryptedHeader: null }
            : crypto,
        };
      }),
      memberships: memberships.map(toMembershipDto),
      envelopes: ownEnvelopes.map(({ envelope, sender, signer }) => ({
        ...toEnvelopeDto(envelope, { userId: sender.userId, keyVersion: signer.cryptoGeneration }),
        senderDeviceId: sender.id,
      })),
      signerProfiles,
      headers: activeHeaders.map(toEncryptedHeader),
      items: currentItems.map(({ item, metadata }) => toEncryptedMetadata(item, metadata)),
      cursor: cursorRows[0]?.cursor ?? 0,
    };
  });

  r.post('/api/v2/vaults/:vaultId/initialize', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: InitializeVaultCryptoRequestSchema,
      response: { 200: VaultCryptoStateSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以初始化加密');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const profile = await getCryptoProfile(db, req.user.id);
    if (!profile) return conflict(reply, '请先设置主密码');
    if (req.body.header.vaultId !== req.params.vaultId || req.body.header.keyEpoch !== req.body.epoch || req.body.header.version !== 1) {
      return badRequest(reply, '加密头与密码库上下文不一致');
    }
    const unsigned = without(req.body, 'manifestSignature');
    if (!await verifyCommandSignature(req.body.manifestSignature, encodeBase64Url(actor.publicSigningKey), 'vault.initialize', {
      userId: req.user.id,
      vaultId: req.params.vaultId,
      request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认创建密码库，请刷新页面后重试');
    let keyPossessionPublicKey: Buffer;
    let header;
    try {
      keyPossessionPublicKey = decodeBase64Url(req.body.keyPossessionPublicKey, { exact: 32 });
      header = decodeCipherBlob(req.body.header.blob);
    } catch {
      return badRequest(reply, '密码库安全信息校验失败，请刷新页面后重试');
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const state = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (!state || state.storageMode !== 'legacy' || state.writeState !== 'open') throw new E2eeConflictError(state?.rowVersion ?? 0);
        if (!await emptyVaultInitializationAllowed(tx, req.params.vaultId, state)) {
          throw new E2eeConflictError(state.rowVersion, 'migration required');
        }
        await lockMigrationRecipientSources(tx);
        const currentProfile = (await tx.select().from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.user.id)).limit(1))[0];
        if (!currentProfile || currentProfile.cryptoGeneration !== profile.cryptoGeneration) {
          throw new VaultInitializationEnvelopeError();
        }
        const checkedEnvelopes = await validateEnvelopes(tx, req.body.envelopes, {
          vaultId: req.params.vaultId,
          epoch: 1,
          signerUserId: req.user.id,
          signerKeyVersion: currentProfile.cryptoGeneration,
          signerPublicKey: encodeBase64Url(currentProfile.publicSigningKey),
        }).catch(() => null);
        const exactRecipients = checkedEnvelopes
          ? await envelopesMatchExpectedRecipients(tx, req.params.vaultId, req.body.envelopes).catch(() => false)
          : false;
        if (!checkedEnvelopes || !exactRecipients) throw new VaultInitializationEnvelopeError();
        const commitments = envelopeCommitments(req.body.envelopes);
        await tx.update(vaults).set({ name: '', updatedAt: new Date() }).where(eq(vaults.id, req.params.vaultId));
        await tx.insert(vaultKeyEpochs).values({
          vaultId: req.params.vaultId,
          epoch: 1,
          previousEpoch: null,
          status: 'active',
          reason: 'initial',
          ...commitments,
          keyPossessionPublicKey,
          createdByUserId: req.user.id,
          createdByDeviceId: actor.id,
          activatedAt: new Date(),
        });
        await insertEnvelopes(
          tx,
          req.body.envelopes,
          checkedEnvelopes,
          actor.id,
          currentProfile.publicSigningKey,
          'active',
        );
        await tx.insert(encryptedVaultHeaders).values({
          vaultId: req.params.vaultId,
          headerVersion: 1,
          keyEpoch: 1,
          schemaVersion: req.body.headerFormatVersion ?? 2,
          ciphertext: header.ciphertext,
          nonce: header.nonce,
          ciphertextDigest: digestBlob(req.body.header.blob),
          createdByDeviceId: actor.id,
          signature: decodeBase64Url(req.body.manifestSignature, { exact: 64 }),
        });
        const now = new Date();
        const updated = (await tx.update(vaultCryptoStates).set({
          storageMode: 'e2ee',
          writeState: 'open',
          activeEpoch: 1,
          activeHeaderVersion: 1,
          accessGeneration: 1,
          rowVersion: state.rowVersion + 1,
          cutoverAt: now,
          legacyReadDisabledAt: now,
          updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).returning())[0]!;
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed',
          vaultId: req.params.vaultId,
          itemId: null,
          payload: { epoch: 1, headerVersion: 1 },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'vault.e2ee.initialize',
          vaultId: req.params.vaultId,
          success: true,
          details: {},
        });
        return { statusCode: 200, response: toVaultCryptoState(updated, null, null, null) };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, error.message === 'migration required'
          ? '该密码库包含旧数据，请先完成数据迁移'
          : '密码库状态已经变化，请刷新后重试');
      }
      if (error instanceof VaultInitializationEnvelopeError) {
        return conflict(reply, '成员、设备或恢复设置刚刚发生变化，请刷新后重新初始化密码库');
      }
      throw error;
    }
  });

  r.patch('/api/v2/vaults/:vaultId/header', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'],
      params: VaultParams,
      body: UpdateEncryptedVaultHeaderRequestSchema,
      response: { 200: EncryptedVaultHeaderSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以管理密码库名称和目录');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (
      req.body.header.vaultId !== req.params.vaultId ||
      req.body.header.version !== req.body.expectedHeaderVersion + 1
    ) return badRequest(reply, '密码库加密信息与版本不一致');
    const unsigned = without(req.body, 'signature');
    const action = req.body.operation === 'rename'
      ? 'vault.rename'
      : req.body.operation === 'details'
        ? 'vault.details.update'
        : 'vault.directories.update';
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), action, {
      userId: req.user.id,
      vaultId: req.params.vaultId,
      request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认密码库修改，请刷新页面后重试');
    let decodedHeader;
    try {
      decodedHeader = decodeCipherBlob(req.body.header.blob);
    } catch {
      return badRequest(reply, '密码库加密信息格式无效');
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const state = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (
          !state || state.storageMode !== 'e2ee' || state.writeState !== 'open' ||
          state.activeEpoch !== req.body.header.keyEpoch ||
          state.activeHeaderVersion !== req.body.expectedHeaderVersion
        ) throw new E2eeConflictError(state?.activeHeaderVersion ?? 0);
        const currentFormat = await activeHeaderFormatVersion(tx, state);
        if (currentFormat > req.body.headerFormatVersion) throw new VaultHeaderFormatOutdatedError();
        const headerRow = (await tx.insert(encryptedVaultHeaders).values({
          vaultId: req.params.vaultId,
          headerVersion: req.body.header.version,
          keyEpoch: req.body.header.keyEpoch,
          schemaVersion: req.body.headerFormatVersion,
          ciphertext: decodedHeader.ciphertext,
          nonce: decodedHeader.nonce,
          ciphertextDigest: digestBlob(req.body.header.blob),
          createdByDeviceId: actor.id,
          signature: decodeBase64Url(req.body.signature, { exact: 64 }),
        }).returning())[0]!;
        const now = new Date();
        await tx.update(vaultCryptoStates).set({
          activeHeaderVersion: req.body.header.version,
          rowVersion: state.rowVersion + 1,
          updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, req.params.vaultId));
        await tx.update(vaults).set({ updatedAt: now }).where(eq(vaults.id, req.params.vaultId));
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed',
          vaultId: req.params.vaultId,
          itemId: null,
          payload: { epoch: req.body.header.keyEpoch, headerVersion: req.body.header.version },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action,
          vaultId: req.params.vaultId,
          success: true,
          details: {},
        });
        return { statusCode: 200, response: toEncryptedHeader(headerRow) };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, '其他设备已经修改密码库设置或目录，请刷新后重试');
      }
      if (error instanceof VaultHeaderFormatOutdatedError) {
        return codedConflict(
          reply,
          'header_format_outdated',
          '当前页面版本较旧，请刷新页面后重新修改密码库设置',
        );
      }
      throw error;
    }
  });

  registerEncryptedMembershipRoutes(app);
  registerEncryptedItemRoutes(app);
  registerRekeyRoute(app);
  registerMigrationRoutes(app);
}

function registerEncryptedMembershipRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.put('/api/v2/vaults/:vaultId/members', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: VaultParams, body: SetEncryptedMembershipRequestSchema,
      response: { 200: SetEncryptedMembershipResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind === 'personal' || access.role !== 'owner') {
      return forbidden(reply, '只有密码库拥有者可以管理成员');
    }
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const profile = await getCryptoProfile(db, req.user.id);
    if (!profile) return conflict(reply, '请先设置主密码');
    if (req.body.subjectKind !== 'user' && req.body.role === 'owner') {
      return badRequest(reply, '用户组不能成为密码库拥有者');
    }
    const membershipMode = req.body.mode ?? 'replace';
    if (membershipMode === 'grant_or_upgrade' && (
      req.body.subjectKind !== 'user' || req.body.role === 'owner'
    )) {
      return badRequest(reply, '批量授权只支持为用户新增审计、查看、编辑权限或将查看升级为编辑');
    }
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'vault.membership.set', {
      userId: req.user.id, vaultId: req.params.vaultId, request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认成员变更，请刷新页面后重试');
    const subjectUsers = await resolveSubjectUsers(db, req.body.subjectKind, req.body.subjectId);
    if (!subjectUsers || subjectUsers.length === 0) return badRequest(reply, '授权对象不存在或没有可用成员');
    const capability = req.body.role === 'auditor' ? 'metadata' as const : 'full' as const;
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockRecipientSets(tx, subjectUsers);
        const lockedSubjectUsers = await resolveSubjectUsers(
          tx,
          req.body.subjectKind,
          req.body.subjectId,
        );
        if (!lockedSubjectUsers || !sameSet(new Set(subjectUsers), new Set(lockedSubjectUsers))) {
          throw new MembershipEnvelopeError();
        }
        const state = (await tx.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, req.params.vaultId))
          .for('update').limit(1))[0];
        if (!state || state.storageMode !== 'e2ee' || !state.activeEpoch ||
          state.accessGeneration !== req.body.expectedAccessGeneration
        ) throw new E2eeConflictError(state?.accessGeneration ?? 0);
        const currentProfile = (await tx.select().from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.user.id)).for('share').limit(1))[0];
        if (!currentProfile || currentProfile.cryptoGeneration !== profile.cryptoGeneration) {
          throw new MembershipEnvelopeError();
        }
        const currentRole = await directSubjectRole(
          tx,
          req.params.vaultId,
          req.body.subjectKind,
          req.body.subjectId,
        );
        if (membershipMode === 'grant_or_upgrade') {
          const currentEffectiveRole = await effectiveRoleForUser(
            tx,
            req.params.vaultId,
            req.body.subjectId,
          );
          if (!grantOrUpgradeAllowed(currentEffectiveRole, req.body.role)) {
            throw new MembershipGrantModeError();
          }
          if (currentRole === req.body.role) {
            return {
              statusCode: 200,
              response: {
                ok: true as const,
                accessGeneration: state.accessGeneration,
                rekeyRequired: false,
                retainedAccess: true,
                rekeyTask: null,
                envelopeTasks: null,
              },
            };
          }
        }
        const currentEffectiveCapability = req.body.subjectKind === 'user'
          ? await resolveAuthorizedVaultCapability(tx, req.params.vaultId, req.body.subjectId)
          : null;
        const reduction = (
          capabilityRank(capability) < capabilityRank(currentRole ? capabilityForRole(currentRole) : null)
        ) || (
          req.body.subjectKind === 'user' &&
          capability === 'metadata' &&
          currentEffectiveCapability === 'full'
        );
        if (reduction && req.body.envelopes.length > 0) {
          throw new MembershipEnvelopeError();
        }
        const preparedEnvelopes = reduction ? [] : await prepareMembershipEnvelopes(tx, req.body.envelopes, {
          vaultId: state.vaultId,
          epoch: state.activeEpoch,
          targetUserIds: subjectUsers,
          capability,
          signerUserId: req.user.id,
          signerKeyVersion: currentProfile.cryptoGeneration,
          signerPublicKey: encodeBase64Url(currentProfile.publicSigningKey),
        });
        if (preparedEnvelopes.length !== req.body.envelopes.length) throw new MembershipEnvelopeError();
        await setSubjectRole(tx, req.params.vaultId, req.body.subjectKind, req.body.subjectId, req.body.role);
        await assertDirectOwnerRemains(tx, req.params.vaultId);
        const now = new Date();
        let task = null;
        let retainedAccess = subjectUsers.length > 0;
        let distribution: Awaited<ReturnType<typeof ensureEnvelopeTasks>> | null = null;
        if (reduction) {
          await cancelEnvelopeTasks(tx, {
            vaultId: state.vaultId,
            authorizationKind: membershipAuthorizationKind(req.body.subjectKind),
            authorizationRef: req.body.subjectId,
            now,
          });
          const revocation = await revokeUsersAndRequireRekey(tx, state, subjectUsers, {
            initiatedByUserId: req.user.id,
            initiatedByDeviceId: actor.id,
            reason: 'role_reduced',
            now,
          });
          task = revocation.rekeyTask;
          retainedAccess = revocation.retainedAccessUserIds.length > 0;
          if (task) {
            collect(await recordSyncEvent(tx, {
              type: 'vault.rekey_required', vaultId: state.vaultId, itemId: null,
              payload: { pendingEpoch: task.toEpoch, taskId: task.id },
            }));
          } else {
            await tx.update(vaultCryptoStates).set({
              accessGeneration: state.accessGeneration + 1,
              rowVersion: state.rowVersion + 1,
              updatedAt: now,
            }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
            collect(await recordSyncEvent(tx, {
              type: 'vault.crypto_changed', vaultId: state.vaultId, itemId: null,
              payload: { accessChanged: true },
            }));
          }
        } else {
          for (const prepared of preparedEnvelopes) {
            const ciphertext = decodeBase64Url(prepared.envelope.sealedKeyBundle, { min: 49, max: 10_000 });
            await tx.insert(vaultKeyEnvelopes).values({
              vaultId: state.vaultId,
              keyEpoch: state.activeEpoch,
              recipientKind: 'user',
              accessScope: capability,
              recipientUserId: prepared.userId,
              recipientKeyFingerprint: prepared.fingerprint,
              authorizationKind: membershipAuthorizationKind(req.body.subjectKind),
              authorizationRef: req.body.subjectId,
              envelopeVersion: prepared.keyVersion,
              ciphertext,
              ciphertextDigest: sha256(ciphertext),
              senderDeviceId: actor.id,
              signerUserId: req.user.id,
              signerKeyVersion: currentProfile.cryptoGeneration,
              signerPublicKey: currentProfile.publicSigningKey,
              signature: decodeBase64Url(prepared.envelope.signature, { exact: 64 }),
              status: 'active',
              activatedAt: now,
            }).onConflictDoNothing();
          }
          distribution = await ensureEnvelopeTasks(tx, {
            vaultId: state.vaultId,
            keyEpoch: state.activeEpoch,
            authorizationKind: membershipAuthorizationKind(req.body.subjectKind),
            authorizationRef: req.body.subjectId,
            recipientUserIds: subjectUsers,
            capability,
            now,
          });
          await tx.update(vaultCryptoStates).set({
            accessGeneration: state.accessGeneration + 1,
            rowVersion: state.rowVersion + 1,
            updatedAt: now,
          }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
          collect(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed', vaultId: state.vaultId, itemId: null,
            payload: { accessChanged: true },
          }));
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'membership.e2ee.set',
          vaultId: state.vaultId,
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            ok: true as const,
            accessGeneration: state.accessGeneration + 1,
            rekeyRequired: task !== null,
            retainedAccess,
            rekeyTask: task ? { id: task.id, fromEpoch: task.fromEpoch, toEpoch: task.toEpoch } : null,
            envelopeTasks: distribution,
          },
        };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, '成员权限刚被其他人更新，请刷新成员列表，确认最新状态后再操作');
      }
      if (error instanceof MembershipEnvelopeError || isUniqueViolation(error)) {
        return conflict(reply, '成员自动访问交付信息不完整，请刷新后重试');
      }
      if (error instanceof MembershipGrantModeError) {
        return codedConflict(
          reply,
          'grant_would_reduce_access',
          '该成员当前权限更高或与目标权限不可直接比较。为避免批量操作意外降权，请打开这个项目的成员管理单独调整',
        );
      }
      if (error instanceof OwnerInvariantError) return conflict(reply, error.message);
      throw error;
    }
  });

  r.delete('/api/v2/vaults/:vaultId/members', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: VaultParams, body: RemoveEncryptedMembershipRequestSchema,
      response: { 200: RemoveEncryptedMembershipResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.vault.kind === 'personal' || access.role !== 'owner') {
      return forbidden(reply, '只有密码库拥有者可以管理成员');
    }
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'vault.membership.remove', {
      userId: req.user.id, vaultId: req.params.vaultId, request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认移除授权，请刷新页面后重试');
    const subjectUsers = await resolveSubjectUsers(db, req.body.subjectKind, req.body.subjectId);
    if (!subjectUsers) return badRequest(reply, '授权对象不存在');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await lockRecipientSets(tx, subjectUsers);
        const lockedSubjectUsers = await resolveSubjectUsers(
          tx,
          req.body.subjectKind,
          req.body.subjectId,
        );
        if (!lockedSubjectUsers || !sameSet(new Set(subjectUsers), new Set(lockedSubjectUsers))) {
          throw new MembershipEnvelopeError();
        }
        const state = (await tx.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, req.params.vaultId))
          .for('update').limit(1))[0];
        if (!state || state.storageMode !== 'e2ee' || !state.activeEpoch ||
          state.accessGeneration !== req.body.expectedAccessGeneration
        ) throw new E2eeConflictError(state?.accessGeneration ?? 0);
        await removeSubjectRole(tx, state.vaultId, req.body.subjectKind, req.body.subjectId);
        await assertDirectOwnerRemains(tx, state.vaultId);
        const now = new Date();
        await cancelEnvelopeTasks(tx, {
          vaultId: state.vaultId,
          authorizationKind: membershipAuthorizationKind(req.body.subjectKind),
          authorizationRef: req.body.subjectId,
          now,
        });
        const revocation = await revokeUsersAndRequireRekey(tx, state, subjectUsers, {
          initiatedByUserId: req.user.id,
          initiatedByDeviceId: actor.id,
          reason: 'member_removed',
          now,
        });
        const task = revocation.rekeyTask;
        if (task) {
          collect(await recordSyncEvent(tx, {
            type: 'vault.rekey_required', vaultId: state.vaultId, itemId: null,
            payload: { pendingEpoch: task.toEpoch, taskId: task.id },
          }));
        } else {
          await tx.update(vaultCryptoStates).set({
            accessGeneration: state.accessGeneration + 1,
            rowVersion: state.rowVersion + 1,
            updatedAt: now,
          }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
          collect(await recordSyncEvent(tx, {
            type: 'vault.crypto_changed', vaultId: state.vaultId, itemId: null,
            payload: { accessChanged: true },
          }));
        }
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'membership.e2ee.remove',
          vaultId: state.vaultId,
          success: true,
          details: {},
        });
        return {
          statusCode: 200,
          response: {
            ok: true as const,
            accessGeneration: state.accessGeneration + 1,
            rekeyRequired: task !== null,
            retainedAccess: revocation.retainedAccessUserIds.length > 0,
            rekeyTask: task ? { id: task.id, fromEpoch: task.fromEpoch, toEpoch: task.toEpoch } : null,
          },
        };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, '成员权限刚被其他人更新，请刷新成员列表，确认最新状态后再操作');
      }
      if (error instanceof MembershipEnvelopeError) {
        return conflict(reply, '授权对象成员刚发生变化，请刷新成员列表后重试');
      }
      if (error instanceof OwnerInvariantError) return conflict(reply, error.message);
      throw error;
    }
  });
}

function registerEncryptedItemRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.post('/api/v2/vaults/:vaultId/items', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: VaultParams, body: CreateEncryptedItemRequestSchema,
      response: { 201: EncryptedItemMetadataSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || !canEditItems(access.role)) return forbidden(reply, '没有新增条目的权限');
    if (req.body.itemId === req.params.vaultId) return badRequest(reply, '条目标识无效');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const unsigned = without(req.body, 'signature');
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'item.create', {
      userId: req.user.id, vaultId: req.params.vaultId, itemId: req.body.itemId, request: unsigned,
    })) return unauthorized(reply, '当前设备无法确认条目修改，请刷新页面后重试');
    let metadata: ReturnType<typeof decodeCipherBlob>;
    let encryptedValue: ReturnType<typeof decodeCipherBlob> | undefined;
    let wrappedDek: ReturnType<typeof decodeCipherBlob> | undefined;
    try {
      metadata = decodeCipherBlob(req.body.metadata);
      encryptedValue = decodeCipherBlob(req.body.encryptedValue);
      wrappedDek = decodeCipherBlob(req.body.wrappedDek, 48);
    } catch { return badRequest(reply, '条目数据校验失败，请刷新页面后重试'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        await assertWritableEpoch(tx, req.params.vaultId, req.body.keyEpoch);
        const item = (await tx.insert(items).values({
          id: req.body.itemId,
          vaultId: req.params.vaultId,
          kind: 'secure_note', title: '', username: null, origin: null, tags: [], favorite: false,
          sensitivity: 'medium', version: 1, secretVersion: 1, updatedBy: req.user.id,
        }).returning())[0]!;
        const signature = decodeBase64Url(req.body.signature, { exact: 64 });
        const metadataRow = (await tx.insert(encryptedItemMetadataVersions).values({
          itemId: item.id, vaultId: item.vaultId, recordVersion: 1, keyEpoch: req.body.keyEpoch,
          ciphertext: metadata.ciphertext, nonce: metadata.nonce, ciphertextDigest: digestBlob(req.body.metadata),
          createdByDeviceId: actor.id, signature,
        }).returning())[0]!;
        await tx.insert(encryptedItemSecretVersions).values({
          itemId: item.id, vaultId: item.vaultId, recordVersion: 1, secretVersion: 1,
          ciphertext: encryptedValue.ciphertext, nonce: encryptedValue.nonce,
          ciphertextDigest: digestBlob(req.body.encryptedValue), createdByDeviceId: actor.id, signature,
        });
        await tx.insert(encryptedItemKeyWraps).values({
          itemId: item.id, vaultId: item.vaultId, secretVersion: 1, keyEpoch: req.body.keyEpoch,
          wrappedDekCiphertext: wrappedDek.ciphertext, wrappedDekNonce: wrappedDek.nonce,
          ciphertextDigest: digestBlob(req.body.wrappedDek), createdByDeviceId: actor.id, signature,
        });
        const dto = toEncryptedMetadata(item, metadataRow);
        collect(await recordSyncEvent(tx, {
          type: 'item.encrypted_upserted', vaultId: item.vaultId, itemId: item.id, payload: { item: dto },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id, action: 'item.e2ee.create', vaultId: item.vaultId,
          itemId: item.id, success: true, details: {},
        });
        return { statusCode: 201, response: dto };
      });
      return reply.code(201).send(result.response);
    } catch (error) {
      if (isUniqueViolation(error)) return conflict(reply, '条目标识或幂等键已经使用');
      if (error instanceof E2eeConflictError) return conflict(reply, '密码库刚刚完成安全更新，请同步后重试');
      throw error;
    }
  });

  r.patch('/api/v2/items/:itemId', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: ItemParams, body: UpdateEncryptedItemRequestSchema,
      response: { 200: EncryptedItemMetadataSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => updateItem(req, reply, false));

  r.put('/api/v2/items/:itemId/secret', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: ItemParams, body: RotateEncryptedSecretRequestSchema,
      response: { 200: EncryptedItemMetadataSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => updateItem(req, reply, true));

  async function updateItem(
    req: EncryptedItemWriteRequest,
    reply: FastifyReply,
    rotateSecret: boolean,
  ) {
    const existing = (await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1))[0];
    if (!existing || existing.deleted) return reply.code(404).send(notFoundBody('条目不存在') as never);
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canEditItems(access.role)) return forbidden(reply, '没有编辑条目的权限');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const signatureKind = rotateSecret ? 'item.rotate_secret' : 'item.update_metadata';
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), signatureKind, {
      userId: req.user.id, vaultId: existing.vaultId, itemId: existing.id,
      request: without(req.body, 'signature'),
    })) return unauthorized(reply, '当前设备无法确认条目修改，请刷新页面后重试');
    if (req.body.metadataFormatVersion !== ITEM_METADATA_FORMAT_VERSION) {
      return reply.code(409).send({
        statusCode: 409,
        error: 'Conflict',
        code: 'metadata_format_outdated',
        message: '当前页面版本较旧，请刷新页面后重新编辑；系统尚未写入这次修改',
        currentVersion: existing.version,
      } as never);
    }
    let metadata: ReturnType<typeof decodeCipherBlob>;
    let encryptedValue: ReturnType<typeof decodeCipherBlob> | undefined;
    let wrappedDek: ReturnType<typeof decodeCipherBlob> | undefined;
    let encryptedValueDigest: Buffer | undefined;
    let wrappedDekDigest: Buffer | undefined;
    try {
      metadata = decodeCipherBlob(req.body.metadata);
      if (rotateSecret) {
        if (!req.body.encryptedValue || !req.body.wrappedDek) throw new Error('missing encrypted secret');
        encryptedValue = decodeCipherBlob(req.body.encryptedValue);
        wrappedDek = decodeCipherBlob(req.body.wrappedDek, 48);
        encryptedValueDigest = digestBlob(req.body.encryptedValue);
        wrappedDekDigest = digestBlob(req.body.wrappedDek);
      }
    } catch { return badRequest(reply, '条目数据校验失败，请刷新页面后重试'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const row = (await tx.select().from(items).where(eq(items.id, existing.id)).for('update').limit(1))[0]!;
        if (row.version !== req.body.expectedVersion) throw new E2eeConflictError(row.version);
        await assertWritableEpoch(tx, row.vaultId, req.body.keyEpoch);
        const nextVersion = row.version + 1;
        const nextSecretVersion = rotateSecret ? nextVersion : row.secretVersion;
        const signature = decodeBase64Url(req.body.signature, { exact: 64 });
        const metadataRow = (await tx.insert(encryptedItemMetadataVersions).values({
          itemId: row.id, vaultId: row.vaultId, recordVersion: nextVersion, keyEpoch: req.body.keyEpoch,
          ciphertext: metadata.ciphertext, nonce: metadata.nonce, ciphertextDigest: digestBlob(req.body.metadata),
          createdByDeviceId: actor.id, signature,
        }).returning())[0]!;
        if (rotateSecret) {
          if (!encryptedValue || !wrappedDek || !encryptedValueDigest || !wrappedDekDigest) {
            throw new Error('missing encrypted secret');
          }
          await tx.insert(encryptedItemSecretVersions).values({
            itemId: row.id, vaultId: row.vaultId, recordVersion: nextVersion, secretVersion: nextSecretVersion,
            ciphertext: encryptedValue.ciphertext, nonce: encryptedValue.nonce,
            ciphertextDigest: encryptedValueDigest, createdByDeviceId: actor.id, signature,
          });
          await tx.insert(encryptedItemKeyWraps).values({
            itemId: row.id, vaultId: row.vaultId, secretVersion: nextSecretVersion, keyEpoch: req.body.keyEpoch,
            wrappedDekCiphertext: wrappedDek.ciphertext, wrappedDekNonce: wrappedDek.nonce,
            ciphertextDigest: wrappedDekDigest, createdByDeviceId: actor.id, signature,
          });
        }
        const updated = (await tx.update(items).set({
          version: nextVersion, secretVersion: nextSecretVersion, updatedAt: new Date(), updatedBy: req.user.id,
        }).where(and(eq(items.id, row.id), eq(items.version, row.version))).returning())[0];
        if (!updated) throw new E2eeConflictError(row.version);
        const dto = toEncryptedMetadata(updated, metadataRow);
        collect(await recordSyncEvent(tx, {
          type: 'item.encrypted_upserted', vaultId: row.vaultId, itemId: row.id, payload: { item: dto },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: rotateSecret ? 'item.e2ee.rotate_secret' : 'item.e2ee.update_metadata',
          vaultId: row.vaultId, itemId: row.id, success: true, details: {},
        });
        return { statusCode: 200, response: dto };
      });
      return reply.code(200).send(result.response as never);
    } catch (error) {
      if (error instanceof E2eeConflictError) return versionConflict(reply, error.currentVersion);
      throw error;
    }
  }

  r.delete('/api/v2/items/:itemId', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: ItemParams, body: DeleteEncryptedItemRequestSchema,
      response: { 200: EncryptedItemMetadataSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const existing = (await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1))[0];
    if (!existing || existing.deleted) return reply.code(404).send(notFoundBody('条目不存在') as never);
    const access = await getVaultAccess(db, req.user, existing.vaultId);
    if (!access || !canEditItems(access.role)) return forbidden(reply, '没有删除条目的权限');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'item.delete', {
      userId: req.user.id, vaultId: existing.vaultId, itemId: existing.id,
      request: without(req.body, 'signature'),
    })) return unauthorized(reply, '当前设备无法确认删除条目，请刷新页面后重试');
    let metadata;
    try { metadata = decodeCipherBlob(req.body.metadata); } catch { return badRequest(reply, '条目数据校验失败，请刷新页面后重试'); }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const row = (await tx.select().from(items).where(eq(items.id, existing.id)).for('update').limit(1))[0]!;
        if (row.version !== req.body.expectedVersion) throw new E2eeConflictError(row.version);
        await assertWritableEpoch(tx, row.vaultId, req.body.keyEpoch);
        const nextVersion = row.version + 1;
        const signature = decodeBase64Url(req.body.signature, { exact: 64 });
        const metadataRow = (await tx.insert(encryptedItemMetadataVersions).values({
          itemId: row.id, vaultId: row.vaultId, recordVersion: nextVersion, keyEpoch: req.body.keyEpoch,
          ciphertext: metadata.ciphertext, nonce: metadata.nonce, ciphertextDigest: digestBlob(req.body.metadata),
          createdByDeviceId: actor.id, signature,
        }).returning())[0]!;
        const updated = (await tx.update(items).set({
          deleted: true, version: nextVersion, updatedAt: new Date(), updatedBy: req.user.id,
        }).where(and(eq(items.id, row.id), eq(items.version, row.version))).returning())[0]!;
        const dto = toEncryptedMetadata(updated, metadataRow);
        collect(await recordSyncEvent(tx, {
          type: 'item.deleted', vaultId: row.vaultId, itemId: row.id,
          payload: { version: nextVersion, keyEpoch: req.body.keyEpoch, metadata: dto },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id, action: 'item.e2ee.delete', vaultId: row.vaultId,
          itemId: row.id, success: true, details: {},
        });
        return { statusCode: 200, response: dto };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) return versionConflict(reply, error.currentVersion);
      throw error;
    }
  });

  r.post('/api/v2/items/:itemId/content', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee'], params: ItemParams, body: EncryptedContentRequestSchema,
      response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    const item = (await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1))[0];
    if (!item || item.deleted) return reply.code(404).send(notFoundBody('条目不存在') as never);
    const access = await getVaultAccess(db, req.user, item.vaultId);
    if (!access || !canReveal(access.role)) return forbidden(reply, '没有查看密码或敏感内容的权限');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.deviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.intentSignature, encodeBase64Url(actor.publicSigningKey), 'item.content.request', {
      userId: req.user.id, vaultId: item.vaultId, itemId: item.id,
      request: without(req.body, 'intentSignature'),
    })) return unauthorized(reply, '当前设备无法确认本次查看，请刷新页面后重试');
    const state = (await db.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, item.vaultId)).limit(1))[0];
    if (!state || state.storageMode !== 'e2ee' || !state.activeEpoch) return conflict(reply, '密码库尚未完成零知识迁移');
    const secretVersion = req.body.secretVersion ?? item.secretVersion;
    const [metadata, secret, keyWrap] = await Promise.all([
      db.select().from(encryptedItemMetadataVersions).where(and(
        eq(encryptedItemMetadataVersions.itemId, item.id),
        eq(encryptedItemMetadataVersions.recordVersion, item.version),
        eq(encryptedItemMetadataVersions.keyEpoch, state.activeEpoch),
      )).limit(1),
      db.select().from(encryptedItemSecretVersions).where(and(
        eq(encryptedItemSecretVersions.itemId, item.id),
        eq(encryptedItemSecretVersions.secretVersion, secretVersion),
      )).limit(1),
      db.select().from(encryptedItemKeyWraps).where(and(
        eq(encryptedItemKeyWraps.itemId, item.id),
        eq(encryptedItemKeyWraps.secretVersion, secretVersion),
        eq(encryptedItemKeyWraps.keyEpoch, state.activeEpoch),
      )).limit(1),
    ]);
    if (!metadata[0] || !secret[0] || !keyWrap[0]) return conflict(reply, '条目内容暂时不完整，请刷新后重试');
    await auditStandalone(db, audit, {
      actorUserId: req.user.id, action: 'item.e2ee.ciphertext_delivered',
      vaultId: item.vaultId, itemId: item.id, success: true, details: {},
    });
    return {
      metadata: toEncryptedMetadata(item, metadata[0]),
      secret: {
        itemId: item.id, vaultId: item.vaultId, secretVersion,
        encryptedValue: encodeCipherBlob(secret[0].nonce, secret[0].ciphertext),
        recordVersion: secret[0].recordVersion,
        signature: encodeBase64Url(secret[0].signature),
        createdAt: secret[0].createdAt.toISOString(),
        createdBy: secret[0].createdByDeviceId,
      },
      keyWrap: {
        itemId: item.id, vaultId: item.vaultId, secretVersion, keyEpoch: state.activeEpoch,
        wrappedDek: encodeCipherBlob(keyWrap[0].wrappedDekNonce, keyWrap[0].wrappedDekCiphertext),
        signature: encodeBase64Url(keyWrap[0].signature),
        createdAt: keyWrap[0].createdAt.toISOString(),
        createdBy: keyWrap[0].createdByDeviceId,
      },
    };
  });

  r.get('/api/v2/items/:itemId/versions', {
    preHandler: [app.requireSession],
    schema: { tags: ['e2ee'], params: ItemParams, response: { 200: z.array(z.unknown()), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const item = (await db.select().from(items).where(eq(items.id, req.params.itemId)).limit(1))[0];
    if (!item) return reply.code(404).send(notFoundBody('条目不存在') as never);
    const access = await getVaultAccess(db, req.user, item.vaultId);
    if (!access || access.role === null) return forbidden(reply, '没有查看条目版本的权限');
    const rows = await db.select().from(encryptedItemSecretVersions)
      .where(eq(encryptedItemSecretVersions.itemId, item.id)).orderBy(asc(encryptedItemSecretVersions.secretVersion));
    return rows.map((row) => ({
      itemId: row.itemId, secretVersion: row.secretVersion, recordVersion: row.recordVersion,
      createdAt: row.createdAt.toISOString(), createdByDeviceId: row.createdByDeviceId,
    }));
  });
}

function registerRekeyRoute(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  r.get('/api/v2/vaults/:vaultId/rekey-material', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee'], params: VaultParams, querystring: RekeyMaterialQuerySchema,
      response: { 200: RekeyMaterialSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const actor = await getActiveDevice(db, req.user.id, req.query.actorDeviceId);
    if (!actor || req.sessionRow.locked || req.sessionRow.unlockedDeviceId !== actor.id) return locked(reply);
    const task = (await db.select().from(vaultRekeyJobs).where(and(
      eq(vaultRekeyJobs.id, req.query.taskId),
      eq(vaultRekeyJobs.vaultId, req.params.vaultId),
      inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
    )).limit(1))[0];
    if (!task) return reply.code(404).send(notFoundBody('这次密码库安全更新已完成或不再需要，请刷新状态') as never);
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (access?.role !== 'owner') {
      const rawOwner = await isVaultOwnerWithoutEnvelope(db, req.params.vaultId, req.user.id);
      if (!rawOwner || !rawOwnerMayCompleteRekey(task, req.user.id, actor.id)) {
        return forbidden(reply, '只有密码库拥有者可以完成安全更新');
      }
    }
    if (!await verifyCommandSignature(req.query.signature, encodeBase64Url(actor.publicSigningKey), 'vault.rekey.material', {
      userId: req.user.id,
      vaultId: req.params.vaultId,
      request: { taskId: task.id, actorDeviceId: actor.id },
    })) return unauthorized(reply, '当前设备无法确认这次安全更新，请刷新页面后重试');
    const state = (await db.select().from(vaultCryptoStates)
      .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).limit(1))[0];
    if (!state?.activeEpoch || state.storageMode !== 'e2ee' || state.writeState !== 'rekeying' ||
      state.activeEpoch !== task.fromEpoch
    ) return conflict(reply, '密码库状态已经变化，请刷新后重试');
    const [headerRows, metadataRows, wrapRows, recipients, recoveryRows] = await Promise.all([
      db.select().from(encryptedVaultHeaders).where(and(
        eq(encryptedVaultHeaders.vaultId, state.vaultId),
        eq(encryptedVaultHeaders.headerVersion, state.activeHeaderVersion),
        eq(encryptedVaultHeaders.keyEpoch, state.activeEpoch),
      )).limit(1),
      db.select({ item: items, metadata: encryptedItemMetadataVersions })
        .from(items).innerJoin(encryptedItemMetadataVersions, and(
          eq(encryptedItemMetadataVersions.itemId, items.id),
          eq(encryptedItemMetadataVersions.recordVersion, items.version),
          eq(encryptedItemMetadataVersions.keyEpoch, state.activeEpoch),
        )).where(and(eq(items.vaultId, state.vaultId), eq(items.deleted, false))),
      db.select({ wrap: encryptedItemKeyWraps, recordVersion: encryptedItemSecretVersions.recordVersion })
        .from(encryptedItemKeyWraps)
        .innerJoin(encryptedItemSecretVersions, and(
          eq(encryptedItemSecretVersions.itemId, encryptedItemKeyWraps.itemId),
          eq(encryptedItemSecretVersions.secretVersion, encryptedItemKeyWraps.secretVersion),
          eq(encryptedItemSecretVersions.vaultId, encryptedItemKeyWraps.vaultId),
        ))
        .innerJoin(items, eq(items.id, encryptedItemKeyWraps.itemId))
        .where(and(
          eq(encryptedItemKeyWraps.vaultId, state.vaultId),
          eq(encryptedItemKeyWraps.keyEpoch, state.activeEpoch),
          eq(items.deleted, false),
        )).orderBy(asc(encryptedItemKeyWraps.itemId), asc(encryptedItemKeyWraps.secretVersion)),
      expectedVaultRecipients(db, state.vaultId),
      db.select().from(enterpriseRecoveryKeys).where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1),
    ]);
    if (!headerRows[0]) return conflict(reply, '密码库安全更新所需数据不完整，请刷新后重试');
    const devices = await expectedVaultDeviceRecipients(db, state.vaultId, recipients);
    reply.header('cache-control', 'no-store');
    return {
      task: {
        id: task.id,
        fromEpoch: task.fromEpoch,
        toEpoch: task.toEpoch,
        reason: task.reason,
        freezeGeneration: task.freezeGeneration,
      },
      state: toVaultCryptoState(state, headerRows[0], null, task),
      header: toEncryptedHeader(headerRows[0]),
      metadata: metadataRows.map(({ item, metadata }) => toEncryptedMetadata(item, metadata)),
      keyWraps: wrapRows.map(({ wrap, recordVersion }) => ({
        itemId: wrap.itemId,
        vaultId: wrap.vaultId,
        secretVersion: wrap.secretVersion,
        recordVersion,
        keyEpoch: wrap.keyEpoch,
        wrappedDek: encodeCipherBlob(wrap.wrappedDekNonce, wrap.wrappedDekCiphertext),
        signature: encodeBase64Url(wrap.signature),
        createdAt: wrap.createdAt.toISOString(),
        createdBy: wrap.createdByDeviceId,
      })),
      recipients,
      devices,
      recoveryKey: recoveryRows[0] ? await enterpriseRecoveryKeyDto(db, recoveryRows[0]) : null,
    };
  });

  r.post('/api/v2/vaults/:vaultId/rekey', {
    preHandler: [app.requireSession, app.requireCsrf],
    schema: {
      tags: ['e2ee'], params: VaultParams, body: RekeyWithHeaderRequestSchema,
      response: { 200: VaultCryptoStateSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (access?.role !== 'owner') {
      const [rawOwner, rotationTask] = await Promise.all([
        isVaultOwnerWithoutEnvelope(db, req.params.vaultId, req.user.id),
        db.select().from(vaultRekeyJobs).where(and(
          eq(vaultRekeyJobs.vaultId, req.params.vaultId),
          eq(vaultRekeyJobs.fromEpoch, req.body.expectedEpoch),
          eq(vaultRekeyJobs.toEpoch, req.body.newEpoch),
          inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
        )).limit(1),
      ]);
      if (!rawOwner || !rotationTask[0] || !rawOwnerMayCompleteRekey(rotationTask[0], req.user.id, actor.id)) {
        return forbidden(reply, '只有密码库拥有者可以完成安全更新');
      }
    }
    const profile = await getCryptoProfile(db, req.user.id);
    if (!profile) return conflict(reply, '请先设置主密码');
    if (req.body.newEpoch !== req.body.expectedEpoch + 1 ||
      req.body.header.vaultId !== req.params.vaultId ||
      req.body.header.keyEpoch !== req.body.newEpoch
    ) return badRequest(reply, '密码库状态已经变化，请刷新后重试');
    if (!await verifyCommandSignature(req.body.manifestSignature, encodeBase64Url(actor.publicSigningKey), 'vault.rekey', {
      userId: req.user.id, vaultId: req.params.vaultId,
      request: without(req.body, 'manifestSignature'),
    })) return unauthorized(reply, '当前设备无法确认这次安全更新，请刷新页面后重试');
    if (req.body.metadataFormatVersion !== ITEM_METADATA_FORMAT_VERSION) {
      return reply.code(409).send({
        statusCode: 409,
        error: 'Conflict',
        code: 'metadata_format_outdated',
        message: '当前页面版本较旧，请刷新页面后重新完成安全更新',
      } as never);
    }
    const checkedEnvelopes = await validateEnvelopes(db, req.body.envelopes, {
      vaultId: req.params.vaultId,
      epoch: req.body.newEpoch,
      signerUserId: req.user.id,
      signerKeyVersion: profile.cryptoGeneration,
      signerPublicKey: encodeBase64Url(profile.publicSigningKey),
    }).catch(() => null);
    const exactRecipients = checkedEnvelopes
      ? await envelopesMatchExpectedRecipients(db, req.params.vaultId, req.body.envelopes).catch(() => false)
      : false;
    if (!checkedEnvelopes || !exactRecipients) {
      return badRequest(reply, '安全更新未覆盖全部保留成员、设备和恢复设置，未做任何变更');
    }
    let keyPossessionPublicKey: Buffer;
    let header;
    try {
      keyPossessionPublicKey = decodeBase64Url(req.body.keyPossessionPublicKey, { exact: 32 });
      header = decodeCipherBlob(req.body.header.blob);
    } catch {
      return badRequest(reply, '密码库安全信息校验失败，请刷新页面后重试');
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const state = (await tx.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (!state || state.storageMode !== 'e2ee' || state.activeEpoch !== req.body.expectedEpoch) {
          throw new E2eeConflictError(state?.activeEpoch ?? 0);
        }
        const currentHeaderFormat = await activeHeaderFormatVersion(tx, state);
        if (currentHeaderFormat > (req.body.headerFormatVersion ?? 2)) {
          throw new VaultHeaderFormatOutdatedError();
        }
        if (req.body.header.version !== state.activeHeaderVersion + 1) throw new E2eeConflictError(state.activeHeaderVersion);
        if (!await envelopesMatchExpectedRecipients(tx, state.vaultId, req.body.envelopes)) {
          throw new E2eeConflictError(state.accessGeneration, 'recipient coverage changed');
        }
        const secretRows = await tx
          .select({ itemId: encryptedItemSecretVersions.itemId, secretVersion: encryptedItemSecretVersions.secretVersion })
          .from(encryptedItemSecretVersions)
          .innerJoin(items, eq(items.id, encryptedItemSecretVersions.itemId))
          .where(and(
            eq(encryptedItemSecretVersions.vaultId, req.params.vaultId),
            eq(items.deleted, false),
          ));
        const metadataRows = await tx
          .select({ itemId: items.id, version: items.version })
          .from(items)
          .where(and(eq(items.vaultId, req.params.vaultId), eq(items.deleted, false)));
        const expectedSecrets = uniquePairs(secretRows, (row) => `${row.itemId}:${row.secretVersion}`);
        const suppliedSecrets = uniquePairs(req.body.rewrappedSecrets, (row) => `${row.itemId}:${row.secretVersion}`);
        const expectedMetadata = uniquePairs(metadataRows, (row) => `${row.itemId}:${row.version}`);
        const suppliedMetadata = uniquePairs(req.body.reencryptedMetadata, (row) => `${row.itemId}:${row.version}`);
        if (!sameSet(expectedSecrets, suppliedSecrets) || !sameSet(expectedMetadata, suppliedMetadata)) {
          throw new E2eeConflictError(state.activeEpoch, 'coverage incomplete');
        }
        const commitments = envelopeCommitments(req.body.envelopes);
        const now = new Date();
        const reason = mapRekeyReason(req.body.reason);
        const pendingTask = (await tx.select().from(vaultRekeyJobs).where(and(
          eq(vaultRekeyJobs.vaultId, state.vaultId),
          inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
        )).for('update').limit(1))[0];
        if (pendingTask && (
          pendingTask.fromEpoch !== req.body.expectedEpoch ||
          pendingTask.toEpoch !== req.body.newEpoch ||
          pendingTask.reason !== reason
        )) throw new E2eeConflictError(state.activeEpoch, 'pending rekey task mismatch');
        await tx.update(vaultCryptoStates).set({
          writeState: 'rekeying', rowVersion: state.rowVersion + 1, updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
        if (pendingTask) {
          const updatedEpoch = await tx.update(vaultKeyEpochs).set({
            reason,
            ...commitments,
            keyPossessionPublicKey,
            createdByUserId: req.user.id,
            createdByDeviceId: actor.id,
          }).where(and(
            eq(vaultKeyEpochs.vaultId, state.vaultId),
            eq(vaultKeyEpochs.epoch, req.body.newEpoch),
            eq(vaultKeyEpochs.status, 'preparing'),
          )).returning({ epoch: vaultKeyEpochs.epoch });
          if (updatedEpoch.length !== 1) throw new E2eeConflictError(state.activeEpoch, 'pending epoch missing');
        } else {
          await tx.insert(vaultKeyEpochs).values({
            vaultId: state.vaultId, epoch: req.body.newEpoch, previousEpoch: req.body.expectedEpoch,
            status: 'preparing', reason, ...commitments,
            keyPossessionPublicKey,
            createdByUserId: req.user.id, createdByDeviceId: actor.id,
          });
        }
        await insertEnvelopes(
          tx,
          req.body.envelopes,
          checkedEnvelopes,
          actor.id,
          profile.publicSigningKey,
          'pending',
        );
        const manifestSignature = decodeBase64Url(req.body.manifestSignature, { exact: 64 });
        await tx.insert(encryptedVaultHeaders).values({
          vaultId: state.vaultId, headerVersion: req.body.header.version, keyEpoch: req.body.newEpoch,
          schemaVersion: req.body.headerFormatVersion ?? 2,
          ciphertext: header.ciphertext, nonce: header.nonce, ciphertextDigest: digestBlob(req.body.header.blob),
          createdByDeviceId: actor.id, signature: manifestSignature,
        });
        for (const record of req.body.rewrappedSecrets) {
          const blob = decodeCipherBlob(record.wrappedDek, 48);
          await tx.insert(encryptedItemKeyWraps).values({
            itemId: record.itemId, vaultId: state.vaultId, secretVersion: record.secretVersion,
            keyEpoch: req.body.newEpoch, wrappedDekCiphertext: blob.ciphertext, wrappedDekNonce: blob.nonce,
            ciphertextDigest: digestBlob(record.wrappedDek), createdByDeviceId: actor.id,
            signature: manifestSignature,
          });
        }
        for (const record of req.body.reencryptedMetadata) {
          const blob = decodeCipherBlob(record.blob);
          await tx.insert(encryptedItemMetadataVersions).values({
            itemId: record.itemId, vaultId: state.vaultId, recordVersion: record.version,
            keyEpoch: req.body.newEpoch, ciphertext: blob.ciphertext, nonce: blob.nonce,
            ciphertextDigest: digestBlob(record.blob), createdByDeviceId: actor.id,
            signature: manifestSignature,
          });
        }
        const jobValues = {
          reason,
          status: 'committed' as const,
          expectedRecipientCount: req.body.envelopes.length,
          distributedRecipientCount: req.body.envelopes.length,
          expectedSecretVersionCount: expectedSecrets.size,
          rewrappedSecretVersionCount: suppliedSecrets.size,
          expectedMetadataVersionCount: expectedMetadata.size,
          reencryptedMetadataVersionCount: suppliedMetadata.size,
          sourceDigest: sha256(JSON.stringify([...expectedSecrets, ...expectedMetadata].sort())),
          resultDigest: sha256(JSON.stringify(req.body)),
          verificationSignature: manifestSignature,
          initiatedByUserId: req.user.id,
          initiatedByDeviceId: actor.id,
          startedAt: pendingTask?.startedAt ?? now,
          committedAt: now,
          updatedAt: now,
        };
        if (pendingTask) {
          await tx.update(vaultRekeyJobs).set(jobValues).where(eq(vaultRekeyJobs.id, pendingTask.id));
        } else {
          await tx.insert(vaultRekeyJobs).values({
            vaultId: state.vaultId,
            fromEpoch: req.body.expectedEpoch,
            toEpoch: req.body.newEpoch,
            freezeGeneration: state.accessGeneration,
            ...jobValues,
          });
        }
        await tx.update(vaultKeyEpochs).set({ status: 'retired', retiredAt: now }).where(and(
          eq(vaultKeyEpochs.vaultId, state.vaultId), eq(vaultKeyEpochs.epoch, req.body.expectedEpoch),
        ));
        await tx.update(vaultKeyEnvelopes).set({ status: 'superseded', revokedAt: now, revocationReason: req.body.reason })
          .where(and(eq(vaultKeyEnvelopes.vaultId, state.vaultId), eq(vaultKeyEnvelopes.keyEpoch, req.body.expectedEpoch), eq(vaultKeyEnvelopes.status, 'active')));
        await tx.update(vaultKeyEpochs).set({ status: 'active', activatedAt: now }).where(and(
          eq(vaultKeyEpochs.vaultId, state.vaultId), eq(vaultKeyEpochs.epoch, req.body.newEpoch),
        ));
        await tx.update(vaultKeyEnvelopes).set({ status: 'active', activatedAt: now }).where(and(
          eq(vaultKeyEnvelopes.vaultId, state.vaultId), eq(vaultKeyEnvelopes.keyEpoch, req.body.newEpoch),
        ));
        const updated = (await tx.update(vaultCryptoStates).set({
          writeState: 'open', activeEpoch: req.body.newEpoch, activeHeaderVersion: req.body.header.version,
          accessGeneration: state.accessGeneration + 1, rowVersion: state.rowVersion + 2, updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, state.vaultId)).returning())[0]!;
        const activatedEnvelopes = await tx.select().from(vaultKeyEnvelopes).where(and(
          eq(vaultKeyEnvelopes.vaultId, state.vaultId),
          eq(vaultKeyEnvelopes.keyEpoch, req.body.newEpoch),
          eq(vaultKeyEnvelopes.status, 'active'),
        ));
        await settleEnvelopeTasksAfterRekey(tx, state.vaultId, req.body.newEpoch, activatedEnvelopes, now);
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed', vaultId: state.vaultId, itemId: null,
          payload: { epoch: req.body.newEpoch, headerVersion: req.body.header.version },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id, action: 'vault.e2ee.rekey', vaultId: state.vaultId,
          success: true, details: {},
        });
        return { statusCode: 200, response: toVaultCryptoState(updated, null, null, null) };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, error.message === 'coverage incomplete'
          ? '安全更新未覆盖全部保留成员、设备和恢复设置，未做任何变更'
          : '密码库状态已经变化，请刷新后重试');
      }
      if (error instanceof VaultHeaderFormatOutdatedError) {
        return codedConflict(
          reply,
          'header_format_outdated',
          '当前页面版本较旧，请刷新页面后重新完成安全更新',
        );
      }
      throw error;
    }
  });
}

function registerMigrationRoutes(app: FastifyInstance): void {
  const { db, bus, audit } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();
  const writeGuard = [app.requireSession, app.requireCsrf];

  r.get('/api/v2/vaults/:vaultId/migration', {
    preHandler: [app.requireSession],
    schema: {
      tags: ['e2ee-migration'],
      params: VaultParams,
      response: { 200: LegacyMigrationStatusResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以查看迁移状态');
    const [jobs, canInitializeEmptyVault] = await Promise.all([
      db.select().from(legacyMigrationJobs)
        .where(eq(legacyMigrationJobs.vaultId, req.params.vaultId)).orderBy(desc(legacyMigrationJobs.attempt)),
      emptyVaultInitializationAllowed(db, req.params.vaultId),
    ]);
    const materials = await migrationRecipientMaterials(db, req.params.vaultId, canInitializeEmptyVault);
    if (!jobs[0]) {
      return {
        status: 'pending' as const,
        job: null,
        materials,
        emptyVaultInitializationAllowed: canInitializeEmptyVault,
      };
    }
    return {
      status: migrationStatus(jobs[0].state),
      job: migrationJobDto(jobs[0]),
      materials,
      emptyVaultInitializationAllowed: canInitializeEmptyVault,
    };
  });

  r.post('/api/v2/vaults/:vaultId/migration/start', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-migration'], params: VaultParams, body: MigrationStartRequestSchema, response: { 201: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以开始迁移');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'migration.start', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'signature'),
    })) return unauthorized(reply, '迁移签名无效');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        await tx.execute(sql`LOCK TABLE vaults, items, item_secret_versions, audit_events, sync_events IN SHARE ROW EXCLUSIVE MODE`);
        const state = (await tx.select().from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, req.params.vaultId)).for('update').limit(1))[0];
        if (!state || state.storageMode !== 'legacy' || state.writeState !== 'open') throw new E2eeConflictError(state?.rowVersion ?? 0);
        const vault = await tx.select().from(vaults).where(eq(vaults.id, req.params.vaultId)).limit(1);
        const directOwner = await tx.select({ id: vaultMemberships.id }).from(vaultMemberships).where(and(
          eq(vaultMemberships.vaultId, req.params.vaultId),
          eq(vaultMemberships.subjectKind, 'user'),
          eq(vaultMemberships.subjectId, req.user.id),
          eq(vaultMemberships.role, 'owner'),
        )).limit(1);
        const profile = await tx.select().from(userCryptoProfiles)
          .where(eq(userCryptoProfiles.userId, req.user.id)).limit(1);
        if (!profile[0]) throw new E2eeConflictError(state.rowVersion, 'crypto profile missing');
        if (!directOwner[0] && vault[0]?.ownerUserId !== req.user.id) {
          throw new E2eeConflictError(state.rowVersion, 'direct owner required');
        }
        const attempts = await tx.select({ value: max(legacyMigrationJobs.attempt) }).from(legacyMigrationJobs)
          .where(eq(legacyMigrationJobs.vaultId, req.params.vaultId));
        const epochs = await tx.select({ value: max(vaultKeyEpochs.epoch) }).from(vaultKeyEpochs)
          .where(eq(vaultKeyEpochs.vaultId, req.params.vaultId));
        const attempt = (attempts[0]?.value ?? 0) + 1;
        const targetEpoch = (epochs[0]?.value ?? 0) + 1;
        const now = new Date();
        await tx.update(vaultCryptoStates).set({
          writeState: 'frozen', rowVersion: state.rowVersion + 1, updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, state.vaultId));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id, action: 'migration.freeze', vaultId: state.vaultId,
          success: true, details: {},
        });
        const sourceManifest = await buildLegacySourceManifest(tx, req.params.vaultId);
        const sourceDigest = legacySourceDigest(sourceManifest);
        const sourceRecords = legacySourceRecords(sourceManifest);
        await tx.insert(vaultKeyEpochs).values({
          vaultId: req.params.vaultId, epoch: targetEpoch, previousEpoch: null,
          status: 'preparing', reason: 'migration',
          metadataKeyCommitment: Buffer.alloc(32), contentKeyCommitment: Buffer.alloc(32),
          recipientSetDigest: Buffer.alloc(32), createdByUserId: req.user.id, createdByDeviceId: actor.id,
        });
        const job = (await tx.insert(legacyMigrationJobs).values({
          vaultId: req.params.vaultId, attempt, state: 'legacy', targetEpoch,
          sourceSnapshotHash: sourceDigest,
          sourceAuditHeadHash: sourceManifest.audit.headHash,
          expectedItemCount: sourceManifest.items.length,
          expectedMetadataVersionCount: sourceManifest.items.length,
          expectedSecretVersionCount: sourceManifest.items.reduce((count, item) => count + item.secretVersions.length, 0),
          expectedRecipientCount: 0,
          expectedAuditEventCount: sourceManifest.audit.eventCount,
          startedByUserId: req.user.id, startedByDeviceId: actor.id,
          exportRecipientUserId: req.user.id,
          exportRecipientKeyVersion: profile[0].cryptoGeneration,
          exportRecipientKeyDigest: sha256(profile[0].publicEncryptionKey),
          exportExpiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000),
          startedAt: now,
        }).returning())[0]!;
        await tx.insert(legacyMigrationRecords).values(sourceRecords.map((record) => ({
          jobId: job.id,
          ...record,
        })));
        await tx.update(legacyMigrationJobs).set({ state: 'preparing', updatedAt: now }).where(eq(legacyMigrationJobs.id, job.id));
        const frozen = (await tx.update(legacyMigrationJobs).set({ state: 'frozen', frozenAt: now, updatedAt: now })
          .where(eq(legacyMigrationJobs.id, job.id)).returning())[0]!;
        await tx.insert(legacyMigrationEvidence).values({
          jobId: job.id, evidenceType: 'source_snapshot', stage: 'frozen', subjectKind: 'vault',
          subjectId: state.vaultId, recordCount: sourceRecords.length,
          digest: sourceDigest, signerDeviceId: actor.id,
          signature: decodeBase64Url(req.body.signature, { exact: 64 }),
        });
        return { statusCode: 201, response: migrationJobDto(frozen) };
      });
      return reply.code(201).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError || isUniqueViolation(error)) {
        if (error instanceof E2eeConflictError && error.message === 'crypto profile missing') {
          return conflict(reply, '请先设置主密码，再开始旧数据迁移');
        }
        if (error instanceof E2eeConflictError && error.message === 'direct owner required') {
          return conflict(reply, '请先把当前用户设为密码库的直接拥有者，再开始迁移');
        }
        return conflict(reply, '密码库已经进入迁移或加密状态');
      }
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/migration/export', {
    preHandler: writeGuard,
    schema: {
      tags: ['e2ee-migration'],
      params: VaultParams,
      body: LegacyMigrationExportClaimRequestSchema,
      response: { 200: LegacyMigrationExportResponseSchema, '4xx': ZeroKnowledgeApiErrorSchema },
    },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以导出迁移快照');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'migration.export.claim', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'signature'),
    })) return unauthorized(reply, '迁移导出签名无效');
    try {
      const claimed = await db.transaction(async (tx) => {
        const job = (await tx.select().from(legacyMigrationJobs).where(and(
          eq(legacyMigrationJobs.vaultId, req.params.vaultId),
          eq(legacyMigrationJobs.state, 'encrypting'),
        )).orderBy(desc(legacyMigrationJobs.attempt)).for('update').limit(1))[0];
        if (!job) throw new E2eeConflictError(0, 'export not ready');
        const migrationExport = (await tx.select().from(legacyMigrationExports).where(and(
          eq(legacyMigrationExports.jobId, job.id),
          eq(legacyMigrationExports.recipientUserId, req.user.id),
        )).for('update').limit(1))[0];
        if (!migrationExport) throw new E2eeConflictError(0, 'export not ready');
        if (migrationExport.claimedAt) throw new E2eeConflictError(0, 'export claimed');
        const now = new Date();
        if (migrationExport.expiresAt.getTime() <= now.getTime()) throw new E2eeConflictError(0, 'export expired');
        await tx.update(legacyMigrationExports).set({
          claimedAt: now,
          claimedByDeviceId: actor.id,
        }).where(eq(legacyMigrationExports.id, migrationExport.id));
        const head = await appendAudit(tx, audit, {
          actorUserId: req.user.id,
          action: 'migration.export_claimed',
          vaultId: req.params.vaultId,
          success: true,
          details: {},
        });
        return {
          head,
          response: {
            sealedExport: encodeBase64Url(migrationExport.sealedExport),
            recipientKeyVersion: migrationExport.recipientKeyVersion,
            sourceDigest: encodeBase64Url(migrationExport.sourceDigest),
          },
        };
      });
      recordAnchor(audit, claimed.head);
      return claimed.response;
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        if (error.message === 'export claimed') return migrationExportGone(reply, '迁移导出已经领取，不能再次下载');
        if (error.message === 'export expired') return migrationExportGone(reply, '迁移导出已经过期，请回滚后重新开始');
        return conflict(reply, '隔离迁移 worker 尚未生成密文导出');
      }
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/migration/target', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-migration'], params: VaultParams, body: MigrationPrepareTargetRequestSchema, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以提交迁移密钥');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    const profile = await getCryptoProfile(db, req.user.id);
    if (!profile) return conflict(reply, '请先设置主密码');
    const job = (await db.select().from(legacyMigrationJobs).where(and(
      eq(legacyMigrationJobs.id, req.body.jobId), eq(legacyMigrationJobs.vaultId, req.params.vaultId),
    )).limit(1))[0];
    if (!job || job.state !== 'encrypting') return conflict(reply, '迁移任务状态不允许提交目标密文');
    if (req.body.header.vaultId !== req.params.vaultId || req.body.header.keyEpoch !== job.targetEpoch || req.body.header.version !== 1) {
      return badRequest(reply, '加密头与迁移任务不匹配');
    }
    if (!await verifyCommandSignature(req.body.manifestSignature, encodeBase64Url(actor.publicSigningKey), 'migration.target.prepare', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'manifestSignature'),
    })) return unauthorized(reply, '迁移目标签名无效');
    const recipients = await validateEnvelopes(db, req.body.envelopes, {
      vaultId: req.params.vaultId, epoch: job.targetEpoch, signerUserId: req.user.id,
      signerKeyVersion: profile.cryptoGeneration, signerPublicKey: encodeBase64Url(profile.publicSigningKey),
    }).catch(() => null);
    const exactRecipients = recipients
      ? await envelopesMatchExpectedRecipients(db, req.params.vaultId, req.body.envelopes).catch(() => false)
      : false;
    if (!recipients || !exactRecipients) return badRequest(reply, '迁移密钥分发必须精确覆盖全部有效成员、设备和当前恢复设置');
    let keyPossessionPublicKey: Buffer;
    let header;
    try {
      keyPossessionPublicKey = decodeBase64Url(req.body.keyPossessionPublicKey, { exact: 32 });
      header = decodeCipherBlob(req.body.header.blob);
    } catch {
      return badRequest(reply, '密码库安全信息校验失败，请刷新页面后重试');
    }
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const lockedJob = (await tx.select().from(legacyMigrationJobs).where(eq(legacyMigrationJobs.id, job.id)).for('update').limit(1))[0]!;
        if (lockedJob.state !== 'encrypting') throw new E2eeConflictError(0);
        const commitments = envelopeCommitments(req.body.envelopes);
        await tx.update(vaultKeyEpochs).set({ ...commitments, keyPossessionPublicKey }).where(and(
          eq(vaultKeyEpochs.vaultId, job.vaultId), eq(vaultKeyEpochs.epoch, job.targetEpoch),
        ));
        await insertEnvelopes(
          tx,
          req.body.envelopes,
          recipients,
          actor.id,
          profile.publicSigningKey,
          'pending',
        );
        const headerRow = (await tx.insert(encryptedVaultHeaders).values({
          vaultId: job.vaultId, headerVersion: 1, keyEpoch: job.targetEpoch,
          schemaVersion: req.body.headerFormatVersion ?? 2,
          ciphertext: header.ciphertext, nonce: header.nonce, ciphertextDigest: digestBlob(req.body.header.blob),
          createdByDeviceId: actor.id, signature: decodeBase64Url(req.body.manifestSignature, { exact: 64 }),
          migrationJobId: job.id,
        }).returning())[0]!;
        await tx.update(legacyMigrationRecords).set({
          targetRecordId: headerRow.id, state: 'encrypted', targetDigest: headerRow.ciphertextDigest,
          updatedAt: new Date(),
        }).where(and(
          eq(legacyMigrationRecords.jobId, job.id), eq(legacyMigrationRecords.sourceKind, 'vault_header'),
          eq(legacyMigrationRecords.sourceId, job.vaultId),
        ));
        await tx.update(legacyMigrationJobs).set({
          expectedRecipientCount: req.body.envelopes.length, updatedAt: new Date(),
        }).where(eq(legacyMigrationJobs.id, job.id));
        await updateMigrationCheckpoint(tx, job.id);
        return { statusCode: 200, response: { ok: true, jobId: job.id } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError || isUniqueViolation(error)) return conflict(reply, '迁移目标已经提交或状态已变化');
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/migration/records', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-migration'], params: VaultParams, body: MigrationUploadRequestSchema, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以上传迁移密文');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'migration.records.upload', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'signature'),
    })) return unauthorized(reply, '迁移记录签名无效');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const job = (await tx.select().from(legacyMigrationJobs).where(and(
          eq(legacyMigrationJobs.id, req.body.jobId), eq(legacyMigrationJobs.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        if (!job || job.state !== 'encrypting') throw new E2eeConflictError(0);
        const signature = decodeBase64Url(req.body.signature, { exact: 64 });
        for (const record of req.body.records) {
          const sourceKind = record.kind === 'metadata' ? 'item_metadata' : 'item_secret';
          const source = (await tx.select().from(legacyMigrationRecords).where(and(
            eq(legacyMigrationRecords.jobId, job.id), eq(legacyMigrationRecords.sourceKind, sourceKind),
            eq(legacyMigrationRecords.sourceId, record.sourceId), eq(legacyMigrationRecords.sourceVersion, record.sourceVersion),
          )).for('update').limit(1))[0];
          const suppliedSourceDigest = decodeBase64Url(record.sourceDigest, { exact: 32 });
          if (!source || !Buffer.from(source.sourceDigest).equals(suppliedSourceDigest)) throw new E2eeConflictError(0, 'source mismatch');
          if (source.state === 'encrypted' || source.state === 'verified') continue;
          if (record.kind === 'metadata') {
            if (record.sourceId !== record.itemId || record.sourceVersion !== record.version) throw new E2eeConflictError(0, 'source mismatch');
            const item = (await tx.select().from(items).where(and(eq(items.id, record.itemId), eq(items.vaultId, job.vaultId))).limit(1))[0];
            if (!item || item.version !== record.version) throw new E2eeConflictError(0, 'source mismatch');
            const blob = decodeCipherBlob(record.blob);
            const inserted = (await tx.insert(encryptedItemMetadataVersions).values({
              itemId: item.id, vaultId: job.vaultId, recordVersion: record.version, keyEpoch: job.targetEpoch,
              ciphertext: blob.ciphertext, nonce: blob.nonce, ciphertextDigest: digestBlob(record.blob),
              createdByDeviceId: actor.id, signature, migrationJobId: job.id,
            }).returning())[0]!;
            await tx.update(legacyMigrationRecords).set({
              targetRecordId: inserted.id, targetDigest: inserted.ciphertextDigest,
              state: 'encrypted', updatedAt: new Date(),
            }).where(and(eq(legacyMigrationRecords.jobId, job.id), eq(legacyMigrationRecords.sourceKind, sourceKind), eq(legacyMigrationRecords.sourceId, source.sourceId), eq(legacyMigrationRecords.sourceVersion, source.sourceVersion)));
          } else {
            const legacy = (await tx.select().from(itemSecretVersions).where(and(
              eq(itemSecretVersions.id, record.sourceId), eq(itemSecretVersions.itemId, record.itemId),
              eq(itemSecretVersions.vaultId, job.vaultId), eq(itemSecretVersions.secretVersion, record.secretVersion),
            )).limit(1))[0];
            if (!legacy || record.sourceVersion !== record.secretVersion || record.recordVersion !== record.secretVersion) throw new E2eeConflictError(0, 'source mismatch');
            const value = decodeCipherBlob(record.encryptedValue);
            const wrap = decodeCipherBlob(record.wrappedDek, 48);
            const inserted = (await tx.insert(encryptedItemSecretVersions).values({
              itemId: record.itemId, vaultId: job.vaultId, recordVersion: record.recordVersion,
              secretVersion: record.secretVersion, ciphertext: value.ciphertext, nonce: value.nonce,
              ciphertextDigest: digestBlob(record.encryptedValue), createdByDeviceId: actor.id,
              signature, legacySecretVersionId: legacy.id, migrationJobId: job.id,
            }).returning())[0]!;
            const targetDigest = sha256(Buffer.concat([digestBlob(record.encryptedValue), digestBlob(record.wrappedDek)]));
            await tx.insert(encryptedItemKeyWraps).values({
              itemId: record.itemId, vaultId: job.vaultId, secretVersion: record.secretVersion,
              keyEpoch: job.targetEpoch, wrappedDekCiphertext: wrap.ciphertext, wrappedDekNonce: wrap.nonce,
              ciphertextDigest: digestBlob(record.wrappedDek), createdByDeviceId: actor.id,
              signature, migrationJobId: job.id,
            });
            await tx.update(legacyMigrationRecords).set({
              targetRecordId: inserted.id, targetDigest, state: 'encrypted', updatedAt: new Date(),
            }).where(and(eq(legacyMigrationRecords.jobId, job.id), eq(legacyMigrationRecords.sourceKind, sourceKind), eq(legacyMigrationRecords.sourceId, source.sourceId), eq(legacyMigrationRecords.sourceVersion, source.sourceVersion)));
          }
        }
        const counts = await updateMigrationCheckpoint(tx, job.id);
        return { statusCode: 200, response: { ok: true, jobId: job.id, ...counts } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) return conflict(reply, error.message === 'source mismatch' ? '迁移来源记录不匹配' : '迁移任务状态已经变化');
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/migration/verify', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-migration'], params: VaultParams, body: LegacyMigrationManifestSchema, response: { 200: z.unknown(), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以验证迁移');
    if (req.body.vaultId !== req.params.vaultId) return badRequest(reply, '迁移清单与密码库不匹配');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'migration.verify', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'signature'),
    })) return unauthorized(reply, '迁移验证签名无效');
    try {
      const verified = await db.transaction(async (tx) => {
        const job = (await tx.select().from(legacyMigrationJobs).where(and(
          eq(legacyMigrationJobs.vaultId, req.params.vaultId), eq(legacyMigrationJobs.state, 'encrypting'),
        )).orderBy(desc(legacyMigrationJobs.attempt)).for('update').limit(1))[0];
        if (!job || !job.sourceSnapshotHash) throw new E2eeConflictError(0);
        const records = await tx.select().from(legacyMigrationRecords).where(eq(legacyMigrationRecords.jobId, job.id));
        if (records.some((record) => record.state !== 'encrypted' || !record.targetDigest)) throw new E2eeConflictError(0, 'coverage incomplete');
        const targetDigest = migrationTargetDigest(records);
        const envelopes = await tx.select().from(vaultKeyEnvelopes).where(and(
          eq(vaultKeyEnvelopes.vaultId, job.vaultId), eq(vaultKeyEnvelopes.keyEpoch, job.targetEpoch),
          eq(vaultKeyEnvelopes.status, 'pending'),
        ));
        const expectedRecipients = envelopes.map((envelope) => envelope.recipientUserId ?? envelope.recipientDeviceId ?? envelope.recipientRecoveryKeyId!).sort();
        if (
          req.body.legacyItemCount !== job.expectedItemCount ||
          req.body.legacySecretVersionCount !== job.expectedSecretVersionCount ||
          req.body.encryptedItemCount !== job.expectedMetadataVersionCount ||
          req.body.encryptedSecretVersionCount !== job.expectedSecretVersionCount ||
          !Buffer.from(job.sourceSnapshotHash).equals(decodeBase64Url(req.body.legacyDigest, { exact: 32 })) ||
          !targetDigest.equals(decodeBase64Url(req.body.encryptedDigest, { exact: 32 })) ||
          !sameSet(new Set(expectedRecipients), new Set(req.body.envelopeRecipientIds))
        ) throw new E2eeConflictError(0, 'manifest mismatch');
        const now = new Date();
        await tx.update(legacyMigrationRecords).set({ state: 'verified', updatedAt: now })
          .where(eq(legacyMigrationRecords.jobId, job.id));
        const updated = (await tx.update(legacyMigrationJobs).set({
          state: 'verifying', verifiedItemCount: job.expectedItemCount,
          verifiedMetadataVersionCount: job.expectedMetadataVersionCount,
          verifiedSecretVersionCount: job.expectedSecretVersionCount,
          verifiedRecipientCount: envelopes.length,
          verifiedAuditEventCount: job.expectedAuditEventCount,
          verifiedAt: now, updatedAt: now,
        }).where(eq(legacyMigrationJobs.id, job.id)).returning())[0]!;
        await tx.insert(legacyMigrationEvidence).values([
          { jobId: job.id, evidenceType: 'record_counts', stage: 'verifying', subjectKind: 'vault', subjectId: job.vaultId, recordCount: records.length, digest: targetDigest, signerDeviceId: actor.id, signature: decodeBase64Url(req.body.signature, { exact: 64 }) },
          { jobId: job.id, evidenceType: 'recipient_coverage', stage: 'verifying', subjectKind: 'vault', subjectId: job.vaultId, recordCount: envelopes.length, digest: sha256(JSON.stringify(expectedRecipients)), signerDeviceId: actor.id, signature: decodeBase64Url(req.body.signature, { exact: 64 }) },
        ]);
        return updated;
      });
      return { status: 'verifying', job: migrationJobDto(verified) };
    } catch (error) {
      if (error instanceof E2eeConflictError) return conflict(reply, error.message === 'coverage incomplete' ? '迁移记录覆盖不完整' : error.message === 'manifest mismatch' ? '迁移清单校验失败' : '迁移任务状态已经变化');
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/migration/cutover', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-migration'], params: VaultParams, body: MigrationCutoverRequestSchema, response: { 200: VaultCryptoStateSchema, '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以完成迁移');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'migration.cutover', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'signature'),
    })) return unauthorized(reply, '迁移切换签名无效');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx, collect) => {
        const job = (await tx.select().from(legacyMigrationJobs).where(and(
          eq(legacyMigrationJobs.id, req.body.jobId), eq(legacyMigrationJobs.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        if (!job || job.state !== 'verifying') throw new E2eeConflictError(0);
        const records = await tx.select().from(legacyMigrationRecords).where(eq(legacyMigrationRecords.jobId, job.id));
        if (records.some((record) => record.state !== 'verified')) throw new E2eeConflictError(0, 'coverage incomplete');
        const header = (await tx.select().from(encryptedVaultHeaders).where(and(
          eq(encryptedVaultHeaders.vaultId, job.vaultId), eq(encryptedVaultHeaders.keyEpoch, job.targetEpoch),
          eq(encryptedVaultHeaders.migrationJobId, job.id),
        )).limit(1))[0];
        if (!header) throw new E2eeConflictError(0, 'coverage incomplete');
        await lockMigrationRecipientSources(tx);
        const stagedEnvelopes = await tx.select().from(vaultKeyEnvelopes).where(and(
          eq(vaultKeyEnvelopes.vaultId, job.vaultId),
          eq(vaultKeyEnvelopes.keyEpoch, job.targetEpoch),
          eq(vaultKeyEnvelopes.status, 'pending'),
        ));
        if (
          stagedEnvelopes.length !== job.expectedRecipientCount ||
          stagedEnvelopes.length !== job.verifiedRecipientCount ||
          !await storedEnvelopesMatchExpectedRecipients(tx, job.vaultId, stagedEnvelopes)
        ) {
          throw new E2eeConflictError(0, 'recipient coverage changed');
        }
        const now = new Date();
        await tx.update(legacyMigrationJobs).set({ state: 'cutover', cutoverAt: now, updatedAt: now }).where(eq(legacyMigrationJobs.id, job.id));
        await tx.update(vaultKeyEpochs).set({ status: 'active', activatedAt: now }).where(and(
          eq(vaultKeyEpochs.vaultId, job.vaultId), eq(vaultKeyEpochs.epoch, job.targetEpoch),
        ));
        await tx.update(vaultKeyEnvelopes).set({ status: 'active', activatedAt: now }).where(and(
          eq(vaultKeyEnvelopes.vaultId, job.vaultId), eq(vaultKeyEnvelopes.keyEpoch, job.targetEpoch),
        ));
        await tx.execute(sql`SET CONSTRAINTS item_secret_versions_ctx_fk DEFERRED`);
        const auditTransition = await rewriteAuditDetailsForVault(tx, audit, job.vaultId);
        const auditTransitionDigest = sha256(canonicalJson({
          jobId: job.id,
          previousHeadHash: auditTransition.previousHeadHash,
          previousHeadId: auditTransition.previousHeadId,
          rewrittenHeadHash: auditTransition.rewrittenHeadHash,
          rewrittenHeadId: auditTransition.rewrittenHeadId,
        }));
        await tx.insert(auditChainRewriteTransitions).values({
          migrationJobId: job.id,
          ...auditTransition,
          transitionDigest: auditTransitionDigest,
        });
        await tx.update(syncEvents).set({ payload: {} }).where(eq(syncEvents.vaultId, job.vaultId));
        await tx.delete(commandDedup);
        await tx.update(vaults).set({ name: '' }).where(eq(vaults.id, job.vaultId));
        await tx.update(itemSecretVersions).set({ itemKind: 'secure_note' })
          .where(eq(itemSecretVersions.vaultId, job.vaultId));
        await tx.update(items).set({
          kind: 'secure_note', title: '', username: null, origin: null, tags: [], favorite: false, sensitivity: 'medium',
        }).where(eq(items.vaultId, job.vaultId));
        const state = (await tx.update(vaultCryptoStates).set({
          storageMode: 'e2ee', writeState: 'open', activeEpoch: job.targetEpoch,
          activeHeaderVersion: header.headerVersion, accessGeneration: 1,
          rowVersion: sql`${vaultCryptoStates.rowVersion} + 1`, cutoverAt: now,
          legacyReadDisabledAt: now, updatedAt: now,
        }).where(eq(vaultCryptoStates.vaultId, job.vaultId)).returning())[0]!;
        await tx.update(legacyMigrationJobs).set({ state: 'e2ee', completedAt: now, updatedAt: now })
          .where(eq(legacyMigrationJobs.id, job.id));
        await tx.insert(legacyMigrationEvidence).values([
          {
            jobId: job.id, evidenceType: 'audit_chain_head', stage: 'cutover', subjectKind: 'audit_chain',
            subjectId: job.vaultId, recordCount: 1, digest: auditTransitionDigest,
            signerDeviceId: actor.id, signature: decodeBase64Url(req.body.signature, { exact: 64 }),
          },
          {
            jobId: job.id, evidenceType: 'cutover', stage: 'e2ee', subjectKind: 'vault',
            subjectId: job.vaultId, recordCount: records.length, digest: migrationTargetDigest(records),
            signerDeviceId: actor.id, signature: decodeBase64Url(req.body.signature, { exact: 64 }),
          },
        ]);
        collect(await recordSyncEvent(tx, {
          type: 'vault.crypto_changed', vaultId: job.vaultId, itemId: null,
          payload: { epoch: job.targetEpoch, headerVersion: header.headerVersion },
        }));
        await appendAudit(tx, audit, {
          actorUserId: req.user.id, action: 'migration.cutover', vaultId: job.vaultId,
          success: true, details: {},
        });
        return { statusCode: 200, response: toVaultCryptoState(state, header, null, null) };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) {
        return conflict(reply, error.message === 'coverage incomplete'
          ? '迁移覆盖不完整，未执行切换'
          : error.message === 'recipient coverage changed'
            ? '成员、用户组、设备或恢复公钥已变化，请回滚后重新迁移'
            : '迁移任务状态已经变化');
      }
      throw error;
    }
  });

  r.post('/api/v2/vaults/:vaultId/migration/rollback', {
    preHandler: writeGuard,
    schema: { tags: ['e2ee-migration'], params: VaultParams, body: MigrationCutoverRequestSchema, response: { 200: z.object({ ok: z.literal(true) }), '4xx': ZeroKnowledgeApiErrorSchema } },
  }, async (req, reply) => {
    const access = await getVaultAccess(db, req.user, req.params.vaultId);
    if (!access || access.role !== 'owner') return forbidden(reply, '只有密码库拥有者可以回滚迁移');
    const actor = await requireActorDevice(db, req.user.id, req.sessionRow, req.body.actorDeviceId, reply);
    if (!actor) return;
    if (!await verifyCommandSignature(req.body.signature, encodeBase64Url(actor.publicSigningKey), 'migration.rollback', {
      userId: req.user.id, vaultId: req.params.vaultId, request: without(req.body, 'signature'),
    })) return unauthorized(reply, '迁移回滚签名无效');
    try {
      const result = await runCommand(db, bus, audit, req.user.id, req.body.idempotencyKey, async (tx) => {
        const job = (await tx.select().from(legacyMigrationJobs).where(and(
          eq(legacyMigrationJobs.id, req.body.jobId), eq(legacyMigrationJobs.vaultId, req.params.vaultId),
        )).for('update').limit(1))[0];
        if (!job || !['frozen', 'encrypting', 'verifying'].includes(job.state)) throw new E2eeConflictError(0);
        const now = new Date();
        await tx.update(legacyMigrationJobs).set({ state: 'failed', lastErrorCode: 'user_rollback', updatedAt: now }).where(eq(legacyMigrationJobs.id, job.id));
        await tx.delete(encryptedVaultHeaders).where(eq(encryptedVaultHeaders.migrationJobId, job.id));
        await tx.delete(encryptedItemMetadataVersions).where(eq(encryptedItemMetadataVersions.migrationJobId, job.id));
        await tx.delete(encryptedItemSecretVersions).where(eq(encryptedItemSecretVersions.migrationJobId, job.id));
        await tx.delete(vaultKeyEnvelopes).where(and(eq(vaultKeyEnvelopes.vaultId, job.vaultId), eq(vaultKeyEnvelopes.keyEpoch, job.targetEpoch)));
        await tx.update(legacyMigrationRecords).set({
          targetRecordId: null, targetDigest: null, state: 'pending', errorCode: null, updatedAt: now,
        }).where(eq(legacyMigrationRecords.jobId, job.id));
        await tx.delete(legacyMigrationCheckpoints).where(eq(legacyMigrationCheckpoints.jobId, job.id));
        await tx.update(vaultKeyEpochs).set({ status: 'compromised', retiredAt: now }).where(and(
          eq(vaultKeyEpochs.vaultId, job.vaultId), eq(vaultKeyEpochs.epoch, job.targetEpoch),
        ));
        await tx.update(vaultCryptoStates).set({ writeState: 'open', rowVersion: sql`${vaultCryptoStates.rowVersion} + 1`, updatedAt: now })
          .where(eq(vaultCryptoStates.vaultId, job.vaultId));
        await tx.update(legacyMigrationJobs).set({ state: 'legacy', rolledBackAt: now, updatedAt: now }).where(eq(legacyMigrationJobs.id, job.id));
        await tx.insert(legacyMigrationEvidence).values({
          jobId: job.id, evidenceType: 'rollback', stage: 'legacy', subjectKind: 'vault', subjectId: job.vaultId,
          digest: sha256(`rollback:${job.id}:${now.toISOString()}`), signerDeviceId: actor.id,
          signature: decodeBase64Url(req.body.signature, { exact: 64 }),
        });
        await appendAudit(tx, audit, {
          actorUserId: req.user.id, action: 'migration.rollback', vaultId: job.vaultId,
          success: true, details: {},
        });
        return { statusCode: 200, response: { ok: true as const } };
      });
      return reply.code(200).send(result.response);
    } catch (error) {
      if (error instanceof E2eeConflictError) return conflict(reply, '迁移已经切换或状态不允许回滚');
      throw error;
    }
  });
}

async function updateMigrationCheckpoint(db: DbOrTx, jobId: string) {
  const records = await db.select().from(legacyMigrationRecords).where(eq(legacyMigrationRecords.jobId, jobId));
  const processedCount = records.filter((record) => record.state !== 'pending').length;
  const succeededCount = records.filter((record) => record.state === 'encrypted' || record.state === 'verified').length;
  const failedCount = records.filter((record) => record.state === 'failed').length;
  const checkpointHash = sha256(JSON.stringify(records.map((record) => ({
    kind: record.sourceKind,
    id: record.sourceId,
    version: record.sourceVersion,
    state: record.state,
    targetDigest: record.targetDigest ? encodeBase64Url(record.targetDigest) : null,
  })).sort((left, right) => `${left.kind}:${left.id}:${left.version}`.localeCompare(`${right.kind}:${right.id}:${right.version}`))));
  await db.insert(legacyMigrationCheckpoints).values({
    jobId,
    stage: 'encrypting',
    processedCount,
    succeededCount,
    failedCount,
    checkpointHash,
    updatedAt: new Date(),
  }).onConflictDoUpdate({
    target: [legacyMigrationCheckpoints.jobId, legacyMigrationCheckpoints.stage],
    set: { processedCount, succeededCount, failedCount, checkpointHash, updatedAt: new Date() },
  });
  return { processedCount, succeededCount, failedCount, totalCount: records.length };
}

function migrationTargetDigest(records: (typeof legacyMigrationRecords.$inferSelect)[]) {
  const encoded = records
    .filter((record) => record.targetDigest)
    .map((record) => `${record.sourceKind}:${record.sourceId}:${record.sourceVersion}:${encodeBase64Url(record.targetDigest!)}`)
    .sort()
    .join('\n');
  return sha256(encoded);
}

async function rewriteAuditDetailsForVault(
  db: DbOrTx,
  audit: Parameters<typeof appendAudit>[1],
  vaultId: string,
) {
  await db.execute(sql`SELECT pg_advisory_xact_lock(${815001})`);
  const rows = await db.select().from(auditEvents).orderBy(asc(auditEvents.id));
  const previousHead = rows.at(-1);
  if (!previousHead) throw new E2eeConflictError(0, 'audit chain missing');
  let prevHash = AUDIT_CHAIN_GENESIS;
  for (const row of rows) {
    const details = row.vaultId === vaultId ? {} : row.details;
    const hash = computeAuditHash(audit.hmacKey, prevHash, {
      ts: row.ts.toISOString(),
      actorUserId: row.actorUserId,
      action: row.action,
      vaultId: row.vaultId,
      itemId: row.itemId,
      success: row.success,
      details,
    });
    await db.update(auditEvents).set({ details, prevHash, hash }).where(eq(auditEvents.id, row.id));
    prevHash = hash;
  }
  return {
    previousHeadId: previousHead.id,
    previousHeadHash: previousHead.hash,
    rewrittenHeadId: previousHead.id,
    rewrittenHeadHash: prevHash,
  };
}

function migrationStatus(state: typeof legacyMigrationJobs.$inferSelect.state): LegacyMigrationStatus {
  if (state === 'legacy') return 'pending';
  if (state === 'e2ee') return 'complete';
  return state;
}

async function emptyVaultInitializationAllowed(
  db: DbOrTx,
  vaultId: string,
  lockedState?: typeof vaultCryptoStates.$inferSelect,
): Promise<boolean> {
  const state = lockedState ?? (await db.select().from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.vaultId, vaultId)).limit(1))[0];
  if (!state || state.storageMode !== 'legacy' || state.writeState !== 'open') return false;
  const legacyItems = await db.select({ id: items.id }).from(items)
    .where(eq(items.vaultId, vaultId)).limit(1);
  if (legacyItems.length > 0) return false;
  const unsafeAudits = await db.select({ id: auditEvents.id }).from(auditEvents).where(and(
    eq(auditEvents.vaultId, vaultId),
    sql`${auditEvents.details} <> '{}'::jsonb`,
  )).limit(1);
  return unsafeAudits.length === 0;
}

function migrationJobDto(row: typeof legacyMigrationJobs.$inferSelect) {
  return {
    id: row.id,
    vaultId: row.vaultId,
    attempt: row.attempt,
    status: migrationStatus(row.state),
    targetEpoch: row.targetEpoch,
    expectedItemCount: row.expectedItemCount,
    expectedMetadataVersionCount: row.expectedMetadataVersionCount,
    expectedSecretVersionCount: row.expectedSecretVersionCount,
    expectedRecipientCount: row.expectedRecipientCount,
    verifiedItemCount: row.verifiedItemCount,
    verifiedMetadataVersionCount: row.verifiedMetadataVersionCount,
    verifiedSecretVersionCount: row.verifiedSecretVersionCount,
    verifiedRecipientCount: row.verifiedRecipientCount,
    sourceDigest: row.sourceSnapshotHash ? encodeBase64Url(row.sourceSnapshotHash) : null,
    lastErrorCode: row.lastErrorCode,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    completedAt: row.completedAt?.toISOString() ?? null,
    rolledBackAt: row.rolledBackAt?.toISOString() ?? null,
  };
}

async function migrationRecipientMaterials(
  db: DbOrTx,
  vaultId: string,
  allowWithoutRecovery = false,
) {
  try {
    const recipients = await expectedVaultRecipients(db, vaultId);
    const recoveryRows = await db.select().from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1);
    const vaultRows = await db.select({ kind: vaults.kind }).from(vaults)
      .where(eq(vaults.id, vaultId)).limit(1);
    const recovery = recoveryRows[0];
    if (!vaultRows[0] || (!recovery && !allowWithoutRecovery)) {
      return null;
    }
    const devices = await expectedVaultDeviceRecipients(db, vaultId, recipients);
    return {
      recipients,
      devices,
      recoveryKey: recovery ? await enterpriseRecoveryKeyDto(db, recovery) : null,
    };
  } catch (error) {
    if (error instanceof MembershipEnvelopeError) return null;
    throw error;
  }
}

async function enterpriseRecoveryKeyDto(
  db: DbOrTx,
  row: typeof enterpriseRecoveryKeys.$inferSelect,
) {
  const approvals = await db.select({ userId: enterpriseRecoveryKeyApprovals.approverUserId })
    .from(enterpriseRecoveryKeyApprovals)
    .where(eq(enterpriseRecoveryKeyApprovals.recoveryKeyId, row.id))
    .orderBy(asc(enterpriseRecoveryKeyApprovals.approvedAt));
  return {
    id: row.id,
    ceremonyId: row.ceremonyId,
    keyFingerprint: row.keyFingerprint,
    publicEncryptionKey: encodeBase64Url(row.publicEncryptionKey),
    threshold: 2 as const,
    shareCount: 3 as const,
    status: row.status,
    ceremonyEvidenceDigest: encodeBase64Url(row.ceremonyEvidenceDigest),
    approvalUserIds: approvals.map((approval) => approval.userId),
    createdAt: row.createdAt.toISOString(),
    retiredAt: row.retiredAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
  };
}

function migrationExportGone(reply: FastifyReply, message: string) {
  return reply.code(410).send({
    statusCode: 410,
    error: 'Gone',
    message,
  } as never);
}

async function requireActorDevice(
  db: DbOrTx,
  userId: string,
  session: { locked: boolean; unlockedDeviceId: string | null },
  deviceId: string,
  reply: FastifyReply,
) {
  if (session.locked || session.unlockedDeviceId !== deviceId) {
    locked(reply);
    return null;
  }
  const device = await getActiveDevice(db, userId, deviceId);
  if (!device) {
    unauthorized(reply, '当前设备未授权或已经撤销');
    return null;
  }
  return device;
}

async function assertWritableEpoch(db: DbOrTx, vaultId: string, epoch: number) {
  const state = (await db.select().from(vaultCryptoStates)
    .where(eq(vaultCryptoStates.vaultId, vaultId)).for('share').limit(1))[0];
  if (!state || state.storageMode !== 'e2ee' || state.writeState !== 'open' || state.activeEpoch !== epoch) {
    throw new E2eeConflictError(state?.activeEpoch ?? 0);
  }
}

async function validateEnvelopes(
  db: DbOrTx,
  envelopes: VaultKeyEnvelopeInput[],
  expected: {
    vaultId: string;
    epoch: number;
    signerUserId: string;
    signerKeyVersion: number;
    signerPublicKey: string;
  },
) {
  const seen = new Set<string>();
  const result = [];
  for (const envelope of envelopes) {
    if (
      envelope.vaultId !== expected.vaultId || envelope.epoch !== expected.epoch ||
      envelope.signerUserId !== expected.signerUserId ||
      envelope.signerKeyVersion !== expected.signerKeyVersion ||
      !await verifyVaultEnvelope(envelope, expected.signerPublicKey)
    ) throw new Error('invalid envelope');
    const recipient = await resolveEnvelopeRecipient(db, envelope);
    const key = `${recipient.recipientKind}:${recipient.fingerprint}:${envelope.capability}`;
    if (seen.has(key)) throw new Error('duplicate envelope');
    seen.add(key);
    decodeBase64Url(envelope.sealedKeyBundle, { min: 49, max: 10_000 });
    decodeBase64Url(envelope.signature, { exact: 64 });
    result.push(recipient);
  }
  return result;
}

async function insertEnvelopes(
  db: DbOrTx,
  envelopes: VaultKeyEnvelopeInput[],
  recipients: Awaited<ReturnType<typeof validateEnvelopes>>,
  senderDeviceId: string,
  signerPublicKey: Buffer,
  status: 'pending' | 'active',
) {
  const now = new Date();
  for (let index = 0; index < envelopes.length; index += 1) {
    const envelope = envelopes[index]!;
    const recipient = recipients[index]!;
    const ciphertext = decodeBase64Url(envelope.sealedKeyBundle, { min: 49, max: 10_000 });
    await db.insert(vaultKeyEnvelopes).values({
      vaultId: envelope.vaultId,
      keyEpoch: envelope.epoch,
      recipientKind: recipient.recipientKind,
      accessScope: envelope.capability,
      recipientUserId: recipient.recipientUserId,
      recipientDeviceId: recipient.recipientDeviceId,
      recipientRecoveryKeyId: recipient.recipientRecoveryKeyId,
      recipientKeyFingerprint: recipient.fingerprint,
      authorizationKind: envelope.recipientKind === 'recovery'
        ? 'recovery'
        : envelope.recipientKind === 'user' && envelope.recipientId === envelope.signerUserId ? 'owner' : 'direct',
      envelopeVersion: envelope.recipientKeyVersion,
      ciphertext,
      ciphertextDigest: sha256(ciphertext),
      senderDeviceId,
      signerUserId: envelope.signerUserId,
      signerKeyVersion: envelope.signerKeyVersion,
      signerPublicKey,
      signature: decodeBase64Url(envelope.signature, { exact: 64 }),
      status,
      ...(status === 'active' ? { activatedAt: now } : {}),
    });
  }
}

function envelopeCommitments(envelopes: VaultKeyEnvelopeInput[]) {
  const metadata = envelopes.filter((envelope) => envelope.capability === 'metadata').map((envelope) => envelope.sealedKeyBundle).sort();
  const content = envelopes.filter((envelope) => envelope.capability !== 'metadata').map((envelope) => envelope.sealedKeyBundle).sort();
  const recipients = envelopes.map((envelope) => `${envelope.recipientKind}:${envelope.recipientId}:${envelope.capability}`).sort();
  return {
    metadataKeyCommitment: sha256(JSON.stringify(metadata)),
    contentKeyCommitment: sha256(JSON.stringify(content)),
    recipientSetDigest: sha256(JSON.stringify(recipients)),
  };
}

function toEncryptedHeader(row: typeof encryptedVaultHeaders.$inferSelect) {
  return {
    vaultId: row.vaultId,
    version: row.headerVersion,
    keyEpoch: row.keyEpoch,
    blob: encodeCipherBlob(row.nonce, row.ciphertext),
    signature: encodeBase64Url(row.signature),
    updatedAt: row.createdAt.toISOString(),
    updatedBy: row.createdByDeviceId,
  };
}

function toEncryptedMetadata(
  item: typeof items.$inferSelect,
  row: typeof encryptedItemMetadataVersions.$inferSelect,
) {
  return {
    itemId: item.id,
    vaultId: item.vaultId,
    version: item.version,
    secretVersion: item.secretVersion,
    keyEpoch: row.keyEpoch,
    deleted: item.deleted,
    blob: encodeCipherBlob(row.nonce, row.ciphertext),
    signature: encodeBase64Url(row.signature),
    createdAt: item.createdAt.toISOString(),
    updatedAt: item.updatedAt.toISOString(),
    updatedBy: item.updatedBy,
  };
}

function toVaultCryptoState(
  state: typeof vaultCryptoStates.$inferSelect,
  header: typeof encryptedVaultHeaders.$inferSelect | null,
  migration: typeof legacyMigrationJobs.$inferSelect | null,
  rekey: typeof vaultRekeyJobs.$inferSelect | null,
  recoveryRequired = false,
) {
  let status: 'legacy' | 'preparing' | 'frozen' | 'encrypting' | 'verifying' | 'e2ee' | 'rekey_required';
  if (state.storageMode === 'e2ee') status = state.writeState === 'rekeying' ? 'rekey_required' : 'e2ee';
  else if (migration) {
    if (migration.state === 'e2ee') status = 'e2ee';
    else if (migration.state === 'failed' || migration.state === 'legacy') status = 'legacy';
    else if (migration.state === 'cutover') status = 'verifying';
    else status = migration.state;
  }
  else status = state.writeState === 'frozen' ? 'frozen' : state.vaultId ? 'legacy' : 'preparing';
  return {
    vaultId: state.vaultId,
    status,
    activeEpoch: state.activeEpoch ?? 0,
    accessGeneration: state.accessGeneration,
    pendingEpoch: rekey && !['committed', 'failed', 'cancelled'].includes(rekey.status) ? rekey.toEpoch : null,
    rekeyTaskId: !recoveryRequired && rekey && !['committed', 'failed', 'cancelled'].includes(rekey.status) ? rekey.id : null,
    encryptedHeader: header ? encodeCipherBlob(header.nonce, header.ciphertext) : null,
    migrationJobId: migration && migration.state !== 'e2ee' ? migration.id : null,
    recoveryRequired,
    recoveryReason: recoveryRequired ? 'missing_current_full_envelope' as const : null,
    updatedAt: state.updatedAt.toISOString(),
  };
}

function latestMigration(rows: (typeof legacyMigrationJobs.$inferSelect)[]) {
  return [...rows].sort((left, right) => right.attempt - left.attempt)[0] ?? null;
}

function activeRekey(rows: (typeof vaultRekeyJobs.$inferSelect)[]) {
  return rows.find((row) => !['committed', 'failed', 'cancelled'].includes(row.status)) ?? null;
}

async function resolveSubjectUsers(
  db: DbOrTx,
  subjectKind: 'user' | 'group' | 'custom_group',
  subjectId: string,
): Promise<string[] | null> {
  if (subjectKind === 'user') {
    const row = (await db.select({ id: users.id }).from(users).where(and(
      eq(users.id, subjectId), eq(users.active, true),
    )).limit(1))[0];
    return row ? [row.id] : null;
  }
  if (subjectKind === 'custom_group') {
    const rows = await db.select({ userId: customGroupMembers.userId })
      .from(customGroupMembers).innerJoin(users, and(
        eq(users.id, customGroupMembers.userId), eq(users.active, true),
      )).where(eq(customGroupMembers.groupId, subjectId));
    return [...new Set(rows.map((row) => row.userId))];
  }
  const rows = await db.select({ id: users.id, groups: users.groups }).from(users).where(eq(users.active, true));
  return rows.filter((row) => row.groups.includes(subjectId)).map((row) => row.id);
}

async function directSubjectRole(
  db: DbOrTx,
  vaultId: string,
  subjectKind: 'user' | 'group' | 'custom_group',
  subjectId: string,
): Promise<MembershipRole | null> {
  if (subjectKind === 'custom_group') {
    return (await db.select({ role: vaultCustomGroupRoles.role }).from(vaultCustomGroupRoles).where(and(
      eq(vaultCustomGroupRoles.vaultId, vaultId), eq(vaultCustomGroupRoles.groupId, subjectId),
    )).limit(1))[0]?.role ?? null;
  }
  return (await db.select({ role: vaultMemberships.role }).from(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, vaultId),
    eq(vaultMemberships.subjectKind, subjectKind),
    eq(vaultMemberships.subjectId, subjectId),
  )).limit(1))[0]?.role ?? null;
}

function capabilityRank(capability: 'metadata' | 'full' | null): number {
  if (capability === 'full') return 2;
  if (capability === 'metadata') return 1;
  return 0;
}

async function prepareMembershipEnvelopes(
  db: DbOrTx,
  envelopes: VaultKeyEnvelopeInput[],
  expected: {
    vaultId: string;
    epoch: number;
    targetUserIds: string[];
    capability: 'metadata' | 'full';
    signerUserId: string;
    signerKeyVersion: number;
    signerPublicKey: string;
  },
) {
  const targets = new Set(expected.targetUserIds);
  const seen = new Set<string>();
  const result: Array<{
    envelope: VaultKeyEnvelopeInput;
    userId: string;
    keyVersion: number;
    fingerprint: string;
  }> = [];
  for (const envelope of envelopes) {
    if (
      envelope.vaultId !== expected.vaultId || envelope.epoch !== expected.epoch ||
      envelope.recipientKind !== 'user' || !targets.has(envelope.recipientId) ||
      envelope.capability !== expected.capability ||
      envelope.signerUserId !== expected.signerUserId ||
      envelope.signerKeyVersion !== expected.signerKeyVersion || seen.has(envelope.recipientId) ||
      !await verifyVaultEnvelope(envelope, expected.signerPublicKey)
    ) throw new MembershipEnvelopeError();
    const recipient = (await db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, envelope.recipientId)).for('share').limit(1))[0];
    if (!recipient || recipient.cryptoGeneration !== envelope.recipientKeyVersion) throw new MembershipEnvelopeError();
    decodeBase64Url(envelope.sealedKeyBundle, { min: 49, max: 10_000 });
    decodeBase64Url(envelope.signature, { exact: 64 });
    seen.add(envelope.recipientId);
    result.push({
      envelope,
      userId: envelope.recipientId,
      keyVersion: recipient.cryptoGeneration,
      fingerprint: publicKeyFingerprint(encodeBase64Url(recipient.publicEncryptionKey)),
    });
  }
  return result;
}

async function expectedVaultRecipients(db: DbOrTx, vaultId: string) {
  const vault = await db.select({ kind: vaults.kind, ownerUserId: vaults.ownerUserId }).from(vaults)
    .where(eq(vaults.id, vaultId)).limit(1);
  const memberships = await db.select().from(vaultMemberships)
    .where(eq(vaultMemberships.vaultId, vaultId));
  const customRoles = await db.select().from(vaultCustomGroupRoles)
    .where(eq(vaultCustomGroupRoles.vaultId, vaultId));
  const activeUsers = await db.select({ id: users.id, groups: users.groups }).from(users)
    .where(eq(users.active, true));
  const customMembers = await db.select().from(customGroupMembers);
  const roles = new Map<string, MembershipRole>();
  if (vault[0]?.kind === 'personal' && vault[0].ownerUserId && activeUsers.some((user) => user.id === vault[0]!.ownerUserId)) {
    roles.set(vault[0].ownerUserId, 'owner');
  } else if (vault[0]?.kind === 'team') {
    const customGroupIdsByUser = new Map<string, string[]>();
    for (const member of customMembers) {
      const groupIds = customGroupIdsByUser.get(member.userId) ?? [];
      groupIds.push(member.groupId);
      customGroupIdsByUser.set(member.userId, groupIds);
    }
    const membershipInputs = [
      ...memberships,
      ...customRoles.map((customRole) => ({
        subjectKind: 'group' as const,
        subjectId: customRole.groupId,
        role: customRole.role,
      })),
    ];
    for (const user of activeUsers) {
      const role = resolveEffectiveRole(membershipInputs, {
        userId: user.id,
        groups: [...user.groups, ...(customGroupIdsByUser.get(user.id) ?? [])],
      });
      if (role) roles.set(user.id, role);
    }
  }
  const userIds = [...roles.keys()];
  const profiles = userIds.length ? await db.select().from(userCryptoProfiles)
    .where(inArray(userCryptoProfiles.userId, userIds)) : [];
  const profileByUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  return userIds.sort().flatMap((userId) => {
    const role = roles.get(userId)!;
    const profile = profileByUser.get(userId);
    if (!profile) return [];
    return [{
      userId,
      role,
      capability: capabilityForRole(role),
      keyVersion: profile.cryptoGeneration,
      encryptionPublicKey: encodeBase64Url(profile.publicEncryptionKey),
      signingPublicKey: encodeBase64Url(profile.publicSigningKey),
    }];
  });
}

async function expectedVaultDeviceRecipients(
  db: DbOrTx,
  _vaultId: string,
  recipients?: Awaited<ReturnType<typeof expectedVaultRecipients>>,
) {
  const effectiveRecipients = recipients ?? await expectedVaultRecipients(db, _vaultId);
  if (effectiveRecipients.length === 0) return [];
  const capabilityByUser = new Map(effectiveRecipients.map((recipient) => [recipient.userId, recipient.capability]));
  const devices = await db.select().from(userDevices).where(and(
    inArray(userDevices.userId, [...capabilityByUser.keys()]),
    eq(userDevices.deviceType, 'extension'),
    eq(userDevices.status, 'active'),
  ));
  return devices.sort((left, right) => left.id.localeCompare(right.id)).map((device) => ({
    deviceId: device.id,
    userId: device.userId,
    capability: capabilityByUser.get(device.userId)!,
    keyVersion: device.deviceGeneration,
    encryptionPublicKey: encodeBase64Url(device.publicEncryptionKey),
    signingPublicKey: encodeBase64Url(device.publicSigningKey),
  }));
}

async function envelopesMatchExpectedRecipients(
  db: DbOrTx,
  vaultId: string,
  envelopes: VaultKeyEnvelopeInput[],
): Promise<boolean> {
  return envelopeRecipientDescriptorsMatchExpected(db, vaultId, envelopes);
}

async function storedEnvelopesMatchExpectedRecipients(
  db: DbOrTx,
  vaultId: string,
  envelopes: Array<Pick<
    typeof vaultKeyEnvelopes.$inferSelect,
    'recipientKind' | 'recipientUserId' | 'recipientDeviceId' | 'recipientRecoveryKeyId' | 'accessScope' | 'envelopeVersion'
  >>,
): Promise<boolean> {
  return envelopeRecipientDescriptorsMatchExpected(db, vaultId, envelopes.map((envelope) => ({
    recipientKind: envelope.recipientKind === 'enterprise_recovery' ? 'recovery' as const : envelope.recipientKind,
    recipientId: envelope.recipientUserId ?? envelope.recipientDeviceId ?? envelope.recipientRecoveryKeyId!,
    capability: envelope.accessScope,
    recipientKeyVersion: envelope.envelopeVersion,
  })));
}

async function envelopeRecipientDescriptorsMatchExpected(
  db: DbOrTx,
  vaultId: string,
  envelopes: Array<Pick<
    VaultKeyEnvelopeInput,
    'recipientKind' | 'recipientId' | 'capability' | 'recipientKeyVersion'
  >>,
): Promise<boolean> {
  const recipients = await expectedVaultRecipients(db, vaultId);
  const recovery = await db.select().from(enterpriseRecoveryKeys)
    .where(eq(enterpriseRecoveryKeys.status, 'active')).limit(1);
  const vault = await db.select({ kind: vaults.kind }).from(vaults)
    .where(eq(vaults.id, vaultId)).limit(1);
  if (!vault[0]) return false;
  const devices = await expectedVaultDeviceRecipients(db, vaultId, recipients);
  const expected = new Map(recipients.map((recipient) => [
    `user:${recipient.userId}:${recipient.capability}`,
    recipient.keyVersion,
  ]));
  if (recovery[0]) expected.set(`recovery:${recovery[0].id}:recovery`, 1);
  for (const device of devices) {
    expected.set(`device:${device.deviceId}:${device.capability}`, device.keyVersion);
  }
  const seen = new Set<string>();
  for (const envelope of envelopes) {
    const recipientId = envelope.recipientKind === 'recovery' && recovery[0]
      && envelope.recipientId === recovery[0].keyFingerprint
      ? recovery[0].id
      : envelope.recipientId;
    const key = `${envelope.recipientKind}:${recipientId}:${envelope.capability}`;
    if (seen.has(key) || expected.get(key) !== envelope.recipientKeyVersion) return false;
    seen.add(key);
  }
  return seen.size === expected.size && [...expected.keys()].every((key) => seen.has(key));
}

async function lockMigrationRecipientSources(db: DbOrTx): Promise<void> {
  await db.execute(sql`
    LOCK TABLE
      vaults,
      vault_memberships,
      vault_custom_group_roles,
      custom_group_members,
      users,
      user_crypto_profiles,
      user_devices,
      enterprise_recovery_keys
    IN SHARE MODE
  `);
}

async function vaultDeletionBlockers(db: DbOrTx, vaultId: string): Promise<string[]> {
  const migration = await db.select({ id: legacyMigrationJobs.id }).from(legacyMigrationJobs)
    .where(eq(legacyMigrationJobs.vaultId, vaultId)).limit(1);
  const recovery = await db.select({ id: enterpriseRecoveryRequests.id }).from(enterpriseRecoveryRequests)
    .where(eq(enterpriseRecoveryRequests.vaultId, vaultId)).limit(1);
  const accountReset = await db.select({ requestId: accountCryptoResetVaults.requestId }).from(accountCryptoResetVaults)
    .where(eq(accountCryptoResetVaults.vaultId, vaultId)).limit(1);
  const blockers: string[] = [];
  if (migration[0]) blockers.push('旧数据迁移记录');
  if (recovery[0]) blockers.push('企业恢复申请记录');
  if (accountReset[0]) blockers.push('账户重置关联记录');
  return blockers;
}

async function activeHeaderFormatVersion(
  db: DbOrTx,
  state: typeof vaultCryptoStates.$inferSelect,
): Promise<number> {
  if (!state.activeEpoch || state.activeHeaderVersion < 1) return 1;
  const row = (await db.select({ schemaVersion: encryptedVaultHeaders.schemaVersion })
    .from(encryptedVaultHeaders)
    .where(and(
      eq(encryptedVaultHeaders.vaultId, state.vaultId),
      eq(encryptedVaultHeaders.keyEpoch, state.activeEpoch),
      eq(encryptedVaultHeaders.headerVersion, state.activeHeaderVersion),
    ))
    .limit(1))[0];
  if (!row) throw new E2eeConflictError(state.activeHeaderVersion, 'active header missing');
  return row.schemaVersion;
}

async function effectiveRoleForUser(
  db: DbOrTx,
  vaultId: string,
  userId: string,
): Promise<MembershipRole | null> {
  const userRows = await db.select({ groups: users.groups }).from(users).where(and(
    eq(users.id, userId),
    eq(users.active, true),
  )).limit(1);
  const memberships = await db.select().from(vaultMemberships)
    .where(eq(vaultMemberships.vaultId, vaultId));
  const customMemberships = await db.select({ groupId: customGroupMembers.groupId }).from(customGroupMembers)
    .where(eq(customGroupMembers.userId, userId));
  if (!userRows[0]) return null;
  const customGroupIds = customMemberships.map((row) => row.groupId);
  const customRoles = customGroupIds.length
    ? await db.select().from(vaultCustomGroupRoles).where(and(
        eq(vaultCustomGroupRoles.vaultId, vaultId),
        inArray(vaultCustomGroupRoles.groupId, customGroupIds),
      ))
    : [];
  return resolveEffectiveRole([
    ...memberships,
    ...customRoles.map((role) => ({
      subjectKind: 'group' as const,
      subjectId: role.groupId,
      role: role.role,
    })),
  ], {
    userId,
    groups: [...userRows[0].groups, ...customGroupIds],
  });
}

function grantOrUpgradeAllowed(
  currentRole: MembershipRole | null,
  requestedRole: MembershipRole,
): boolean {
  if (requestedRole === 'owner') return false;
  if (currentRole === null) return true;
  if (currentRole === requestedRole) return true;
  return currentRole === 'viewer' && requestedRole === 'editor';
}

async function setSubjectRole(
  db: DbOrTx,
  vaultId: string,
  subjectKind: 'user' | 'group' | 'custom_group',
  subjectId: string,
  role: MembershipRole,
) {
  if (subjectKind === 'custom_group') {
    if (role === 'owner') throw new OwnerInvariantError();
    await db.insert(vaultCustomGroupRoles).values({ vaultId, groupId: subjectId, role })
      .onConflictDoUpdate({
        target: [vaultCustomGroupRoles.vaultId, vaultCustomGroupRoles.groupId],
        set: { role },
      });
    return;
  }
  await db.insert(vaultMemberships).values({ vaultId, subjectKind, subjectId, role })
    .onConflictDoUpdate({
      target: [vaultMemberships.vaultId, vaultMemberships.subjectKind, vaultMemberships.subjectId],
      set: { role },
    });
}

async function removeSubjectRole(
  db: DbOrTx,
  vaultId: string,
  subjectKind: 'user' | 'group' | 'custom_group',
  subjectId: string,
) {
  if (subjectKind === 'custom_group') {
    await db.delete(vaultCustomGroupRoles).where(and(
      eq(vaultCustomGroupRoles.vaultId, vaultId), eq(vaultCustomGroupRoles.groupId, subjectId),
    ));
    return;
  }
  await db.delete(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, vaultId),
    eq(vaultMemberships.subjectKind, subjectKind),
    eq(vaultMemberships.subjectId, subjectId),
  ));
}

async function assertDirectOwnerRemains(db: DbOrTx, vaultId: string) {
  const state = (await db.select({ activeEpoch: vaultCryptoStates.activeEpoch })
    .from(vaultCryptoStates).where(eq(vaultCryptoStates.vaultId, vaultId)).limit(1))[0];
  const owners = await db.select({ userId: vaultMemberships.subjectId }).from(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, vaultId),
    eq(vaultMemberships.subjectKind, 'user'),
    eq(vaultMemberships.role, 'owner'),
  ));
  if (owners.length === 0) throw new OwnerInvariantError();
  if (!state?.activeEpoch) return;
  const ownerIds = owners.map((owner) => owner.userId);
  const activeOwners = await db.select({ id: users.id }).from(users).where(and(
    inArray(users.id, ownerIds),
    eq(users.active, true),
  ));
  const profiles = await db.select().from(userCryptoProfiles)
    .where(inArray(userCryptoProfiles.userId, ownerIds));
  const envelopes = await db.select().from(vaultKeyEnvelopes).where(and(
    eq(vaultKeyEnvelopes.vaultId, vaultId),
    eq(vaultKeyEnvelopes.keyEpoch, state.activeEpoch),
    eq(vaultKeyEnvelopes.recipientKind, 'user'),
    inArray(vaultKeyEnvelopes.recipientUserId, ownerIds),
    eq(vaultKeyEnvelopes.accessScope, 'full'),
    eq(vaultKeyEnvelopes.status, 'active'),
  ));
  const activeOwnerIds = new Set(activeOwners.map((owner) => owner.id));
  const profileByUser = new Map(profiles.map((profile) => [profile.userId, profile]));
  const ready = envelopes.some((envelope) => {
    if (!envelope.recipientUserId || !activeOwnerIds.has(envelope.recipientUserId)) return false;
    const profile = profileByUser.get(envelope.recipientUserId);
    return Boolean(profile &&
      envelope.envelopeVersion === profile.cryptoGeneration &&
      envelope.recipientKeyFingerprint === publicKeyFingerprint(encodeBase64Url(profile.publicEncryptionKey)));
  });
  if (!ready) {
    throw new OwnerInvariantError('系统正在自动准备另一位拥有者的访问；确认其可以打开当前密码库前，不能移除或降权唯一可用拥有者');
  }
}

function membershipAuthorizationKind(subjectKind: 'user' | 'group' | 'custom_group') {
  if (subjectKind === 'custom_group') return 'custom_group' as const;
  if (subjectKind === 'group') return 'directory_group' as const;
  return 'direct' as const;
}

function uniquePairs<T>(rows: T[], key: (row: T) => string) {
  return new Set(rows.map(key));
}

function sameSet(left: Set<string>, right: Set<string>) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function mapRekeyReason(reason: RekeyVaultRequest['reason']): 'membership_change' | 'device_compromise' | 'manual' | 'ownership_transfer' {
  if (reason === 'device_compromised') return 'device_compromise';
  if (reason === 'manual_rotation') return 'manual';
  if (reason === 'ownership_transfer') return 'ownership_transfer';
  return 'membership_change';
}

async function isVaultOwnerWithoutEnvelope(db: DbOrTx, vaultId: string, userId: string): Promise<boolean> {
  const vault = await db.select({ kind: vaults.kind, ownerUserId: vaults.ownerUserId })
    .from(vaults).where(eq(vaults.id, vaultId)).limit(1);
  const membership = await db.select({ id: vaultMemberships.id }).from(vaultMemberships).where(and(
    eq(vaultMemberships.vaultId, vaultId),
    eq(vaultMemberships.subjectKind, 'user'),
    eq(vaultMemberships.subjectId, userId),
    eq(vaultMemberships.role, 'owner'),
  )).limit(1);
  return vault[0]?.kind === 'personal' ? vault[0].ownerUserId === userId : Boolean(membership[0]);
}

function rawOwnerMayCompleteRekey(
  task: typeof vaultRekeyJobs.$inferSelect,
  userId: string,
  deviceId: string,
): boolean {
  if (task.reason === 'device_compromise') {
    return task.initiatedByUserId === userId && task.initiatedByDeviceId === deviceId;
  }
  return task.reason === 'membership_change' &&
    task.initiatedByUserId === null &&
    task.initiatedByDeviceId === null;
}

function without<T extends Record<string, unknown>, K extends keyof T>(input: T, key: K): Omit<T, K> {
  const clone = { ...input };
  delete clone[key];
  return clone;
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === '23505');
}

function isForeignKeyViolation(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === '23503');
}

function badRequest(reply: FastifyReply, message: string) {
  return reply.code(400).send({ statusCode: 400, error: 'Bad Request', message } as never);
}

function unauthorized(reply: FastifyReply, message: string) {
  return reply.code(401).send({ statusCode: 401, error: 'Unauthorized', message } as never);
}

function forbidden(reply: FastifyReply, message: string) {
  return reply.code(403).send({ statusCode: 403, error: 'Forbidden', message } as never);
}

function conflict(reply: FastifyReply, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', message } as never);
}

function codedConflict(reply: FastifyReply, code: string, message: string) {
  return reply.code(409).send({ statusCode: 409, error: 'Conflict', code, message } as never);
}

function locked(reply: FastifyReply) {
  return reply.code(423).send({ statusCode: 423, error: 'Locked', message: '工作台已锁定，请先使用主密码或已授权设备解锁' } as never);
}

function versionConflict(reply: FastifyReply, currentVersion: number) {
  return reply.code(409).send({
    statusCode: 409,
    error: 'Conflict',
    message: '其他设备已经修改该条目。密码或敏感内容不会自动合并。',
    currentVersion,
  } as never);
}

function notFoundBody(message: string) {
  return { statusCode: 404, error: 'Not Found', message };
}
