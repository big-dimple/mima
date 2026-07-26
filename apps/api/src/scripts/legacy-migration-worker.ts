import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { and, eq, sql } from 'drizzle-orm';
import { FileMasterKeyProvider } from '@mima/crypto';
import {
  legacyMigrationExports,
  legacyMigrationJobs,
  legacyMigrationRecords,
  userCryptoProfiles,
  vaultMemberships,
  vaults,
} from '../db/schema.ts';
import { createDb, createPoolForUrl } from '../db/factory.ts';
import {
  buildLegacySourceManifest,
  legacySourceDigest,
  legacySourceRecords,
} from '../migration/legacy-source.ts';
import { sealLegacyExport } from '../migration/sealed-export.ts';
import { assertMigrationDatabaseRole, MigrationDatabaseRoleError } from '../migration/database-role.ts';

class MigrationWorkerError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export async function runLegacyMigrationWorker(jobId: string): Promise<{
  jobId: string;
  sourceDigest: string;
  sealedExportDigest: string;
}> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(jobId)) {
    throw new MigrationWorkerError('job_id_invalid');
  }
  const databaseUrlFile = requiredEnvironment('MIMA_MIGRATION_DATABASE_URL_FILE');
  const expectedDatabaseRole = requiredEnvironment('MIMA_MIGRATION_DATABASE_ROLE');
  const legacyKeyDirectory = requiredEnvironment('MIMA_LEGACY_CONTENT_KEY_DIR');
  const databaseUrl = readPrivateValue(databaseUrlFile);
  const pool = createPoolForUrl(databaseUrl);
  const db = createDb(pool);
  try {
    await assertMigrationDatabaseRole(pool, expectedDatabaseRole, jobId);
    const keys = new FileMasterKeyProvider(legacyKeyDirectory);
    return await db.transaction(async (tx) => {
      const job = (
        await tx.select().from(legacyMigrationJobs)
          .where(eq(legacyMigrationJobs.id, jobId)).for('update').limit(1)
      )[0];
      if (!job || job.state !== 'frozen' || !job.sourceSnapshotHash) {
        throw new MigrationWorkerError('job_not_frozen');
      }
      if (
        !job.exportRecipientUserId
        || !job.exportRecipientKeyVersion
        || !job.exportRecipientKeyDigest
        || !job.exportExpiresAt
        || job.exportExpiresAt.getTime() <= Date.now()
      ) {
        throw new MigrationWorkerError('export_binding_invalid');
      }
      const existingExport = await tx.select({ id: legacyMigrationExports.id })
        .from(legacyMigrationExports).where(eq(legacyMigrationExports.jobId, job.id)).limit(1);
      if (existingExport[0]) throw new MigrationWorkerError('export_already_exists');

      const profile = await tx.select().from(userCryptoProfiles)
        .where(eq(userCryptoProfiles.userId, job.exportRecipientUserId)).limit(1);
      const vault = await tx.select({
        id: vaults.id,
        ownerUserId: vaults.ownerUserId,
      }).from(vaults).where(eq(vaults.id, job.vaultId)).limit(1);
      const directOwner = await tx.select({ id: vaultMemberships.id }).from(vaultMemberships).where(and(
        eq(vaultMemberships.vaultId, job.vaultId),
        eq(vaultMemberships.subjectKind, 'user'),
        eq(vaultMemberships.subjectId, job.exportRecipientUserId),
        eq(vaultMemberships.role, 'owner'),
      )).limit(1);
      const recipient = profile[0];
      const sourceVault = vault[0];
      if (!recipient || !sourceVault || (!directOwner[0] && sourceVault.ownerUserId !== job.exportRecipientUserId)) {
        throw new MigrationWorkerError('recipient_not_current_owner');
      }
      const keyDigest = sha256(recipient.publicEncryptionKey);
      if (
        recipient.cryptoGeneration !== job.exportRecipientKeyVersion
        || !keyDigest.equals(job.exportRecipientKeyDigest)
      ) {
        throw new MigrationWorkerError('recipient_key_changed');
      }

      const manifest = await buildLegacySourceManifest(tx, job.vaultId, {
        eventCount: job.expectedAuditEventCount,
        headHash: job.sourceAuditHeadHash,
      });
      const sourceDigest = legacySourceDigest(manifest);
      if (!sourceDigest.equals(job.sourceSnapshotHash)) {
        throw new MigrationWorkerError('source_digest_changed');
      }
      const expectedRecords = legacySourceRecords(manifest);
      const storedRecords = await tx.select().from(legacyMigrationRecords)
        .where(eq(legacyMigrationRecords.jobId, job.id));
      assertFrozenRecords(expectedRecords, storedRecords);
      const secretVersionCount = manifest.items.reduce(
        (count, item) => count + item.secretVersions.length,
        0,
      );
      if (
        manifest.items.length !== job.expectedItemCount
        || manifest.items.length !== job.expectedMetadataVersionCount
        || secretVersionCount !== job.expectedSecretVersionCount
      ) {
        throw new MigrationWorkerError('source_count_changed');
      }

      const sealedBase64Url = await sealLegacyExport({
        jobId: job.id,
        sourceDigest: sourceDigest.toString('base64url'),
        recipientUserId: job.exportRecipientUserId,
        recipientKeyVersion: job.exportRecipientKeyVersion,
        recipientPublicKey: recipient.publicEncryptionKey.toString('base64url'),
        manifest,
      }, keys);
      const sealedExport = Buffer.from(sealedBase64Url, 'base64url');
      const sealedExportDigest = sha256(sealedExport);
      await tx.execute(sql`
        INSERT INTO legacy_migration_exports (
          job_id,
          vault_id,
          recipient_user_id,
          recipient_key_version,
          recipient_key_digest,
          source_digest,
          sealed_export,
          sealed_export_digest,
          expires_at
        ) VALUES (
          ${job.id},
          ${job.vaultId},
          ${job.exportRecipientUserId},
          ${job.exportRecipientKeyVersion},
          ${keyDigest},
          ${sourceDigest},
          ${sealedExport},
          ${sealedExportDigest},
          ${job.exportExpiresAt}
        )
      `);
      await tx.update(legacyMigrationJobs).set({
        state: 'encrypting',
        updatedAt: new Date(),
      }).where(and(
        eq(legacyMigrationJobs.id, job.id),
        eq(legacyMigrationJobs.state, 'frozen'),
      ));
      await tx.execute(sql`
        INSERT INTO legacy_migration_evidence (
          job_id,
          evidence_type,
          stage,
          subject_kind,
          subject_id,
          record_count,
          digest
        ) VALUES (
          ${job.id},
          'ciphertext_digest',
          'encrypting',
          'vault',
          ${job.vaultId},
          ${expectedRecords.length},
          ${sealedExportDigest}
        )
      `);
      sealedExport.fill(0);
      return {
        jobId: job.id,
        sourceDigest: sourceDigest.toString('base64url'),
        sealedExportDigest: sealedExportDigest.toString('base64url'),
      };
    });
  } finally {
    await pool.end();
  }
}

function assertFrozenRecords(
  expected: ReturnType<typeof legacySourceRecords>,
  stored: Array<typeof legacyMigrationRecords.$inferSelect>,
): void {
  if (expected.length !== stored.length) throw new MigrationWorkerError('source_record_count_changed');
  const storedByKey = new Map(stored.map((record) => [
    `${record.sourceKind}:${record.sourceId}:${record.sourceVersion}`,
    record,
  ]));
  for (const record of expected) {
    const key = `${record.sourceKind}:${record.sourceId}:${record.sourceVersion}`;
    const frozen = storedByKey.get(key);
    if (!frozen || frozen.state !== 'pending' || !frozen.sourceDigest.equals(record.sourceDigest)) {
      throw new MigrationWorkerError('source_record_changed');
    }
  }
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new MigrationWorkerError('worker_configuration_invalid');
  return value;
}

function readPrivateValue(path: string): string {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new MigrationWorkerError('database_url_file_not_private');
  }
  const value = readFileSync(path, 'utf8').trim();
  if (!value) throw new MigrationWorkerError('database_url_file_empty');
  return value;
}

function sha256(value: Uint8Array): Buffer {
  return createHash('sha256').update(value).digest();
}

function parseJobId(argv: string[]): string {
  const index = argv.indexOf('--job');
  if (index < 0 || !argv[index + 1]) throw new MigrationWorkerError('job_id_missing');
  return argv[index + 1]!;
}

async function checkDatabaseRoleOnly(jobId: string): Promise<{ databaseRole: string; jobId: string; restricted: true }> {
  const databaseUrlFile = requiredEnvironment('MIMA_MIGRATION_DATABASE_URL_FILE');
  const expectedDatabaseRole = requiredEnvironment('MIMA_MIGRATION_DATABASE_ROLE');
  const databaseUrl = readPrivateValue(databaseUrlFile);
  const pool = createPoolForUrl(databaseUrl);
  try {
    await assertMigrationDatabaseRole(pool, expectedDatabaseRole, jobId);
    return { databaseRole: expectedDatabaseRole, jobId, restricted: true };
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && /legacy-migration-worker\.(?:ts|js)$/.test(process.argv[1])) {
  const args = process.argv.slice(2);
  const jobId = parseJobId(args);
  const operation = args.includes('--check-database-role')
    ? checkDatabaseRoleOnly(jobId)
    : runLegacyMigrationWorker(jobId);
  operation
    .then((result) => {
      process.stdout.write(`${JSON.stringify(result)}\n`);
    })
    .catch((error: unknown) => {
      const code = error instanceof MigrationWorkerError || error instanceof MigrationDatabaseRoleError
        ? error.message
        : 'worker_failed';
      process.stderr.write(`[migration-worker] ${code}\n`);
      process.exitCode = 1;
    });
}
