import type {
  CipherBlob,
  EncryptedVaultHeader,
  LegacyMigrationJob as ContractLegacyMigrationJob,
  LegacyMigrationManifest,
  LegacyMigrationMaterials as ContractLegacyMigrationMaterials,
  LegacyMigrationRecipient as ContractLegacyMigrationRecipient,
  LegacyMigrationStatus as ContractLegacyMigrationStatus,
  LegacyMigrationStatusResponse as ContractLegacyMigrationStatusResponse,
  VaultCryptoState,
  VaultKeyEnvelopeInput,
} from '@mima/contracts';

export type LegacyMigrationStatus = ContractLegacyMigrationStatus;
export type LegacyMigrationJob = ContractLegacyMigrationJob;
export type LegacyMigrationRecipient = ContractLegacyMigrationRecipient;
export type LegacyMigrationMaterials = ContractLegacyMigrationMaterials;
export type LegacyMigrationStatusResponse = ContractLegacyMigrationStatusResponse;

export interface LegacyMigrationStartRequest {
  idempotencyKey: string;
  actorDeviceId: string;
  signature: string;
}

export interface LegacyMigrationExportClaimRequest {
  actorDeviceId: string;
  signature: string;
}

export interface LegacyMigrationExportResponse {
  sealedExport: string;
  recipientKeyVersion: number;
  sourceDigest: string;
}

export interface LegacyMigrationTargetRequest {
  idempotencyKey: string;
  jobId: string;
  headerFormatVersion: 3;
  keyPossessionPublicKey: string;
  header: Omit<EncryptedVaultHeader, 'updatedAt' | 'updatedBy'>;
  envelopes: VaultKeyEnvelopeInput[];
  actorDeviceId: string;
  manifestSignature: string;
}

export type LegacyMigrationRecord =
  | {
      kind: 'metadata';
      sourceId: string;
      sourceVersion: number;
      sourceDigest: string;
      itemId: string;
      version: number;
      blob: CipherBlob;
    }
  | {
      kind: 'secret';
      sourceId: string;
      sourceVersion: number;
      sourceDigest: string;
      itemId: string;
      recordVersion: number;
      secretVersion: number;
      encryptedValue: CipherBlob;
      wrappedDek: CipherBlob;
    };

export interface LegacyMigrationUploadRequest {
  idempotencyKey: string;
  jobId: string;
  actorDeviceId: string;
  records: LegacyMigrationRecord[];
  signature: string;
}

export type LegacyMigrationVerifyRequest = LegacyMigrationManifest;

export interface LegacyMigrationActionRequest {
  idempotencyKey: string;
  jobId: string;
  actorDeviceId: string;
  signature: string;
}

export interface PreparedLegacyMigration {
  jobId: string;
  vaultId: string;
  target: LegacyMigrationTargetRequest;
  recordBatches: LegacyMigrationUploadRequest[];
}

export interface LegacyMigrationUploadResponse {
  ok: true;
  jobId: string;
  processedCount: number;
  succeededCount: number;
  failedCount: number;
  totalCount: number;
}

export type LegacyMigrationCutoverResponse = VaultCryptoState;
