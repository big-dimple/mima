import type { E2eeKeyring } from '@mima/client-core';

export const WEB_CRYPTO_WORKER_METHODS = [
  'setup',
  'prepareAccountCryptoReset',
  'unlockPendingAccountCryptoReset',
  'prepareAccountCryptoResetActivation',
  'commitAccountCryptoReset',
  'abortAccountCryptoReset',
  'unlock',
  'enrollWebDevice',
  'signServerChallenge',
  'prepareMasterPasswordChange',
  'prepareIdentityRotation',
  'commitIdentityRotation',
  'abortIdentityRotation',
  'migrationStartIntent',
  'createLegacyKeyRetirementIntent',
  'approveLegacyKeyRetirementIntent',
  'completeLegacyKeyRetirementIntent',
  'migrationExportClaimIntent',
  'prepareLegacyMigration',
  'migrationVerificationIntent',
  'migrationActionIntent',
  'commitLegacyMigration',
  'abortLegacyMigration',
  'decryptBootstrap',
  'decryptMetadataRecord',
  'decryptContent',
  'initializeVault',
  'prepareVaultCreation',
  'encryptVaultRename',
  'encryptVaultDetails',
  'encryptVaultDirectories',
  'prepareEnterpriseRecoveryEnvelope',
  'prepareManagedEnterpriseRecoveryKey',
  'prepareManagedEnterpriseRecoveryKeyApproval',
  'prepareManagedRecoveryCaseApproval',
  'prepareInterruptedHandoffRecoveryCase',
  'prepareRecovery',
  'commitRecovery',
  'abortRecovery',
  'approveExtensionEnrollment',
  'prepareExtensionTrustedUnlock',
  'prepareExtensionSessionResume',
  'revokeDevice',
  'prepareMembershipSet',
  'prepareMembershipRemoval',
  'prepareVaultDeletion',
  'prepareUninitializedVaultDeletion',
  'prepareEnvelopeTaskCompletion',
  'prepareOwnershipTransfer',
  'prepareOwnershipTransferAcceptance',
  'prepareOwnershipTransferCancellation',
  'rekeyMaterialIntent',
  'prepareVaultRekey',
  'commitVaultRekey',
  'abortVaultRekey',
  'encryptCreate',
  'encryptMetadataUpdate',
  'encryptRotation',
  'contentIntent',
  'encryptDelete',
  'encryptOfflineSnapshot',
  'decryptOfflineSnapshot',
  'dropVault',
] as const satisfies readonly (keyof E2eeKeyring)[];

export type WebCryptoWorkerMethod = (typeof WEB_CRYPTO_WORKER_METHODS)[number];

const allowedMethods = new Set<string>(WEB_CRYPTO_WORKER_METHODS);

export function isWebCryptoWorkerMethod(value: unknown): value is WebCryptoWorkerMethod {
  return typeof value === 'string' && allowedMethods.has(value);
}

export interface WebCryptoWorkerRequest {
  id: number;
  method: WebCryptoWorkerMethod;
  args: unknown[];
}

export type WebCryptoWorkerResponse =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: { message: string; code?: string } };
