import {
  createUnsignedVaultKeyGrant,
  enterpriseRecoveryTransferEvidenceDigest,
  type VaultKeys,
} from '@mima/e2ee';
import type { RecoveryInput } from './protocol.ts';

export async function createRecoveryTransfer(input: RecoveryInput, vaultKeys: VaultKeys) {
  if (!vaultKeys.contentKey) throw new Error('recovery envelope does not contain full vault keys');
  const recoveredEnvelope = await createUnsignedVaultKeyGrant(
    { ...vaultKeys, contentKey: vaultKeys.contentKey },
    input.target.encryptionPublicKey,
    {
      vaultId: input.vaultId,
      recipientKind: 'user',
      recipientId: input.target.userId,
      recipientKeyVersion: input.target.keyVersion,
      capability: input.targetCapability,
      signerUserId: input.target.userId,
      signerKeyVersion: input.target.keyVersion,
    },
  );
  const evidenceBody = {
    protocol: 'lm-e2ee-v1' as const,
    kind: 'enterprise-recovery-transfer' as const,
    formatVersion: 1 as const,
    requestId: input.requestId,
    requestDigest: input.requestDigest,
    vaultId: input.vaultId,
    epoch: input.epoch,
    recoveryKeyId: input.recovery.keyId,
    ceremonyId: input.recovery.ceremonyId,
    recoveryCeremonyDigest: input.recovery.ceremonyDigest,
    targetUserId: input.target.userId,
    targetCapability: input.targetCapability,
    recoveredEnvelope,
  };
  return {
    ...evidenceBody,
    toolEvidenceDigest: await enterpriseRecoveryTransferEvidenceDigest(evidenceBody),
  };
}
