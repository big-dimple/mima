import {
  destroyKeyPair,
  destroyVaultKeys,
  openVaultKeyGrant,
  recoverEnterpriseRecoveryKey,
} from '@mima/e2ee';
import type { RecoveryCaseInput } from './protocol.ts';
import { createRecoveryTransfer } from './transfer.ts';

export async function createRecoveryCaseTransfer(
  input: RecoveryCaseInput,
  shares: readonly string[],
) {
  if (shares.length !== 2) throw new Error('请选择两份不同的恢复材料');
  const recoveryKey = await recoverEnterpriseRecoveryKey(shares, {
    ceremonyId: input.recovery.ceremonyId,
    ceremonyDigest: input.recovery.ceremonyDigest,
    publicKey: input.recovery.publicKey,
  });
  try {
    const results = [];
    for (const item of input.items) {
      const vaultKeys = await openVaultKeyGrant(
        item.recoveryEnvelope,
        recoveryKey,
        item.trustedOwnerSigningPublicKey,
        {
          vaultId: item.vaultId,
          recipientId: item.recovery.keyId,
          epoch: item.epoch,
        },
      );
      try {
        results.push(await createRecoveryTransfer(item, vaultKeys));
      } finally {
        await destroyVaultKeys(vaultKeys);
      }
    }
    return {
      protocol: 'mima-e2ee-v2' as const,
      kind: 'enterprise-recovery-case-transfer' as const,
      caseId: input.caseId,
      caseDigest: input.caseDigest,
      results,
    };
  } finally {
    await destroyKeyPair(recoveryKey);
  }
}
