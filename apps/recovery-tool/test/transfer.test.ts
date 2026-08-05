import { afterEach, describe, expect, it } from 'vitest';
import {
  createEnterpriseRecoveryKit,
  createVaultKeyGrant,
  createVaultKeys,
  destroyKeyPair,
  destroyVaultKeys,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  openVaultKeyGrant,
  signVaultKeyGrant,
  type EncryptionKeyPair,
  type SigningKeyPair,
  type VaultKeys,
} from '@mima/e2ee';
import { createRecoveryCaseTransfer } from '../src/case-transfer.ts';
import { createRecoveryTransfer } from '../src/transfer.ts';
import type { RecoveryCaseInput, RecoveryInput } from '../src/protocol.ts';

const vaults: VaultKeys[] = [];
const keyPairs: Array<EncryptionKeyPair | SigningKeyPair> = [];

afterEach(async () => {
  await Promise.all(vaults.splice(0).map(destroyVaultKeys));
  await Promise.all(keyPairs.splice(0).map(destroyKeyPair));
});

describe('recovery tool transfer capability', () => {
  it.each(['metadata', 'full'] as const)('emits an exact %s envelope', async (capability) => {
    const vaultKeys = await createVaultKeys(3);
    const target = await generateEncryptionKeyPair();
    const signer = await generateSigningKeyPair();
    vaults.push(vaultKeys);
    keyPairs.push(target, signer);
    const input = recoveryInput(capability, target.publicKey);
    const transfer = await createRecoveryTransfer(input, vaultKeys);
    expect(transfer.targetCapability).toBe(capability);
    expect(transfer.formatVersion).toBe(1);
    expect(transfer.recoveredEnvelope.capability).toBe(capability);
    expect(transfer).not.toHaveProperty('unsignedEnvelope');
    const signed = await signVaultKeyGrant(transfer.recoveredEnvelope, signer.privateKey);
    const opened = await openVaultKeyGrant(signed, target, signer.publicKey, {
      vaultId: input.vaultId,
      recipientId: input.target.userId,
      epoch: input.epoch,
      recipientKeyVersion: input.target.keyVersion,
    });
    vaults.push(opened);
    expect(opened.contentKey !== undefined).toBe(capability === 'full');
  });

  it('uses two shares once and returns one result for every vault in the case', async () => {
    const kit = await createEnterpriseRecoveryKit('multi-vault-case');
    const target = await generateEncryptionKeyPair();
    const ownerSigner = await generateSigningKeyPair();
    keyPairs.push(target, ownerSigner);
    const inputs: RecoveryInput[] = [];
    for (const [index, capability] of (['full', 'metadata'] as const).entries()) {
      const vaultKeys = await createVaultKeys(index + 1);
      vaults.push(vaultKeys);
      const vaultId = `20000000-0000-4000-8000-00000000000${index + 1}`;
      const recoveryEnvelope = await createVaultKeyGrant(
        vaultKeys,
        kit.publicKey,
        ownerSigner.privateKey,
        {
          vaultId,
          recipientKind: 'recovery',
          recipientId: '30000000-0000-4000-8000-000000000001',
          recipientKeyVersion: 1,
          capability: 'recovery',
          signerUserId: 'u-owner',
          signerKeyVersion: 1,
        },
      );
      inputs.push({
        ...recoveryInput(capability, target.publicKey),
        requestId: `10000000-0000-4000-8000-00000000000${index + 1}`,
        vaultId,
        epoch: index + 1,
        recovery: {
          keyId: '30000000-0000-4000-8000-000000000001',
          ceremonyId: kit.ceremonyId,
          ceremonyDigest: kit.ceremonyDigest,
          publicKey: kit.publicKey,
        },
        recoveryEnvelope,
        trustedOwnerSigningPublicKey: ownerSigner.publicKey,
      });
    }
    const input: RecoveryCaseInput = {
      protocol: 'mima-e2ee-v2',
      kind: 'enterprise-recovery-case-package',
      caseId: '40000000-0000-4000-8000-000000000001',
      caseDigest: 'F'.repeat(43),
      recovery: inputs[0]!.recovery,
      items: inputs,
    };

    const result = await createRecoveryCaseTransfer(input, [kit.shares[0]!, kit.shares[2]!]);

    expect(result.results).toHaveLength(2);
    expect(result.results.map((entry) => entry.vaultId)).toEqual(inputs.map((entry) => entry.vaultId));
    expect(result.results.map((entry) => entry.targetCapability)).toEqual(['full', 'metadata']);
  });
});

function recoveryInput(
  targetCapability: RecoveryInput['targetCapability'],
  encryptionPublicKey: string,
): RecoveryInput {
  return {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-request-package',
    requestId: '10000000-0000-4000-8000-000000000001',
    requestDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    vaultId: '20000000-0000-4000-8000-000000000001',
    epoch: 3,
    targetCapability,
    recovery: {
      keyId: '30000000-0000-4000-8000-000000000001',
      ceremonyId: 'ceremony-1',
      ceremonyDigest: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      publicKey: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
    },
    recoveryEnvelope: {
      vaultId: '20000000-0000-4000-8000-000000000001',
      epoch: 3,
      recipientKind: 'recovery',
      recipientId: '30000000-0000-4000-8000-000000000001',
      recipientKeyVersion: 1,
      capability: 'recovery',
      sealedKeyBundle: 'placeholder',
      signerUserId: 'u-owner',
      signerKeyVersion: 1,
      signature: 'placeholder',
    },
    trustedOwnerSigningPublicKey: 'placeholder',
    target: { userId: 'u-auditor', encryptionPublicKey, keyVersion: 2 },
  };
}
