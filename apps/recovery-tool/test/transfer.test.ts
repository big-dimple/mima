import { afterEach, describe, expect, it } from 'vitest';
import {
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
import { createRecoveryTransfer } from '../src/transfer.ts';
import type { RecoveryInput } from '../src/protocol.ts';

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
