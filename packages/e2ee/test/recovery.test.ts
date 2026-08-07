import { describe, expect, it } from 'vitest';
import {
  createEnterpriseRecoveryKit,
  createUnsignedVaultKeyGrant,
  createVaultKeyGrant,
  createVaultKeys,
  destroyKeyPair,
  destroyVaultKeys,
  generateSigningKeyPair,
  generateEncryptionKeyPair,
  inspectRecoveryShare,
  openVaultKeyGrant,
  recoverEnterpriseRecoveryKey,
  signVaultKeyGrant,
} from '../src/index.ts';

describe('enterprise recovery', () => {
  it('reconstructs a 2-of-3 offline recovery key and opens recovery grants', async () => {
    const kit = await createEnterpriseRecoveryKit('ceremony-2026-07-18');
    const info = await inspectRecoveryShare(kit.shares[0]);
    expect(info).toMatchObject({
      ceremonyId: kit.ceremonyId,
      ceremonyDigest: kit.ceremonyDigest,
      publicKey: kit.publicKey,
      shareIndex: 1,
      threshold: 2,
      shareCount: 3,
    });

    const recovered = await recoverEnterpriseRecoveryKey(
      [kit.shares[0], kit.shares[2]],
      { ceremonyDigest: kit.ceremonyDigest, publicKey: kit.publicKey },
    );
    const vaultKeys = await createVaultKeys(1);
    const signer = await generateSigningKeyPair();
    const grant = await createVaultKeyGrant(
      vaultKeys,
      kit.publicKey,
      signer.privateKey,
      {
        vaultId: 'vault-recovery-test',
        recipientKind: 'recovery',
        recipientId: kit.ceremonyId,
        recipientKeyVersion: 1,
        capability: 'recovery',
        signerUserId: 'owner-user',
        signerKeyVersion: 1,
      },
    );

    const recoveredVaultKeys = await openVaultKeyGrant(grant, recovered, signer.publicKey, {
      vaultId: 'vault-recovery-test',
      recipientId: kit.ceremonyId,
      epoch: 1,
    });
    expect(recoveredVaultKeys).toMatchObject({ keyEpoch: 1 });

    const targetEncryption = await generateEncryptionKeyPair();
    const targetSigning = await generateSigningKeyPair();
    const unsigned = await createUnsignedVaultKeyGrant(
      recoveredVaultKeys as Required<typeof recoveredVaultKeys>,
      targetEncryption.publicKey,
      {
        vaultId: 'vault-recovery-test',
        recipientKind: 'user',
        recipientId: 'recovered-user',
        recipientKeyVersion: 1,
        capability: 'full',
        signerUserId: 'recovered-user',
        signerKeyVersion: 1,
      },
    );
    const targetGrant = await signVaultKeyGrant(unsigned, targetSigning.privateKey);
    await expect(openVaultKeyGrant(targetGrant, targetEncryption, targetSigning.publicKey, {
      vaultId: 'vault-recovery-test',
      recipientId: 'recovered-user',
      epoch: 1,
    })).resolves.toMatchObject({ keyEpoch: 1 });

    await destroyKeyPair(recovered);
    await destroyKeyPair(signer);
    await destroyKeyPair(targetEncryption);
    await destroyKeyPair(targetSigning);
    await destroyVaultKeys(recoveredVaultKeys);
    await destroyVaultKeys(vaultKeys);
  });

  it('rejects insufficient, duplicate, mixed, and corrupted shares', async () => {
    const first = await createEnterpriseRecoveryKit('ceremony-a');
    const second = await createEnterpriseRecoveryKit('ceremony-b');

    await expect(recoverEnterpriseRecoveryKey([first.shares[0]])).rejects.toThrow();
    await expect(recoverEnterpriseRecoveryKey([first.shares[0], first.shares[0]])).rejects.toThrow();
    await expect(recoverEnterpriseRecoveryKey([first.shares[0], second.shares[1]])).rejects.toThrow();
    const corrupted = `${first.shares[1].slice(0, -1)}${first.shares[1].endsWith('A') ? 'B' : 'A'}`;
    await expect(recoverEnterpriseRecoveryKey([first.shares[0], corrupted])).rejects.toThrow();
  });

  it('supports any two administrator shares from sets of two through six', async () => {
    for (const shareCount of [2, 4, 6]) {
      const kit = await createEnterpriseRecoveryKit(`managed-${shareCount}`, shareCount);
      expect(kit).toMatchObject({ threshold: 2, shareCount });
      expect(kit.shares).toHaveLength(shareCount);
      const recovered = await recoverEnterpriseRecoveryKey(
        [kit.shares[0]!, kit.shares[shareCount - 1]!],
        { ceremonyDigest: kit.ceremonyDigest, publicKey: kit.publicKey },
      );
      expect(recovered.publicKey).toBe(kit.publicKey);
      await destroyKeyPair(recovered);
    }

    await expect(createEnterpriseRecoveryKit('too-few', 1)).rejects.toThrow();
    await expect(createEnterpriseRecoveryKit('too-many', 7)).rejects.toThrow();
  });
});
