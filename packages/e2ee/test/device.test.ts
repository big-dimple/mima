import { describe, expect, it } from 'vitest';
import {
  createSignedDeviceCertificate,
  destroyKeyPair,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  verifySignedDeviceCertificate,
} from '../src/index.ts';

describe('device certificates', () => {
  it('binds public device keys without uploading private key material', async () => {
    const accountSigner = await generateSigningKeyPair();
    const deviceEncryption = await generateEncryptionKeyPair();
    const deviceSigning = await generateSigningKeyPair();
    const signed = await createSignedDeviceCertificate({
      accountId: 'user-1',
      deviceId: 'device-1',
      deviceType: 'extension',
      encryptionPublicKey: deviceEncryption.publicKey,
      signingPublicKey: deviceSigning.publicKey,
      keyVersion: 1,
      issuedAt: '2026-07-18T12:00:00.000Z',
    }, accountSigner.privateKey);

    await expect(verifySignedDeviceCertificate(signed, accountSigner.publicKey, {
      accountId: 'user-1',
      deviceId: 'device-1',
      deviceType: 'extension',
    })).resolves.toMatchObject({ signingPublicKey: deviceSigning.publicKey });
    expect(signed).not.toHaveProperty('privateKey');

    const wrongSigner = await generateSigningKeyPair();
    await expect(verifySignedDeviceCertificate(signed, wrongSigner.publicKey)).rejects.toThrow();
    await expect(verifySignedDeviceCertificate({
      ...signed,
      certificate: `${signed.certificate.slice(0, -1)}${signed.certificate.endsWith('A') ? 'B' : 'A'}`,
    }, accountSigner.publicKey)).rejects.toThrow();

    await destroyKeyPair(wrongSigner);
    await destroyKeyPair(accountSigner);
    await destroyKeyPair(deviceEncryption);
    await destroyKeyPair(deviceSigning);
  });
});
