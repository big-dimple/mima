import type { CryptoDevice } from '@mima/contracts';
import { verifySignedDeviceCertificate } from '@mima/e2ee';
import type { LocalDeviceRecord } from './protocol.ts';

export async function verifyApprovedDevice(
  record: LocalDeviceRecord,
  device: CryptoDevice,
  profileSigningPublicKey: string,
): Promise<LocalDeviceRecord> {
  assertServerDeviceMatches(record, device);
  const certificate = await verifySignedDeviceCertificate(
    { certificate: device.certificate, signature: device.certificateSignature },
    profileSigningPublicKey,
    { accountId: device.userId, deviceId: record.deviceId, deviceType: 'extension' },
  );
  if (
    certificate.encryptionPublicKey !== record.encryptionPublicKey ||
    certificate.signingPublicKey !== record.signingPublicKey ||
    certificate.keyVersion !== device.keyVersion
  ) {
    throw new Error('此扩展保存的授权信息与当前浏览器不一致，请重新配对');
  }
  return {
    ...record,
    userId: device.userId,
    certificate: device.certificate,
    certificateSignature: device.certificateSignature,
  };
}

export function assertServerDeviceMatches(
  record: LocalDeviceRecord,
  device: CryptoDevice,
): void {
  if (
    device.id !== record.deviceId ||
    device.deviceType !== 'extension' ||
    device.encryptionPublicKey !== record.encryptionPublicKey ||
    device.signingPublicKey !== record.signingPublicKey
  ) {
    throw new Error('服务端记录与此扩展不一致，请撤销该扩展后重新配对');
  }
}
