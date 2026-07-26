import { signBytes, verifyBytes } from './asymmetric.ts';
import { E2EE_PROTOCOL, E2eeError } from './constants.ts';
import {
  assertIdentifier,
  assertPositiveVersion,
  canonicalJson,
  decodeUtf8,
  fromBase64Url,
  sodiumReady,
  toBase64Url,
  utf8,
  type JsonValue,
} from './encoding.ts';

export type DeviceType = 'desktop' | 'extension' | 'mobile' | 'web';

export interface DeviceCertificate {
  protocol: typeof E2EE_PROTOCOL;
  kind: 'device-certificate';
  accountId: string;
  deviceId: string;
  deviceType: DeviceType;
  encryptionPublicKey: string;
  signingPublicKey: string;
  keyVersion: number;
  issuedAt: string;
}

export interface SignedDeviceCertificate {
  certificate: string;
  signature: string;
}

export async function createSignedDeviceCertificate(
  input: Omit<DeviceCertificate, 'kind' | 'protocol'>,
  userSigningPrivateKey: Uint8Array,
): Promise<SignedDeviceCertificate> {
  const payload: DeviceCertificate = {
    protocol: E2EE_PROTOCOL,
    kind: 'device-certificate',
    ...input,
  };
  await validateDeviceCertificate(payload);
  const bytes = utf8(canonicalJson(payload as unknown as JsonValue));
  try {
    return {
      certificate: await toBase64Url(bytes),
      signature: await signBytes(bytes, userSigningPrivateKey),
    };
  } finally {
    bytes.fill(0);
  }
}

export async function verifySignedDeviceCertificate(
  signed: SignedDeviceCertificate,
  trustedUserSigningPublicKey: string,
  expected: { accountId?: string; deviceId?: string; deviceType?: DeviceType } = {},
): Promise<DeviceCertificate> {
  const certificateBytes = await fromBase64Url(signed.certificate);
  try {
    if (!(await verifyBytes(signed.signature, certificateBytes, trustedUserSigningPublicKey))) {
      throw new E2eeError('verification_failed', 'Device certificate signature is invalid');
    }
    const certificate = parseDeviceCertificate(decodeUtf8(certificateBytes));
    await validateDeviceCertificate(certificate);
    if (
      (expected.accountId && expected.accountId !== certificate.accountId) ||
      (expected.deviceId && expected.deviceId !== certificate.deviceId) ||
      (expected.deviceType && expected.deviceType !== certificate.deviceType)
    ) {
      throw new E2eeError('verification_failed', 'Device certificate scope does not match');
    }
    return certificate;
  } finally {
    certificateBytes.fill(0);
  }
}

function parseDeviceCertificate(encoded: string): DeviceCertificate {
  try {
    const parsed = JSON.parse(encoded) as Partial<DeviceCertificate>;
    const expectedKeys = [
      'accountId',
      'deviceId',
      'deviceType',
      'encryptionPublicKey',
      'issuedAt',
      'keyVersion',
      'kind',
      'protocol',
      'signingPublicKey',
    ];
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Object.keys(parsed).sort().join(',') !== expectedKeys.join(',') ||
      parsed.protocol !== E2EE_PROTOCOL ||
      parsed.kind !== 'device-certificate' ||
      typeof parsed.accountId !== 'string' ||
      typeof parsed.deviceId !== 'string' ||
      typeof parsed.deviceType !== 'string' ||
      typeof parsed.encryptionPublicKey !== 'string' ||
      typeof parsed.signingPublicKey !== 'string' ||
      typeof parsed.keyVersion !== 'number' ||
      typeof parsed.issuedAt !== 'string'
    ) {
      throw new E2eeError('invalid_input', 'Device certificate is invalid');
    }
    return parsed as DeviceCertificate;
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError('invalid_input', 'Device certificate is invalid', { cause: error });
  }
}

async function validateDeviceCertificate(certificate: DeviceCertificate): Promise<void> {
  assertIdentifier(certificate.accountId, 'accountId');
  assertIdentifier(certificate.deviceId, 'deviceId');
  assertPositiveVersion(certificate.keyVersion, 'keyVersion');
  if (!['desktop', 'extension', 'mobile', 'web'].includes(certificate.deviceType)) {
    throw new E2eeError('invalid_input', 'Device type is invalid');
  }
  if (!Number.isFinite(Date.parse(certificate.issuedAt))) {
    throw new E2eeError('invalid_input', 'Device certificate timestamp is invalid');
  }
  const crypto = await sodiumReady();
  const encryptionPublicKey = await fromBase64Url(
    certificate.encryptionPublicKey,
    crypto.crypto_box_PUBLICKEYBYTES,
  );
  const signingPublicKey = await fromBase64Url(
    certificate.signingPublicKey,
    crypto.crypto_sign_PUBLICKEYBYTES,
  );
  crypto.memzero(encryptionPublicKey);
  crypto.memzero(signingPublicKey);
}
