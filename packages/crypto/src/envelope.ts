import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/** 密封结果：只允许这些字段落库，绝不落明文。 */
export interface EncryptedSecret {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  /** wrapIv(12) || wrapTag(16) || wrappedKey(32) */
  wrappedDek: Buffer;
  keyVersion: string;
}

/** AAD 固定包含这四个字段，防止密文在条目/版本之间被移花接木。 */
export interface SecretAad {
  vaultId: string;
  itemId: string;
  secretVersion: number;
  itemKind: string;
}

export interface MasterKeyProvider {
  /** 返回 32 字节 KEK。未知版本必须抛错。 */
  getKey(version: string): Buffer;
  activeVersion(): string;
  listVersions(): string[];
}

const DEK_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;

export function aadBytes(aad: SecretAad): Buffer {
  return Buffer.from(
    `mima.v1|${aad.vaultId}|${aad.itemId}|${aad.secretVersion}|${aad.itemKind}`,
    'utf8',
  );
}

export function encryptSecret(
  provider: MasterKeyProvider,
  aad: SecretAad,
  plaintext: string,
): EncryptedSecret {
  const dek = randomBytes(DEK_LEN);
  try {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    cipher.setAAD(aadBytes(aad));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const keyVersion = provider.activeVersion();
    const wrappedDek = wrapDek(provider.getKey(keyVersion), dek, aad);
    return { ciphertext, iv, authTag, wrappedDek, keyVersion };
  } finally {
    dek.fill(0);
  }
}

export function decryptSecret(
  provider: MasterKeyProvider,
  aad: SecretAad,
  enc: Omit<EncryptedSecret, 'keyVersion'> & { keyVersion: string },
): string {
  const dek = unwrapDek(provider.getKey(enc.keyVersion), enc.wrappedDek, aad);
  try {
    const decipher = createDecipheriv('aes-256-gcm', dek, enc.iv);
    decipher.setAAD(aadBytes(aad));
    decipher.setAuthTag(enc.authTag);
    return Buffer.concat([decipher.update(enc.ciphertext), decipher.final()]).toString('utf8');
  } finally {
    dek.fill(0);
  }
}

/** 用目标版本 KEK 重新包装 DEK；密文本体不动。 */
export function rewrapDek(
  provider: MasterKeyProvider,
  aad: SecretAad,
  wrappedDek: Buffer,
  fromKeyVersion: string,
  toKeyVersion: string,
): Buffer {
  const dek = unwrapDek(provider.getKey(fromKeyVersion), wrappedDek, aad);
  try {
    return wrapDek(provider.getKey(toKeyVersion), dek, aad);
  } finally {
    dek.fill(0);
  }
}

function wrapDek(kek: Buffer, dek: Buffer, aad: SecretAad): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', kek, iv);
  cipher.setAAD(aadBytes(aad));
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), wrapped]);
}

function unwrapDek(kek: Buffer, wrappedDek: Buffer, aad: SecretAad): Buffer {
  if (wrappedDek.length !== IV_LEN + TAG_LEN + DEK_LEN) {
    throw new Error('malformed wrapped DEK');
  }
  const iv = wrappedDek.subarray(0, IV_LEN);
  const tag = wrappedDek.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const body = wrappedDek.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAAD(aadBytes(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}
