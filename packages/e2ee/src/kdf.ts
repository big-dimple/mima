import {
  E2eeError,
  KDF_ALGORITHM,
  KDF_ITERATIONS,
  KDF_MEMORY_KIB,
  KDF_PARALLELISM,
  KDF_SALT_BYTES,
  KEY_BYTES,
} from './constants.ts';
import { fromBase64Url, sodiumReady, toBase64Url, utf8 } from './encoding.ts';

export interface KdfProfile {
  algorithm: typeof KDF_ALGORITHM;
  memoryKiB: typeof KDF_MEMORY_KIB;
  iterations: typeof KDF_ITERATIONS;
  parallelism: typeof KDF_PARALLELISM;
  salt: string;
  outputBytes: typeof KEY_BYTES;
}

export async function createKdfProfile(salt?: Uint8Array): Promise<KdfProfile> {
  const crypto = await sodiumReady();
  const actualSalt = salt ? new Uint8Array(salt) : crypto.randombytes_buf(KDF_SALT_BYTES);
  if (actualSalt.byteLength !== KDF_SALT_BYTES) {
    crypto.memzero(actualSalt);
    throw new E2eeError('invalid_input', `Argon2id salt must be ${KDF_SALT_BYTES} bytes`);
  }
  try {
    return {
      algorithm: KDF_ALGORITHM,
      memoryKiB: KDF_MEMORY_KIB,
      iterations: KDF_ITERATIONS,
      parallelism: KDF_PARALLELISM,
      salt: await toBase64Url(actualSalt),
      outputBytes: KEY_BYTES,
    };
  } finally {
    crypto.memzero(actualSalt);
  }
}

export async function deriveMasterKey(
  password: string | Uint8Array,
  profile: KdfProfile,
): Promise<Uint8Array> {
  validateKdfProfile(profile);
  const crypto = await sodiumReady();
  const salt = await fromBase64Url(profile.salt, KDF_SALT_BYTES);
  const passwordBytes = typeof password === 'string' ? utf8(password) : new Uint8Array(password);
  if (passwordBytes.byteLength === 0) {
    crypto.memzero(passwordBytes);
    crypto.memzero(salt);
    throw new E2eeError('invalid_input', 'Master password must not be empty');
  }
  try {
    return crypto.crypto_pwhash(
      KEY_BYTES,
      passwordBytes,
      salt,
      KDF_ITERATIONS,
      KDF_MEMORY_KIB * 1024,
      crypto.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    crypto.memzero(passwordBytes);
    crypto.memzero(salt);
  }
}

export function validateKdfProfile(profile: KdfProfile): void {
  if (
    profile.algorithm !== KDF_ALGORITHM ||
    profile.memoryKiB !== KDF_MEMORY_KIB ||
    profile.iterations !== KDF_ITERATIONS ||
    profile.parallelism !== KDF_PARALLELISM ||
    profile.outputBytes !== KEY_BYTES
  ) {
    throw new E2eeError('unsupported_protocol', 'Unsupported Argon2id profile');
  }
}
