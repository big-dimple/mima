import type { AadContext } from './aad.ts';
import { aadBytes, normalizeCryptoError } from './aad.ts';
import {
  AAD_VERSION,
  AEAD_NONCE_BYTES,
  E2EE_PROTOCOL,
  E2eeError,
  KEY_BYTES,
} from './constants.ts';
import { assertProtocol, fromBase64Url, sodiumReady, toBase64Url } from './encoding.ts';

export interface CipherBlob {
  suite: typeof E2EE_PROTOCOL;
  aadVersion: typeof AAD_VERSION;
  nonce: string;
  ciphertext: string;
}

export type AeadEnvelope = CipherBlob;

export async function encryptBytes(
  key: Uint8Array,
  plaintext: Uint8Array,
  context: AadContext,
): Promise<CipherBlob> {
  const crypto = await sodiumReady();
  assertKey(key);
  const nonce = crypto.randombytes_buf(AEAD_NONCE_BYTES);
  const aad = aadBytes(context);
  try {
    const ciphertext = crypto.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      aad,
      null,
      nonce,
      key,
    );
    return {
      suite: E2EE_PROTOCOL,
      aadVersion: AAD_VERSION,
      nonce: await toBase64Url(nonce),
      ciphertext: await toBase64Url(ciphertext),
    };
  } finally {
    crypto.memzero(nonce);
    crypto.memzero(aad);
  }
}

export async function decryptBytes(
  key: Uint8Array,
  envelope: CipherBlob,
  context: AadContext,
): Promise<Uint8Array> {
  validateAeadEnvelope(envelope);
  assertKey(key);
  const crypto = await sodiumReady();
  const nonce = await fromBase64Url(envelope.nonce, AEAD_NONCE_BYTES);
  const ciphertext = await fromBase64Url(envelope.ciphertext);
  const aad = aadBytes(context);
  try {
    return crypto.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      aad,
      nonce,
      key,
    );
  } catch (error) {
    throw normalizeCryptoError(error);
  } finally {
    crypto.memzero(nonce);
    crypto.memzero(ciphertext);
    crypto.memzero(aad);
  }
}

export function validateAeadEnvelope(envelope: CipherBlob): void {
  assertProtocol(envelope.suite);
  if (envelope.aadVersion !== AAD_VERSION) {
    throw new E2eeError('unsupported_protocol', 'Unsupported AAD version');
  }
}

function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== KEY_BYTES) {
    throw new E2eeError('invalid_input', `AEAD key must be ${KEY_BYTES} bytes`);
  }
}
