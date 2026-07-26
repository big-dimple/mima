import { normalizeCryptoError } from './aad.ts';
import { E2eeError } from './constants.ts';
import { fromBase64Url, sodiumReady, toBase64Url } from './encoding.ts';

export interface EncryptionKeyPair {
  publicKey: string;
  privateKey: Uint8Array;
}

export interface SigningKeyPair {
  publicKey: string;
  privateKey: Uint8Array;
}

export async function generateEncryptionKeyPair(seed?: Uint8Array): Promise<EncryptionKeyPair> {
  const crypto = await sodiumReady();
  let pair: { publicKey: Uint8Array; privateKey: Uint8Array };
  if (seed) {
    if (seed.byteLength !== crypto.crypto_box_SEEDBYTES) {
      throw new E2eeError('invalid_input', `X25519 seed must be ${crypto.crypto_box_SEEDBYTES} bytes`);
    }
    pair = crypto.crypto_box_seed_keypair(seed);
  } else {
    pair = crypto.crypto_box_keypair();
  }
  return { publicKey: await toBase64Url(pair.publicKey), privateKey: pair.privateKey };
}

export async function generateSigningKeyPair(seed?: Uint8Array): Promise<SigningKeyPair> {
  const crypto = await sodiumReady();
  let pair: { publicKey: Uint8Array; privateKey: Uint8Array };
  if (seed) {
    if (seed.byteLength !== crypto.crypto_sign_SEEDBYTES) {
      throw new E2eeError('invalid_input', `Ed25519 seed must be ${crypto.crypto_sign_SEEDBYTES} bytes`);
    }
    pair = crypto.crypto_sign_seed_keypair(seed);
  } else {
    pair = crypto.crypto_sign_keypair();
  }
  return { publicKey: await toBase64Url(pair.publicKey), privateKey: pair.privateKey };
}

export async function sealBytes(plaintext: Uint8Array, recipientPublicKey: string): Promise<string> {
  const crypto = await sodiumReady();
  const publicKey = await fromBase64Url(recipientPublicKey, crypto.crypto_box_PUBLICKEYBYTES);
  try {
    return await toBase64Url(crypto.crypto_box_seal(plaintext, publicKey));
  } finally {
    crypto.memzero(publicKey);
  }
}

export async function openSealedBytes(
  ciphertext: string,
  recipient: EncryptionKeyPair,
): Promise<Uint8Array> {
  const crypto = await sodiumReady();
  const publicKey = await fromBase64Url(recipient.publicKey, crypto.crypto_box_PUBLICKEYBYTES);
  const sealed = await fromBase64Url(ciphertext);
  try {
    return crypto.crypto_box_seal_open(sealed, publicKey, recipient.privateKey);
  } catch (error) {
    throw normalizeCryptoError(error);
  } finally {
    crypto.memzero(publicKey);
    crypto.memzero(sealed);
  }
}

export async function signBytes(message: Uint8Array, privateKey: Uint8Array): Promise<string> {
  const crypto = await sodiumReady();
  if (privateKey.byteLength !== crypto.crypto_sign_SECRETKEYBYTES) {
    throw new E2eeError('invalid_input', 'Invalid Ed25519 private key');
  }
  return toBase64Url(crypto.crypto_sign_detached(message, privateKey));
}

export async function verifyBytes(
  signature: string,
  message: Uint8Array,
  publicKey: string,
): Promise<boolean> {
  const crypto = await sodiumReady();
  const signatureBytes = await fromBase64Url(signature, crypto.crypto_sign_BYTES);
  const publicKeyBytes = await fromBase64Url(publicKey, crypto.crypto_sign_PUBLICKEYBYTES);
  try {
    return crypto.crypto_sign_verify_detached(signatureBytes, message, publicKeyBytes);
  } finally {
    crypto.memzero(signatureBytes);
    crypto.memzero(publicKeyBytes);
  }
}

export async function encryptionPublicKeyFromPrivate(privateKey: Uint8Array): Promise<string> {
  const crypto = await sodiumReady();
  if (privateKey.byteLength !== crypto.crypto_box_SECRETKEYBYTES) {
    throw new E2eeError('invalid_input', 'Invalid X25519 private key');
  }
  return toBase64Url(crypto.crypto_scalarmult_base(privateKey));
}

export async function signingPublicKeyFromPrivate(privateKey: Uint8Array): Promise<string> {
  const crypto = await sodiumReady();
  if (privateKey.byteLength !== crypto.crypto_sign_SECRETKEYBYTES) {
    throw new E2eeError('invalid_input', 'Invalid Ed25519 private key');
  }
  return toBase64Url(crypto.crypto_sign_ed25519_sk_to_pk(privateKey));
}

export async function destroyKeyPair(pair: EncryptionKeyPair | SigningKeyPair): Promise<void> {
  const crypto = await sodiumReady();
  crypto.memzero(pair.privateKey);
}
