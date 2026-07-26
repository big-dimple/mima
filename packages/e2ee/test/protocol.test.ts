import { describe, expect, it } from 'vitest';
import {
  E2eeError,
  aadBytes,
  canonicalJson,
  createKdfProfile,
  createUnlockChallenge,
  decryptBytes,
  deriveMasterKey,
  encryptBytes,
  fromBase64Url,
  generateSigningKeyPair,
  signBytes,
  signUnlockChallenge,
  sodiumReady,
  toBase64Url,
  verifyBytes,
  verifyUnlockChallenge,
} from '../src/index.ts';

function bytesFromHex(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error('invalid test hex');
  return Uint8Array.from(hex.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function hexFromBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function mutateBase64Url(value: string): string {
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}

describe('lm-e2ee-v1 protocol primitives', () => {
  it('uses stable canonical JSON and structured AAD', () => {
    expect(canonicalJson({ z: 1, a: { y: true, x: null } })).toBe(
      '{"a":{"x":null,"y":true},"z":1}',
    );
    expect(new TextDecoder().decode(aadBytes({
      blobType: 'item-content',
      vaultId: 'vault-1',
      itemId: 'item-1',
      recordVersion: 2,
      secretVersion: 3,
      keyEpoch: 4,
    }))).toBe(
      '{"accountId":null,"blobType":"item-content","deviceId":null,"itemId":"item-1","keyEpoch":4,"protocol":"lm-e2ee-v1","recipientId":null,"recordVersion":2,"secretVersion":3,"vaultId":"vault-1"}',
    );
  });

  it('derives a deterministic 32-byte Argon2id13 key with the fixed profile', async () => {
    const salt = bytesFromHex('000102030405060708090a0b0c0d0e0f');
    const profile = await createKdfProfile(salt);
    expect(profile).toEqual({
      algorithm: 'argon2id13',
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      salt: 'AAECAwQFBgcICQoLDA0ODw',
      outputBytes: 32,
    });
    const first = await deriveMasterKey('correct horse battery staple', profile);
    const second = await deriveMasterKey('correct horse battery staple', profile);
    expect(first).toEqual(second);
    expect(first).toHaveLength(32);
    expect(hexFromBytes(first)).toBe(
      '0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e',
    );
    first.fill(0);
    second.fill(0);
  });

  it('matches RFC 8032 Ed25519 test vector 1', async () => {
    const seed = bytesFromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const pair = await generateSigningKeyPair(seed);
    const publicKey = await fromBase64Url(pair.publicKey);
    expect(hexFromBytes(publicKey)).toBe(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    );
    const signature = await signBytes(new Uint8Array(), pair.privateKey);
    const signatureBytes = await fromBase64Url(signature);
    expect(hexFromBytes(signatureBytes)).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
    expect(await verifyBytes(signature, new Uint8Array(), pair.publicKey)).toBe(true);
    pair.privateKey.fill(0);
    publicKey.fill(0);
    signatureBytes.fill(0);
  });

  it('rejects wrong AAD and tampered XChaCha20 ciphertext', async () => {
    const crypto = await sodiumReady();
    const key = crypto.randombytes_buf(32);
    const context = {
      blobType: 'item-content' as const,
      vaultId: 'vault-1',
      itemId: 'item-1',
      recordVersion: 1,
      secretVersion: 1,
      keyEpoch: 1,
    };
    const plaintext = new TextEncoder().encode('password-canary');
    const blob = await encryptBytes(key, plaintext, context);
    expect(blob).toMatchObject({ suite: 'lm-e2ee-v1', aadVersion: 1 });
    expect(new TextDecoder().decode(await decryptBytes(key, blob, context))).toBe('password-canary');
    await expect(decryptBytes(key, blob, { ...context, itemId: 'item-2' })).rejects.toMatchObject({
      code: 'authentication_failed',
    });
    await expect(
      decryptBytes(key, { ...blob, ciphertext: mutateBase64Url(blob.ciphertext) }, context),
    ).rejects.toBeInstanceOf(E2eeError);
    key.fill(0);
    plaintext.fill(0);
  });

  it('decrypts the fixed XChaCha20-Poly1305 structured-AAD vector', async () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    const plaintext = await decryptBytes(
      key,
      {
        suite: 'lm-e2ee-v1',
        aadVersion: 1,
        nonce: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3',
        ciphertext: 'UDAgqltBcehM0SKdeVPABFPYQ3waK1O2de2SPcs',
      },
      {
        blobType: 'item-content',
        vaultId: 'vault-vector',
        itemId: 'item-vector',
        recordVersion: 1,
        secretVersion: 1,
        keyEpoch: 1,
      },
    );
    expect(new TextDecoder().decode(plaintext)).toBe('Mima vector 1');
    key.fill(0);
    plaintext.fill(0);
  });

  it('signs a session- and device-bound unlock challenge', async () => {
    const pair = await generateSigningKeyPair();
    const challenge = await createUnlockChallenge({
      challengeId: 'challenge-1',
      accountId: 'user-1',
      deviceId: 'device-1',
      sessionId: 'session-1',
      issuedAt: '2026-07-18T10:00:00.000Z',
      expiresAt: '2026-07-18T10:05:00.000Z',
    });
    const signed = await signUnlockChallenge(challenge, pair.privateKey);
    expect(await verifyUnlockChallenge(signed, pair.publicKey)).toBe(true);
    expect(
      await verifyUnlockChallenge({ ...signed, sessionId: 'other-session' }, pair.publicKey),
    ).toBe(false);
    pair.privateKey.fill(0);
  });

  it('round-trips base64url without padding', async () => {
    const original = bytesFromHex('fffefdfcfbfa00');
    const encoded = await toBase64Url(original);
    expect(encoded).not.toContain('=');
    expect(await fromBase64Url(encoded)).toEqual(original);
  });
});
