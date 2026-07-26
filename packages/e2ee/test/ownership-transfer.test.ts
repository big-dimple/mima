import { describe, expect, it } from 'vitest';
import {
  ownershipTransferAcceptanceDigest,
  signVaultKeyPossession,
  vaultKeyPossessionPublicKey,
  verifyVaultKeyPossession,
} from '../src/ownership-transfer.ts';

const EVIDENCE = {
  transferId: '11111111-1111-4111-8111-111111111111',
  vaultId: '22222222-2222-4222-8222-222222222222',
  keyEpoch: 7,
  envelopeTaskId: '33333333-3333-4333-8333-333333333333',
  fromOwnerUserId: 'user:old-owner',
  toOwnerUserId: 'user:new-owner',
  expectedAccessGeneration: 7,
  actorDeviceId: '44444444-4444-4444-8444-444444444444',
  idempotencyKey: '55555555-5555-4555-8555-555555555555',
  completedEnvelopeId: '66666666-6666-4666-8666-666666666666',
  envelopeCiphertextDigest: 'ZmFrZS1lbmNyeXB0ZWQtZW52ZWxvcGUtZGlnZXN0',
};

const KEYS = {
  metadataKey: Uint8Array.from({ length: 32 }, (_, index) => index),
  contentKey: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
};

describe('ownership transfer acceptance evidence', () => {
  it('has a stable SHA-256 vector and binds every authorization field', async () => {
    const digest = await ownershipTransferAcceptanceDigest(EVIDENCE);
    expect(digest).toBe('WE1BBiMQTsl-UzwrAV0XuJ4kMDDx4tDSqj1QysdnTGs');

    for (const mutation of [
      { transferId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
      { keyEpoch: 8 },
      { envelopeTaskId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
      { expectedAccessGeneration: 8 },
      { actorDeviceId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' },
      { idempotencyKey: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' },
      { completedEnvelopeId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' },
      { envelopeCiphertextDigest: 'dGFtcGVyZWQ' },
    ]) {
      expect(await ownershipTransferAcceptanceDigest({ ...EVIDENCE, ...mutation })).not.toBe(digest);
    }
  });

  it('derives a stable epoch key and proves possession of both vault keys', async () => {
    const publicKey = await vaultKeyPossessionPublicKey(KEYS, {
      vaultId: EVIDENCE.vaultId,
      keyEpoch: EVIDENCE.keyEpoch,
    });
    const signature = await signVaultKeyPossession(KEYS, EVIDENCE);

    expect(publicKey).toBe('_3v4LwY5DBWhMb9lUHxKKHDCfZ_HFy8la7LT-q972tg');
    expect(signature).toBe(
      'zpUkWBqlpMxIhX2gZSPpOSxcuDt9n6dQaWMDm8VgD3PEP7Cj1-IgMYwBbPnD9fgAPg0L8JFmdubNFvQMI07uDw',
    );
    expect(await verifyVaultKeyPossession(signature, publicKey, EVIDENCE)).toBe(true);

    const wrongContentKey = { ...KEYS, contentKey: Uint8Array.from(KEYS.contentKey) };
    wrongContentKey.contentKey[0] = wrongContentKey.contentKey[0]! ^ 1;
    const wrongPublicKey = await vaultKeyPossessionPublicKey(wrongContentKey, {
      vaultId: EVIDENCE.vaultId,
      keyEpoch: EVIDENCE.keyEpoch,
    });
    expect(await verifyVaultKeyPossession(signature, wrongPublicKey, EVIDENCE)).toBe(false);

    for (const mutation of [
      { keyEpoch: EVIDENCE.keyEpoch + 1 },
      { completedEnvelopeId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
      { envelopeCiphertextDigest: 'dGFtcGVyZWQ' },
    ]) {
      expect(await verifyVaultKeyPossession(signature, publicKey, { ...EVIDENCE, ...mutation })).toBe(false);
    }
  });
});
