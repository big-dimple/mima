import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  accountCryptoResetApprovals,
  accountCryptoResetRequests,
  systemRoleAssignments,
  userCryptoProfiles,
} from '../../src/db/schema.ts';
import { freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let target: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;
let ordinaryUser: TestSession;

beforeAll(async () => {
  app = await freshTestApp('mima_test_account_crypto_reset_db');
  target = await login(app, 'bob');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  ordinaryUser = await login(app, 'carol');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: adminOne.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: adminTwo.userId, role: 'platform-admin', assignedBy: 'test' },
  ]).onConflictDoNothing();
  await app.ctx.db.insert(userCryptoProfiles).values({
    userId: target.userId,
    profileVersion: 1,
    cryptoGeneration: 1,
    kdfSalt: randomBytes(16),
    wrappedAccountKeyCiphertext: randomBytes(96),
    wrappedAccountKeyNonce: randomBytes(24),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    signingKeyFingerprint: randomBytes(32).toString('base64url'),
  });
});

afterAll(async () => {
  await app.close();
});

describe('account crypto reset database approval guards', () => {
  it('requires two distinct platform admins and rejects self, duplicate, non-admin and expired approvals', async () => {
    const request = await insertResetRequest();
    await expect(app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: request.id,
      approverUserId: target.userId,
      requestDigest: request.requestDigest,
    })).rejects.toThrow();
    await expect(app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: request.id,
      approverUserId: ordinaryUser.userId,
      requestDigest: request.requestDigest,
    })).rejects.toThrow();

    await app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: request.id,
      approverUserId: adminOne.userId,
      requestDigest: request.requestDigest,
    });
    expect(await resetStatus(request.id)).toBe('pending');
    await expect(app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: request.id,
      approverUserId: adminOne.userId,
      requestDigest: request.requestDigest,
    })).rejects.toThrow();

    await app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: request.id,
      approverUserId: adminTwo.userId,
      requestDigest: request.requestDigest,
    });
    expect(await resetStatus(request.id)).toBe('approved');
    await app.ctx.db.insert(systemRoleAssignments).values({
      userId: ordinaryUser.userId,
      role: 'platform-admin',
      assignedBy: 'test',
    });
    await expect(app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: request.id,
      approverUserId: ordinaryUser.userId,
      requestDigest: request.requestDigest,
    })).rejects.toThrow();
    await expect(app.ctx.db.update(accountCryptoResetRequests).set({
      status: 'activated',
      activatedAt: new Date(),
    }).where(eq(accountCryptoResetRequests.id, request.id))).rejects.toThrow();

    await app.ctx.db.update(accountCryptoResetRequests).set({
      status: 'cancelled',
      cancelledAt: new Date(),
    }).where(eq(accountCryptoResetRequests.id, request.id));
    const expired = await insertResetRequest({
      createdAt: new Date(Date.now() - 2 * 60 * 60_000),
      expiresAt: new Date(Date.now() - 60 * 60_000),
    });
    await expect(app.ctx.db.insert(accountCryptoResetApprovals).values({
      requestId: expired.id,
      approverUserId: adminOne.userId,
      requestDigest: expired.requestDigest,
    })).rejects.toThrow();
    const replacement = await insertResetRequest();
    expect(await resetStatus(expired.id)).toBe('expired');
    expect(await resetStatus(replacement.id)).toBe('pending');
  });
});

async function insertResetRequest(times: { createdAt?: Date; expiresAt?: Date } = {}) {
  const profile = (await app.ctx.db.select().from(userCryptoProfiles)
    .where(eq(userCryptoProfiles.userId, target.userId)).limit(1))[0]!;
  const createdAt = times.createdAt ?? new Date();
  const expiresAt = times.expiresAt ?? new Date(createdAt.getTime() + 60 * 60_000);
  return (await app.ctx.db.insert(accountCryptoResetRequests).values({
    targetUserId: target.userId,
    expectedProfileVersion: profile.profileVersion,
    expectedCryptoGeneration: profile.cryptoGeneration,
    newCryptoGeneration: profile.cryptoGeneration + 1,
    kdfMemoryKib: 65_536,
    kdfIterations: 3,
    kdfParallelism: 1,
    kdfSalt: randomBytes(16),
    wrappedAccountKeyCiphertext: randomBytes(96),
    wrappedAccountKeyNonce: randomBytes(24),
    publicEncryptionKey: differentKey(profile.publicEncryptionKey),
    publicSigningKey: differentKey(profile.publicSigningKey),
    signingKeyFingerprint: randomBytes(32).toString('base64url'),
    candidateDeviceId: randomUUID(),
    candidateDeviceType: 'web',
    candidateDeviceEncryptionPublicKey: randomBytes(32),
    candidateDeviceSigningPublicKey: randomBytes(32),
    candidateDeviceKeyFingerprint: randomBytes(32).toString('base64url'),
    candidateDeviceCertificatePayload: randomBytes(96),
    candidateDeviceCertificateSignature: randomBytes(64),
    candidateUserProof: randomBytes(64),
    requestDigest: randomBytes(32),
    createdByUserId: target.userId,
    createdAt,
    expiresAt,
  }).returning())[0]!;
}

async function resetStatus(requestId: string) {
  return (await app.ctx.db.select({ status: accountCryptoResetRequests.status })
    .from(accountCryptoResetRequests)
    .where(eq(accountCryptoResetRequests.id, requestId)).limit(1))[0]?.status;
}

function differentKey(current: Uint8Array): Buffer {
  let candidate = randomBytes(32);
  while (candidate.equals(Buffer.from(current))) candidate = randomBytes(32);
  return candidate;
}
