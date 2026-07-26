import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { generateSigningKeyPair, signBytes, type SigningKeyPair } from '@mima/e2ee';
import {
  extensionSessions,
  sessionUnlockChallenges,
  userCryptoProfiles,
  userDevices,
} from '../../src/db/schema.ts';
import { hashToken } from '../../src/plugins/auth.ts';
import { retainExtensionSessionHandoff } from '../../src/services/extension-sessions.ts';
import { freshStrictTestApp, login } from './helpers.ts';

let app: FastifyInstance;
let userId: string;
let deviceId: string;
let otherDeviceId: string;
let signingKeyPair: SigningKeyPair;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_extension_session_handoff');
  userId = (await login(app, 'bob')).userId;
  deviceId = randomUUID();
  otherDeviceId = randomUUID();
  signingKeyPair = await generateSigningKeyPair();
  await app.ctx.db.insert(userDevices).values([
    extensionDevice(deviceId, userId, Buffer.from(signingKeyPair.publicKey, 'base64url')),
    extensionDevice(otherDeviceId, userId),
  ]);
  await app.ctx.db.insert(userCryptoProfiles).values({
    userId,
    kdfSalt: randomBytes(16),
    wrappedAccountKeyCiphertext: randomBytes(48),
    wrappedAccountKeyNonce: randomBytes(24),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    signingKeyFingerprint: `extension-session-handoff-profile-${randomUUID()}`,
  });
});

afterAll(async () => {
  signingKeyPair.privateKey.fill(0);
  await app.close();
});

describe('extension session handoff', () => {
  it('retains the current response session and one newest handoff session', async () => {
    const sessions = [
      sessionRow(deviceId, userId, 'oldest', new Date('2026-01-01T00:00:00.000Z')),
      sessionRow(deviceId, userId, 'middle', new Date('2026-01-01T00:00:01.000Z')),
      sessionRow(deviceId, userId, 'newest', new Date('2026-01-01T00:00:02.000Z')),
    ];
    await app.ctx.db.insert(extensionSessions).values(sessions);

    const retained = await app.ctx.db.transaction(
      (tx) => retainExtensionSessionHandoff(tx, deviceId, sessions[0]!.id),
    );

    expect(retained).toEqual([sessions[0]!.id, sessions[2]!.id]);
    const rows = await app.ctx.db.select({ id: extensionSessions.id })
      .from(extensionSessions)
      .where(eq(extensionSessions.deviceId, deviceId));
    expect(rows.map((row) => row.id).sort()).toEqual(
      [sessions[0]!.id, sessions[2]!.id].sort(),
    );
  });

  it('creates an unlock challenge from a durable extension session without an enrollment row', async () => {
    const token = 'challenge-without-enrollment';
    const session = sessionRow(deviceId, userId, token, new Date('2026-01-01T00:00:04.000Z'));
    await app.ctx.db.insert(extensionSessions).values(session);

    const response = await app.inject({
      method: 'POST',
      url: '/api/v2/extension/unlock-challenges',
      headers: { authorization: `Bearer ${token}` },
      payload: { deviceId },
    });

    expect(response.statusCode, response.body).toBe(200);
    const body = response.json() as { id: string; challenge: string };
    const challenge = (await app.ctx.db.select().from(sessionUnlockChallenges)
      .where(eq(sessionUnlockChallenges.id, body.id)))[0]!;
    expect(challenge.sessionId).toBeNull();
    expect(challenge.extensionSessionId).toBe(session.id);

    const signature = await signBytes(
      Buffer.from(body.challenge, 'base64url'),
      signingKeyPair.privateKey,
    );
    const completed = await app.inject({
      method: 'POST',
      url: '/api/v2/extension/crypto-unlock',
      headers: { authorization: `Bearer ${token}` },
      payload: { challengeId: body.id, deviceId, signature },
    });
    expect(completed.statusCode, completed.body).toBe(200);
    const consumed = (await app.ctx.db.select().from(sessionUnlockChallenges)
      .where(eq(sessionUnlockChallenges.id, body.id)))[0]!;
    expect(consumed.consumedAt).toBeInstanceOf(Date);
  });

  it('unpairing one bearer removes every handoff session for that device only', async () => {
    const activeToken = 'newest';
    const otherToken = 'other-device';
    await app.ctx.db.insert(extensionSessions).values(
      sessionRow(otherDeviceId, userId, otherToken, new Date('2026-01-01T00:00:03.000Z')),
    );

    const response = await app.inject({
      method: 'DELETE',
      url: '/api/v2/extension/session',
      headers: { authorization: `Bearer ${activeToken}` },
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(await app.ctx.db.select().from(extensionSessions)
      .where(eq(extensionSessions.deviceId, deviceId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(extensionSessions)
      .where(eq(extensionSessions.deviceId, otherDeviceId))).toHaveLength(1);
  });
});

function extensionDevice(id: string, targetUserId: string, signingPublicKey = randomBytes(32)) {
  return {
    id,
    userId: targetUserId,
    deviceType: 'extension' as const,
    status: 'active' as const,
    trustMethod: 'device_approval' as const,
    keyFingerprint: `extension-session-handoff-${id}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: signingPublicKey,
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  };
}

function sessionRow(
  targetDeviceId: string,
  targetUserId: string,
  token: string,
  createdAt: Date,
) {
  return {
    id: randomUUID(),
    tokenHash: hashToken(token),
    userId: targetUserId,
    deviceId: targetDeviceId,
    securityGeneration: 1,
    createdAt,
    expiresAt: new Date('2126-01-01T00:00:00.000Z'),
  };
}
