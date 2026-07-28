import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  deviceEnrollmentRequests,
  extensionPairingCodes,
  sessions,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let session: TestSession;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_extension_pairing_status');
  session = await login(app, 'bob');
});

afterAll(async () => {
  if (app) await app.close();
});

describe('extension pairing status correlation', () => {
  it('tracks the exact code and lets a claimed enrollment outlive the short code timer', async () => {
    const sourceSession = (await app.ctx.db.select().from(sessions)
      .where(eq(sessions.userId, session.userId)).limit(1))[0]!;
    const waitingCode = 'WAITING2';
    const claimedCode = 'CLAIMED2';
    const enrollment = (await app.ctx.db.insert(deviceEnrollmentRequests).values({
      userId: session.userId,
      requestedBySessionId: sourceSession.id,
      requestedDeviceId: randomUUID(),
      deviceType: 'extension',
      requestingKeyFingerprint: '1111 2222 3333 4444 5555 6666 7777 8888',
      requestingEncryptionPublicKey: randomBytes(32),
      requestingSigningPublicKey: randomBytes(32),
      joinChannelPublicKey: randomBytes(32),
      challengeHash: randomBytes(32),
      expiresAt: new Date(Date.now() + 5 * 60_000),
    }).returning())[0]!;
    await app.ctx.db.insert(extensionPairingCodes).values([
      {
        code: waitingCode,
        userId: session.userId,
        sessionId: sourceSession.id,
        expiresAt: new Date(Date.now() + 120_000),
      },
      {
        code: claimedCode,
        userId: session.userId,
        sessionId: sourceSession.id,
        enrollmentRequestId: enrollment.id,
        usedAt: new Date(),
        expiresAt: new Date(Date.now() - 1_000),
      },
    ]);

    const waiting = await app.inject({
      method: 'POST',
      url: '/api/v2/extension/pairing/status',
      ...authed(session),
      payload: { code: waitingCode.toLowerCase() },
    });
    expect(waiting.statusCode, waiting.body).toBe(200);
    expect(waiting.json()).toEqual({ status: 'waiting', enrollment: null });

    const claimed = await app.inject({
      method: 'POST',
      url: '/api/v2/extension/pairing/status',
      ...authed(session),
      payload: { code: claimedCode },
    });
    expect(claimed.statusCode, claimed.body).toBe(200);
    expect(claimed.json()).toMatchObject({
      status: 'claimed',
      enrollment: {
        enrollmentId: enrollment.id,
        fingerprint: enrollment.requestingKeyFingerprint,
        status: 'pending',
      },
    });
  });

  it('does not expose another browser session pairing code', async () => {
    const otherSession = await login(app, 'bob');
    const sourceSession = (await app.ctx.db.select().from(sessions)
      .where(eq(sessions.csrfToken, otherSession.csrf)).limit(1))[0]!;
    const code = 'OTHER222';
    await app.ctx.db.insert(extensionPairingCodes).values({
      code,
      userId: session.userId,
      sessionId: sourceSession.id,
      expiresAt: new Date(Date.now() + 120_000),
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/v2/extension/pairing/status',
      ...authed(session),
      payload: { code },
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toEqual({ status: 'expired', enrollment: null });
  });
});
