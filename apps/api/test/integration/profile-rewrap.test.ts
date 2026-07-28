import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { UnlockChallenge, UserCryptoProfile } from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import { auditEvents, syncEvents, userCryptoProfiles } from '../../src/db/schema.ts';
import type { SyncEventRow } from '../../src/services/bus.ts';
import { verifyAuditChain } from '../../src/services/audit.ts';
import {
  TEST_API_HOST,
  authed,
  freshStrictTestApp,
  login,
  testServerOrigin,
  type TestSession,
} from './helpers.ts';

let app: FastifyInstance;
let session: TestSession;
let origin: string;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_profile_rewrap');
  await app.listen({ host: TEST_API_HOST, port: 0 });
  const address = app.server.address();
  origin = testServerOrigin(typeof address === 'object' && address ? address.port : 0);
  session = await login(app, 'bob');
});

afterAll(async () => {
  await app.close();
});

describe('main-password profile rewrap', () => {
  it('atomically updates the wrap, audit chain, and targeted sync event', async () => {
    const keyring = new E2eeKeyring();
    const setup = await keyring.setup('old correct horse battery staple', {
      accountId: session.userId,
      deviceId: crypto.randomUUID(),
      deviceName: 'Primary browser',
      platform: 'integration:test',
    });
    const create = await app.inject({
      method: 'POST',
      url: '/api/v2/crypto/profile',
      ...authed(session),
      payload: setup.request,
    });
    expect(create.statusCode, create.body).toBe(201);
    await expect(verifyAuditChain(app.ctx.db, app.ctx.audit)).resolves.toMatchObject({
      headId: expect.any(Number),
      anchorId: expect.any(Number),
    });
    const profile = create.json() as UserCryptoProfile;
    const request = await keyring.prepareMasterPasswordChange(
      'old correct horse battery staple',
      'new correct horse battery staple',
      profile,
    );
    const published: SyncEventRow[] = [];
    const unsubscribe = app.ctx.bus.subscribe((row) => published.push(row));

    const response = await app.inject({
      method: 'PUT',
      url: '/api/v2/crypto/profile',
      ...authed(session),
      payload: request,
    });
    unsubscribe();

    expect(response.statusCode, response.body).toBe(200);
    const updated = response.json() as UserCryptoProfile;
    expect(updated.profileVersion).toBe(2);
    expect(updated.keyVersion).toBe(profile.keyVersion);
    expect(updated.encryptionPublicKey).toBe(profile.encryptionPublicKey);
    expect(updated.signingPublicKey).toBe(profile.signingPublicKey);
    expect(updated.kdf.salt).toBe(request.kdf.salt);
    expect(updated.encryptedAccountBundle).toEqual(request.encryptedAccountBundle);

    expect(published).toHaveLength(1);
    expect(published[0]).toMatchObject({
      type: 'crypto.profile_rewrapped',
      vaultId: '00000000-0000-0000-0000-000000000000',
      itemId: null,
      payload: {
        userId: session.userId,
        actorDeviceId: setup.deviceId,
        profileVersion: 2,
      },
    });
    const [storedProfile, storedEvent, storedAudit] = await Promise.all([
      app.ctx.db.select().from(userCryptoProfiles)
        .where(eq(userCryptoProfiles.userId, session.userId)).limit(1),
      app.ctx.db.select().from(syncEvents)
        .where(eq(syncEvents.type, 'crypto.profile_rewrapped')).limit(1),
      app.ctx.db.select().from(auditEvents).where(and(
        eq(auditEvents.actorUserId, session.userId),
        eq(auditEvents.action, 'crypto.profile.rewrap'),
      )).limit(1),
    ]);
    expect(storedProfile[0]?.profileVersion).toBe(2);
    expect(storedEvent[0]?.payload).toEqual(published[0]?.payload);
    expect(storedAudit).toHaveLength(1);

    const otherSession = await login(app, 'alice');
    const otherKeyring = new E2eeKeyring();
    const otherSetup = await otherKeyring.setup('other correct horse battery staple', {
      accountId: otherSession.userId,
      deviceId: crypto.randomUUID(),
      deviceName: 'Other browser',
      platform: 'integration:test',
    });
    const otherCreate = await app.inject({
      method: 'POST',
      url: '/api/v2/crypto/profile',
      ...authed(otherSession),
      payload: otherSetup.request,
    });
    expect(otherCreate.statusCode, otherCreate.body).toBe(201);
    const [ownStream, otherStream] = await Promise.all([
      openEventStream(session),
      openEventStream(otherSession),
    ]);
    const ownEvent = await ownStream.waitFor((event) => event.type === 'crypto.profile_rewrapped');
    const otherEvent = await otherStream.waitFor((event) => event.type === 'sync.cursor');
    expect(ownEvent).toMatchObject({
      type: 'crypto.profile_rewrapped',
      actorDeviceId: setup.deviceId,
      profileVersion: 2,
    });
    expect(otherEvent).toEqual({ type: 'sync.cursor', cursor: ownEvent.cursor });
    await Promise.all([ownStream.close(), otherStream.close()]);
    await otherKeyring.lock();

    const replay = await app.inject({
      method: 'PUT',
      url: '/api/v2/crypto/profile',
      ...authed(session),
      payload: request,
    });
    expect(replay.statusCode).toBe(409);
    expect(await app.ctx.db.select().from(syncEvents)
      .where(eq(syncEvents.type, 'crypto.profile_rewrapped'))).toHaveLength(1);

    const lock = await app.inject({
      method: 'POST',
      url: '/api/session/lock',
      ...authed(session),
    });
    expect(lock.statusCode, lock.body).toBe(200);
    const challenge = await app.inject({
      method: 'POST',
      url: '/api/v2/session/unlock-challenge',
      ...authed(session),
      payload: { deviceId: setup.deviceId },
    });
    expect(challenge.statusCode, challenge.body).toBe(200);
    const complete = await app.inject({
      method: 'POST',
      url: '/api/v2/session/crypto-unlock',
      ...authed(session),
      payload: await keyring.signServerChallenge(challenge.json() as UnlockChallenge),
    });
    expect(complete.statusCode, complete.body).toBe(200);
    await expect(verifyAuditChain(app.ctx.db, app.ctx.audit)).resolves.toMatchObject({
      headId: expect.any(Number),
      anchorId: expect.any(Number),
    });
    await keyring.lock();
  });
});

async function openEventStream(target: TestSession): Promise<{
  waitFor: (predicate: (event: Record<string, unknown>) => boolean) => Promise<Record<string, unknown>>;
  close: () => Promise<void>;
}> {
  const trustedOrigin = app.ctx.webOrigins[0];
  if (!trustedOrigin) throw new Error('test requires one trusted web origin');
  const response = await fetch(`${origin}/api/v2/events?cursor=0`, {
    headers: { cookie: target.cookie, origin: trustedOrigin },
  });
  expect(response.status).toBe(200);
  expect(response.headers.get('access-control-allow-origin')).toBe(trustedOrigin);
  expect(response.headers.get('access-control-allow-credentials')).toBe('true');
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  return {
    waitFor: async (predicate) => {
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        const result = await reader.read();
        if (result.done) break;
        buffer += decoder.decode(result.value, { stream: true });
        const frames = buffer.split('\n\n');
        buffer = frames.pop() ?? '';
        for (const frame of frames) {
          const data = frame.split('\n')
            .filter((line) => line.startsWith('data:'))
            .map((line) => line.slice(5).trim())
            .join('\n');
          if (!data) continue;
          const event = JSON.parse(data) as Record<string, unknown>;
          if (predicate(event)) return event;
        }
      }
      throw new Error('timed out waiting for SSE event');
    },
    close: () => reader.cancel(),
  };
}
