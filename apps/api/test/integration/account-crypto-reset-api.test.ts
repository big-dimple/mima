import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { AccountCryptoResetRequest, UserCryptoProfile } from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import {
  sessions,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
} from '../../src/db/schema.ts';
import { authed, freshTestApp, key, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let target: TestSession;
let otherTargetSession: TestSession;
let adminOne: TestSession;
let adminTwo: TestSession;

beforeAll(async () => {
  app = await freshTestApp('mima_test_account_crypto_reset_api');
  target = await login(app, 'bob');
  adminOne = await login(app, 'alice');
  adminTwo = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: adminOne.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: adminTwo.userId, role: 'platform-admin', assignedBy: 'test' },
  ]).onConflictDoNothing();
});

afterAll(async () => {
  await app.close();
});

describe('account crypto reset API', () => {
  it('requires two admins and atomically replaces profile/device while revoking old sessions', async () => {
    const oldKeyring = new E2eeKeyring();
    const setup = await oldKeyring.setup('old correct horse battery staple', {
      accountId: target.userId,
      deviceId: crypto.randomUUID(),
      deviceName: 'Old browser',
      platform: 'test',
    });
    const profileResponse = await app.inject({
      method: 'POST',
      url: '/api/v2/crypto/profile',
      ...authed(target),
      payload: setup.request,
    });
    expect(profileResponse.statusCode).toBe(201);
    const profile = profileResponse.json() as UserCryptoProfile;
    otherTargetSession = await login(app, 'bob');
    expect((await app.inject({ method: 'POST', url: '/api/session/lock', ...authed(target) })).statusCode).toBe(200);

    const candidateKeyring = new E2eeKeyring();
    const candidate = await candidateKeyring.prepareAccountCryptoReset(
      'new correct horse battery staple',
      profile,
      crypto.randomUUID(),
    );
    const create = await app.inject({
      method: 'POST',
      url: '/api/v2/account-crypto-resets',
      ...authed(target),
      payload: candidate.request,
    });
    expect(create.statusCode).toBe(201);
    let reset = create.json() as AccountCryptoResetRequest;
    expect(reset.status).toBe('pending');

    const selfApproval = await app.inject({
      method: 'POST',
      url: `/api/v2/account-crypto-resets/${reset.id}/approve`,
      ...authed(target),
      payload: { idempotencyKey: key(), requestDigest: reset.requestDigest },
    });
    expect(selfApproval.statusCode).toBe(403);

    for (const [index, admin] of [adminOne, adminTwo].entries()) {
      const approval = await app.inject({
        method: 'POST',
        url: `/api/v2/account-crypto-resets/${reset.id}/approve`,
        ...authed(admin),
        payload: { idempotencyKey: key(), requestDigest: reset.requestDigest },
      });
      expect(approval.statusCode).toBe(200);
      reset = approval.json() as AccountCryptoResetRequest;
      expect(reset.status).toBe(index === 0 ? 'pending' : 'approved');
    }

    const activation = await candidateKeyring.prepareAccountCryptoResetActivation(target.userId, reset);
    const activated = await app.inject({
      method: 'POST',
      url: `/api/v2/account-crypto-resets/${reset.id}/activate`,
      ...authed(target),
      payload: activation.request,
    });
    expect(activated.statusCode, activated.body).toBe(200);
    const body = activated.json() as {
      request: AccountCryptoResetRequest;
      profile: UserCryptoProfile;
      device: { id: string; keyVersion: number };
      revokedDeviceCount: number;
    };
    expect(body.request.status).toBe('activated');
    expect(body.profile.keyVersion).toBe(2);
    expect(body.device.id).toBe(candidate.deviceBundle.deviceId);
    expect(body.device.keyVersion).toBe(2);
    expect(body.revokedDeviceCount).toBe(1);

    const profiles = await app.ctx.db.select().from(userCryptoProfiles)
      .where(eq(userCryptoProfiles.userId, target.userId));
    expect(profiles).toHaveLength(1);
    expect(profiles[0]!.cryptoGeneration).toBe(2);
    const activeDevices = await app.ctx.db.select().from(userDevices).where(and(
      eq(userDevices.userId, target.userId),
      eq(userDevices.status, 'active'),
    ));
    expect(activeDevices.map((device) => device.id)).toEqual([candidate.deviceBundle.deviceId]);
    const targetSessions = await app.ctx.db.select().from(sessions)
      .where(eq(sessions.userId, target.userId));
    expect(targetSessions).toHaveLength(1);
    expect(targetSessions[0]).toMatchObject({
      locked: false,
      unlockedDeviceId: candidate.deviceBundle.deviceId,
    });

    const revokedSession = await app.inject({
      method: 'GET',
      url: '/api/session',
      headers: { cookie: otherTargetSession.cookie },
    });
    expect(revokedSession.statusCode).toBe(401);
    await oldKeyring.lock();
    await candidateKeyring.commitAccountCryptoReset();
    await candidateKeyring.lock();
  });
});
