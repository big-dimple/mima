import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { LegacyKeyRetirementResponse } from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import { systemRoleAssignments, vaults } from '../../src/db/schema.ts';
import { authed, freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let alice: TestSession;
let dave: TestSession;
let aliceKeyring: E2eeKeyring;
let daveKeyring: E2eeKeyring;

beforeAll(async () => {
  app = await freshTestApp('mima_test_legacy_key_retirement_fresh');
  alice = await login(app, 'alice');
  dave = await login(app, 'dave');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: alice.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: dave.userId, role: 'platform-admin', assignedBy: 'test' },
  ]);
  aliceKeyring = await setupCrypto(alice, 'alice fresh install password');
  daveKeyring = await setupCrypto(dave, 'dave fresh install password');
  await app.ctx.db.update(vaults).set({ name: '' });
});

afterAll(async () => {
  await Promise.all([aliceKeyring.lock(), daveKeyring.lock()]);
  await app.close();
});

describe('fresh-install legacy KEK status', () => {
  it('requires the same dual-approved evidence before marking legacy KEK retirement not applicable', async () => {
    const create = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement',
      ...authed(alice),
      payload: await aliceKeyring.createLegacyKeyRetirementIntent(alice.userId, {
        reasonCode: 'fresh_install',
        retireBy: null,
        copyInventoryDigest: randomBytes(32).toString('base64url'),
        copyManifestDigest: randomBytes(32).toString('base64url'),
        kekFingerprintDigest: null,
      }),
    });
    expect(create.statusCode, create.body).toBe(201);
    let plan = create.json() as LegacyKeyRetirementResponse;
    const evidenceDigest = randomBytes(32).toString('base64url');
    for (const [session, keyring] of [[alice, aliceKeyring], [dave, daveKeyring]] as const) {
      const approval = await app.inject({
        method: 'POST',
        url: '/api/v2/legacy-key-retirement/approve',
        ...authed(session),
        payload: await keyring.approveLegacyKeyRetirementIntent(
          session.userId,
          plan.planDigest!,
          evidenceDigest,
        ),
      });
      expect(approval.statusCode, approval.body).toBe(200);
      plan = approval.json() as LegacyKeyRetirementResponse;
    }
    expect(plan.status).toBe('approved');
    const complete = await app.inject({
      method: 'POST',
      url: '/api/v2/legacy-key-retirement/complete',
      ...authed(alice),
      payload: await aliceKeyring.completeLegacyKeyRetirementIntent(
        alice.userId,
        plan.planDigest!,
        evidenceDigest,
      ),
    });
    expect(complete.statusCode, complete.body).toBe(200);
    expect(complete.json()).toMatchObject({
      status: 'not_applicable',
      reasonCode: 'fresh_install',
      legacyKeyState: 'not_applicable',
      migratedJobCount: 0,
      evidenceJobCount: 0,
    });
  });
});

async function setupCrypto(session: TestSession, mainPassword: string) {
  const keyring = new E2eeKeyring();
  const setup = await keyring.setup(mainPassword, {
    accountId: session.userId,
    deviceId: crypto.randomUUID(),
    deviceName: 'Fresh install retirement test',
    platform: 'test',
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(session),
    payload: setup.request,
  });
  expect(response.statusCode, response.body).toBe(201);
  return keyring;
}
