import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import {
  enterpriseRecoveryCases,
  enterpriseRecoveryKeys,
  systemRoleAssignments,
  userCryptoProfiles,
} from '../../src/db/schema.ts';
import { authed, freshTestApp, key, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let administrator: TestSession;
let target: TestSession;
let recoveryKeyId: string;

beforeAll(async () => {
  app = await freshTestApp('mima_test_enterprise_recovery_case_expiry');
  administrator = await login(app, 'alice');
  const secondAdministrator = await login(app, 'dave');
  target = await login(app, 'bob');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: administrator.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: secondAdministrator.userId, role: 'platform-admin', assignedBy: 'test' },
  ]);
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
  const recoveryPublicKey = randomBytes(32);
  const recoveryKey = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: `expiry-${randomUUID()}`,
    keyFingerprint: createHash('sha256').update(recoveryPublicKey).digest('base64url'),
    publicEncryptionKey: recoveryPublicKey,
    status: 'active',
    ceremonyEvidenceDigest: randomBytes(32),
    createdByUserId: administrator.userId,
  }).returning())[0]!;
  recoveryKeyId = recoveryKey.id;
});

afterAll(async () => {
  await app.close();
});

describe('enterprise recovery case terminal transitions', () => {
  it('expires an unfinished case without blocking the workspace or a new request', async () => {
    const now = Date.now();
    const expiredCaseId = randomUUID();
    await app.ctx.db.insert(enterpriseRecoveryCases).values({
      id: expiredCaseId,
      kind: 'forgot_password',
      targetUserId: target.userId,
      recoveryKeyId,
      createdByUserId: administrator.userId,
      createdAt: new Date(now - 25 * 60 * 60_000),
      expiresAt: new Date(now - 60 * 60_000),
    });

    const workspace = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/workspace',
      ...authed(administrator),
    });
    expect(workspace.statusCode, workspace.body).toBe(200);

    const listed = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/cases',
      ...authed(administrator),
    });
    expect(listed.statusCode, listed.body).toBe(200);
    expect(listed.json()).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: expiredCaseId, status: 'expired', lastErrorCode: 'case_expired' }),
    ]));
    const expired = (await app.ctx.db.select().from(enterpriseRecoveryCases)
      .where(eq(enterpriseRecoveryCases.id, expiredCaseId)).limit(1))[0]!;
    expect(expired.expiredAt).toBeInstanceOf(Date);

    const created = await app.inject({
      method: 'POST',
      url: '/api/v2/recovery/cases',
      ...authed(administrator),
      payload: {
        idempotencyKey: key(),
        kind: 'forgot_password',
        targetUserId: target.userId,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    expect(created.json()).toMatchObject({ status: 'waiting_for_target' });

    const createdCaseId = (created.json() as { id: string }).id;
    const cancelled = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/cases/${createdCaseId}/cancel`,
      ...authed(administrator),
      payload: { idempotencyKey: key(), caseDigest: null },
    });
    expect(cancelled.statusCode, cancelled.body).toBe(200);
    expect(cancelled.json()).toMatchObject({ status: 'cancelled', lastErrorCode: 'case_cancelled' });
  });
});
