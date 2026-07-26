import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { enterpriseRecoveryCeremonyDigest } from '@mima/e2ee';
import {
  enterpriseRecoveryKeyApprovals,
  enterpriseRecoveryKeys,
  systemRoleAssignments,
  userCryptoProfiles,
  userDevices,
  users,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, key, login, type TestSession } from './helpers.ts';

const LOCAL_ADMIN_REQUIRED = '企业恢复公钥只能由本地授权的系统管理员操作';

let app: FastifyInstance;
let directoryGroupMember: TestSession;
let localAdminOne: TestSession;
let localAdminTwo: TestSession;
let stagedKeyId: string;
let stagedEvidenceDigest: string;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_enterprise_recovery_admin_source');
  directoryGroupMember = await login(app, 'alice');
  localAdminOne = await login(app, 'dave');
  localAdminTwo = await login(app, 'carol');
  await app.ctx.db.insert(systemRoleAssignments).values([
    { userId: localAdminOne.userId, role: 'platform-admin', assignedBy: 'test' },
    { userId: localAdminTwo.userId, role: 'platform-admin', assignedBy: 'test' },
  ]);
  await markRecoveryAdministratorsReady([directoryGroupMember, localAdminOne, localAdminTwo]);

  const staged = await recoveryKeyPayload(`staged-${randomUUID()}`);
  const row = (await app.ctx.db.insert(enterpriseRecoveryKeys).values({
    ceremonyId: staged.ceremonyId,
    keyFingerprint: staged.keyFingerprint,
    publicEncryptionKey: Buffer.from(staged.publicEncryptionKey, 'base64url'),
    ceremonyEvidenceDigest: Buffer.from(staged.ceremonyEvidenceDigest, 'base64url'),
    createdByUserId: localAdminOne.userId,
  }).returning())[0]!;
  await app.ctx.db.insert(enterpriseRecoveryKeyApprovals).values([
    {
      recoveryKeyId: row.id,
      approverUserId: localAdminOne.userId,
      ceremonyEvidenceDigest: Buffer.from(staged.ceremonyEvidenceDigest, 'base64url'),
    },
    {
      recoveryKeyId: row.id,
      approverUserId: localAdminTwo.userId,
      ceremonyEvidenceDigest: Buffer.from(staged.ceremonyEvidenceDigest, 'base64url'),
    },
  ]);
  stagedKeyId = row.id;
  stagedEvidenceDigest = staged.ceremonyEvidenceDigest;
});

afterAll(async () => {
  await app.close();
});

describe('enterprise recovery key local administrator boundary', () => {
  it('rejects a directory-group-only member with explicit 403 responses', async () => {
    const session = await app.inject({
      method: 'GET',
      url: '/api/session',
      headers: { cookie: directoryGroupMember.cookie },
    });
    expect(session.statusCode, session.body).toBe(200);
    expect((session.json() as { user: {
      isPlatformAdmin: boolean;
      isLocalPlatformAdmin: boolean;
    } }).user).toMatchObject({ isPlatformAdmin: false, isLocalPlatformAdmin: false });
    expect(await app.ctx.db.select().from(systemRoleAssignments).where(and(
      eq(systemRoleAssignments.userId, directoryGroupMember.userId),
      eq(systemRoleAssignments.role, 'platform-admin'),
    ))).toHaveLength(0);

    const registration = await recoveryKeyPayload(`legacy-register-${randomUUID()}`);
    const responses = await Promise.all([
      app.inject({
        method: 'GET',
        url: '/api/v2/recovery/readiness',
        headers: { cookie: directoryGroupMember.cookie },
      }),
      app.inject({
        method: 'POST',
        url: '/api/v2/recovery/key',
        ...authed(directoryGroupMember),
        payload: registration,
      }),
      app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${stagedKeyId}/approve`,
        ...authed(directoryGroupMember),
        payload: { idempotencyKey: key(), ceremonyEvidenceDigest: stagedEvidenceDigest },
      }),
      app.inject({
        method: 'POST',
        url: `/api/v2/recovery/keys/${stagedKeyId}/activate`,
        ...authed(directoryGroupMember),
        payload: { idempotencyKey: key(), ceremonyEvidenceDigest: stagedEvidenceDigest },
      }),
    ]);

    for (const response of responses) {
      expect(response.statusCode, response.body).toBe(403);
      expect((response.json() as { message: string }).message).toBe(LOCAL_ADMIN_REQUIRED);
    }
    expect(await app.ctx.db.select().from(enterpriseRecoveryKeys)
      .where(eq(enterpriseRecoveryKeys.ceremonyId, registration.ceremonyId))).toHaveLength(0);
    expect(await app.ctx.db.select().from(enterpriseRecoveryKeyApprovals).where(and(
      eq(enterpriseRecoveryKeyApprovals.recoveryKeyId, stagedKeyId),
      eq(enterpriseRecoveryKeyApprovals.approverUserId, directoryGroupMember.userId),
    ))).toHaveLength(0);
  });

  it('accepts register, approve and activate after a local role assignment is added', async () => {
    await app.ctx.db.insert(systemRoleAssignments).values({
      userId: directoryGroupMember.userId,
      role: 'platform-admin',
      assignedBy: 'test',
    });

    const session = await app.inject({
      method: 'GET',
      url: '/api/session',
      headers: { cookie: directoryGroupMember.cookie },
    });
    expect(session.statusCode, session.body).toBe(200);
    expect((session.json() as { user: { isLocalPlatformAdmin: boolean } })
      .user.isLocalPlatformAdmin).toBe(true);

    const registration = await recoveryKeyPayload(`local-register-${randomUUID()}`);
    const registered = await app.inject({
      method: 'POST',
      url: '/api/v2/recovery/key',
      ...authed(directoryGroupMember),
      payload: registration,
    });
    expect(registered.statusCode, registered.body).toBe(201);

    const readiness = await app.inject({
      method: 'GET',
      url: '/api/v2/recovery/readiness',
      headers: { cookie: directoryGroupMember.cookie },
    });
    expect(readiness.statusCode, readiness.body).toBe(200);
    expect(readiness.json()).toMatchObject({ ready: true, readyAdministratorCount: 3 });

    const approved = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/keys/${stagedKeyId}/approve`,
      ...authed(directoryGroupMember),
      payload: { idempotencyKey: key(), ceremonyEvidenceDigest: stagedEvidenceDigest },
    });
    expect(approved.statusCode, approved.body).toBe(200);

    const activated = await app.inject({
      method: 'POST',
      url: `/api/v2/recovery/keys/${stagedKeyId}/activate`,
      ...authed(directoryGroupMember),
      payload: { idempotencyKey: key(), ceremonyEvidenceDigest: stagedEvidenceDigest },
    });
    expect(activated.statusCode, activated.body).toBe(200);
    expect((activated.json() as { status: string }).status).toBe('active');
  });
});

async function markRecoveryAdministratorsReady(administrators: TestSession[]) {
  await app.ctx.db.update(users).set({ source: 'oidc' })
    .where(inArray(users.id, administrators.map((administrator) => administrator.userId)));
  await app.ctx.db.insert(userCryptoProfiles).values(administrators.map((administrator) => ({
    userId: administrator.userId,
    profileVersion: 1,
    cryptoGeneration: 1,
    kdfSalt: randomBytes(16),
    wrappedAccountKeyCiphertext: randomBytes(96),
    wrappedAccountKeyNonce: randomBytes(24),
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    signingKeyFingerprint: `admin-source-profile-${administrator.userId}-${randomUUID()}`,
  })));
  await app.ctx.db.insert(userDevices).values(administrators.map((administrator) => ({
    id: randomUUID(),
    userId: administrator.userId,
    deviceType: 'web' as const,
    status: 'active' as const,
    trustMethod: 'master_password' as const,
    deviceGeneration: 1,
    keyFingerprint: `admin-source-device-${administrator.userId}-${randomUUID()}`,
    publicEncryptionKey: randomBytes(32),
    publicSigningKey: randomBytes(32),
    certificatePayload: randomBytes(96),
    certificateSignature: randomBytes(64),
    activatedAt: new Date(),
  })));
}

async function recoveryKeyPayload(ceremonyId: string) {
  const publicKey = randomBytes(32);
  const publicEncryptionKey = publicKey.toString('base64url');
  const keyFingerprint = createHash('sha256').update(publicKey).digest('base64url');
  return {
    ceremonyId,
    publicEncryptionKey,
    keyFingerprint,
    threshold: 2 as const,
    shareCount: 3 as const,
    ceremonyEvidenceDigest: await enterpriseRecoveryCeremonyDigest({
      ceremonyId,
      publicKey: publicEncryptionKey,
      publicKeyFingerprint: keyFingerprint,
    }),
  };
}
