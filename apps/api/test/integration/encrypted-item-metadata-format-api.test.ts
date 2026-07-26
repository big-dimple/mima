import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type {
  EncryptedItemMetadata,
  RotateEncryptedSecretRequest,
  UpdateEncryptedItemRequest,
  UserCryptoProfile,
} from '@mima/contracts';
import { E2eeKeyring } from '../../../../packages/client-core/src/e2ee-keyring.ts';
import { itemPayload } from '../../../../packages/client-core/src/e2ee-model.ts';
import {
  encryptedItemMetadataVersions,
  encryptedItemSecretVersions,
  items,
  vaults,
} from '../../src/db/schema.ts';
import { authed, freshStrictTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let session: TestSession;
let keyring: E2eeKeyring;
let profile: UserCryptoProfile;
let vaultId: string;

beforeAll(async () => {
  app = await freshStrictTestApp('mima_test_item_metadata_format');
  session = await login(app, 'bob');
  keyring = new E2eeKeyring();
  const setup = await keyring.setup('metadata format integration password', {
    accountId: session.userId,
    deviceId: randomUUID(),
    deviceName: 'Metadata format integration browser',
    platform: 'integration:test',
  });
  const profileResponse = await app.inject({
    method: 'POST',
    url: '/api/v2/crypto/profile',
    ...authed(session),
    payload: setup.request,
  });
  expect(profileResponse.statusCode, profileResponse.body).toBe(201);
  profile = profileResponse.json() as UserCryptoProfile;

  const personalVault = (await app.ctx.db.select().from(vaults).where(and(
    eq(vaults.kind, 'personal'),
    eq(vaults.ownerUserId, session.userId),
  )).limit(1))[0]!;
  vaultId = personalVault.id;
  const initialize = await keyring.initializeVault(
    session.userId,
    vaultId,
    '个人密码库',
    profile,
    null,
  );
  const initializeResponse = await app.inject({
    method: 'POST',
    url: `/api/v2/vaults/${vaultId}/initialize`,
    ...authed(session),
    payload: initialize,
  });
  expect(initializeResponse.statusCode, initializeResponse.body).toBe(200);
});

afterAll(async () => {
  await keyring.lock();
  await app.close();
});

describe('encrypted item metadata format gate', () => {
  it('rejects signed legacy update and rotation requests without changing ciphertext state', async () => {
    const create = await keyring.encryptCreate(session.userId, vaultId, {
      kind: 'login',
      title: 'Tencent sub-account',
      username: 'sub-account-user',
      origin: 'https://accounts.example.test',
      loginUrl: 'https://accounts.example.test/login/tenant/example-a',
      tags: [],
      favorite: false,
      sensitivity: 'medium',
      secretValue: 'initial-password',
    });
    const createResponse = await app.inject({
      method: 'POST',
      url: `/api/v2/vaults/${vaultId}/items`,
      ...authed(session),
      payload: create,
    });
    expect(createResponse.statusCode, createResponse.body).toBe(201);
    const createdRecord = createResponse.json() as EncryptedItemMetadata;
    const createdItem = await keyring.decryptMetadataRecord(createdRecord);

    const update = await keyring.encryptMetadataUpdate(session.userId, createdItem, {
      ...itemPayload(createdItem),
      title: 'Tencent sub-account updated',
    });
    const outdatedUpdate = await outdatedRequest('item.update_metadata', createdItem.id, update);
    const beforeOutdatedUpdate = await ciphertextState(createdItem.id);
    const outdatedUpdateResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/items/${createdItem.id}`,
      ...authed(session),
      payload: outdatedUpdate,
    });
    expect(outdatedUpdateResponse.statusCode, outdatedUpdateResponse.body).toBe(409);
    expect(await ciphertextState(createdItem.id)).toEqual(beforeOutdatedUpdate);

    const legacyUpdate = await legacyRequest('item.update_metadata', createdItem.id, update);
    const beforeUpdate = await ciphertextState(createdItem.id);
    const legacyUpdateResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/items/${createdItem.id}`,
      ...authed(session),
      payload: legacyUpdate,
    });
    expect(legacyUpdateResponse.statusCode, legacyUpdateResponse.body).toBe(409);
    expect(legacyUpdateResponse.json()).toMatchObject({
      code: 'metadata_format_outdated',
      message: '当前页面版本较旧，请刷新页面后重新编辑；系统尚未写入这次修改',
      currentVersion: 1,
    });
    expect(await ciphertextState(createdItem.id)).toEqual(beforeUpdate);

    const updateResponse = await app.inject({
      method: 'PATCH',
      url: `/api/v2/items/${createdItem.id}`,
      ...authed(session),
      payload: update,
    });
    expect(updateResponse.statusCode, updateResponse.body).toBe(200);
    const updatedItem = await keyring.decryptMetadataRecord(updateResponse.json() as EncryptedItemMetadata);
    expect(updatedItem.loginUrl).toBe(
      'https://accounts.example.test/login/tenant/example-a',
    );

    const rotation = await keyring.encryptRotation(session.userId, updatedItem, 'rotated-password');
    const legacyRotation = await legacyRequest('item.rotate_secret', updatedItem.id, rotation);
    const beforeRotation = await ciphertextState(updatedItem.id);
    const legacyRotationResponse = await app.inject({
      method: 'PUT',
      url: `/api/v2/items/${updatedItem.id}/secret`,
      ...authed(session),
      payload: legacyRotation,
    });
    expect(legacyRotationResponse.statusCode, legacyRotationResponse.body).toBe(409);
    expect(legacyRotationResponse.json()).toMatchObject({ currentVersion: 2 });
    expect(await ciphertextState(updatedItem.id)).toEqual(beforeRotation);

    const rotationResponse = await app.inject({
      method: 'PUT',
      url: `/api/v2/items/${updatedItem.id}/secret`,
      ...authed(session),
      payload: rotation,
    });
    expect(rotationResponse.statusCode, rotationResponse.body).toBe(200);
    const rotatedItem = await keyring.decryptMetadataRecord(rotationResponse.json() as EncryptedItemMetadata);
    expect(rotatedItem.loginUrl).toBe(updatedItem.loginUrl);
    expect(rotatedItem.version).toBe(3);
    expect(rotatedItem.secretVersion).toBe(3);
  });
});

async function legacyRequest<T extends UpdateEncryptedItemRequest | RotateEncryptedSecretRequest>(
  kind: 'item.update_metadata' | 'item.rotate_secret',
  itemId: string,
  request: T,
): Promise<Omit<T, 'metadataFormatVersion'>> {
  const { signature: _signature, metadataFormatVersion: _format, ...unsigned } = request;
  const signer = keyring as unknown as {
    signCommand(
      commandKind: string,
      userId: string,
      scope: { vaultId: string; itemId: string },
      body: object,
    ): Promise<string>;
  };
  return {
    ...unsigned,
    signature: await signer.signCommand(kind, session.userId, { vaultId, itemId }, unsigned),
  } as Omit<T, 'metadataFormatVersion'>;
}

async function outdatedRequest<T extends UpdateEncryptedItemRequest | RotateEncryptedSecretRequest>(
  kind: 'item.update_metadata' | 'item.rotate_secret',
  itemId: string,
  request: T,
): Promise<T> {
  const { signature: _signature, ...rest } = request;
  const unsigned = { ...rest, metadataFormatVersion: 3 as const };
  const signer = keyring as unknown as {
    signCommand(
      commandKind: string,
      userId: string,
      scope: { vaultId: string; itemId: string },
      body: object,
    ): Promise<string>;
  };
  return {
    ...unsigned,
    signature: await signer.signCommand(kind, session.userId, { vaultId, itemId }, unsigned),
  } as T;
}

async function ciphertextState(itemId: string) {
  const item = (await app.ctx.db.select({
    version: items.version,
    secretVersion: items.secretVersion,
  }).from(items).where(eq(items.id, itemId)).limit(1))[0]!;
  const metadata = await app.ctx.db.select({
    version: encryptedItemMetadataVersions.recordVersion,
    digest: encryptedItemMetadataVersions.ciphertextDigest,
  }).from(encryptedItemMetadataVersions).where(eq(encryptedItemMetadataVersions.itemId, itemId));
  const secrets = await app.ctx.db.select({
    version: encryptedItemSecretVersions.recordVersion,
    digest: encryptedItemSecretVersions.ciphertextDigest,
  }).from(encryptedItemSecretVersions).where(eq(encryptedItemSecretVersions.itemId, itemId));
  return {
    ...item,
    metadata: metadata.map((row) => ({ version: row.version, digest: row.digest.toString('hex') })),
    secrets: secrets.map((row) => ({ version: row.version, digest: row.digest.toString('hex') })),
  };
}
