import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { DirectoryUnavailableError } from '../../src/auth/directory.ts';
import { LdapDirectoryService, type LdapConnector, type LdapOptions } from '../../src/auth/ldap.ts';
import { freshTestApp } from './helpers.ts';

let app: FastifyInstance;

beforeAll(async () => {
  app = await freshTestApp('mima_test_ldap_directory_gate');
});

afterAll(async () => {
  await app.close();
});

describe('LDAP directory bootstrap gate', () => {
  it('requires an explicit successful CLI sync before serving or auto-applying the directory', async () => {
    const options: LdapOptions = {
      directoryId: 'test-ad',
      urls: ['ldaps://dc.example.test:636'],
      bindDn: 'CN=readonly,DC=example,DC=test',
      bindPasswordFile: '/not-used',
      baseDn: 'DC=example,DC=test',
      userFilter: '(objectClass=user)',
      loginAttribute: 'sAMAccountName',
      stableIdAttribute: 'objectGUID',
      displayNameAttribute: 'displayName',
      emailAttribute: 'mail',
      connectTimeoutMs: 1_000,
      operationTimeoutMs: 1_000,
      syncIntervalMs: 300_000,
      maxStaleMs: 1_800_000,
      pageSize: 500,
      maxDropPercent: 50,
    };
    const connector = {
      options,
      listUsers: () => Promise.reject(new Error('automatic first sync must not run')),
    } as unknown as LdapConnector;
    const directory = new LdapDirectoryService(app.ctx.db, connector);

    await expect(directory.listDirectory()).rejects.toBeInstanceOf(DirectoryUnavailableError);
  });
});
