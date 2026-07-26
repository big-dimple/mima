import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as oidc from 'openid-client';
import { AuthentikOidcAuthenticator } from '../../src/auth/oidc.ts';
import type { OidcTransactionStore } from '../../src/auth/transaction-store.ts';

vi.mock('openid-client', () => ({
  calculatePKCECodeChallenge: vi.fn(async () => 'challenge'),
  buildAuthorizationUrl: vi.fn(() => new URL('https://auth.example.test/authorize')),
  discovery: vi.fn(async () => ({})),
  randomNonce: vi.fn(() => 'nonce'),
  randomPKCECodeVerifier: vi.fn(() => 'verifier'),
  randomState: vi.fn(() => 'state'),
}));

const directories: string[] = [];

afterEach(() => {
  vi.clearAllMocks();
  while (directories.length > 0) rmSync(directories.pop()!, { recursive: true, force: true });
});

describe('OIDC form-post callback', () => {
  it('requests form_post so authorization codes never enter the callback URL', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'mima-oidc-form-post-'));
    directories.push(directory);
    const secretFile = join(directory, 'client-secret');
    writeFileSync(secretFile, 'test-client-secret\n', { mode: 0o600 });
    const transactions = { create: vi.fn(async () => undefined) } as unknown as OidcTransactionStore;
    const authenticator = new AuthentikOidcAuthenticator(transactions, {
      issuer: 'https://auth.example.test/application/o/mima/',
      clientId: 'mima',
      clientSecretFile: secretFile,
      redirectUri: 'https://mima.example.test/api/auth/oidc/callback',
    });

    await authenticator.beginLogin();

    expect(oidc.buildAuthorizationUrl).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      response_type: 'code',
      response_mode: 'form_post',
      code_challenge_method: 'S256',
    }));
    expect(transactions.create).toHaveBeenCalledWith('state', expect.objectContaining({
      codeVerifier: 'verifier',
      nonce: 'nonce',
    }));
  });
});
