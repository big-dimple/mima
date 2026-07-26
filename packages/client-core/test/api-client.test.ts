import { afterEach, describe, expect, it, vi } from 'vitest';
import { CSRF_HEADER, type AtomicCreateEncryptedVaultRequest } from '@mima/contracts';
import { ApiClient, ApiRequestError } from '../src/api-client.ts';
import { ZeroKnowledgeApiClient } from '../src/zero-knowledge-api-client.ts';

const directory = {
  users: [{ id: 'u-1', username: 'bob', displayName: 'Bob Li' }],
  groups: ['group:default/ops'],
  syncedAt: '2026-07-17T00:00:00.000Z',
};

describe('ApiClient directory cache', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('deduplicates in-flight requests and clears the session cache on logout', async () => {
    const fetcher = vi.fn().mockImplementation(async () =>
      new Response(JSON.stringify(directory), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetcher);
    const api = new ApiClient('https://mima.example.test');

    const [first, second] = await Promise.all([api.directory(), api.directory()]);
    expect(first).toEqual(directory);
    expect(second).toEqual(directory);
    expect(fetcher).toHaveBeenCalledOnce();

    await api.directory();
    expect(fetcher).toHaveBeenCalledOnce();

    api.setCsrfToken(null);
    await api.directory();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

describe('ZeroKnowledgeApiClient error boundary', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('strips a legacy plaintext currentItem from an error response', async () => {
    const canary = 'legacy-title-canary';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      statusCode: 409,
      error: 'Conflict',
      message: '版本冲突',
      currentVersion: 2,
      currentItem: { title: canary, username: canary },
    }), {
      status: 409,
      headers: { 'content-type': 'application/json' },
    })));
    const api = new ZeroKnowledgeApiClient('https://mima.example.test');

    try {
      await api.sendEncryptedCommand('PATCH', '/api/v2/items/item-id', { ciphertext: 'opaque' });
      throw new Error('request should have failed');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiRequestError);
      const requestError = error as ApiRequestError;
      expect(requestError.body).toEqual({
        statusCode: 409,
        error: 'Conflict',
        message: '版本冲突',
        currentVersion: 2,
      });
      expect(JSON.stringify(requestError.body)).not.toContain(canary);
    }
  });
});

describe.each([
  ['ApiClient', () => new ApiClient('https://mima.example.test')],
  ['ZeroKnowledgeApiClient', () => new ZeroKnowledgeApiClient('https://mima.example.test')],
])('%s team vault creation', (_name, createClient) => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends the complete client-generated encrypted vault in one request', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'vault-id' }), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetcher);
    const api = createClient();
    api.setCsrfToken('csrf-create-vault');

    const request = {
      idempotencyKey: 'create-vault-0001',
      vaultId: '11111111-1111-4111-8111-111111111111',
      epoch: 1,
      headerFormatVersion: 3,
      keyPossessionPublicKey: 'a',
      header: {
        vaultId: '11111111-1111-4111-8111-111111111111',
        version: 1,
        keyEpoch: 1,
        blob: { suite: 'lm-e2ee-v1', aadVersion: 1, nonce: 'a', ciphertext: 'b' },
      },
      envelopes: [{
        vaultId: '11111111-1111-4111-8111-111111111111',
        epoch: 1,
        recipientKind: 'user',
        recipientId: 'u-1',
        recipientKeyVersion: 1,
        capability: 'full',
        sealedKeyBundle: 'a',
        signerUserId: 'u-1',
        signerKeyVersion: 1,
        signature: 'a',
      }],
      actorDeviceId: '22222222-2222-4222-8222-222222222222',
      manifestSignature: 'a',
    } satisfies AtomicCreateEncryptedVaultRequest;

    await api.createEncryptedVault(request);

    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://mima.example.test/api/v2/vaults');
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({ [CSRF_HEADER]: 'csrf-create-vault' });
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toEqual(request);
  });
});

describe.each([
  ['ApiClient', () => new ApiClient('https://mima.example.test')],
  ['ZeroKnowledgeApiClient', () => new ZeroKnowledgeApiClient('https://mima.example.test')],
])('%s enterprise recovery key lifecycle', (_name, createClient) => {
  afterEach(() => vi.unstubAllGlobals());

  it('uses the versioned recovery key routes and binds mutations to the CSRF token', async () => {
    const key = enterpriseRecoveryKey();
    const fetcher = vi.fn().mockImplementation(async (input: string, init: RequestInit) => {
      const body = input.endsWith('/api/v2/recovery/keys') && init.method === 'GET' ? [key] : key;
      return new Response(JSON.stringify(body), {
        status: init.method === 'POST' && input.endsWith('/api/v2/recovery/key') ? 201 : 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetcher);
    const api = createClient();
    api.setCsrfToken('csrf-recovery-key');
    const registerRequest = {
      ceremonyId: key.ceremonyId,
      publicEncryptionKey: key.publicEncryptionKey,
      keyFingerprint: key.keyFingerprint,
      threshold: 2 as const,
      shareCount: 3 as const,
      ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
    };
    const approvalRequest = {
      idempotencyKey: 'approval-command-1',
      ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
    };
    const activationRequest = {
      idempotencyKey: 'activation-command-1',
      ceremonyEvidenceDigest: key.ceremonyEvidenceDigest,
    };

    await api.recoveryKey();
    await api.recoveryKeys();
    await api.registerRecoveryKey(registerRequest);
    await api.approveRecoveryKey(key.id, approvalRequest);
    await api.activateRecoveryKey(key.id, activationRequest);

    expect(fetcher.mock.calls.map(([url, init]) => [url, (init as RequestInit).method])).toEqual([
      ['https://mima.example.test/api/v2/recovery/key', 'GET'],
      ['https://mima.example.test/api/v2/recovery/keys', 'GET'],
      ['https://mima.example.test/api/v2/recovery/key', 'POST'],
      [`https://mima.example.test/api/v2/recovery/keys/${key.id}/approve`, 'POST'],
      [`https://mima.example.test/api/v2/recovery/keys/${key.id}/activate`, 'POST'],
    ]);
    expect(JSON.parse((fetcher.mock.calls[2]?.[1] as RequestInit).body as string)).toEqual(registerRequest);
    expect(JSON.parse((fetcher.mock.calls[3]?.[1] as RequestInit).body as string)).toEqual(approvalRequest);
    expect(JSON.parse((fetcher.mock.calls[4]?.[1] as RequestInit).body as string)).toEqual(activationRequest);
    for (const call of fetcher.mock.calls.slice(2)) {
      expect((call[1] as RequestInit).headers).toMatchObject({ [CSRF_HEADER]: 'csrf-recovery-key' });
    }
  });
});

function enterpriseRecoveryKey() {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    ceremonyId: 'production-recovery-2026',
    keyFingerprint: 'A'.repeat(43),
    publicEncryptionKey: 'B'.repeat(43),
    threshold: 2 as const,
    shareCount: 3 as const,
    status: 'pending' as const,
    ceremonyEvidenceDigest: 'C'.repeat(43),
    createdAt: '2026-07-19T00:00:00.000Z',
    retiredAt: null,
  };
}
