import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  EncryptedCommandOutbox,
  EncryptedSyncClient,
  MemoryEncryptedStorage,
  type ApiClient,
} from '../src/index.ts';

afterEach(() => vi.unstubAllGlobals());

describe('EncryptedSyncClient', () => {
  it('parses v2 encrypted events in order and signals ready after application', async () => {
    const frames = [
      { type: 'sync.cursor', cursor: 4 },
      { type: 'sync.ready', cursor: 7, vaultIds: [] },
    ];
    const body = frames.map((event) => `data: ${JSON.stringify(event)}\n\n`).join('');
    const fetcher = vi.fn().mockResolvedValue(new Response(body, {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    }));
    vi.stubGlobal('fetch', fetcher);
    const applied: string[] = [];
    const client = new EncryptedSyncClient({
      baseUrl: 'https://mima.example.test',
      getCursor: () => 3,
      onEvent: async (event) => {
        applied.push(`${event.type}:${event.cursor}`);
      },
    });
    client.onReady(() => client.stop());
    client.start();
    await vi.waitFor(() => expect(applied).toEqual(['sync.cursor:4', 'sync.ready:7']));
    expect(fetcher).toHaveBeenCalledWith(
      'https://mima.example.test/api/v2/events?cursor=3',
      expect.objectContaining({ credentials: 'include' }),
    );
  });

  it('stops and reports an expired session on 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 401 })));
    const unauthorized = vi.fn();
    const client = new EncryptedSyncClient({ getCursor: () => 0, onEvent: vi.fn() });
    client.onUnauthorized(unauthorized);
    client.start();
    await vi.waitFor(() => expect(unauthorized).toHaveBeenCalledOnce());
  });

  it('keeps the encrypted outbox paused until sync.ready is applied', async () => {
    let releaseReady!: () => void;
    const readyGate = new Promise<void>((resolve) => { releaseReady = resolve; });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      `data: ${JSON.stringify({ type: 'sync.ready', cursor: 1, vaultIds: [] })}\n\n`,
      { status: 200 },
    )));
    const sendEncryptedCommand = vi.fn().mockResolvedValue({ ok: true });
    const storage = new MemoryEncryptedStorage();
    const outbox = new EncryptedCommandOutbox({ sendEncryptedCommand } as unknown as ApiClient, storage);
    await outbox.restore('user-1');
    await outbox.enqueue({
      id: 'encrypted-command-1',
      accountId: 'user-1',
      kind: 'item.create',
      method: 'POST',
      path: '/api/v2/vaults/4e23c38e-d931-4b4b-88ee-b4f1716a86b0/items',
      body: { metadata: { nonce: 'bm9uY2U', ciphertext: 'Y2lwaGVy' }, signature: 'c2ln' },
      createdAt: new Date().toISOString(),
    });
    const sync = new EncryptedSyncClient({
      getCursor: () => 0,
      onEvent: async () => readyGate,
    });
    sync.onReady(() => {
      outbox.setOnline(true);
      sync.stop();
    });
    sync.start();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendEncryptedCommand).not.toHaveBeenCalled();
    releaseReady();
    await vi.waitFor(() => expect(sendEncryptedCommand).toHaveBeenCalledOnce());
  });

  it('rejects plaintext legacy event shapes before application', async () => {
    const legacy = {
      type: 'item.upserted',
      cursor: 1,
      item: { title: 'must-not-enter-v2-client', secretValue: 'plaintext' },
    };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(`data: ${JSON.stringify(legacy)}\n\n`, { status: 200 }))
      .mockImplementation(() => new Promise(() => undefined));
    vi.stubGlobal('fetch', fetcher);
    const applied = vi.fn();
    const client = new EncryptedSyncClient({ getCursor: () => 0, onEvent: applied });
    client.start();
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(applied).not.toHaveBeenCalled();
    client.stop();
  });
});

describe('EncryptedCommandOutbox retry policy', () => {
  const command = {
    id: 'encrypted-command-retry',
    accountId: 'user-1',
    kind: 'item.update' as const,
    method: 'PATCH' as const,
    path: '/api/v2/items/4e23c38e-d931-4b4b-88ee-b4f1716a86b0',
    body: { metadata: { nonce: 'bm9uY2U', ciphertext: 'Y2lwaGVy' }, signature: 'c2ln' },
    createdAt: new Date().toISOString(),
  };

  it.each([500, 429, 423])('retains a command after transient HTTP %s', async (status) => {
    const storage = new MemoryEncryptedStorage();
    const sendEncryptedCommand = vi.fn().mockRejectedValue(Object.assign(new Error('temporary'), { status }));
    const outbox = new EncryptedCommandOutbox({ sendEncryptedCommand } as unknown as ApiClient, storage);
    await outbox.restore('user-1');
    await outbox.enqueue(command);
    outbox.setOnline(true);
    await vi.waitFor(() => expect(sendEncryptedCommand).toHaveBeenCalledOnce());
    expect(outbox.size).toBe(1);
    expect(await storage.listCommands('user-1')).toHaveLength(1);
    outbox.setOnline(false);
  });

  it('persists a conflicting command without retrying it automatically', async () => {
    const storage = new MemoryEncryptedStorage();
    const conflict = Object.assign(new Error('conflict'), {
      status: 409,
      body: { currentVersion: 7 },
    });
    const sendEncryptedCommand = vi.fn().mockRejectedValue(conflict);
    const outbox = new EncryptedCommandOutbox({
      sendEncryptedCommand,
    } as unknown as ApiClient, storage);
    const onError = vi.fn();
    const onConflict = vi.fn();
    outbox.onError(onError);
    outbox.onConflict(onConflict);
    await outbox.restore('user-1');
    await outbox.enqueue(command);
    outbox.setOnline(true);
    await vi.waitFor(() => expect(onConflict).toHaveBeenCalled());
    expect(outbox.size).toBe(1);
    expect(onError).toHaveBeenCalledWith(conflict, expect.objectContaining({ id: command.id }));
    expect(await storage.listCommands('user-1')).toEqual([
      expect.objectContaining({
        id: command.id,
        conflict: expect.objectContaining({ reason: 'version_conflict', currentVersion: 7 }),
      }),
    ]);

    outbox.setOnline(true);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(sendEncryptedCommand).toHaveBeenCalledOnce();

    const restoredSend = vi.fn().mockResolvedValue({ ok: true });
    const restored = new EncryptedCommandOutbox({
      sendEncryptedCommand: restoredSend,
    } as unknown as ApiClient, storage);
    const restoredConflict = vi.fn();
    restored.onConflict(restoredConflict);
    await restored.restore('user-1');
    restored.setOnline(true);
    await vi.waitFor(() => expect(restoredConflict).toHaveBeenCalled());
    expect(restoredSend).not.toHaveBeenCalled();
    restoredConflict.mockClear();
    restored.replayConflicts();
    expect(restoredConflict).toHaveBeenCalledOnce();
    expect(await restored.discardConflict(command.id)).toBe(1);
    expect(await storage.listCommands('user-1')).toEqual([]);
  });

  it('isolates later commands for the conflicted item and keeps syncing unrelated items', async () => {
    const storage = new MemoryEncryptedStorage();
    const conflict = Object.assign(new Error('conflict'), {
      status: 409,
      body: { currentVersion: 3 },
    });
    const sendEncryptedCommand = vi.fn()
      .mockRejectedValueOnce(conflict)
      .mockResolvedValue({ ok: true });
    const outbox = new EncryptedCommandOutbox({ sendEncryptedCommand } as unknown as ApiClient, storage);
    await outbox.restore('user-1');
    await outbox.enqueue(command);
    await outbox.enqueue({
      ...command,
      id: 'same-item-later-command',
      kind: 'item.rotate',
      method: 'PUT',
      path: `${command.path}/secret`,
      createdAt: new Date(Date.parse(command.createdAt) + 1).toISOString(),
    });
    const unrelated = {
      ...command,
      id: 'unrelated-item-command',
      path: '/api/v2/items/5f34d49f-e042-4c5c-91ff-c502827b97c1',
      createdAt: new Date(Date.parse(command.createdAt) + 2).toISOString(),
    };
    await outbox.enqueue(unrelated);

    outbox.setOnline(true);
    await vi.waitFor(() => expect(sendEncryptedCommand).toHaveBeenCalledTimes(2));
    expect(sendEncryptedCommand.mock.calls[1]?.[1]).toBe(unrelated.path);
    expect(outbox.size).toBe(2);
    expect(await outbox.discardConflict(command.id)).toBe(2);
    expect(outbox.size).toBe(0);
    expect(await storage.listCommands('user-1')).toEqual([]);
  });
});
