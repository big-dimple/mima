import { describe, expect, it, vi } from 'vitest';
import { PanelActions, type PanelBrowserAdapter } from '../src/panel-actions.ts';
import { PanelApi, PanelApiError } from '../src/panel-api.ts';
import { PanelModel } from '../src/panel-model.ts';
import type { DecryptedExtensionItem } from '../src/protocol.ts';
import { extSession, MemoryExtensionStorage } from './helpers.ts';

const item: DecryptedExtensionItem = {
  id: 'item-1',
  vaultId: 'vault-1',
  kind: 'login',
  title: 'Internal',
  username: 'bob',
  origin: 'https://internal.example.test',
  loginUrl: 'https://internal.example.test/login/subAccount/example-b?type=subAccount',
  loginUrls: [
    'https://internal.example.test/login/subAccount/example-b?type=subAccount',
    'https://secondary.example.test/login',
  ],
  tags: [],
  favorite: false,
  sensitivity: 'medium',
  secretState: 'present',
  version: 1,
  secretVersion: 1,
  keyEpoch: 1,
};

function browser(url: string | null = item.loginUrl ?? item.origin): PanelBrowserAdapter {
  return {
    ensureApiAccess: vi.fn().mockResolvedValue(true),
    ensureSiteAccess: vi.fn().mockResolvedValue(true),
    isProtectedWorkbenchOrigin: vi.fn().mockReturnValue(false),
    readActiveTab: vi.fn().mockResolvedValue({
      tabId: 7,
      origin: url ? new URL(url).origin : null,
      url,
    }),
    executeFill: vi.fn().mockResolvedValue({ ok: true }),
    openUrl: vi.fn().mockResolvedValue(undefined),
    writeClipboard: vi.fn().mockResolvedValue(undefined),
    schedule: vi.fn(),
    requestTrustedUnlock: vi.fn(),
    loadSession: vi.fn().mockResolvedValue(null),
    adoptSession: vi.fn().mockImplementation(async (session) => session),
    invalidateSession: vi.fn().mockResolvedValue(null),
    clearSession: vi.fn().mockResolvedValue(undefined),
    completeTrustedUnlock: vi.fn().mockResolvedValue(undefined),
    isWorkbenchUnlocked: vi.fn().mockReturnValue(true),
  };
}

function readyModel(): PanelModel {
  const model = new PanelModel();
  model.state.session = extSession();
  model.state.device = { deviceId: 'device-1' } as never;
  model.state.tabId = 7;
  model.state.tabOrigin = item.origin;
  model.state.tabUrl = item.loginUrl ?? item.origin;
  model.setReady([item]);
  return model;
}

describe('PanelActions', () => {
  it('opens a URL-only entry without requesting ciphertext', async () => {
    const model = readyModel();
    const api = { encryptedContent: vi.fn() } as unknown as PanelApi;
    const adapter = browser();
    const actions = new PanelActions(
      model,
      api,
      adapter,
      new MemoryExtensionStorage(),
      { unlocked: true } as never,
    );
    const entry = { ...item, secretState: 'absent' as const };

    await expect(actions.open(entry)).resolves.toBe('已打开网址');
    expect(adapter.openUrl).toHaveBeenCalledWith(item.loginUrl);
    await expect(actions.copy(entry)).resolves.toBe('该条目未保存密码');
    expect(api.encryptedContent).not.toHaveBeenCalled();
  });

  it('keeps the pairing key inside the Worker and completes approval without entering a password in the extension', async () => {
    const model = new PanelModel();
    model.setPairing();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const record = {
      deviceId: 'device-1',
      fingerprint: '1111 2222 3333 4444 5555 6666 7777 8888',
      name: 'Test extension',
      platform: 'browser-extension/test',
    } as never;
    const approvedRecord = { ...record, pairingOnly: true, userId: session.user.id } as never;
    const trustedRecord = {
      ...approvedRecord,
      pairingOnly: undefined,
      webUnlock: { version: 1 },
    } as never;
    const bootstrap = {
      profile: {
        userId: session.user.id,
        profileVersion: 1,
        keyVersion: 1,
        suite: 'lm-e2ee-v1',
        kdf: {},
        encryptedAccountBundle: {},
        encryptionPublicKey: 'account-encryption-key',
        signingPublicKey: 'profile-signing-public-key',
      },
      items: [],
      contents: [],
    } as never;
    const api = {
      claimPairingCode: vi.fn().mockResolvedValue({
        enrollmentId: 'enrollment-1',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        fingerprint: record.fingerprint,
        pollToken: 'poll-token',
        status: 'pending',
      }),
      pairingStatus: vi.fn().mockResolvedValue({
        enrollmentId: 'enrollment-1',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        fingerprint: record.fingerprint,
        status: 'approved',
        sealedApproval: 'sealed-approval',
      }),
      requestUnlockChallenge: vi.fn().mockResolvedValue({
        id: 'challenge-1',
        challenge: 'challenge',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }),
      completeUnlock: vi.fn().mockResolvedValue(undefined),
      encryptedBootstrap: vi.fn().mockResolvedValue(bootstrap),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      createPairingDevice: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return record;
      }),
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      pairingRequest: vi.fn().mockResolvedValue({ code: 'ABCDEFG2', device: {} }),
      openPairingApproval: vi.fn().mockResolvedValue({
        session,
        device: { id: 'device-1', userId: session.user.id },
        profileSigningPublicKey: 'profile-signing-public-key',
      }),
      verifyApprovedDevice: vi.fn().mockResolvedValue(approvedRecord),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockResolvedValue(trustedRecord),
      signChallenge: vi.fn().mockResolvedValue('challenge-signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-request' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await actions.pair({
      code: 'ABCDEFG2',
      deviceName: 'Test extension',
      platform: 'browser-extension/test',
    });

    expect(model.state.phase).toBe('awaiting_approval');
    expect(keyring.unlocked).toBe(true);
    await expect(actions.checkPairingApproval()).resolves.toBe('approved');
    expect(keyring.createPairingDevice).toHaveBeenCalledOnce();
    expect(keyring.createTrustedUnlockRequest).toHaveBeenCalledOnce();
    expect(adapter.requestTrustedUnlock).toHaveBeenCalledOnce();
    expect(keyring.completeTrustedUnlock).toHaveBeenCalledOnce();
    expect(storage.device).toEqual(trustedRecord);
    expect(model.state.phase).toBe('ready');
    expect(model.state.items).toEqual([item]);
    expect(storage.pending).toBeNull();
  });

  it('renews a trusted device session through the unlocked workbench instead of pairing again', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const renewedSession = extSession();
    const device = {
      deviceId: 'device-1',
      name: 'Office Edge',
      webUnlock: { version: 1 },
    } as never;
    storage.device = device;
    const bootstrap = { profile: {}, items: [], contents: [] } as never;
    const api = {
      loadSession: vi.fn().mockResolvedValue(null),
      requestUnlockChallenge: vi.fn().mockResolvedValue({
        id: 'challenge-1',
        challenge: 'challenge',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }),
      completeUnlock: vi.fn().mockResolvedValue({ unlocked: true }),
      encryptedBootstrap: vi.fn().mockResolvedValue(bootstrap),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      signChallenge: vi.fn().mockResolvedValue('challenge-signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-request' },
      session: renewedSession,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await actions.startup();

    expect(adapter.requestTrustedUnlock).toHaveBeenCalledOnce();
    expect(model.state.session).toEqual(renewedSession);
    expect(model.state.phase).toBe('ready');
    expect(model.state.items).toEqual([item]);
  });

  it('keeps one bearer snapshot through challenge, unlock confirmation, and bootstrap', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const pinnedSession = { ...extSession(), token: 'pinned-token', generation: 4 };
    const newerSession = { ...extSession(), token: 'newer-token', generation: 5 };
    const device = {
      deviceId: 'device-1',
      userId: pinnedSession.user.id,
      name: 'Office Edge',
      webUnlock: { version: 1 },
    } as never;
    model.state.device = device;
    const bootstrap = { profile: {}, items: [], contents: [] } as never;
    const actionsRef: { current: PanelActions | null } = { current: null };
    const api = {
      requestUnlockChallenge: vi.fn().mockImplementation(async (_deviceId, session) => {
        expect(session).toEqual(pinnedSession);
        await actionsRef.current!.syncSession(newerSession);
        return {
          id: 'challenge-1',
          challenge: 'challenge',
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        };
      }),
      completeUnlock: vi.fn().mockImplementation(async (_input, session) => {
        expect(session).toEqual(pinnedSession);
        return { unlocked: true };
      }),
      encryptedBootstrap: vi.fn().mockImplementation(async (session) => {
        expect(session).toEqual(pinnedSession);
        return bootstrap;
      }),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-pinned' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      signChallenge: vi.fn().mockResolvedValue('challenge-signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-pinned' },
      session: pinnedSession,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);
    actionsRef.current = actions;

    await actions.tryTrustedUnlock();

    expect(api.requestUnlockChallenge).toHaveBeenCalledOnce();
    expect(api.completeUnlock).toHaveBeenCalledOnce();
    expect(api.encryptedBootstrap).toHaveBeenCalledOnce();
    expect(adapter.completeTrustedUnlock).toHaveBeenCalledWith('trusted-pinned');
    expect(model.state.session).toEqual(newerSession);
    expect(model.state.phase).toBe('ready');
  });

  it('does not revive a recovery after the coordinator clears its current session', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = { ...extSession(), generation: 4 };
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      name: 'Office Edge',
      webUnlock: { version: 1 },
    } as never;
    model.state.device = device;
    const actionsRef: { current: PanelActions | null } = { current: null };
    const api = {
      requestUnlockChallenge: vi.fn().mockImplementation(async () => {
        await actionsRef.current!.syncSession(null);
        return {
          id: 'challenge-1',
          challenge: 'challenge',
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        };
      }),
      completeUnlock: vi.fn().mockResolvedValue({ unlocked: true }),
      encryptedBootstrap: vi.fn().mockResolvedValue({ profile: {}, items: [], contents: [] }),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-cleared' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      signChallenge: vi.fn().mockResolvedValue('challenge-signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-cleared' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);
    actionsRef.current = actions;

    await actions.tryTrustedUnlock();

    expect(model.state.session).toBeNull();
    expect(model.state.phase).toBe('locked');
    expect(model.state.items).toEqual([]);
    expect(keyring.lock).toHaveBeenCalled();
    expect(adapter.completeTrustedUnlock).toHaveBeenCalledWith('trusted-cleared');
  });

  it('uses offline cache only after an actual network failure', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      webUnlock: { version: 1 },
    } as never;
    model.state.device = device;
    storage.cache = {
      version: 1,
      bootstrap: { profile: {}, items: [], contents: [] } as never,
      contents: {},
      updatedAt: new Date().toISOString(),
    };
    const api = {
      requestUnlockChallenge: vi.fn().mockRejectedValue(
        new PanelApiError('无法连接Mima服务', null),
      ),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-request' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await actions.tryTrustedUnlock();

    expect(model.state.phase).toBe('ready');
    expect(model.state.offline).toBe(true);
    expect(model.state.items).toEqual([item]);
  });

  it('does not mislabel permission or cryptographic failures as offline', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      webUnlock: { version: 1 },
    } as never;
    model.state.device = device;
    storage.cache = {
      version: 1,
      bootstrap: { profile: {}, items: [], contents: [] } as never,
      contents: {},
      updatedAt: new Date().toISOString(),
    };
    const api = { requestUnlockChallenge: vi.fn() } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      loadBootstrap: vi.fn(),
    };
    const adapter = browser();
    adapter.ensureApiAccess = vi.fn().mockResolvedValue(false);
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-request' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await expect(actions.tryTrustedUnlock()).rejects.toThrow('未授权扩展访问Mima服务');

    expect(model.state.phase).toBe('locked');
    expect(model.state.offline).toBe(false);
    expect(keyring.loadBootstrap).not.toHaveBeenCalled();
  });

  it('stops duplicate automatic recovery after failure but allows explicit and relock retries', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      webUnlock: { version: 1 },
    } as never;
    model.state.device = device;
    const api = { requestUnlockChallenge: vi.fn() } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
    };
    const adapter = browser();
    adapter.ensureApiAccess = vi.fn().mockResolvedValue(false);
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-request' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await expect(actions.tryTrustedUnlock()).rejects.toThrow('未授权扩展访问Mima服务');
    await expect(actions.tryTrustedUnlock()).resolves.toBeUndefined();
    expect(adapter.requestTrustedUnlock).toHaveBeenCalledTimes(1);

    await expect(actions.tryTrustedUnlock({ force: true }))
      .rejects.toThrow('未授权扩展访问Mima服务');
    expect(adapter.requestTrustedUnlock).toHaveBeenCalledTimes(2);

    actions.allowAutomaticTrustedUnlock();
    await expect(actions.tryTrustedUnlock()).rejects.toThrow('未授权扩展访问Mima服务');
    expect(adapter.requestTrustedUnlock).toHaveBeenCalledTimes(3);
  });

  it('collapses repeated recovery clicks into one trusted unlock request', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      webUnlock: { version: 1 },
    } as never;
    model.state.device = device;
    storage.cache = {
      version: 1,
      bootstrap: { profile: {}, items: [], contents: [] } as never,
      contents: {},
      updatedAt: new Date().toISOString(),
    };
    const api = {
      requestUnlockChallenge: vi.fn().mockRejectedValue(
        new PanelApiError('无法连接Mima服务', null),
      ),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    let releaseTrustedUnlock!: () => void;
    const trustedUnlockGate = new Promise<void>((resolve) => { releaseTrustedUnlock = resolve; });
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockImplementation(async () => {
      await trustedUnlockGate;
      return { response: { requestId: 'trusted-request' }, session } as never;
    });
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    const first = actions.tryTrustedUnlock();
    const second = actions.tryTrustedUnlock();
    await vi.waitFor(() => expect(adapter.requestTrustedUnlock).toHaveBeenCalledTimes(1));
    releaseTrustedUnlock();
    await Promise.all([first, second]);

    expect(adapter.requestTrustedUnlock).toHaveBeenCalledTimes(1);
    expect(model.state.phase).toBe('ready');
  });

  it('keeps a legacy device when its browser session is gone instead of returning to pairing', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const device = {
      deviceId: 'legacy-device-1',
      name: 'Office Edge',
      pairingOnly: undefined,
    } as never;
    storage.device = device;
    const api = { loadSession: vi.fn().mockResolvedValue(null) } as unknown as PanelApi;
    const keyring = { unlocked: false, lock: vi.fn().mockResolvedValue(undefined) };
    const actions = new PanelActions(model, api, browser(), storage, keyring as never);

    await actions.startup();

    expect(model.state.phase).toBe('locked');
    expect(model.state.error).toContain('无需配对码');
    expect(storage.device).toEqual(device);
  });

  it('upgrades a legacy device through the unlocked workbench without another pairing code', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const legacyDevice = {
      deviceId: 'legacy-device-1',
      name: 'Office Edge',
      pairingOnly: undefined,
    } as never;
    const trustedDevice = { ...legacyDevice, webUnlock: { version: 1 } } as never;
    storage.device = legacyDevice;
    const bootstrap = { profile: {}, items: [], contents: [] } as never;
    const api = {
      loadSession: vi.fn().mockResolvedValue(null),
      requestUnlockChallenge: vi.fn().mockResolvedValue({
        id: 'challenge-1',
        challenge: 'challenge',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }),
      completeUnlock: vi.fn().mockResolvedValue({ unlocked: true }),
      encryptedBootstrap: vi.fn().mockResolvedValue(bootstrap),
      claimPairingCode: vi.fn(),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      unlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
      completeTrustedUnlock: vi.fn().mockResolvedValue(trustedDevice),
      signChallenge: vi.fn().mockResolvedValue('challenge-signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-request' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await actions.startup();
    await actions.unlock('one-time-main-password');

    expect(api.claimPairingCode).not.toHaveBeenCalled();
    expect(keyring.unlock).toHaveBeenCalledWith(legacyDevice, 'one-time-main-password');
    expect(adapter.requestTrustedUnlock).toHaveBeenCalledOnce();
    expect(storage.device).toEqual(trustedDevice);
    expect(model.state.phase).toBe('ready');
  });

  it('preserves local device data when the workbench cannot yet confirm authorization', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const device = {
      deviceId: 'device-1',
      name: 'Office Edge',
      webUnlock: { version: 1 },
    } as never;
    storage.device = device;
    storage.cache = { version: 1, bootstrap: {} as never, contents: {}, updatedAt: new Date().toISOString() };
    const api = { loadSession: vi.fn().mockResolvedValue(null) } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockResolvedValue(undefined),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-request' }),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockRejectedValue(
      new Error('扩展设备未获得当前账号授权'),
    );
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await actions.startup();

    expect(model.state.phase).toBe('locked');
    expect(storage.device).toEqual(device);
    expect(storage.cache).not.toBeNull();
  });

  it('settles immediately as locked when no matching workbench is unlocked', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      name: 'Office Edge',
      webUnlock: { version: 1 },
    } as never;
    storage.session = session;
    storage.device = device;
    const api = { loadSession: vi.fn().mockResolvedValue(session) } as unknown as PanelApi;
    const adapter = browser();
    adapter.loadSession = vi.fn().mockResolvedValue(session);
    adapter.isWorkbenchUnlocked = vi.fn().mockReturnValue(false);
    const keyring = { unlocked: false, lock: vi.fn().mockResolvedValue(undefined) };
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await actions.startup();

    expect(adapter.requestTrustedUnlock).not.toHaveBeenCalled();
    expect(model.state.phase).toBe('locked');
    expect(model.state.error).toContain('工作台尚未解锁');
  });

  it('rejects fill before any ciphertext request when the website address differs', async () => {
    const model = readyModel();
    const storage = new MemoryExtensionStorage();
    const api = { encryptedContent: vi.fn() } as unknown as PanelApi;
    const keyring = { unlocked: true } as never;
    const adapter = browser('https://different.example.test/login');
    const actions = new PanelActions(model, api, adapter, storage, keyring);

    await expect(actions.fill(item)).resolves.toBe('网址不一致，已取消填充');
    expect(api.encryptedContent).not.toHaveBeenCalled();
    expect(adapter.executeFill).not.toHaveBeenCalled();
  });

  it('stops before reading ciphertext when site access is denied', async () => {
    const model = readyModel();
    const storage = new MemoryExtensionStorage();
    const api = { encryptedContent: vi.fn() } as unknown as PanelApi;
    const adapter = browser();
    adapter.ensureSiteAccess = vi.fn().mockResolvedValue(false);
    const actions = new PanelActions(model, api, adapter, storage, { unlocked: true } as never);

    await expect(actions.fill(item)).resolves.toBe('未授权扩展访问当前网站，已取消填充');
    expect(adapter.ensureSiteAccess).toHaveBeenCalledWith('https://internal.example.test');
    expect(api.encryptedContent).not.toHaveBeenCalled();
    expect(adapter.executeFill).not.toHaveBeenCalled();
  });

  it('never fills the Mima workbench itself', async () => {
    const model = readyModel();
    model.state.tabOrigin = item.origin;
    model.state.tabUrl = item.loginUrl;
    const storage = new MemoryExtensionStorage();
    const api = { encryptedContent: vi.fn() } as unknown as PanelApi;
    const adapter = browser();
    adapter.isProtectedWorkbenchOrigin = vi.fn().mockReturnValue(true);
    const actions = new PanelActions(model, api, adapter, storage, { unlocked: true } as never);

    await expect(actions.fill(item)).resolves.toBe('Mima工作台不接受扩展填充');
    expect(adapter.ensureSiteAccess).not.toHaveBeenCalled();
    expect(api.encryptedContent).not.toHaveBeenCalled();
    expect(adapter.executeFill).not.toHaveBeenCalled();
  });

  it('fills a saved full login URL while keeping the exact origin boundary', async () => {
    const model = readyModel();
    const storage = new MemoryExtensionStorage();
    const api = { encryptedContent: vi.fn().mockResolvedValue({ encrypted: true }) } as unknown as PanelApi;
    const keyring = {
      unlocked: true,
      signContentIntent: vi.fn().mockResolvedValue('signature'),
      decryptContent: vi.fn().mockResolvedValue('password'),
    };
    const adapter = browser(item.loginUrl!);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await expect(actions.fill(item)).resolves.toBe('已填充登录表单');
    expect(api.encryptedContent).toHaveBeenCalledOnce();
    expect(adapter.ensureSiteAccess).toHaveBeenCalledWith('https://internal.example.test');
    expect(adapter.executeFill).toHaveBeenCalledWith(7, 'bob', 'password');
  });

  it('recomputes the active full URL after same-site navigation', async () => {
    const model = readyModel();
    const adapter = browser('https://accounts.example.test/login/tenant/example-b');
    const actions = new PanelActions(
      model,
      {} as PanelApi,
      adapter,
      new MemoryExtensionStorage(),
      { unlocked: true } as never,
    );

    await actions.refreshActiveTab();

    expect(model.state.tabOrigin).toBe('https://accounts.example.test');
    expect(model.state.tabUrl).toBe('https://accounts.example.test/login/tenant/example-b');
  });

  it('drops content that finishes decrypting after lock', async () => {
    const model = readyModel();
    const storage = new MemoryExtensionStorage();
    storage.cache = { version: 1, bootstrap: {} as never, contents: {}, updatedAt: new Date().toISOString() };
    const encryptedContent = vi.fn().mockResolvedValue({ encrypted: true });
    const api = { encryptedContent } as unknown as PanelApi;
    let finishDecrypt!: (value: string) => void;
    const keyring = {
      unlocked: true,
      signContentIntent: vi.fn().mockResolvedValue('signature'),
      decryptContent: vi.fn().mockReturnValue(new Promise<string>((resolve) => { finishDecrypt = resolve; })),
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) { this.unlocked = false; }),
    };
    const adapter = browser();
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    const pending = actions.copy(item);
    await vi.waitFor(() => expect(keyring.decryptContent).toHaveBeenCalled());
    await actions.lock();
    finishDecrypt('must-not-reach-clipboard');

    await expect(pending).resolves.toBeNull();
    expect(adapter.writeClipboard).not.toHaveBeenCalled();
    expect(model.state.items).toEqual([]);
  });

  it('confirms a workbench revocation with the server before clearing local data', async () => {
    const model = readyModel();
    const storage = new MemoryExtensionStorage();
    storage.session = extSession();
    storage.device = { deviceId: 'device-1' } as never;
    storage.cache = { version: 1, bootstrap: {} as never, contents: {}, updatedAt: new Date().toISOString() };
    const api = {
      requestUnlockChallenge: vi.fn().mockRejectedValue(new PanelApiError('revoked', 403)),
    } as unknown as PanelApi;
    const keyring = { unlocked: true, lock: vi.fn().mockResolvedValue(undefined) };
    const actions = new PanelActions(model, api, browser(), storage, keyring as never);

    await expect(actions.confirmWorkbenchDeviceRevocation('another-device')).resolves.toBe(false);
    expect(api.requestUnlockChallenge).not.toHaveBeenCalled();
    await expect(actions.confirmWorkbenchDeviceRevocation('device-1')).resolves.toBe(true);
    expect(api.requestUnlockChallenge).toHaveBeenCalledWith('device-1');
    expect(storage.session).toBeNull();
    expect(storage.device).toBeNull();
    expect(storage.cache).toBeNull();
    expect(model.state.phase).toBe('revoked');
  });

  it('clears local device and ciphertext when the server reports revocation', async () => {
    const model = readyModel();
    const storage = new MemoryExtensionStorage();
    storage.session = extSession();
    storage.device = { deviceId: 'device-1' } as never;
    storage.cache = { version: 1, bootstrap: {} as never, contents: {}, updatedAt: new Date().toISOString() };
    const api = {
      encryptedContent: vi.fn().mockRejectedValue(new PanelApiError('revoked', 403)),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: true,
      signContentIntent: vi.fn().mockResolvedValue('signature'),
      lock: vi.fn().mockResolvedValue(undefined),
    };
    const actions = new PanelActions(model, api, browser(), storage, keyring as never);

    await expect(actions.copy(item)).rejects.toThrow('revoked');
    expect(storage.session).toBeNull();
    expect(storage.device).toBeNull();
    expect(storage.cache).toBeNull();
    expect(model.state.phase).toBe('revoked');
    expect(model.state.items).toEqual([]);
  });

  it('always leaves the unlocking phase after the current bearer returns 401', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      webUnlock: { version: 1 },
    } as never;
    model.state.session = session;
    model.state.device = device;
    model.setLocked();
    const api = {
      requestUnlockChallenge: vi.fn().mockRejectedValue(
        new PanelApiError('expired', 401, session.generation ?? 0),
      ),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      unlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
      }),
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({
        requestId: 'trusted-recovery',
        expiresAt: new Date(Date.now() + 5_000).toISOString(),
      }),
    };
    const adapter = browser();
    adapter.invalidateSession = vi.fn().mockResolvedValue(null);
    adapter.requestTrustedUnlock = vi.fn().mockRejectedValue(
      new Error('没有找到可确认此账号的已解锁工作台'),
    );
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    await expect(actions.unlock('main-password')).rejects.toThrow('已解锁工作台');

    expect(model.state.phase).toBe('locked');
    expect(model.state.phase).not.toBe('unlocking');
    expect(model.state.session).toBeNull();
    expect(adapter.invalidateSession).toHaveBeenCalledWith(1);
  });

  it('automatically renews once when a reused bearer is actually invalid', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const firstSession = extSession();
    const renewedSession = { ...extSession(), token: 'renewed-token', generation: 2 };
    const device = {
      deviceId: 'device-1',
      userId: firstSession.user.id,
      webUnlock: { version: 1 },
    } as never;
    model.state.session = firstSession;
    model.state.device = device;
    model.setLocked();
    const bootstrap = { profile: {}, items: [], contents: [] } as never;
    const api = {
      requestUnlockChallenge: vi.fn()
        .mockRejectedValueOnce(new PanelApiError('expired', 401, 1))
        .mockResolvedValue({
          id: 'challenge-2',
          challenge: 'challenge',
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }),
      completeUnlock: vi.fn().mockResolvedValue({ unlocked: true }),
      encryptedBootstrap: vi.fn().mockResolvedValue(bootstrap),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn()
        .mockResolvedValueOnce({ requestId: 'trusted-1' })
        .mockResolvedValueOnce({ requestId: 'trusted-2' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      signChallenge: vi.fn().mockResolvedValue('signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn()
      .mockResolvedValueOnce({ response: { requestId: 'trusted-1' }, session: firstSession } as never)
      .mockResolvedValueOnce({ response: { requestId: 'trusted-2' }, session: renewedSession } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);
    adapter.invalidateSession = vi.fn().mockImplementation(async () => {
      await actions.syncSession(null);
      return null;
    });

    await actions.tryTrustedUnlock();

    expect(adapter.requestTrustedUnlock).toHaveBeenCalledTimes(2);
    expect(adapter.invalidateSession).toHaveBeenCalledWith(1);
    expect(model.state.session).toEqual(renewedSession);
    expect(model.state.phase).toBe('ready');
  });

  it('retries a stale 401 with the newer coordinated bearer', async () => {
    const model = readyModel();
    const replacement = { ...extSession(), token: 'newer-token', generation: 2 };
    const bootstrap = { profile: {}, items: [], contents: [] } as never;
    const api = {
      encryptedBootstrap: vi.fn()
        .mockRejectedValueOnce(new PanelApiError('stale request', 401, 1))
        .mockResolvedValue(bootstrap),
    } as unknown as PanelApi;
    const adapter = browser();
    adapter.invalidateSession = vi.fn().mockResolvedValue(replacement);
    const keyring = { unlocked: true, loadBootstrap: vi.fn().mockResolvedValue([item]) };
    const actions = new PanelActions(
      model,
      api,
      adapter,
      new MemoryExtensionStorage(),
      keyring as never,
    );

    await actions.refreshData();

    expect(api.encryptedBootstrap).toHaveBeenCalledTimes(2);
    expect(adapter.invalidateSession).toHaveBeenCalledWith(1);
    expect(model.state.session).toEqual(replacement);
    expect(model.state.phase).toBe('ready');
  });

  it('drops a bootstrap result that arrives after the extension was locked', async () => {
    const model = new PanelModel();
    const storage = new MemoryExtensionStorage();
    const session = extSession();
    const device = {
      deviceId: 'device-1',
      userId: session.user.id,
      webUnlock: { version: 1 },
    } as never;
    storage.session = session;
    storage.device = device;
    let finishChallenge!: (value: { id: string; challenge: string; expiresAt: string }) => void;
    const api = {
      loadSession: vi.fn().mockResolvedValue(session),
      requestUnlockChallenge: vi.fn().mockReturnValue(new Promise((resolve) => {
        finishChallenge = resolve;
      })),
      completeUnlock: vi.fn().mockResolvedValue({ unlocked: true }),
      encryptedBootstrap: vi.fn().mockResolvedValue({ profile: {}, items: [], contents: [] }),
    } as unknown as PanelApi;
    const keyring = {
      unlocked: false,
      lock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = false;
      }),
      createTrustedUnlockRequest: vi.fn().mockResolvedValue({ requestId: 'trusted-1' }),
      completeTrustedUnlock: vi.fn().mockImplementation(async function (this: { unlocked: boolean }) {
        this.unlocked = true;
        return device;
      }),
      signChallenge: vi.fn().mockResolvedValue('signature'),
      loadBootstrap: vi.fn().mockResolvedValue([item]),
    };
    const adapter = browser();
    adapter.requestTrustedUnlock = vi.fn().mockResolvedValue({
      response: { requestId: 'trusted-1' },
      session,
    } as never);
    const actions = new PanelActions(model, api, adapter, storage, keyring as never);

    const startup = actions.startup();
    await vi.waitFor(() => expect(api.requestUnlockChallenge).toHaveBeenCalledOnce());
    await actions.lock();
    finishChallenge({
      id: 'challenge-1',
      challenge: 'challenge',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    await startup;

    expect(model.state.phase).toBe('locked');
    expect(model.state.items).toEqual([]);
  });
});
