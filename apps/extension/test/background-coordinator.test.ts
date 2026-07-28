import { describe, expect, it, vi } from 'vitest';
import type { ExtensionTrustedUnlockRequest } from '@mima/e2ee';
import {
  BackgroundCoordinator,
  type CoordinatorSessionStore,
} from '../src/background-coordinator.ts';
import type { ExtSession } from '../src/protocol.ts';
import { extSession } from './helpers.ts';

class MemorySessionStore implements CoordinatorSessionStore {
  session: ExtSession | null = null;
  generation = 0;

  async loadSession() { return this.session ? structuredClone(this.session) : null; }
  async saveSession(session: ExtSession) { this.session = structuredClone(session); }
  async removeSession() { this.session = null; }
  async loadGeneration() { return this.generation; }
  async saveGeneration(generation: number) { this.generation = generation; }
}

class FakePort {
  readonly messages: unknown[] = [];
  postMessage(message: unknown) { this.messages.push(message); }
}

function request(requestId: string): ExtensionTrustedUnlockRequest {
  return {
    requestId,
    accountId: 'user-1',
    deviceId: 'device-1',
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
  } as ExtensionTrustedUnlockRequest;
}

function unlockWorkbench(
  coordinator: BackgroundCoordinator,
  port: FakePort,
  stateGeneration = 1,
  focused = false,
): void {
  coordinator.registerWorkbench(port);
  coordinator.handleWorkbenchMessage(port, {
    kind: 'workbench_state',
    protocolVersion: 2,
    endpointId: `endpoint-${crypto.randomUUID()}`,
    accountId: 'user-1',
    unlocked: true,
    stateGeneration,
    visibility: 'visible',
    focused,
  });
}

describe('BackgroundCoordinator', () => {
  it('reports whether a workbench is registered and unlocked for an account', () => {
    const coordinator = new BackgroundCoordinator(new MemorySessionStore());
    const workbench = new FakePort();

    expect(coordinator.hasRegisteredWorkbench()).toBe(false);
    expect(coordinator.hasUnlockedWorkbench('user-1')).toBe(false);

    coordinator.registerWorkbench(workbench);
    expect(coordinator.hasRegisteredWorkbench()).toBe(true);
    expect(coordinator.hasUnlockedWorkbench('user-1')).toBe(false);

    coordinator.handleWorkbenchMessage(workbench, {
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: true,
      stateGeneration: 1,
    });
    expect(coordinator.hasUnlockedWorkbench('user-1')).toBe(true);
    expect(coordinator.hasUnlockedWorkbench('user-2')).toBe(false);

    coordinator.unregisterWorkbench(workbench);
    expect(coordinator.hasRegisteredWorkbench()).toBe(false);
    expect(coordinator.hasUnlockedWorkbench('user-1')).toBe(false);
  });

  it('routes a request to the newest matching unlocked workbench instead of broadcasting', async () => {
    const store = new MemorySessionStore();
    store.session = extSession();
    store.generation = 1;
    const coordinator = new BackgroundCoordinator(store);
    const first = new FakePort();
    const second = new FakePort();
    const locked = new FakePort();
    const sidePanel = new FakePort();
    unlockWorkbench(coordinator, first);
    unlockWorkbench(coordinator, second);
    coordinator.registerWorkbench(locked);
    coordinator.handleWorkbenchMessage(locked, {
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: false,
      stateGeneration: 1,
    });
    coordinator.registerSidePanel(sidePanel);

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-1'),
    });

    await vi.waitFor(() => expect(second.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_request',
      needsSession: false,
    })));
    expect(first.messages).not.toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_request',
    }));
    expect(locked.messages).not.toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_request',
    }));
    coordinator.handleWorkbenchMessage(second, {
      kind: 'trusted_unlock_response',
      requestId: 'request-1',
      response: { requestId: 'request-1' },
    });
    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'request-1',
    })));
    expect(store.session).toMatchObject({ generation: 1, token: 'opaque-extension-token' });
  });

  it('keeps the last focused leader when a newer standby tab registers', async () => {
    const store = new MemorySessionStore();
    store.session = extSession();
    store.generation = 1;
    const coordinator = new BackgroundCoordinator(store);
    const leader = new FakePort();
    const newerStandby = new FakePort();
    const sidePanel = new FakePort();
    unlockWorkbench(coordinator, leader, 1, true);
    unlockWorkbench(coordinator, newerStandby);
    coordinator.registerSidePanel(sidePanel);

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-sticky-leader'),
    });

    await vi.waitFor(() => expect(leader.messages.filter(isTrustedRequest)).toHaveLength(1));
    expect(newerStandby.messages.filter(isTrustedRequest)).toHaveLength(0);
    coordinator.handleWorkbenchMessage(leader, {
      kind: 'trusted_unlock_response',
      requestId: 'request-sticky-leader',
      response: { requestId: 'request-sticky-leader' },
    });
    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'request-sticky-leader',
    })));
  });

  it('replaces a sticky legacy leader when a v2 workbench is available', async () => {
    const store = new MemorySessionStore();
    store.session = extSession();
    store.generation = 1;
    const coordinator = new BackgroundCoordinator(store);
    const legacyLeader = new FakePort();
    const currentWorkbench = new FakePort();
    const sidePanel = new FakePort();
    coordinator.registerWorkbench(legacyLeader);
    coordinator.handleWorkbenchMessage(legacyLeader, {
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: true,
      stateGeneration: 1,
      visibility: 'visible',
      focused: true,
    });
    unlockWorkbench(coordinator, currentWorkbench);
    coordinator.registerSidePanel(sidePanel);

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-current-protocol'),
    });

    await vi.waitFor(() => expect(currentWorkbench.messages.filter(isTrustedRequest)).toHaveLength(1));
    expect(legacyLeader.messages.filter(isTrustedRequest)).toHaveLength(0);
  });

  it('serializes session recovery across side panels and reuses the resulting bearer', async () => {
    const store = new MemorySessionStore();
    const coordinator = new BackgroundCoordinator(store);
    const workbench = new FakePort();
    const firstPanel = new FakePort();
    const secondPanel = new FakePort();
    unlockWorkbench(coordinator, workbench);
    coordinator.registerSidePanel(firstPanel);
    coordinator.registerSidePanel(secondPanel);

    coordinator.handleSidePanelMessage(firstPanel, {
      kind: 'trusted_unlock_request',
      request: request('request-1'),
    });
    coordinator.handleSidePanelMessage(secondPanel, {
      kind: 'trusted_unlock_request',
      request: request('request-2'),
    });

    await vi.waitFor(() => expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(1));
    expect(workbench.messages.filter(isTrustedRequest)[0]).toMatchObject({ needsSession: true });
    coordinator.handleWorkbenchMessage(workbench, {
      kind: 'trusted_unlock_response',
      requestId: 'request-1',
      response: { requestId: 'request-1' },
      session: extSession(),
    });

    await vi.waitFor(() => expect(firstPanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'request-1',
    })));
    expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(1);
    coordinator.handleSidePanelMessage(firstPanel, {
      kind: 'trusted_unlock_complete',
      requestId: 'complete-request-1',
      trustedRequestId: 'request-1',
    });

    await vi.waitFor(() => expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(2));
    expect(workbench.messages.filter(isTrustedRequest)[1]).toMatchObject({ needsSession: false });
    coordinator.handleWorkbenchMessage(workbench, {
      kind: 'trusted_unlock_response',
      requestId: 'request-2',
      response: { requestId: 'request-2' },
    });

    await vi.waitFor(() => {
      expect(firstPanel.messages).toContainEqual(expect.objectContaining({
        kind: 'trusted_unlock_response',
        requestId: 'request-1',
      }));
      expect(secondPanel.messages).toContainEqual(expect.objectContaining({
        kind: 'trusted_unlock_response',
        requestId: 'request-2',
      }));
    });
    expect(workbench.messages.filter((message) => (
      isTrustedRequest(message) && message.needsSession === true
    ))).toHaveLength(1);
    expect(store.session).toMatchObject({ generation: 1, deviceId: 'device-1' });
  });

  it('holds an existing bearer transaction until the first side panel confirms bootstrap', async () => {
    const store = new MemorySessionStore();
    store.session = extSession();
    store.generation = 1;
    const coordinator = new BackgroundCoordinator(store);
    const workbench = new FakePort();
    const firstPanel = new FakePort();
    const secondPanel = new FakePort();
    unlockWorkbench(coordinator, workbench);
    coordinator.registerSidePanel(firstPanel);
    coordinator.registerSidePanel(secondPanel);

    coordinator.handleSidePanelMessage(firstPanel, {
      kind: 'trusted_unlock_request',
      request: request('existing-1'),
    });
    coordinator.handleSidePanelMessage(secondPanel, {
      kind: 'trusted_unlock_request',
      request: request('existing-2'),
    });

    await vi.waitFor(() => expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(1));
    expect(workbench.messages.filter(isTrustedRequest)[0]).toMatchObject({ needsSession: false });
    coordinator.handleWorkbenchMessage(workbench, {
      kind: 'trusted_unlock_response',
      requestId: 'existing-1',
      response: { requestId: 'existing-1' },
    });
    await vi.waitFor(() => expect(firstPanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'existing-1',
    })));
    expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(1);

    coordinator.handleSidePanelMessage(firstPanel, {
      kind: 'trusted_unlock_complete',
      requestId: 'complete-existing-1',
      trustedRequestId: 'existing-1',
    });

    await vi.waitFor(() => expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(2));
    expect(workbench.messages.filter(isTrustedRequest)[1]).toMatchObject({ needsSession: false });
  });

  it('tries another unlocked tab when the first tab cannot confirm', async () => {
    const coordinator = new BackgroundCoordinator(new MemorySessionStore());
    const first = new FakePort();
    const second = new FakePort();
    const sidePanel = new FakePort();
    unlockWorkbench(coordinator, first);
    unlockWorkbench(coordinator, second);
    coordinator.registerSidePanel(sidePanel);
    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-fallback'),
    });

    await vi.waitFor(() => expect(second.messages.filter(isTrustedRequest)).toHaveLength(1));
    coordinator.handleWorkbenchMessage(second, {
      kind: 'trusted_unlock_error',
      requestId: 'request-fallback',
      message: '密码库尚未解锁',
    });
    await vi.waitFor(() => expect(first.messages.filter(isTrustedRequest)).toHaveLength(1));
    expect(sidePanel.messages).not.toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_error',
    }));

    coordinator.handleWorkbenchMessage(first, {
      kind: 'trusted_unlock_response',
      requestId: 'request-fallback',
      response: { requestId: 'request-fallback' },
      session: extSession(),
    });
    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'request-fallback',
    })));
  });

  it('returns a useful error immediately when the only unlocked workbench cannot recover', async () => {
    const coordinator = new BackgroundCoordinator(new MemorySessionStore());
    const workbench = new FakePort();
    const sidePanel = new FakePort();
    unlockWorkbench(coordinator, workbench);
    coordinator.registerSidePanel(sidePanel);
    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-single-error'),
    });

    await vi.waitFor(() => expect(workbench.messages.filter(isTrustedRequest)).toHaveLength(1));
    coordinator.handleWorkbenchMessage(workbench, {
      kind: 'trusted_unlock_error',
      requestId: 'request-single-error',
      message: '密码库尚未解锁',
    });

    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual({
      kind: 'trusted_unlock_error',
      requestId: 'request-single-error',
      message: '工作台尚未完成主密码解锁。请先解锁同一账号的工作台，再重试。',
    }));
  });

  it('fails over when the newest unlocked workbench stops responding', async () => {
    const coordinator = new BackgroundCoordinator(
      new MemorySessionStore(),
      () => Date.now(),
      25,
    );
    const older = new FakePort();
    const sleepingNewest = new FakePort();
    const sidePanel = new FakePort();
    unlockWorkbench(coordinator, older);
    unlockWorkbench(coordinator, sleepingNewest);
    coordinator.registerSidePanel(sidePanel);

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-sleeping-tab'),
    });

    await vi.waitFor(() => expect(sleepingNewest.messages.filter(isTrustedRequest)).toHaveLength(1));
    await vi.waitFor(() => expect(older.messages.filter(isTrustedRequest)).toHaveLength(1));
    coordinator.handleWorkbenchMessage(older, {
      kind: 'trusted_unlock_response',
      requestId: 'request-sleeping-tab',
      response: { requestId: 'request-sleeping-tab' },
      session: extSession(),
    });

    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'request-sleeping-tab',
    })));
  });

  it('keeps one acknowledged leader while its session recovery is still running', async () => {
    const coordinator = new BackgroundCoordinator(
      new MemorySessionStore(),
      () => Date.now(),
      200,
    );
    const standby = new FakePort();
    const leader = new FakePort();
    const sidePanel = new FakePort();
    unlockWorkbench(coordinator, standby);
    unlockWorkbench(coordinator, leader, 1, true);
    coordinator.registerSidePanel(sidePanel);

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'trusted_unlock_request',
      request: request('request-acknowledged'),
    });

    await vi.waitFor(() => expect(leader.messages.filter(isTrustedRequest)).toHaveLength(1));
    coordinator.handleWorkbenchMessage(leader, {
      kind: 'trusted_unlock_ack',
      requestId: 'request-acknowledged',
    });
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(standby.messages.filter(isTrustedRequest)).toHaveLength(0);

    coordinator.handleWorkbenchMessage(leader, {
      kind: 'trusted_unlock_response',
      requestId: 'request-acknowledged',
      response: { requestId: 'request-acknowledged' },
      session: extSession(),
    });
    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual(expect.objectContaining({
      kind: 'trusted_unlock_response',
      requestId: 'request-acknowledged',
    })));
  });

  it('does not let a stale 401 generation remove a newer bearer', async () => {
    const store = new MemorySessionStore();
    store.session = { ...extSession(), token: 'new-token', generation: 4 };
    store.generation = 4;
    const coordinator = new BackgroundCoordinator(store);
    const sidePanel = new FakePort();
    coordinator.registerSidePanel(sidePanel);

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'session_invalidate',
      requestId: 'invalidate-1',
      expectedGeneration: 3,
    });

    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual({
      kind: 'session_operation_response',
      requestId: 'invalidate-1',
      session: expect.objectContaining({ token: 'new-token', generation: 4 }),
    }));
    expect(store.session).toMatchObject({ token: 'new-token', generation: 4 });
  });

  it('versions empty session state so late null messages can be rejected', async () => {
    const store = new MemorySessionStore();
    store.session = { ...extSession(), generation: 4 };
    store.generation = 4;
    const coordinator = new BackgroundCoordinator(store);
    const sidePanel = new FakePort();
    coordinator.registerSidePanel(sidePanel);
    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual(expect.objectContaining({
      kind: 'session_state',
      session: expect.objectContaining({ generation: 4 }),
      sessionGeneration: 4,
    })));

    coordinator.handleSidePanelMessage(sidePanel, {
      kind: 'session_invalidate',
      requestId: 'invalidate-current',
      expectedGeneration: 4,
    });

    await vi.waitFor(() => expect(sidePanel.messages).toContainEqual({
      kind: 'session_state',
      session: null,
      sessionGeneration: 5,
    }));
    expect(store.session).toBeNull();
    expect(store.generation).toBe(5);
  });
});

function isTrustedRequest(message: unknown): message is Record<string, unknown> {
  return Boolean(
    message
    && typeof message === 'object'
    && 'kind' in message
    && message.kind === 'trusted_unlock_request',
  );
}
