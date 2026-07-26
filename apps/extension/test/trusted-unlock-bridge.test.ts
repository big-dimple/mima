import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  ExtensionTrustedUnlockRequest,
  ExtensionTrustedUnlockResponse,
} from '@mima/e2ee';
import { ExtensionTrustedUnlockBridge } from '../src/trusted-unlock-bridge.ts';
import { extSession } from './helpers.ts';

class FakePort {
  readonly messages: unknown[] = [];
  private messageListener: ((message: unknown) => void) | null = null;
  private disconnectListener: (() => void) | null = null;
  readonly onMessage = {
    addListener: (listener: (message: unknown) => void) => { this.messageListener = listener; },
  };
  readonly onDisconnect = {
    addListener: (listener: () => void) => { this.disconnectListener = listener; },
  };

  postMessage(message: unknown) { this.messages.push(message); }
  receive(message: unknown) { this.messageListener?.(message); }
  disconnect() { this.disconnectListener?.(); }
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('ExtensionTrustedUnlockBridge', () => {
  it('correlates a one-time workbench response with the extension request', async () => {
    const port = new FakePort();
    const connect = vi.fn().mockReturnValue(port);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const bridge = new ExtensionTrustedUnlockBridge();
    const request = {
      requestId: 'request-1',
      expiresAt: new Date(Date.now() + 5_000).toISOString(),
    } as ExtensionTrustedUnlockRequest;
    const response = { requestId: request.requestId } as ExtensionTrustedUnlockResponse;
    const session = extSession();

    const pending = bridge.request(request);
    expect(connect).toHaveBeenCalledWith({ name: 'mima-sidepanel-v1' });
    expect(port.messages).toEqual([{ kind: 'trusted_unlock_request', request }]);
    port.receive({
      kind: 'trusted_unlock_response',
      requestId: request.requestId,
      response,
      session,
    });
    await expect(pending).resolves.toEqual({ response, session });
  });

  it('locks and retries the side panel when workbench state changes', () => {
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const bridge = new ExtensionTrustedUnlockBridge();
    const locked = vi.fn();
    const unlocked = vi.fn();
    const revoked = vi.fn();
    bridge.onWorkbenchLocked(locked);
    bridge.onWorkbenchUnlocked(unlocked);
    bridge.onDeviceRevoked(revoked);

    const request = {
      requestId: 'request-2',
      expiresAt: new Date(Date.now() + 5_000).toISOString(),
    } as ExtensionTrustedUnlockRequest;
    void bridge.request(request).catch(() => undefined);
    port.receive({ kind: 'workbench_locked' });
    port.receive({ kind: 'workbench_locked' });
    port.receive({ kind: 'workbench_unlocked' });
    port.receive({ kind: 'workbench_unlocked' });
    port.receive({ kind: 'workbench_device_revoked', deviceId: 'extension-device-1' });

    expect(locked).toHaveBeenCalledOnce();
    expect(unlocked).toHaveBeenCalledOnce();
    expect(revoked).toHaveBeenCalledWith('extension-device-1');
    port.disconnect();
  });

  it('reconnects and resends an in-flight request after the runtime port closes', async () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    const connect = vi.fn()
      .mockReturnValueOnce(first)
      .mockReturnValueOnce(second);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const bridge = new ExtensionTrustedUnlockBridge();
    bridge.start();
    const request = {
      requestId: 'request-reconnect',
      expiresAt: new Date(Date.now() + 5_000).toISOString(),
    } as ExtensionTrustedUnlockRequest;
    const response = { requestId: request.requestId } as ExtensionTrustedUnlockResponse;
    const session = extSession();

    const pending = bridge.request(request);
    first.disconnect();
    await vi.advanceTimersByTimeAsync(100);

    expect(connect).toHaveBeenCalledTimes(2);
    expect(second.messages).toContainEqual({ kind: 'trusted_unlock_request', request });
    second.receive({
      kind: 'trusted_unlock_response',
      requestId: request.requestId,
      response,
      session,
    });
    await expect(pending).resolves.toEqual({ response, session });
  });

  it('coordinates conditional session invalidation and receives shared session changes', async () => {
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const bridge = new ExtensionTrustedUnlockBridge();
    const changed = vi.fn();
    bridge.onSessionChanged(changed);
    bridge.start();

    const pending = bridge.invalidateSession(3);
    const operation = port.messages.find((message) => (
      message
      && typeof message === 'object'
      && 'kind' in message
      && message.kind === 'session_invalidate'
    )) as { requestId: string };
    const replacement = { ...extSession(), token: 'replacement', generation: 4 };
    port.receive({ kind: 'session_state', session: replacement });
    port.receive({
      kind: 'session_operation_response',
      requestId: operation.requestId,
      session: replacement,
    });

    await expect(pending).resolves.toEqual(replacement);
    expect(changed).toHaveBeenCalledWith(replacement);
  });

  it('loads the background-owned session and reliably confirms a completed unlock transaction', async () => {
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const bridge = new ExtensionTrustedUnlockBridge();
    bridge.start();

    const loaded = bridge.loadSession();
    const loadMessage = port.messages.find((message) => (
      message
      && typeof message === 'object'
      && 'kind' in message
      && message.kind === 'session_get'
    )) as { requestId: string };
    const session = { ...extSession(), generation: 4 };
    port.receive({
      kind: 'session_operation_response',
      requestId: loadMessage.requestId,
      session,
    });
    await expect(loaded).resolves.toEqual(session);

    const completed = bridge.completeTrustedUnlock('trusted-request-1');
    const completionMessage = port.messages.find((message) => (
      message
      && typeof message === 'object'
      && 'kind' in message
      && message.kind === 'trusted_unlock_complete'
    )) as { requestId: string; trustedRequestId: string };
    expect(completionMessage.trustedRequestId).toBe('trusted-request-1');
    port.receive({
      kind: 'session_operation_response',
      requestId: completionMessage.requestId,
      session: null,
    });
    await expect(completed).resolves.toBeUndefined();
  });

  it('ignores a late legacy null state after a newer trusted session arrives', async () => {
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const bridge = new ExtensionTrustedUnlockBridge();
    const changed = vi.fn();
    bridge.onSessionChanged(changed);
    const request = {
      requestId: 'request-generation-fence',
      expiresAt: new Date(Date.now() + 5_000).toISOString(),
    } as ExtensionTrustedUnlockRequest;
    const session = { ...extSession(), generation: 7 };

    const pending = bridge.request(request);
    port.receive({
      kind: 'trusted_unlock_response',
      requestId: request.requestId,
      response: { requestId: request.requestId },
      session,
    });
    await pending;
    port.receive({ kind: 'session_state', session: null });
    port.receive({ kind: 'session_state', session: null, sessionGeneration: 7 });

    expect(changed).not.toHaveBeenCalled();
    port.receive({ kind: 'session_state', session: null, sessionGeneration: 8 });
    expect(changed).toHaveBeenCalledOnce();
    expect(changed).toHaveBeenCalledWith(null);
  });
});
