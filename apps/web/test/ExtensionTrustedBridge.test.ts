import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  ExtensionTrustedUnlockRequest,
  ExtensionTrustedUnlockResponse,
} from '@mima/e2ee';
import { EXTENSION_WORKBENCH_WAKE_EVENT } from '@mima/e2ee';
import type { ExtensionSessionResponse } from '@mima/contracts';
import { WorkbenchExtensionBridge } from '../src/extension-trusted-bridge.ts';

class FakePort {
  readonly messages: unknown[] = [];
  disconnected = false;
  private messageListener: ((message: unknown) => void) | null = null;
  private disconnectListener: (() => void) | null = null;
  readonly onMessage = {
    addListener: (listener: (message: unknown) => void) => { this.messageListener = listener; },
  };
  readonly onDisconnect = {
    addListener: (listener: () => void) => { this.disconnectListener = listener; },
  };

  postMessage(message: unknown) { this.messages.push(message); }
  disconnect() { this.disconnected = true; this.disconnectListener?.(); }
  receive(message: unknown) { this.messageListener?.(message); }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('WorkbenchExtensionBridge', () => {
  it('uses the fixed extension channel and returns only a bound trusted unlock response', async () => {
    const port = new FakePort();
    const connect = vi.fn().mockReturnValue(port);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const request = { requestId: 'request-1' } as ExtensionTrustedUnlockRequest;
    const response = { requestId: 'request-1' } as ExtensionTrustedUnlockResponse;
    const session = {
      token: 'opaque-token',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      user: { id: 'user-1' },
    } as ExtensionSessionResponse;
    const respond = vi.fn().mockResolvedValue({ response, session });
    const bridge = new WorkbenchExtensionBridge(respond);

    bridge.start();
    expect(connect).toHaveBeenCalledWith(
      'gkhbkfdgghiaoohpldbjkpmopaojjhhp',
      { name: 'mima-workbench-v1' },
    );
    port.receive({ kind: 'trusted_unlock_request', request });
    await vi.waitFor(() => expect(respond).toHaveBeenCalledWith(request, true));
    expect(port.messages).toContainEqual({
      kind: 'trusted_unlock_response',
      requestId: request.requestId,
      response,
      session,
    });

    bridge.setState('user-1', true);
    bridge.notifyLocked();
    bridge.notifyDeviceRevoked('extension-device-1');
    expect(port.messages).toContainEqual(expect.objectContaining({
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: true,
      stateGeneration: 1,
      protocolVersion: 2,
    }));
    expect(port.messages).toContainEqual(expect.objectContaining({
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: false,
      stateGeneration: 2,
      protocolVersion: 2,
    }));
    expect(port.messages).toContainEqual({
      kind: 'workbench_device_revoked',
      deviceId: 'extension-device-1',
    });
    bridge.stop();
    expect(port.disconnected).toBe(true);
  });

  it('returns a user-safe error when the workbench cannot approve the request', async () => {
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const bridge = new WorkbenchExtensionBridge(async () => {
      throw new Error('密码库尚未解锁，不能确认扩展');
    });
    bridge.start();
    port.receive({
      kind: 'trusted_unlock_request',
      request: { requestId: 'request-2' },
    });

    await vi.waitFor(() => expect(port.messages).toContainEqual({
      kind: 'trusted_unlock_error',
      requestId: 'request-2',
      message: '密码库尚未解锁，不能确认扩展',
    }));
    bridge.stop();
  });

  it('skips bearer renewal when the background already has a valid session', async () => {
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const request = { requestId: 'request-reuse' } as ExtensionTrustedUnlockRequest;
    const response = { requestId: request.requestId } as ExtensionTrustedUnlockResponse;
    const respond = vi.fn().mockResolvedValue({ response });
    const bridge = new WorkbenchExtensionBridge(respond);
    bridge.start();

    port.receive({ kind: 'trusted_unlock_request', request, needsSession: false });

    await vi.waitFor(() => expect(respond).toHaveBeenCalledWith(request, false));
    expect(port.messages).toContainEqual({
      kind: 'trusted_unlock_response',
      requestId: request.requestId,
      response,
    });
    bridge.stop();
  });

  it('replays the current unlock state after the extension runtime reconnects', async () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    const connect = vi.fn()
      .mockReturnValueOnce(first)
      .mockReturnValueOnce(second);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const bridge = new WorkbenchExtensionBridge(vi.fn());
    bridge.start();
    bridge.setState('user-1', true);

    first.disconnect();
    await vi.advanceTimersByTimeAsync(1_500);

    expect(connect).toHaveBeenCalledTimes(2);
    expect(second.messages).toContainEqual(expect.objectContaining({
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: true,
      stateGeneration: 1,
      protocolVersion: 2,
    }));
    bridge.stop();
  });

  it('keeps a healthy port connected when the extension probes a visible workbench', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    const connect = vi.fn().mockReturnValue(port);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const bridge = new WorkbenchExtensionBridge(vi.fn());
    bridge.start();
    bridge.setState('user-1', true);

    window.dispatchEvent(new CustomEvent(EXTENSION_WORKBENCH_WAKE_EVENT));
    const probe = port.messages.find((message) => (
      message
      && typeof message === 'object'
      && 'kind' in message
      && message.kind === 'workbench_probe'
    )) as { probeId: string };
    port.receive({ kind: 'workbench_probe_ack', probeId: probe.probeId });
    await vi.advanceTimersByTimeAsync(1_000);

    expect(port.disconnected).toBe(false);
    expect(connect).toHaveBeenCalledTimes(1);
    bridge.stop();
  });

  it('replays the authoritative unlock state when a healthy workbench is awakened', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    vi.stubGlobal('chrome', { runtime: { connect: vi.fn().mockReturnValue(port) } });
    const bridge = new WorkbenchExtensionBridge(vi.fn());
    bridge.start();
    bridge.setState('user-1', true);

    window.dispatchEvent(new CustomEvent(EXTENSION_WORKBENCH_WAKE_EVENT));
    const stateMessages = port.messages.filter((message) => (
      message
      && typeof message === 'object'
      && 'kind' in message
      && message.kind === 'workbench_state'
    ));

    expect(stateMessages).toHaveLength(3);
    expect(stateMessages.at(-1)).toEqual(expect.objectContaining({
      accountId: 'user-1',
      unlocked: true,
      stateGeneration: 2,
      protocolVersion: 2,
    }));
    bridge.stop();
  });

  it('reconnects a hidden workbench immediately without relying on throttled page timers', () => {
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    const first = new FakePort();
    const second = new FakePort();
    const connect = vi.fn()
      .mockReturnValueOnce(first)
      .mockReturnValueOnce(second);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const bridge = new WorkbenchExtensionBridge(vi.fn());
    bridge.start();
    bridge.setState('user-1', true);

    window.dispatchEvent(new CustomEvent(EXTENSION_WORKBENCH_WAKE_EVENT));

    expect(first.disconnected).toBe(true);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(second.messages).toContainEqual(expect.objectContaining({
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: true,
      visibility: 'hidden',
      protocolVersion: 2,
    }));
    bridge.stop();
  });

  it('reconnects only after a wake probe proves the old port unresponsive', async () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    const connect = vi.fn()
      .mockReturnValueOnce(first)
      .mockReturnValueOnce(second);
    vi.stubGlobal('chrome', { runtime: { connect } });
    const bridge = new WorkbenchExtensionBridge(vi.fn());
    bridge.start();
    bridge.setState('user-1', true);

    window.dispatchEvent(new CustomEvent(EXTENSION_WORKBENCH_WAKE_EVENT));
    expect(first.disconnected).toBe(false);
    await vi.advanceTimersByTimeAsync(750);

    expect(first.disconnected).toBe(true);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(second.messages).toContainEqual(expect.objectContaining({
      kind: 'workbench_state',
      accountId: 'user-1',
      unlocked: true,
      stateGeneration: 2,
      protocolVersion: 2,
    }));
    bridge.stop();
  });
});
