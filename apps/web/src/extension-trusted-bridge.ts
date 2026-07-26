/// <reference types="chrome" />
import type {
  ExtensionTrustedUnlockRequest,
} from '@mima/e2ee';
import { EXTENSION_WORKBENCH_WAKE_EVENT } from '@mima/e2ee';
import type { ExtensionTrustedUnlockResult } from '@mima/client-core';

const EXTENSION_ID = import.meta.env.VITE_MIMA_EXTENSION_ID
  ?? 'gkhbkfdgghiaoohpldbjkpmopaojjhhp';
const PORT_NAME = 'mima-workbench-v1';
const WORKBENCH_PROTOCOL_VERSION = 2;
const PROBE_TIMEOUT_MS = 750;

interface PendingProbe {
  id: string;
  port: chrome.runtime.Port;
  timer: ReturnType<typeof setTimeout>;
}

export class WorkbenchExtensionBridge {
  private port: chrome.runtime.Port | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingProbe: PendingProbe | null = null;
  private stopped = false;
  private readonly endpointId = crypto.randomUUID();
  private readonly wakeListener = () => {
    this.updatePresence();
    if (document.visibilityState !== 'visible') {
      this.reconnect();
      return;
    }
    this.probeConnection();
  };
  private readonly presenceListener = () => this.updatePresence();
  private state = {
    accountId: null as string | null,
    unlocked: false,
    stateGeneration: 0,
    visibility: document.visibilityState === 'visible' ? 'visible' as const : 'hidden' as const,
    focused: document.hasFocus(),
  };

  constructor(
    private readonly respond: (
      request: ExtensionTrustedUnlockRequest,
      needsSession: boolean,
    ) => Promise<ExtensionTrustedUnlockResult>,
  ) {}

  start(): void {
    this.stopped = false;
    window.addEventListener(EXTENSION_WORKBENCH_WAKE_EVENT, this.wakeListener);
    window.addEventListener('focus', this.presenceListener);
    window.addEventListener('blur', this.presenceListener);
    window.addEventListener('pageshow', this.presenceListener);
    document.addEventListener('visibilitychange', this.presenceListener);
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.clearPendingProbe();
    window.removeEventListener(EXTENSION_WORKBENCH_WAKE_EVENT, this.wakeListener);
    window.removeEventListener('focus', this.presenceListener);
    window.removeEventListener('blur', this.presenceListener);
    window.removeEventListener('pageshow', this.presenceListener);
    document.removeEventListener('visibilitychange', this.presenceListener);
    this.port?.disconnect();
    this.port = null;
  }

  setState(accountId: string | null, unlocked: boolean): void {
    const normalizedUnlocked = Boolean(accountId && unlocked);
    if (
      this.state.accountId === accountId
      && this.state.unlocked === normalizedUnlocked
      && this.state.stateGeneration > 0
    ) return;
    this.state = {
      ...this.state,
      accountId,
      unlocked: normalizedUnlocked,
      stateGeneration: this.state.stateGeneration + 1,
    };
    this.postState();
  }

  notifyLocked(): void {
    this.setState(this.state.accountId, false);
  }

  notifyUnlocked(): void {
    this.setState(this.state.accountId, true);
  }

  notifyDeviceRevoked(deviceId: string): void {
    this.post({ kind: 'workbench_device_revoked', deviceId });
  }

  private connect(): void {
    if (this.stopped || this.port || typeof chrome === 'undefined' || !chrome.runtime?.connect) return;
    try {
      const port = chrome.runtime.connect(EXTENSION_ID, { name: PORT_NAME });
      port.onMessage.addListener((message: unknown) => this.onMessage(port, message));
      port.onDisconnect.addListener(() => {
        if (this.port !== port) return;
        this.clearPendingProbe(port);
        this.port = null;
        this.scheduleReconnect();
      });
      this.port = port;
      this.postState();
    } catch {
      this.port = null;
      this.scheduleReconnect();
    }
  }

  private reconnect(): void {
    if (this.stopped) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    const previous = this.port;
    this.clearPendingProbe(previous ?? undefined);
    this.port = null;
    try {
      previous?.disconnect();
    } catch {
      this.port = null;
    }
    this.connect();
  }

  private onMessage(port: chrome.runtime.Port, message: unknown): void {
    if (
      message
      && typeof message === 'object'
      && 'kind' in message
      && message.kind === 'workbench_probe_ack'
      && 'probeId' in message
      && typeof message.probeId === 'string'
      && this.pendingProbe?.port === port
      && this.pendingProbe.id === message.probeId
    ) {
      this.clearPendingProbe(port);
      return;
    }
    if (
      !message ||
      typeof message !== 'object' ||
      !('kind' in message) ||
      message.kind !== 'trusted_unlock_request' ||
      !('request' in message)
    ) return;
    const request = message.request as ExtensionTrustedUnlockRequest;
    const needsSession = !('needsSession' in message) || message.needsSession !== false;
    if (!this.postToCurrentPort(port, {
      kind: 'trusted_unlock_ack',
      requestId: request.requestId,
      endpointId: this.endpointId,
    })) return;
    void this.respond(request, needsSession).then((result) => {
      this.postToCurrentPort(port, {
        kind: 'trusted_unlock_response',
        requestId: request.requestId,
        response: result.response,
        ...(result.session ? { session: result.session } : {}),
      });
    }).catch((error) => {
      this.postToCurrentPort(port, {
        kind: 'trusted_unlock_error',
        requestId: request.requestId,
        message: error instanceof Error ? error.message : '工作台未能确认扩展',
      });
    });
  }

  private postToCurrentPort(port: chrome.runtime.Port, message: object): boolean {
    if (this.port !== port) return false;
    try {
      port.postMessage(message);
      return true;
    } catch {
      if (this.port === port) this.reconnect();
      return false;
    }
  }

  private post(message: object): void {
    this.connect();
    try {
      this.port?.postMessage(message);
    } catch {
      this.reconnect();
    }
  }

  private postState(): void {
    if (!this.port) {
      this.connect();
      return;
    }
    try {
      this.port.postMessage({
        kind: 'workbench_state',
        protocolVersion: WORKBENCH_PROTOCOL_VERSION,
        endpointId: this.endpointId,
        ...this.state,
      });
    } catch {
      this.reconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 1_500);
  }

  private probeConnection(): void {
    if (this.stopped) return;
    const port = this.port;
    if (!port) {
      this.connect();
      return;
    }
    this.clearPendingProbe(port);
    const probeId = crypto.randomUUID();
    const timer = setTimeout(() => {
      if (this.pendingProbe?.id !== probeId || this.pendingProbe.port !== port) return;
      this.pendingProbe = null;
      if (this.port === port) this.reconnect();
    }, PROBE_TIMEOUT_MS);
    this.pendingProbe = { id: probeId, port, timer };
    try {
      port.postMessage({ kind: 'workbench_probe', probeId, endpointId: this.endpointId });
    } catch {
      this.clearPendingProbe(port);
      this.reconnect();
    }
  }

  private clearPendingProbe(port?: chrome.runtime.Port): void {
    if (!this.pendingProbe || (port && this.pendingProbe.port !== port)) return;
    clearTimeout(this.pendingProbe.timer);
    this.pendingProbe = null;
  }

  private updatePresence(): void {
    const visibility = document.visibilityState === 'visible' ? 'visible' as const : 'hidden' as const;
    const focused = document.hasFocus();
    if (this.state.visibility === visibility && this.state.focused === focused) return;
    this.state = {
      ...this.state,
      visibility,
      focused,
      stateGeneration: this.state.stateGeneration + 1,
    };
    this.postState();
  }
}
