/// <reference types="chrome" />
import type { ExtensionTrustedUnlockRequest } from '@mima/e2ee';
import type { ExtSession, WorkbenchTrustedUnlockResult } from './protocol.ts';

const PORT_NAME = 'mima-sidepanel-v1';
const SESSION_OPERATION_TIMEOUT_MS = 10_000;
const RECONNECT_DELAY_MS = 100;

interface PendingTrustedUnlock {
  request: ExtensionTrustedUnlockRequest;
  promise: Promise<WorkbenchTrustedUnlockResult>;
  resolve: (response: WorkbenchTrustedUnlockResult) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingSessionOperation {
  message: object;
  resolve: (session: ExtSession | null) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class ExtensionTrustedUnlockBridge {
  private port: chrome.runtime.Port | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private started = false;
  private readonly pending = new Map<string, PendingTrustedUnlock>();
  private readonly sessionOperations = new Map<string, PendingSessionOperation>();
  private readonly lockedListeners = new Set<(accountId: string | null) => void>();
  private readonly unlockedListeners = new Set<(accountId: string | null) => void>();
  private readonly revokedListeners = new Set<(deviceId: string) => void>();
  private readonly sessionListeners = new Set<(session: ExtSession | null) => void>();
  private readonly workbenchStates = new Map<string, boolean>();
  private anonymousWorkbenchState: boolean | undefined;
  private lastSessionGeneration = 0;
  private sessionStateInitialized = false;

  start(): void {
    this.started = true;
    this.ensurePort();
  }

  request(request: ExtensionTrustedUnlockRequest): Promise<WorkbenchTrustedUnlockResult> {
    const existing = this.pending.get(request.requestId);
    if (existing) return existing.promise;
    let resolve!: (response: WorkbenchTrustedUnlockResult) => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<WorkbenchTrustedUnlockResult>((onResolve, onReject) => {
      resolve = onResolve;
      reject = onReject;
    });
    const timer = setTimeout(() => {
      this.pending.delete(request.requestId);
      reject(new Error(
        '工作台确认超时。请确认同一账号的工作台已经解锁，然后重试。',
      ));
    }, Math.max(0, Date.parse(request.expiresAt) - Date.now()));
    this.pending.set(request.requestId, { request, promise, resolve, reject, timer });
    this.post({ kind: 'trusted_unlock_request', request });
    return promise;
  }

  adoptSession(session: ExtSession, deviceId: string): Promise<ExtSession> {
    return this.sessionOperation({ kind: 'session_adopt', session, deviceId }).then((managed) => {
      if (!managed) throw new Error('扩展连接没有正确建立，请重试');
      return managed;
    });
  }

  loadSession(): Promise<ExtSession | null> {
    return this.sessionOperation({ kind: 'session_get' });
  }

  invalidateSession(expectedGeneration: number): Promise<ExtSession | null> {
    return this.sessionOperation({ kind: 'session_invalidate', expectedGeneration });
  }

  clearSession(): Promise<void> {
    return this.sessionOperation({ kind: 'session_clear' }).then(() => undefined);
  }

  completeTrustedUnlock(trustedRequestId: string): Promise<void> {
    return this.sessionOperation({
      kind: 'trusted_unlock_complete',
      trustedRequestId,
    }).then(() => undefined);
  }

  onWorkbenchLocked(listener: (accountId: string | null) => void): () => void {
    this.lockedListeners.add(listener);
    return () => this.lockedListeners.delete(listener);
  }

  onWorkbenchUnlocked(listener: (accountId: string | null) => void): () => void {
    this.unlockedListeners.add(listener);
    return () => this.unlockedListeners.delete(listener);
  }

  onDeviceRevoked(listener: (deviceId: string) => void): () => void {
    this.revokedListeners.add(listener);
    return () => this.revokedListeners.delete(listener);
  }

  onSessionChanged(listener: (session: ExtSession | null) => void): () => void {
    this.sessionListeners.add(listener);
    return () => this.sessionListeners.delete(listener);
  }

  isWorkbenchUnlocked(accountId: string | null | undefined): boolean {
    return Boolean(accountId && this.workbenchStates.get(accountId));
  }

  private sessionOperation(message: object): Promise<ExtSession | null> {
    const requestId = crypto.randomUUID();
    const request = { ...message, requestId };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.sessionOperations.delete(requestId);
        reject(new Error('扩展连接协调超时，请关闭侧边栏后重新打开'));
      }, SESSION_OPERATION_TIMEOUT_MS);
      this.sessionOperations.set(requestId, { message: request, resolve, reject, timer });
      this.post(request);
    });
  }

  private ensurePort(): chrome.runtime.Port | null {
    if (this.port) return this.port;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    try {
      const port = chrome.runtime.connect({ name: PORT_NAME });
      port.onMessage.addListener((message: unknown) => this.onMessage(message));
      port.onDisconnect.addListener(() => {
        if (this.port !== port) return;
        this.port = null;
        this.scheduleReconnect();
      });
      this.port = port;
      this.resendPending();
      return port;
    } catch {
      this.port = null;
      this.scheduleReconnect();
      return null;
    }
  }

  private scheduleReconnect(): void {
    if (!this.started || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.ensurePort();
    }, RECONNECT_DELAY_MS);
  }

  private resendPending(): void {
    const port = this.port;
    if (!port) return;
    try {
      for (const pending of this.pending.values()) {
        port.postMessage({ kind: 'trusted_unlock_request', request: pending.request });
      }
      for (const pending of this.sessionOperations.values()) port.postMessage(pending.message);
    } catch {
      this.port = null;
      this.scheduleReconnect();
    }
  }

  private post(message: object): void {
    const existingPort = this.port;
    const port = this.ensurePort();
    if (!port || !existingPort) return;
    try {
      port.postMessage(message);
    } catch {
      this.port = null;
      this.scheduleReconnect();
    }
  }

  private onMessage(message: unknown): void {
    if (!message || typeof message !== 'object' || !('kind' in message)) return;
    if (message.kind === 'workbench_locked' || message.kind === 'workbench_unlocked') {
      const accountId = 'accountId' in message && typeof message.accountId === 'string'
        ? message.accountId
        : null;
      const unlocked = message.kind === 'workbench_unlocked';
      if (accountId) {
        const previous = this.workbenchStates.get(accountId);
        this.workbenchStates.set(accountId, unlocked);
        if (previous === unlocked) return;
      } else {
        if (this.anonymousWorkbenchState === unlocked) return;
        this.anonymousWorkbenchState = unlocked;
      }
      const listeners = message.kind === 'workbench_unlocked'
        ? this.unlockedListeners
        : this.lockedListeners;
      for (const listener of listeners) listener(accountId);
      return;
    }
    if (
      message.kind === 'workbench_device_revoked'
      && 'deviceId' in message
      && typeof message.deviceId === 'string'
    ) {
      for (const listener of this.revokedListeners) listener(message.deviceId);
      return;
    }
    if (message.kind === 'session_state' && 'session' in message) {
      const session = (message.session ?? null) as ExtSession | null;
      const generation = 'sessionGeneration' in message
        && Number.isSafeInteger(message.sessionGeneration)
        && (message.sessionGeneration as number) >= 0
        ? message.sessionGeneration as number
        : validSessionGeneration(session?.generation)
          ? session.generation
          : null;
      if (!this.acceptSessionState(session, generation)) return;
      for (const listener of this.sessionListeners) listener(session);
      return;
    }
    if (!('requestId' in message) || typeof message.requestId !== 'string') return;
    if (message.kind === 'session_operation_response') {
      const pending = this.sessionOperations.get(message.requestId);
      if (!pending) return;
      this.sessionOperations.delete(message.requestId);
      clearTimeout(pending.timer);
      const session = 'session' in message ? (message.session as ExtSession | null) : null;
      this.rememberSession(session);
      pending.resolve(session);
      return;
    }
    const pending = this.pending.get(message.requestId);
    if (!pending) return;
    this.pending.delete(message.requestId);
    clearTimeout(pending.timer);
    if (
      message.kind === 'trusted_unlock_response'
      && 'response' in message
      && 'session' in message
    ) {
      this.rememberSession(message.session as ExtSession);
      pending.resolve({
        response: message.response,
        session: message.session,
      } as WorkbenchTrustedUnlockResult);
      return;
    }
    const detail = 'message' in message && typeof message.message === 'string'
      ? message.message
      : '工作台未能确认扩展。请确认工作台已解锁后重试。';
    pending.reject(new Error(detail));
  }

  private acceptSessionState(session: ExtSession | null, generation: number | null): boolean {
    if (generation === null) {
      if (this.sessionStateInitialized) return false;
      this.sessionStateInitialized = true;
      return true;
    }
    if (session === null) {
      if (this.sessionStateInitialized && generation <= this.lastSessionGeneration) return false;
    } else if (this.sessionStateInitialized && generation < this.lastSessionGeneration) {
      return false;
    }
    this.sessionStateInitialized = true;
    this.lastSessionGeneration = Math.max(this.lastSessionGeneration, generation);
    return true;
  }

  private rememberSession(session: ExtSession | null): void {
    if (!validSessionGeneration(session?.generation)) return;
    this.sessionStateInitialized = true;
    this.lastSessionGeneration = Math.max(this.lastSessionGeneration, session.generation);
  }
}

function validSessionGeneration(value: number | undefined): value is number {
  return Number.isSafeInteger(value) && (value ?? 0) >= 0;
}
