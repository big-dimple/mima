import type { ExtensionTrustedUnlockRequest } from '@mima/e2ee';
import type { ExtSession } from './protocol.ts';

export interface CoordinatorPort {
  postMessage(message: unknown): void;
}

export interface CoordinatorWorkbenchEndpoint {
  tabId: number | null;
  documentId: string | null;
  origin: string;
}

export interface CoordinatorSessionStore {
  loadSession(): Promise<ExtSession | null>;
  saveSession(session: ExtSession): Promise<void>;
  removeSession(): Promise<void>;
  loadGeneration(): Promise<number>;
  saveGeneration(generation: number): Promise<void>;
}

interface WorkbenchState {
  accountId: string | null;
  unlocked: boolean;
  generation: number;
  order: number;
  activityOrder: number;
  protocolVersion: number;
  endpointId: string | null;
  endpoint: CoordinatorWorkbenchEndpoint | null;
  visibility: 'visible' | 'hidden';
  focused: boolean;
}

interface PendingTrustedUnlock {
  request: ExtensionTrustedUnlockRequest;
  sidePanel: CoordinatorPort | null;
  timer: ReturnType<typeof setTimeout>;
  attemptTimer: ReturnType<typeof setTimeout> | null;
  status: 'queued' | 'dispatched';
  acknowledged: boolean;
  selectedWorkbench: CoordinatorPort | null;
  needsSession: boolean;
  recoveryKey: string | null;
  attemptedWorkbenches: Set<CoordinatorPort>;
  createdAt: number;
  legacyGraceTimer: ReturnType<typeof setTimeout> | null;
}

interface AwaitingTrustedUnlockCompletion {
  recoveryKey: string;
  sidePanel: CoordinatorPort;
  timer: ReturnType<typeof setTimeout>;
}

const TRUSTED_UNLOCK_TIMEOUT_MESSAGE =
  '没有找到可确认此账号的已解锁工作台。请先打开并解锁同一账号的工作台，然后重试。';
const TRUSTED_UNLOCK_COMPLETION_TIMEOUT_MS = 35_000;

export class BackgroundCoordinator {
  private readonly workbenches = new Map<CoordinatorPort, WorkbenchState>();
  private readonly sidePanels = new Set<CoordinatorPort>();
  private readonly pending = new Map<string, PendingTrustedUnlock>();
  private readonly activeRecoveries = new Set<string>();
  private readonly awaitingCompletion = new Map<string, AwaitingTrustedUnlockCompletion>();
  private readonly leaders = new Map<string, CoordinatorPort>();
  private nextWorkbenchOrder = 0;
  private nextActivityOrder = 0;
  private sessionQueue: Promise<void> = Promise.resolve();
  private pumpPromise: Promise<void> | null = null;
  private pumpRequested = false;

  constructor(
    private readonly store: CoordinatorSessionStore,
    private readonly now: () => number = () => Date.now(),
    private readonly workbenchAckTimeoutMs = 1_500,
    private readonly legacyWorkbenchGraceMs = 1_000,
  ) {}

  registerWorkbench(
    port: CoordinatorPort,
    endpoint: CoordinatorWorkbenchEndpoint | null = null,
  ): void {
    this.workbenches.set(port, {
      accountId: null,
      unlocked: false,
      generation: -1,
      order: this.nextWorkbenchOrder++,
      activityOrder: -1,
      protocolVersion: 1,
      endpointId: null,
      endpoint,
      visibility: 'hidden',
      focused: false,
    });
  }

  hasRegisteredWorkbench(): boolean {
    return this.workbenches.size > 0;
  }

  hasUnlockedWorkbench(accountId: string): boolean {
    return [...this.workbenches.values()].some(
      (state) => state.accountId === accountId && state.unlocked,
    );
  }

  unregisterWorkbench(port: CoordinatorPort): void {
    const previous = this.workbenches.get(port);
    this.workbenches.delete(port);
    if (previous?.accountId && this.leaders.get(previous.accountId) === port) {
      this.leaders.delete(previous.accountId);
    }
    for (const pending of this.pending.values()) {
      if (pending.selectedWorkbench !== port) continue;
      this.releaseSelectedWorkbench(pending, true);
    }
    if (previous?.accountId) this.broadcastWorkbenchState(previous.accountId);
    this.requestPump();
  }

  registerSidePanel(port: CoordinatorPort): void {
    this.sidePanels.add(port);
    void this.withSessionLock(async () => {
      const session = await this.loadManagedSession();
      const generation = session?.generation ?? await this.store.loadGeneration();
      this.postSessionState(port, session, generation);
    });
    for (const accountId of this.knownAccountIds()) {
      this.postWorkbenchState(port, accountId);
    }
  }

  unregisterSidePanel(port: CoordinatorPort): void {
    this.sidePanels.delete(port);
    for (const pending of this.pending.values()) {
      if (pending.sidePanel === port) pending.sidePanel = null;
    }
    for (const [requestId, completion] of this.awaitingCompletion) {
      if (completion.sidePanel === port) this.releaseAwaitingCompletion(requestId);
    }
  }

  handleWorkbenchMessage(port: CoordinatorPort, message: unknown): void {
    if (!isRecord(message) || typeof message.kind !== 'string') return;
    if (message.kind === 'workbench_probe' && typeof message.probeId === 'string') {
      this.postWorkbench(port, { kind: 'workbench_probe_ack', probeId: message.probeId });
      return;
    }
    if (message.kind === 'workbench_state') {
      this.handleWorkbenchState(port, message);
      return;
    }
    if (message.kind === 'workbench_locked' || message.kind === 'workbench_unlocked') {
      const current = this.workbenches.get(port);
      if (!current?.accountId) return;
      this.handleWorkbenchState(port, {
        kind: 'workbench_state',
        protocolVersion: current.protocolVersion,
        endpointId: current.endpointId,
        accountId: current.accountId,
        unlocked: message.kind === 'workbench_unlocked',
        stateGeneration: current.generation + 1,
        visibility: current.visibility,
        focused: current.focused,
      });
      return;
    }
    if (message.kind === 'workbench_device_revoked' && typeof message.deviceId === 'string') {
      this.broadcast({ kind: 'workbench_device_revoked', deviceId: message.deviceId });
      void this.withSessionLock(async () => {
        const session = await this.loadManagedSession();
        if (session?.deviceId !== message.deviceId) return;
        const generation = await this.clearManagedSession();
        this.broadcastSessionState(null, generation);
      });
      return;
    }
    if (
      message.kind === 'trusted_unlock_ack'
      && typeof message.requestId === 'string'
    ) {
      this.handleTrustedUnlockAck(port, message.requestId);
      return;
    }
    if (
      message.kind === 'trusted_unlock_response'
      || message.kind === 'trusted_unlock_error'
    ) {
      this.handleTrustedUnlockResult(port, message);
    }
  }

  handleSidePanelMessage(port: CoordinatorPort, message: unknown): void {
    if (!isRecord(message) || typeof message.kind !== 'string') return;
    if (message.kind === 'trusted_unlock_request' && isTrustedUnlockRequest(message.request)) {
      this.enqueueTrustedUnlock(port, message.request);
      return;
    }
    if (message.kind === 'session_get' && typeof message.requestId === 'string') {
      void this.withSessionLock(async () => {
        const session = await this.loadManagedSession();
        this.post(port, { kind: 'session_operation_response', requestId: message.requestId, session });
      });
      return;
    }
    if (
      message.kind === 'trusted_unlock_complete'
      && typeof message.requestId === 'string'
      && typeof message.trustedRequestId === 'string'
    ) {
      const completion = this.awaitingCompletion.get(message.trustedRequestId);
      if (completion?.sidePanel === port) {
        this.releaseAwaitingCompletion(message.trustedRequestId);
      }
      this.post(port, {
        kind: 'session_operation_response',
        requestId: message.requestId,
        session: null,
      });
      return;
    }
    if (message.kind === 'session_adopt' && typeof message.requestId === 'string') {
      if (!isExtSession(message.session) || typeof message.deviceId !== 'string') return;
      const rawSession = message.session;
      const deviceId = message.deviceId;
      const requestId = message.requestId;
      void this.withSessionLock(async () => {
        const session = await this.adoptSession(rawSession, deviceId);
        this.broadcastSessionState(session, session.generation ?? 0);
        this.post(port, { kind: 'session_operation_response', requestId, session });
        this.requestPump();
      });
      return;
    }
    if (
      message.kind === 'session_invalidate'
      && typeof message.requestId === 'string'
      && Number.isSafeInteger(message.expectedGeneration)
    ) {
      void this.withSessionLock(async () => {
        const state = await this.invalidateSession(message.expectedGeneration as number);
        this.broadcastSessionState(state.session, state.generation);
        this.post(port, {
          kind: 'session_operation_response',
          requestId: message.requestId,
          session: state.session,
        });
        this.requestPump();
      });
      return;
    }
    if (message.kind === 'session_clear' && typeof message.requestId === 'string') {
      void this.withSessionLock(async () => {
        const generation = await this.clearManagedSession();
        this.broadcastSessionState(null, generation);
        this.post(port, {
          kind: 'session_operation_response',
          requestId: message.requestId,
          session: null,
        });
        this.requestPump();
      });
    }
  }

  private handleWorkbenchState(port: CoordinatorPort, message: Record<string, unknown>): void {
    const current = this.workbenches.get(port);
    if (!current) return;
    const protocolVersion = Number.isSafeInteger(message.protocolVersion)
      && (message.protocolVersion as number) >= 2
      ? message.protocolVersion as number
      : 1;
    const endpointId = protocolVersion >= 2 && typeof message.endpointId === 'string'
      && message.endpointId.length >= 8
      ? message.endpointId
      : null;
    if (protocolVersion >= 2 && !endpointId) return;
    if (current.endpointId && endpointId !== current.endpointId) return;
    const accountId = typeof message.accountId === 'string' && message.accountId
      ? message.accountId
      : null;
    const unlocked = message.unlocked === true && accountId !== null;
    const generation = Number.isSafeInteger(message.stateGeneration)
      ? message.stateGeneration as number
      : current.generation + 1;
    if (generation <= current.generation) return;
    const previousAccountId = current.accountId;
    const visibility = message.visibility === 'visible' ? 'visible' : 'hidden';
    const focused = message.focused === true;
    const activityOrder = unlocked && visibility === 'visible' && focused
      ? this.nextActivityOrder++
      : current.activityOrder;
    this.workbenches.set(port, {
      ...current,
      accountId,
      unlocked,
      generation,
      activityOrder,
      protocolVersion,
      endpointId,
      visibility,
      focused,
    });
    for (const pending of this.pending.values()) pending.attemptedWorkbenches.delete(port);

    if (previousAccountId && previousAccountId !== accountId && this.leaders.get(previousAccountId) === port) {
      this.leaders.delete(previousAccountId);
    }
    if (!unlocked && previousAccountId && this.leaders.get(previousAccountId) === port) {
      this.leaders.delete(previousAccountId);
    }
    if (accountId && unlocked && visibility === 'visible' && focused) {
      this.leaders.set(accountId, port);
    }

    if (!unlocked) {
      for (const pending of this.pending.values()) {
        if (pending.selectedWorkbench !== port) continue;
        this.releaseSelectedWorkbench(pending, true);
      }
    }

    if (previousAccountId && previousAccountId !== accountId) {
      this.broadcastWorkbenchState(previousAccountId);
    }
    if (accountId) this.broadcastWorkbenchState(accountId);
    this.requestPump();
  }

  private enqueueTrustedUnlock(
    sidePanel: CoordinatorPort,
    request: ExtensionTrustedUnlockRequest,
  ): void {
    const existing = this.pending.get(request.requestId);
    if (existing) {
      existing.sidePanel = sidePanel;
      return;
    }
    const delay = Math.max(0, Date.parse(request.expiresAt) - this.now());
    const pending: PendingTrustedUnlock = {
      request,
      sidePanel,
      timer: setTimeout(() => this.timeoutTrustedUnlock(request.requestId), delay),
      attemptTimer: null,
      status: 'queued',
      acknowledged: false,
      selectedWorkbench: null,
      needsSession: false,
      recoveryKey: null,
      attemptedWorkbenches: new Set(),
      createdAt: this.now(),
      legacyGraceTimer: null,
    };
    if (this.legacyWorkbenchGraceMs > 0) {
      pending.legacyGraceTimer = setTimeout(() => {
        pending.legacyGraceTimer = null;
        this.requestPump();
      }, Math.min(this.legacyWorkbenchGraceMs, delay));
    }
    this.pending.set(request.requestId, pending);
    this.requestPump();
  }

  private handleTrustedUnlockResult(port: CoordinatorPort, message: Record<string, unknown>): void {
    if (typeof message.requestId !== 'string') return;
    const pending = this.pending.get(message.requestId);
    if (!pending || pending.status !== 'dispatched' || pending.selectedWorkbench !== port) return;
    if (message.kind === 'trusted_unlock_error') {
      this.releaseSelectedWorkbench(pending, true);
      this.requestPump();
      return;
    }
    if (!('response' in message)) return;
    if (pending.attemptTimer) clearTimeout(pending.attemptTimer);
    pending.attemptTimer = null;

    void this.withSessionLock(async () => {
      let session: ExtSession | null;
      if (isExtSession(message.session)) {
        session = await this.adoptSession(message.session, pending.request.deviceId);
        this.broadcastSessionState(session, session.generation ?? 0);
      } else {
        session = await this.loadManagedSession();
      }
      if (!session || !this.sessionMatchesRequest(session, pending.request)) {
        this.releaseSelectedWorkbench(pending, true);
        this.requestPump();
        return;
      }
      this.completeTrustedUnlock(pending, message.response, session);
      this.requestPump();
    });
  }

  private handleTrustedUnlockAck(port: CoordinatorPort, requestId: string): void {
    const pending = this.pending.get(requestId);
    if (!pending || pending.status !== 'dispatched' || pending.selectedWorkbench !== port) return;
    pending.acknowledged = true;
    if (pending.attemptTimer) clearTimeout(pending.attemptTimer);
    pending.attemptTimer = null;
  }

  private requestPump(): void {
    this.pumpRequested = true;
    if (this.pumpPromise) return;
    this.pumpPromise = this.runPump().finally(() => {
      this.pumpPromise = null;
      if (this.pumpRequested) this.requestPump();
    });
  }

  private async runPump(): Promise<void> {
    while (this.pumpRequested) {
      this.pumpRequested = false;
      for (const pending of this.pending.values()) {
        if (pending.status !== 'queued' || !pending.sidePanel) continue;
        if (Date.parse(pending.request.expiresAt) <= this.now()) {
          this.timeoutTrustedUnlock(pending.request.requestId);
          continue;
        }
        const workbench = this.selectWorkbench(pending);
        if (!workbench) continue;
        const session = await this.withSessionLock(
          async () => this.loadManagedSession(),
        );
        const needsSession = !session || !this.sessionMatchesRequest(session, pending.request);
        const recoveryKey = `${pending.request.accountId}:${pending.request.deviceId}`;
        if (this.activeRecoveries.has(recoveryKey)) continue;
        pending.status = 'dispatched';
        pending.acknowledged = false;
        pending.selectedWorkbench = workbench;
        pending.needsSession = needsSession;
        pending.recoveryKey = recoveryKey;
        this.activeRecoveries.add(recoveryKey);
        try {
          const remaining = Math.max(0, Date.parse(pending.request.expiresAt) - this.now());
          const workbenchState = this.workbenches.get(workbench);
          const ackTimeout = workbenchState?.protocolVersion && workbenchState.protocolVersion >= 2
            ? this.workbenchAckTimeoutMs
            : 6_000;
          pending.attemptTimer = setTimeout(
            () => this.timeoutWorkbenchAttempt(pending.request.requestId, workbench),
            Math.min(ackTimeout, remaining),
          );
          workbench.postMessage({
            kind: 'trusted_unlock_request',
            request: pending.request,
            needsSession,
          });
        } catch {
          this.unregisterWorkbench(workbench);
        }
      }
    }
  }

  private selectWorkbench(pending: PendingTrustedUnlock): CoordinatorPort | null {
    const candidates = [...this.workbenches.entries()]
      .filter(([port, state]) => (
        state.unlocked
        && state.accountId === pending.request.accountId
        && !pending.attemptedWorkbenches.has(port)
      ));
    const highestProtocolVersion = candidates.reduce(
      (highest, [, state]) => Math.max(highest, state.protocolVersion),
      0,
    );
    if (
      highestProtocolVersion < 2
      && this.now() < pending.createdAt + this.legacyWorkbenchGraceMs
    ) return null;
    const leader = this.leaders.get(pending.request.accountId);
    const leaderCandidate = candidates.find(([port]) => port === leader);
    if (leaderCandidate && leaderCandidate[1].protocolVersion >= highestProtocolVersion) {
      return leaderCandidate[0];
    }
    if (leader) this.leaders.delete(pending.request.accountId);
    candidates.sort((left, right) => (
      right[1].protocolVersion - left[1].protocolVersion
      || Number(right[1].focused) - Number(left[1].focused)
      || Number(right[1].visibility === 'visible') - Number(left[1].visibility === 'visible')
      || right[1].activityOrder - left[1].activityOrder
      || right[1].order - left[1].order
    ));
    const selected = candidates[0]?.[0] ?? null;
    if (selected) this.leaders.set(pending.request.accountId, selected);
    return selected;
  }

  private completeTrustedUnlock(
    pending: PendingTrustedUnlock,
    response: unknown,
    session: ExtSession,
  ): void {
    this.pending.delete(pending.request.requestId);
    clearTimeout(pending.timer);
    if (pending.legacyGraceTimer) clearTimeout(pending.legacyGraceTimer);
    pending.legacyGraceTimer = null;
    if (pending.attemptTimer) clearTimeout(pending.attemptTimer);
    pending.attemptTimer = null;
    const sidePanel = pending.sidePanel;
    if (!sidePanel || !pending.recoveryKey) {
      this.releaseRecovery(pending);
      return;
    }
    const recoveryKey = pending.recoveryKey;
    pending.recoveryKey = null;
    const requestId = pending.request.requestId;
    const timer = setTimeout(
      () => this.releaseAwaitingCompletion(requestId),
      TRUSTED_UNLOCK_COMPLETION_TIMEOUT_MS,
    );
    this.awaitingCompletion.set(requestId, { recoveryKey, sidePanel, timer });
    this.post(sidePanel, {
      kind: 'trusted_unlock_response',
      requestId,
      response,
      session,
    });
  }

  private timeoutTrustedUnlock(requestId: string): void {
    const pending = this.pending.get(requestId);
    if (!pending) return;
    this.pending.delete(requestId);
    clearTimeout(pending.timer);
    if (pending.legacyGraceTimer) clearTimeout(pending.legacyGraceTimer);
    pending.legacyGraceTimer = null;
    if (pending.attemptTimer) clearTimeout(pending.attemptTimer);
    pending.attemptTimer = null;
    this.releaseRecovery(pending);
    if (pending.sidePanel) {
      this.post(pending.sidePanel, {
        kind: 'trusted_unlock_error',
        requestId,
        message: TRUSTED_UNLOCK_TIMEOUT_MESSAGE,
      });
    }
    this.requestPump();
  }

  private timeoutWorkbenchAttempt(requestId: string, workbench: CoordinatorPort): void {
    const pending = this.pending.get(requestId);
    if (!pending || pending.selectedWorkbench !== workbench || pending.acknowledged) return;
    if (this.leaders.get(pending.request.accountId) === workbench) {
      this.leaders.delete(pending.request.accountId);
    }
    this.releaseSelectedWorkbench(pending, true);
    this.requestPump();
  }

  private releaseSelectedWorkbench(
    pending: PendingTrustedUnlock,
    markAttempted: boolean,
  ): void {
    if (pending.attemptTimer) clearTimeout(pending.attemptTimer);
    pending.attemptTimer = null;
    this.releaseRecovery(pending);
    const selected = pending.selectedWorkbench;
    pending.status = 'queued';
    pending.acknowledged = false;
    pending.selectedWorkbench = null;
    pending.needsSession = false;
    if (markAttempted && selected) pending.attemptedWorkbenches.add(selected);
  }

  private releaseRecovery(pending: PendingTrustedUnlock): void {
    if (pending.recoveryKey) this.activeRecoveries.delete(pending.recoveryKey);
    pending.recoveryKey = null;
  }

  private releaseAwaitingCompletion(requestId: string): void {
    const completion = this.awaitingCompletion.get(requestId);
    if (!completion) return;
    this.awaitingCompletion.delete(requestId);
    clearTimeout(completion.timer);
    this.activeRecoveries.delete(completion.recoveryKey);
    this.requestPump();
  }

  private async loadManagedSession(): Promise<ExtSession | null> {
    const session = await this.store.loadSession();
    if (!session) return null;
    if (Date.parse(session.expiresAt) <= this.now()) {
      await this.clearManagedSession();
      return null;
    }
    const storedGeneration = await this.store.loadGeneration();
    const generation = validGeneration(session.generation)
      ? Math.max(session.generation, storedGeneration)
      : Math.max(1, storedGeneration);
    if (session.generation !== generation) {
      const managed = { ...session, generation };
      await Promise.all([
        this.store.saveGeneration(generation),
        this.store.saveSession(managed),
      ]);
      return managed;
    }
    if (storedGeneration !== generation) await this.store.saveGeneration(generation);
    return session;
  }

  private async adoptSession(session: ExtSession, deviceId: string): Promise<ExtSession> {
    const current = await this.loadManagedSession();
    const storedGeneration = await this.store.loadGeneration();
    const generation = Math.max(storedGeneration, current?.generation ?? 0) + 1;
    const managed = { ...session, generation, deviceId };
    await Promise.all([
      this.store.saveGeneration(generation),
      this.store.saveSession(managed),
    ]);
    return managed;
  }

  private async invalidateSession(expectedGeneration: number): Promise<{
    session: ExtSession | null;
    generation: number;
  }> {
    const current = await this.loadManagedSession();
    if (!current) return { session: null, generation: await this.store.loadGeneration() };
    if ((current.generation ?? 0) !== expectedGeneration) {
      return { session: current, generation: current.generation ?? await this.store.loadGeneration() };
    }
    return { session: null, generation: await this.clearManagedSession() };
  }

  private async clearManagedSession(): Promise<number> {
    const current = await this.store.loadSession();
    const storedGeneration = await this.store.loadGeneration();
    const generation = Math.max(storedGeneration, current?.generation ?? 0) + 1;
    await Promise.all([
      this.store.saveGeneration(generation),
      this.store.removeSession(),
    ]);
    return generation;
  }

  private sessionMatchesRequest(
    session: ExtSession,
    request: ExtensionTrustedUnlockRequest,
  ): boolean {
    return session.user.id === request.accountId
      && (!session.deviceId || session.deviceId === request.deviceId)
      && Date.parse(session.expiresAt) > this.now();
  }

  private withSessionLock<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.sessionQueue.then(operation, operation);
    this.sessionQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  private knownAccountIds(): Set<string> {
    return new Set(
      [...this.workbenches.values()]
        .map((state) => state.accountId)
        .filter((accountId): accountId is string => Boolean(accountId)),
    );
  }

  private broadcastWorkbenchState(accountId: string): void {
    for (const sidePanel of this.sidePanels) this.postWorkbenchState(sidePanel, accountId);
  }

  private postWorkbenchState(port: CoordinatorPort, accountId: string): void {
    const unlocked = this.hasUnlockedWorkbench(accountId);
    this.post(port, {
      kind: unlocked ? 'workbench_unlocked' : 'workbench_locked',
      accountId,
    });
  }

  private broadcast(message: unknown): void {
    for (const sidePanel of this.sidePanels) this.post(sidePanel, message);
  }

  private broadcastSessionState(session: ExtSession | null, sessionGeneration: number): void {
    this.broadcast({ kind: 'session_state', session, sessionGeneration });
  }

  private postSessionState(
    port: CoordinatorPort,
    session: ExtSession | null,
    sessionGeneration: number,
  ): void {
    this.post(port, { kind: 'session_state', session, sessionGeneration });
  }

  private post(port: CoordinatorPort, message: unknown): void {
    try {
      port.postMessage(message);
    } catch {
      this.unregisterSidePanel(port);
    }
  }

  private postWorkbench(port: CoordinatorPort, message: unknown): void {
    try {
      port.postMessage(message);
    } catch {
      this.unregisterWorkbench(port);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object');
}

function isTrustedUnlockRequest(value: unknown): value is ExtensionTrustedUnlockRequest {
  return isRecord(value)
    && typeof value.requestId === 'string'
    && typeof value.accountId === 'string'
    && typeof value.deviceId === 'string'
    && typeof value.expiresAt === 'string';
}

function isExtSession(value: unknown): value is ExtSession {
  return isRecord(value)
    && typeof value.token === 'string'
    && typeof value.expiresAt === 'string'
    && isRecord(value.user)
    && typeof value.user.id === 'string';
}

function validGeneration(value: number | undefined): value is number {
  return Number.isSafeInteger(value) && (value ?? 0) >= 1;
}
