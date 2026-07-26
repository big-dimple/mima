import type {
  DecryptedExtensionItem,
  ExtSession,
  LocalDeviceRecord,
  PendingEnrollment,
} from './protocol.ts';

export type PanelPhase =
  | 'loading'
  | 'pairing'
  | 'awaiting_approval'
  | 'locked'
  | 'unlocking'
  | 'ready'
  | 'revoked'
  | 'error';

export interface PanelState {
  phase: PanelPhase;
  session: ExtSession | null;
  device: LocalDeviceRecord | null;
  pendingEnrollment: PendingEnrollment | null;
  items: DecryptedExtensionItem[];
  tabOrigin: string | null;
  tabUrl: string | null;
  tabId: number | null;
  search: string;
  offline: boolean;
  error: string | null;
}

export class PanelModel {
  readonly state: PanelState = {
    phase: 'loading',
    session: null,
    device: null,
    pendingEnrollment: null,
    items: [],
    tabOrigin: null,
    tabUrl: null,
    tabId: null,
    search: '',
    offline: false,
    error: null,
  };

  private securityGeneration = 0;

  setLoading(): void {
    this.state.phase = 'loading';
    this.state.error = null;
  }

  setPairing(message: string | null = null): void {
    this.clearDecryptedState();
    this.state.phase = 'pairing';
    this.state.error = message;
  }

  setAwaitingApproval(pending: PendingEnrollment): void {
    this.clearDecryptedState();
    this.state.pendingEnrollment = pending;
    this.state.phase = 'awaiting_approval';
    this.state.error = null;
  }

  setLocked(message: string | null = null): void {
    this.bumpSecurityGeneration();
    this.clearDecryptedState();
    this.state.phase = 'locked';
    this.state.error = message;
  }

  setUnlocking(): void {
    this.state.phase = 'unlocking';
    this.state.error = null;
  }

  setReady(items: DecryptedExtensionItem[], offline = false): void {
    this.state.items = items;
    this.state.offline = offline;
    this.state.phase = 'ready';
    this.state.error = null;
  }

  setRevoked(): void {
    this.bumpSecurityGeneration();
    this.state.session = null;
    this.state.device = null;
    this.state.pendingEnrollment = null;
    this.clearDecryptedState();
    this.state.phase = 'revoked';
    this.state.error = '此扩展设备已被撤销，请重新配对';
  }

  setError(message: string): void {
    this.bumpSecurityGeneration();
    this.clearDecryptedState();
    this.state.phase = 'error';
    this.state.error = message;
  }

  handleCryptoWorkerFailure(message: string): void {
    if (this.state.session && this.state.device) {
      this.setLocked(message);
      return;
    }
    this.setError(message);
  }

  captureSecurityGeneration(): number {
    return this.securityGeneration;
  }

  isSecurityGenerationCurrent(generation: number): boolean {
    return generation === this.securityGeneration;
  }

  bumpSecurityGeneration(): void {
    this.securityGeneration += 1;
  }

  private clearDecryptedState(): void {
    this.state.items = [];
    this.state.search = '';
    this.state.tabId = null;
    this.state.tabOrigin = null;
    this.state.tabUrl = null;
    this.state.offline = false;
  }
}

export type { ExtSession } from './protocol.ts';
