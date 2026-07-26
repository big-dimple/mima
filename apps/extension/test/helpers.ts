import type { ExtensionStorage } from '../src/extension-storage.ts';
import type {
  CiphertextCache,
  ExtSession,
  LocalDeviceRecord,
  PendingEnrollment,
} from '../src/protocol.ts';

export class MemoryExtensionStorage implements ExtensionStorage {
  session: ExtSession | null = null;
  device: LocalDeviceRecord | null = null;
  pending: PendingEnrollment | null = null;
  pendingPollToken: string | null = null;
  cache: CiphertextCache | null = null;

  async loadSession() { return this.session; }
  async saveSession(session: ExtSession) { this.session = structuredClone(session); }
  async removeSession() { this.session = null; }
  async loadDevice() { return this.device; }
  async saveDevice(device: LocalDeviceRecord) { this.device = structuredClone(device); }
  async removeDevice() { this.device = null; }
  async loadPendingEnrollment() { return this.pending; }
  async savePendingEnrollment(pending: PendingEnrollment) { this.pending = structuredClone(pending); }
  async removePendingEnrollment() { this.pending = null; }
  async loadPendingPollToken() { return this.pendingPollToken; }
  async savePendingPollToken(token: string) { this.pendingPollToken = token; }
  async removePendingPollToken() { this.pendingPollToken = null; }
  async loadCiphertextCache() { return this.cache; }
  async saveCiphertextCache(cache: CiphertextCache) { this.cache = structuredClone(cache); }
  async removeCiphertextCache() { this.cache = null; }
  async clearAll() {
    this.session = null;
    this.device = null;
    this.pending = null;
    this.pendingPollToken = null;
    this.cache = null;
  }

  serialized(): string {
    return JSON.stringify({
      session: this.session,
      device: this.device,
      pending: this.pending,
      cache: this.cache,
    });
  }
}

export function extSession(expiresAt = new Date(Date.now() + 60_000).toISOString()): ExtSession {
  return {
    token: 'opaque-extension-token',
    expiresAt,
    generation: 1,
    deviceId: 'device-1',
    user: {
      id: 'user-1',
      username: 'bob',
      displayName: 'Bob Li',
      email: 'bob@example.test',
      groups: [],
      isPlatformAdmin: false,
    },
  };
}
