import type {
  CiphertextCache,
  LocalDeviceRecord,
  PendingEnrollment,
} from './protocol.ts';

export const SESSION_KEY = 'lmE2eeSession';
export const SESSION_GENERATION_KEY = 'lmE2eeSessionGeneration';
const DEVICE_KEY = 'lmE2eeDevice';
const PENDING_KEY = 'lmE2eePendingEnrollment';
const PENDING_TOKEN_KEY = 'lmE2eePendingPollToken';
const CACHE_KEY = 'lmE2eeCiphertextCache';

export interface ExtensionStorage {
  loadDevice(): Promise<LocalDeviceRecord | null>;
  saveDevice(device: LocalDeviceRecord): Promise<void>;
  removeDevice(): Promise<void>;
  loadPendingEnrollment(): Promise<PendingEnrollment | null>;
  savePendingEnrollment(pending: PendingEnrollment): Promise<void>;
  removePendingEnrollment(): Promise<void>;
  loadPendingPollToken(): Promise<string | null>;
  savePendingPollToken(token: string): Promise<void>;
  removePendingPollToken(): Promise<void>;
  loadCiphertextCache(): Promise<CiphertextCache | null>;
  saveCiphertextCache(cache: CiphertextCache): Promise<void>;
  removeCiphertextCache(): Promise<void>;
  clearAll(): Promise<void>;
}

export function createChromeExtensionStorage(): ExtensionStorage {
  return {
    async loadDevice() {
      const data = await chrome.storage.local.get(DEVICE_KEY);
      return (data[DEVICE_KEY] as LocalDeviceRecord | undefined) ?? null;
    },
    async saveDevice(device) {
      await chrome.storage.local.set({ [DEVICE_KEY]: device });
    },
    async removeDevice() {
      await chrome.storage.local.remove(DEVICE_KEY);
    },
    async loadPendingEnrollment() {
      const data = await chrome.storage.local.get(PENDING_KEY);
      return (data[PENDING_KEY] as PendingEnrollment | undefined) ?? null;
    },
    async savePendingEnrollment(pending) {
      await chrome.storage.local.set({ [PENDING_KEY]: pending });
    },
    async removePendingEnrollment() {
      await chrome.storage.local.remove(PENDING_KEY);
    },
    async loadPendingPollToken() {
      const data = await chrome.storage.session.get(PENDING_TOKEN_KEY);
      return (data[PENDING_TOKEN_KEY] as string | undefined) ?? null;
    },
    async savePendingPollToken(token) {
      await chrome.storage.session.set({ [PENDING_TOKEN_KEY]: token });
    },
    async removePendingPollToken() {
      await chrome.storage.session.remove(PENDING_TOKEN_KEY);
    },
    async loadCiphertextCache() {
      const data = await chrome.storage.local.get(CACHE_KEY);
      return (data[CACHE_KEY] as CiphertextCache | undefined) ?? null;
    },
    async saveCiphertextCache(cache) {
      await chrome.storage.local.set({ [CACHE_KEY]: cache });
    },
    async removeCiphertextCache() {
      await chrome.storage.local.remove(CACHE_KEY);
    },
    async clearAll() {
      await Promise.all([
        chrome.storage.session.remove(PENDING_TOKEN_KEY),
        chrome.storage.local.remove([DEVICE_KEY, PENDING_KEY, CACHE_KEY]),
      ]);
    },
  };
}
