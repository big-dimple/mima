import type {
  ExtensionBootstrap,
  ExtensionContentRequest,
  ExtensionContentResponse,
  PairingClaimRequest,
  PairingClaimResponse,
  PairingStatusResponse,
  ExtSession,
  UnlockChallengeResponse,
} from './protocol.ts';
import {
  ITEM_METADATA_FORMAT_HEADER,
  ITEM_METADATA_FORMAT_VERSION,
} from '@mima/contracts';
import { PanelModel } from './panel-model.ts';

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export class PanelApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly sessionGeneration: number | null = null,
  ) {
    super(message);
    this.name = 'PanelApiError';
  }
}

export class PanelApi {
  constructor(
    private readonly baseUrl: string,
    private readonly model: PanelModel,
    private readonly fetcher: Fetcher = (...args) => fetch(...args),
  ) {}

  claimPairingCode(request: PairingClaimRequest): Promise<PairingClaimResponse> {
    return this.send('/api/v2/extension/pairing/claim', {
      method: 'POST',
      body: JSON.stringify(request),
    }, false);
  }

  pairingStatus(enrollmentId: string, pollToken: string): Promise<PairingStatusResponse> {
    return this.send(`/api/v2/extension/pairing/${encodeURIComponent(enrollmentId)}`, {
      headers: { 'x-pairing-token': pollToken },
    }, false);
  }

  requestUnlockChallenge(deviceId: string, session?: ExtSession): Promise<UnlockChallengeResponse> {
    return this.send('/api/v2/extension/unlock-challenges', {
      method: 'POST',
      body: JSON.stringify({ deviceId }),
    }, session);
  }

  completeUnlock(input: {
    challengeId: string;
    deviceId: string;
    signature: string;
  }, session?: ExtSession): Promise<{ unlocked: true }> {
    return this.send('/api/v2/extension/crypto-unlock', {
      method: 'POST',
      body: JSON.stringify(input),
    }, session);
  }

  encryptedBootstrap(session?: ExtSession): Promise<ExtensionBootstrap> {
    return this.send('/api/v2/extension/bootstrap', undefined, session);
  }

  encryptedContent(
    itemId: string,
    request: ExtensionContentRequest,
    session?: ExtSession,
  ): Promise<ExtensionContentResponse> {
    return this.send(`/api/v2/extension/items/${encodeURIComponent(itemId)}/content`, {
      method: 'POST',
      body: JSON.stringify(request),
    }, session);
  }

  revokeSession(session?: ExtSession): Promise<{ ok: boolean }> {
    return this.send('/api/v2/extension/session', { method: 'DELETE' }, session);
  }

  private async send<T>(
    path: string,
    init?: RequestInit,
    sessionOverride?: ExtSession | false,
  ): Promise<T> {
    const headers = new Headers(init?.headers);
    headers.set(ITEM_METADATA_FORMAT_HEADER, String(ITEM_METADATA_FORMAT_VERSION));
    let sessionGeneration: number | null = null;
    const authenticated = sessionOverride !== false;
    if (authenticated) {
      const session = sessionOverride ?? this.model.state.session;
      if (!session) throw new PanelApiError('扩展尚未配对', 401);
      sessionGeneration = session.generation ?? 0;
      headers.set('authorization', `Bearer ${session.token}`);
    }
    if (init?.body) headers.set('content-type', 'application/json');

    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}${path}`, { ...init, headers });
    } catch {
      throw new PanelApiError('无法连接Mima服务', null);
    }
    if (response.status === 401 && authenticated) {
      throw new PanelApiError('扩展在线连接需要恢复', 401, sessionGeneration);
    }
    if (response.status === 403 && authenticated) {
      throw new PanelApiError('当前设备已被撤销或没有访问权限', 403);
    }
    if (response.status === 426) {
      const body = (await response.json().catch(() => ({}))) as { message?: string };
      throw new PanelApiError(body.message ?? '扩展版本较旧，请更新扩展后继续使用', 426);
    }
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as { message?: string };
      throw new PanelApiError(body.message ?? `HTTP ${response.status}`, response.status);
    }
    if (response.status === 204) return undefined as T;
    return response.json() as Promise<T>;
  }
}
