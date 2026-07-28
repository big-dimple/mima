import { CLIPBOARD_CLEAR_MS } from '@mima/contracts';
import type { UserCryptoProfile } from '@mima/contracts';
import type {
  AccountBundle,
  ExtensionTrustedUnlockRequest,
} from '@mima/e2ee';
import type { ActiveTabContext } from './active-tab.ts';
import { DeviceRevokedError } from './crypto-errors.ts';
import type { ExtensionKeyringPort } from './crypto-worker-protocol.ts';
import type { ExtensionStorage } from './extension-storage.ts';
import { PanelApi, PanelApiError } from './panel-api.ts';
import { PanelModel } from './panel-model.ts';
import type {
  CiphertextCache,
  DecryptedExtensionItem,
  ExtSession,
  ExtensionBootstrap,
  LocalDeviceRecord,
  PairingApproval,
  WorkbenchTrustedUnlockResult,
} from './protocol.ts';
import { extensionItemLoginUrls, extensionItemMatchesSite } from './site-match.ts';

export interface PanelBrowserAdapter {
  ensureApiAccess(): Promise<boolean>;
  ensureSiteAccess(origin: string): Promise<boolean>;
  isProtectedWorkbenchOrigin(origin: string): boolean;
  readActiveTab(): Promise<ActiveTabContext>;
  executeFill(tabId: number, username: string | null, value: string): Promise<{ ok: boolean; reason?: string }>;
  openUrl(url: string): Promise<void>;
  writeClipboard(value: string): Promise<void>;
  schedule(callback: () => void, delayMs: number): void;
  requestTrustedUnlock(
    request: ExtensionTrustedUnlockRequest,
  ): Promise<WorkbenchTrustedUnlockResult>;
  loadSession(): Promise<ExtSession | null>;
  adoptSession(session: ExtSession, deviceId: string): Promise<ExtSession>;
  invalidateSession(expectedGeneration: number): Promise<ExtSession | null>;
  clearSession(): Promise<void>;
  completeTrustedUnlock(requestId: string): Promise<void>;
  isWorkbenchUnlocked(accountId: string | null | undefined): boolean;
}

export class PanelActions {
  private trustedUnlockInFlight: Promise<void> | null = null;
  private automaticTrustedUnlockBlocked = false;
  private automaticTrustedUnlockGeneration = 0;
  private sessionInvalidationInFlight = 0;
  private clipboardGeneration = 0;
  private clipboardPending = false;

  constructor(
    private readonly model: PanelModel,
    private readonly api: PanelApi,
    private readonly browser: PanelBrowserAdapter,
    private readonly storage: ExtensionStorage,
    private readonly keyring: ExtensionKeyringPort,
  ) {}

  async startup(): Promise<void> {
    await this.keyring.lock();
    const [session, device, pending, cache] = await Promise.all([
      this.browser.loadSession(),
      this.storage.loadDevice(),
      this.storage.loadPendingEnrollment(),
      this.storage.loadCiphertextCache(),
    ]);
    this.model.state.device = device;
    if (pending && Date.parse(pending.expiresAt) > Date.now()) {
      if (device?.pairingOnly) {
        await this.browser.clearSession().catch(() => undefined);
        await this.storage.clearAll();
        this.model.state.device = null;
        this.model.setPairing('侧边栏曾在配对完成前关闭，请重新生成一次性配对码');
        return;
      }
      this.model.setAwaitingApproval(pending);
      return;
    }
    if (pending) {
      await Promise.all([
        this.storage.removePendingEnrollment(),
        this.storage.removePendingPollToken(),
      ]);
    }
    this.model.state.pendingEnrollment = null;
    if (session) this.adoptModelSession(session);
    if (device?.webUnlock) {
      if (!this.browser.isWorkbenchUnlocked(device.userId)) {
        this.model.setLocked(session
          ? '工作台尚未解锁。可输入同一主密码本地解锁，或先解锁工作台后自动联动。'
          : '此扩展仍受信任。可从已解锁工作台恢复；工作台暂时不可用时，也可用主密码打开本机保存的数据。',
        Boolean(cache));
        return;
      }
      try {
        await this.tryTrustedUnlock();
        return;
      } catch {
        return;
      }
    }
    if (device && !device.pairingOnly) {
      this.model.setLocked(session
        ? '此设备需要完成一次兼容升级。用主密码解锁后，以后工作台和扩展会一起解锁。'
        : '此扩展仍受信任。打开并解锁工作台，再输入一次主密码完成升级；无需配对码。',
      Boolean(cache));
      return;
    }
    if (session || this.model.state.session) {
      await this.browser.clearSession().catch(() => undefined);
    }
    if (device?.pairingOnly) await this.storage.clearAll();
    this.model.state.session = null;
    this.model.state.device = null;
    this.model.setPairing();
  }

  async pair(input: {
    code: string;
    unlockFactor?: string;
    deviceName: string;
    platform: string;
  }): Promise<void> {
    if (!(await this.browser.ensureApiAccess())) {
      throw new Error('未授权扩展访问Mima服务');
    }
    try {
      let record = this.model.state.device ?? await this.storage.loadDevice();
      let existingDeviceProof: string | undefined;
      if (record) {
        if (record.pairingOnly) throw new Error('上一次配对没有完成，请取消后重新配对');
        if (!input.unlockFactor) throw new Error('请输入当前设备的主密码');
        await this.keyring.unlock(record, input.unlockFactor);
        existingDeviceProof = await this.keyring.pairingProof(input.code, record);
      } else {
        record = await this.keyring.createPairingDevice({
          deviceId: crypto.randomUUID(),
          name: input.deviceName,
          platform: input.platform,
        });
      }

      const request = await this.keyring.pairingRequest(input.code, record, existingDeviceProof);
      const claimed = await this.api.claimPairingCode(request);
      if (claimed.fingerprint !== record.fingerprint) {
        throw new Error('工作台返回的设备指纹与本机不一致');
      }
      this.model.state.device = record;
      await this.storage.saveDevice(record);
      const pending = {
        enrollmentId: claimed.enrollmentId,
        expiresAt: claimed.expiresAt,
        fingerprint: claimed.fingerprint,
        ...(claimed.sealedApproval ? { sealedApproval: claimed.sealedApproval } : {}),
      };
      await Promise.all([
        this.storage.savePendingEnrollment(pending),
        this.storage.savePendingPollToken(claimed.pollToken),
      ]);
      this.model.setAwaitingApproval(pending);
      this.schedulePendingPairingLock(pending);
      if (claimed.status === 'approved' && claimed.sealedApproval) {
        await this.acceptSealedApproval(claimed.sealedApproval);
      }
    } catch (error) {
      await this.keyring.lock();
      throw error;
    }
  }

  async checkPairingApproval(unlockFactor?: string): Promise<'pending' | 'awaiting_unlock' | 'approved'> {
    const pending = this.model.state.pendingEnrollment;
    if (!pending) throw new Error('没有待确认的扩展配对');
    if (Date.parse(pending.expiresAt) <= Date.now()) {
      await this.keyring.lock();
      await Promise.all([
        this.storage.removePendingEnrollment(),
        this.storage.removePendingPollToken(),
      ]);
      this.model.state.pendingEnrollment = null;
      this.model.setPairing('配对申请已过期，请重新生成一次性配对码');
      throw new Error('配对申请已过期');
    }
    if (pending.sealedApproval) {
      if (!this.keyring.unlocked) {
        const record = this.model.state.device;
        if (!record) throw new Error('此扩展的本机授权不完整，请重新配对');
        if (!unlockFactor) {
          throw new Error(record.unlockFactorKind === 'web-main-password'
            ? '请输入主密码后领取配对授权'
            : '请输入旧版扩展解锁密码后领取配对授权');
        }
        await this.keyring.unlock(record, unlockFactor);
      }
      await this.acceptSealedApproval(pending.sealedApproval);
      return 'approved';
    }
    const pollToken = await this.storage.loadPendingPollToken();
    if (!pollToken) {
      await this.storage.removePendingEnrollment();
      this.model.state.pendingEnrollment = null;
      this.model.setPairing('浏览器已关闭或配对状态已清除，请重新生成配对码');
      throw new Error('本次配对已过期，请重新生成配对码');
    }
    const status = await this.api.pairingStatus(pending.enrollmentId, pollToken);
    if (status.fingerprint !== pending.fingerprint) {
      throw new Error('配对确认返回了不同的设备指纹');
    }
    if (status.status === 'expired' || status.status === 'rejected') {
      await this.keyring.lock();
      await Promise.all([
        this.storage.removePendingEnrollment(),
        this.storage.removePendingPollToken(),
      ]);
      this.model.state.pendingEnrollment = null;
      this.model.setPairing(status.status === 'rejected' ? '工作台已拒绝这次配对' : '配对申请已过期');
      throw new Error(this.model.state.error ?? '配对失败');
    }
    if (status.status === 'pending') return 'pending';
    if (!status.sealedApproval) throw new Error('服务端未返回设备加密的配对授权');
    const approvedPending = { ...pending, sealedApproval: status.sealedApproval };
    await Promise.all([
      this.storage.savePendingEnrollment(approvedPending),
      this.storage.removePendingPollToken(),
    ]);
    this.model.setAwaitingApproval(approvedPending);
    if (this.keyring.unlocked) {
      await this.acceptSealedApproval(status.sealedApproval);
      return 'approved';
    }
    return 'awaiting_unlock';
  }

  async unlock(unlockFactor: string): Promise<void> {
    const device = this.model.state.device;
    const session = this.model.state.session;
    if (!device) throw new Error('扩展尚未完成配对');
    if (!session) {
      if (device.webUnlock) {
        await this.unlockLocalCache(device, unlockFactor);
        return;
      }
      if (device.pairingOnly) throw new Error('上一次配对没有完成，请重新配对');
      await this.upgradeLegacyDeviceWithWorkbench(device, unlockFactor);
      return;
    }
    this.model.setUnlocking();
    const generation = this.model.captureSecurityGeneration();
    try {
      await withTimeout((async () => {
        await this.keyring.unlock(device, unlockFactor);
        if (!this.model.isSecurityGenerationCurrent(generation)) return;
        await this.loadReadyState(unlockFactor, generation);
      })(), UNLOCK_ATTEMPT_TIMEOUT_MS);
    } catch (error) {
      if (!this.model.isSecurityGenerationCurrent(generation)) return;
      const recovered = await this.handleUnlockFailure(error, true);
      if (recovered) return;
      throw new Error(this.model.state.error ?? errorMessage(error, '解锁失败，请重试'));
    }
  }

  async tryTrustedUnlock(options: { force?: boolean } = {}): Promise<void> {
    const device = this.model.state.device;
    if (!device?.webUnlock) return;
    if (this.trustedUnlockInFlight) return this.trustedUnlockInFlight;
    if (options.force) this.allowAutomaticTrustedUnlock();
    if (!options.force && this.automaticTrustedUnlockBlocked) return;
    const automaticGeneration = this.automaticTrustedUnlockGeneration;
    const task = this.runTrustedUnlock(device);
    this.trustedUnlockInFlight = task;
    try {
      await task;
      if (this.model.state.phase === 'ready') this.automaticTrustedUnlockBlocked = false;
      else if (automaticGeneration === this.automaticTrustedUnlockGeneration) {
        this.automaticTrustedUnlockBlocked = true;
      }
    } catch (error) {
      if (automaticGeneration === this.automaticTrustedUnlockGeneration) {
        this.automaticTrustedUnlockBlocked = true;
      }
      throw error;
    } finally {
      if (this.trustedUnlockInFlight === task) this.trustedUnlockInFlight = null;
    }
  }

  allowAutomaticTrustedUnlock(): void {
    this.automaticTrustedUnlockBlocked = false;
    this.automaticTrustedUnlockGeneration += 1;
  }

  async lock(): Promise<void> {
    this.model.setLocked();
    await this.keyring.lock();
    await this.clearSensitiveClipboard();
  }

  async syncSession(session: ExtSession | null): Promise<void> {
    if (session) {
      this.adoptModelSession(session);
      return;
    }
    if (!this.model.state.session) return;
    this.model.state.session = null;
    if (this.model.state.phase === 'unlocking' && this.sessionInvalidationInFlight > 0) return;
    if (this.model.state.phase === 'ready' || this.model.state.phase === 'unlocking') {
      this.model.setLocked(
        '工作台已更新安全状态，扩展正在等待同一账号重新解锁。',
      );
      await this.keyring.lock();
      await this.clearSensitiveClipboard();
    }
  }

  async confirmWorkbenchDeviceRevocation(deviceId: string): Promise<boolean> {
    const device = this.model.state.device ?? await this.storage.loadDevice();
    if (!device || device.deviceId !== deviceId) return false;
    try {
      await this.api.requestUnlockChallenge(deviceId);
      return false;
    } catch (error) {
      if (isConfirmedDeviceRevocation(error)) {
        await this.handleRevocation();
        return true;
      }
      throw error;
    }
  }

  async refreshData(): Promise<void> {
    if (!this.keyring.unlocked) throw new Error('扩展已锁定，请先用主密码解锁');
    if (!this.model.state.session) {
      throw new Error('当前正在使用本机数据；恢复在线连接后才能刷新');
    }
    if (!(await this.browser.ensureApiAccess())) throw new Error('未授权扩展访问Mima服务');
    const generation = this.model.captureSecurityGeneration();
    let bootstrap: ExtensionBootstrap;
    try {
      bootstrap = await this.withSessionRetry((session) => this.api.encryptedBootstrap(session));
    } catch (error) {
      if (isConfirmedDeviceRevocation(error)) await this.handleRevocation();
      if (error instanceof SessionUnavailableError) {
        await this.recoverAfterSessionLoss();
        throw new Error(this.model.state.error ?? '扩展连接已恢复，请重试刚才的操作');
      }
      throw error;
    }
    if (!this.canContinueUnlock(generation, 'ready')) return;
    let items: DecryptedExtensionItem[];
    try {
      items = await this.keyring.loadBootstrap(bootstrap);
    } catch (error) {
      if (error instanceof DeviceRevokedError) {
        await this.handleRevocation();
      } else {
        this.model.setLocked(errorMessage(error, '本地数据校验失败，请重新打开扩展'));
        await this.keyring.lock();
      }
      throw error;
    }
    if (!this.canContinueUnlock(generation, 'ready')) return;
    await this.saveBootstrap(bootstrap).catch(() => undefined);
    const activeTab = await this.browser.readActiveTab();
    if (!this.canContinueUnlock(generation, 'ready')) return;
    this.applyActiveTab(activeTab);
    this.model.setReady(items);
  }

  async refreshActiveTab(): Promise<void> {
    if (this.model.state.phase !== 'ready') return;
    this.applyActiveTab(await this.browser.readActiveTab());
  }

  async unpair(): Promise<string | null> {
    this.model.setLocked();
    await this.keyring.lock();
    await this.clearSensitiveClipboard();
    let warning: string | null = null;
    if (this.model.state.session) {
      try {
        await this.api.revokeSession(this.model.state.session);
      } catch {
        warning = '暂时无法通知服务端撤销设备，请在工作台的设备列表中撤销';
      }
    }
    await this.browser.clearSession().catch(() => undefined);
    await this.storage.clearAll();
    this.model.state.session = null;
    this.model.state.device = null;
    this.model.state.pendingEnrollment = null;
    this.model.setPairing(warning);
    return warning;
  }

  async cancelPendingPairing(): Promise<void> {
    await this.keyring.lock();
    await this.clearSensitiveClipboard();
    await this.browser.clearSession().catch(() => undefined);
    await this.storage.clearAll();
    this.model.state.session = null;
    this.model.state.device = null;
    this.model.state.pendingEnrollment = null;
    this.model.setPairing();
  }

  async fill(item: DecryptedExtensionItem): Promise<string | null> {
    if (item.secretState === 'absent') return '该条目未保存密码';
    if (!item.canReveal) return '你当前只能查看条目信息，不能填充密码或敏感内容';
    const expectedSite = {
      origin: this.model.state.tabOrigin,
      url: this.model.state.tabUrl,
    };
    if (!expectedSite.origin || !extensionItemMatchesSite(item, expectedSite)) {
      return '网址不一致，已取消填充';
    }
    if (this.browser.isProtectedWorkbenchOrigin(expectedSite.origin)) {
      return 'Mima工作台不接受扩展填充';
    }
    if (!(await this.browser.ensureSiteAccess(expectedSite.origin))) {
      return '未授权扩展访问当前网站，已取消填充';
    }
    const activeTab = await this.browser.readActiveTab();
    this.applyActiveTab(activeTab);
    if (activeTab.tabId === null || !extensionItemMatchesSite(item, activeTab)) {
      return '网址不一致，已取消填充';
    }
    const generation = this.model.captureSecurityGeneration();
    const targetTabId = activeTab.tabId;
    const value = await this.readSensitiveContent(item, 'fill');
    if (!this.canUseDecrypted(generation)) return null;
    const latestTab = await this.browser.readActiveTab();
    this.applyActiveTab(latestTab);
    if (
      !this.canUseDecrypted(generation) ||
      latestTab.tabId !== targetTabId ||
      !extensionItemMatchesSite(item, latestTab)
    ) {
      return '页面已变化，已取消填充';
    }
    const outcome = await this.browser.executeFill(targetTabId, item.username, value);
    return outcome.ok ? '已填充登录表单' : (outcome.reason ?? '填充失败');
  }

  async copy(item: DecryptedExtensionItem): Promise<string | null> {
    if (item.secretState === 'absent') return '该条目未保存密码';
    if (!item.canReveal) return '你当前只能查看条目信息，不能复制密码或敏感内容';
    const generation = this.model.captureSecurityGeneration();
    const value = await this.readSensitiveContent(item, 'copy');
    if (!this.canUseDecrypted(generation)) return null;
    const clipboardGeneration = ++this.clipboardGeneration;
    await this.browser.writeClipboard(value);
    this.clipboardPending = true;
    if (!this.canUseDecrypted(generation)) {
      this.clipboardPending = false;
      this.clipboardGeneration += 1;
      await this.browser.writeClipboard('').catch(() => undefined);
      return null;
    }
    this.browser.schedule(() => {
      if (clipboardGeneration !== this.clipboardGeneration) return;
      this.clipboardGeneration += 1;
      this.clipboardPending = false;
      void this.browser.writeClipboard('').catch(() => undefined);
    }, CLIPBOARD_CLEAR_MS);
    return '已复制，30 秒后尽力清理剪贴板';
  }

  async open(item: DecryptedExtensionItem): Promise<string> {
    const url = item.kind === 'login' ? extensionItemLoginUrls(item)[0] ?? null : null;
    if (!url) throw new Error('该条目没有可打开的网址');
    await this.browser.openUrl(url);
    return '已打开网址';
  }

  private async readSensitiveContent(
    item: DecryptedExtensionItem,
    purpose: 'copy' | 'fill',
  ): Promise<string> {
    if (item.secretState === 'absent') throw new Error('该条目未保存密码');
    if (!item.canReveal) throw new Error('你当前只能查看条目信息，不能查看密码或敏感内容');
    if (!this.keyring.unlocked) throw new Error('扩展已锁定，请先用主密码解锁');
    const cacheKey = contentCacheKey(item);
    let encrypted;
    let fetchedOnline = false;
    if (!this.model.state.session || this.model.state.offline) {
      const cache = await this.storage.loadCiphertextCache();
      const cached = cache?.contents[cacheKey];
      if (!cached) throw new Error('本机没有保存这条敏感内容；恢复在线连接后再试');
      return this.keyring.decryptContent(item, cached);
    }
    try {
      encrypted = await this.withSessionRetry(async (session) => {
        const signature = await this.keyring.signContentIntent({
          itemId: item.id,
          purpose,
          secretVersion: item.secretVersion,
        });
        return this.api.encryptedContent(item.id, {
          purpose,
          secretVersion: item.secretVersion,
          deviceId: this.model.state.device!.deviceId,
          intentSignature: signature,
        }, session);
      });
      fetchedOnline = true;
    } catch (error) {
      if (isConfirmedDeviceRevocation(error)) {
        await this.handleRevocation();
        throw error;
      }
      if (error instanceof PanelApiError && error.code === 'extension_access_denied') {
        await this.refreshData().catch(() => undefined);
        throw error;
      }
      if (error instanceof SessionUnavailableError) {
        await this.recoverAfterSessionLoss();
        throw new Error(this.model.state.error ?? '扩展连接已恢复，请重试刚才的操作');
      }
      if (error instanceof PanelApiError && error.status !== null) throw error;
      const cache = await this.storage.loadCiphertextCache();
      encrypted = cache?.contents[cacheKey];
      if (!encrypted) throw error;
    }
    const value = await this.keyring.decryptContent(item, encrypted);
    if (fetchedOnline) {
      const cache = await this.storage.loadCiphertextCache();
      if (cache) {
        cache.contents[cacheKey] = encrypted;
        cache.updatedAt = new Date().toISOString();
        await this.storage.saveCiphertextCache(cache).catch(() => undefined);
      }
    }
    return value;
  }

  private async acceptApproval(approval: PairingApproval): Promise<void> {
    const record = this.model.state.device;
    if (!record) throw new Error('此扩展的本机授权不完整，请重新配对');
    if (approval.session.user.id !== approval.device.userId) {
      throw new Error('本次配对返回了其他设备的信息，已拒绝继续；请重新生成配对码');
    }
    const approved = await this.keyring.verifyApprovedDevice(
      record,
      approval.device,
      approval.profileSigningPublicKey,
    );
    const session = await this.browser.adoptSession(approval.session, approved.deviceId);
    await Promise.all([
      this.storage.saveDevice(approved),
      this.storage.removePendingEnrollment(),
      this.storage.removePendingPollToken(),
    ]);
    this.model.state.device = approved;
    this.model.state.session = session;
    this.model.state.pendingEnrollment = null;
  }

  private async acceptSealedApproval(sealedApproval: string): Promise<void> {
    const record = this.model.state.device;
    if (!record) throw new Error('此扩展的本机授权不完整，请重新配对');
    try {
      const approval = await this.keyring.openPairingApproval(sealedApproval);
      await this.acceptApproval(approval);
    } catch (error) {
      await this.keyring.lock();
      throw error;
    }
    this.model.setUnlocking();
    const generation = this.model.captureSecurityGeneration();
    try {
      await withTimeout(
        this.loadReadyState(undefined, generation),
        UNLOCK_ATTEMPT_TIMEOUT_MS,
      );
    } catch (error) {
      if (!this.model.isSecurityGenerationCurrent(generation)) return;
      const recovered = await this.handleUnlockFailure(error, true);
      if (!recovered) throw new Error(this.model.state.error ?? errorMessage(error, '解锁失败'));
    }
  }

  private async loadReadyState(
    legacyUnlockFactor: string | undefined,
    generation: number,
    initialSession: ExtSession | null = this.model.state.session,
  ): Promise<void> {
    const device = this.model.state.device;
    if (!device || !initialSession) throw new Error('扩展尚未完成配对');
    let bootstrap: ExtensionBootstrap | null = null;
    let offline = false;
    try {
      if (!(await this.browser.ensureApiAccess())) {
        throw new Error('未授权扩展访问Mima服务');
      }
      bootstrap = await this.withSessionRetry(async (session) => {
        const challenge = await this.api.requestUnlockChallenge(device.deviceId, session);
        if (Date.parse(challenge.expiresAt) <= Date.now()) {
          throw new Error('解锁确认已过期，请重试');
        }
        const signature = await this.keyring.signChallenge(challenge.challenge);
        await this.api.completeUnlock({
          challengeId: challenge.id,
          deviceId: device.deviceId,
          signature,
        }, session);
        return this.api.encryptedBootstrap(session);
      }, initialSession);
    } catch (error) {
      if (error instanceof PanelApiError && error.status !== null) throw error;
      if (error instanceof SessionUnavailableError) throw error;
      if (!(error instanceof PanelApiError)) throw error;
      const cache = await this.storage.loadCiphertextCache();
      if (!cache) throw error;
      bootstrap = cache.bootstrap;
      offline = true;
    }
    if (!this.canContinueUnlock(generation)) return;
    const items = await this.keyring.loadBootstrap(bootstrap);
    if (!this.canContinueUnlock(generation)) return;
    if (!bootstrap.profile) throw new Error('当前账号尚未设置主密码，请先在工作台完成设置');
    if (!device.webUnlock) {
      const accountBundle = accountBundleFromProfile(bootstrap.profile);
      const upgraded = device.pairingOnly
        ? await this.provisionTrustedUnlock(device, accountBundle)
        : legacyUnlockFactor
          ? await this.keyring.upgradeTrustedUnlock(device, legacyUnlockFactor, accountBundle)
          : null;
      if (!upgraded) throw new Error('扩展需要用主密码完成一次兼容升级');
      if (!this.canContinueUnlock(generation)) return;
      await this.storage.saveDevice(upgraded);
      this.model.state.device = upgraded;
    }
    if (!offline) await this.saveBootstrap(bootstrap).catch(() => undefined);
    const activeTab = await this.browser.readActiveTab();
    if (!this.canContinueUnlock(generation)) return;
    this.applyActiveTab(activeTab);
    this.model.setReady(items, offline);
  }

  private async runTrustedUnlock(device: LocalDeviceRecord): Promise<void> {
    this.model.setUnlocking();
    const generation = this.model.captureSecurityGeneration();
    try {
      await withTimeout(
        this.unlockWithWorkbench(device, generation),
        TRUSTED_UNLOCK_ATTEMPT_TIMEOUT_MS,
      );
    } catch (error) {
      if (!this.model.isSecurityGenerationCurrent(generation)) return;
      await this.handleUnlockFailure(error, false);
      throw new Error(this.model.state.error ?? errorMessage(
        error,
        '工作台联动暂时不可用。请确认同一账号的工作台已解锁后重试。',
      ));
    }
  }

  private async unlockWithWorkbench(
    device: LocalDeviceRecord,
    generation: number,
  ): Promise<void> {
    let currentDevice = device;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const request = await this.keyring.createTrustedUnlockRequest(currentDevice);
      if (!this.canContinueUnlock(generation)) return;
      const result = await this.browser.requestTrustedUnlock(request);
      try {
        if (!this.canContinueUnlock(generation)) return;
        const updated = await this.keyring.completeTrustedUnlock(currentDevice, result.response);
        if (!this.canContinueUnlock(generation)) return;
        await this.storage.saveDevice(updated);
        this.model.state.device = updated;
        this.adoptModelSession(result.session);
        currentDevice = updated;
        try {
          await this.loadReadyState(undefined, generation, result.session);
          return;
        } catch (error) {
          if (!(error instanceof SessionUnavailableError) || attempt > 0) throw error;
          if (!this.canContinueUnlock(generation)) return;
          await this.keyring.lock();
        }
      } finally {
        await this.browser.completeTrustedUnlock(request.requestId).catch(() => undefined);
      }
    }
  }

  private async upgradeLegacyDeviceWithWorkbench(
    device: LocalDeviceRecord,
    unlockFactor: string,
  ): Promise<void> {
    this.model.setUnlocking();
    const generation = this.model.captureSecurityGeneration();
    try {
      await withTimeout((async () => {
        await this.keyring.unlock(device, unlockFactor);
        if (!this.canContinueUnlock(generation)) return;
        const request = await this.keyring.createTrustedUnlockRequest(device);
        const result = await this.browser.requestTrustedUnlock(request);
        try {
          if (!this.canContinueUnlock(generation)) return;
          const upgraded = await this.keyring.completeTrustedUnlock(device, result.response);
          if (!this.canContinueUnlock(generation)) return;
          await this.storage.saveDevice(upgraded);
          this.model.state.device = upgraded;
          this.adoptModelSession(result.session);
          await this.loadReadyState(undefined, generation, result.session);
        } finally {
          await this.browser.completeTrustedUnlock(request.requestId).catch(() => undefined);
        }
      })(), TRUSTED_UNLOCK_ATTEMPT_TIMEOUT_MS);
    } catch (error) {
      if (!this.model.isSecurityGenerationCurrent(generation)) return;
      await this.keyring.lock();
      if (isConfirmedDeviceRevocation(error)) {
        await this.handleRevocation();
      } else {
        this.model.setLocked(errorMessage(
          error,
          '升级未完成。此扩展仍受信任；请保持工作台已解锁后重试，无需重新配对',
        ));
      }
      throw error;
    }
  }

  private async provisionTrustedUnlock(
    device: LocalDeviceRecord,
    accountBundle: AccountBundle,
  ): Promise<LocalDeviceRecord> {
    const request = await this.keyring.createTrustedUnlockRequest(device, accountBundle);
    const result = await this.browser.requestTrustedUnlock(request);
    try {
      this.adoptModelSession(result.session);
      return await this.keyring.completeTrustedUnlock(device, result.response);
    } finally {
      await this.browser.completeTrustedUnlock(request.requestId).catch(() => undefined);
    }
  }

  private async handleUnlockFailure(
    error: unknown,
    allowTrustedRecovery: boolean,
  ): Promise<boolean> {
    await this.keyring.lock();
    if (isConfirmedDeviceRevocation(error)) {
      await this.handleRevocation();
      return false;
    }
    if (error instanceof SessionUnavailableError) {
      this.model.setLocked(
        '扩展连接状态已更新，但自动恢复尚未完成。请保持同一账号工作台已解锁后再次恢复，无需重新配对。',
      );
      if (allowTrustedRecovery && this.model.state.device?.webUnlock) {
        try {
          await this.tryTrustedUnlock();
          return this.model.state.phase === 'ready';
        } catch {
          return false;
        }
      }
      return false;
    }
    this.model.setLocked(errorMessage(error, '解锁失败，请重试'));
    return false;
  }

  private async saveBootstrap(bootstrap: ExtensionBootstrap): Promise<void> {
    const { contents: bootstrapContents, ...baseBootstrap } = bootstrap;
    await this.storage.saveCiphertextCache({
      version: 1,
      bootstrap: baseBootstrap,
      contents: currentBootstrapContents(bootstrap, bootstrapContents),
      updatedAt: new Date().toISOString(),
    });
  }

  private async handleRevocation(): Promise<void> {
    this.model.setRevoked();
    await this.keyring.lock();
    await this.clearSensitiveClipboard();
    await this.browser.clearSession().catch(() => undefined);
    await this.storage.clearAll();
  }

  private async recoverAfterSessionLoss(): Promise<boolean> {
    this.model.state.session = null;
    this.model.setLocked(this.model.state.device?.webUnlock
      ? '连接状态已更新，但自动恢复尚未完成。请保持同一账号工作台已解锁后再次恢复，无需重新配对。'
      : '连接状态已更新。此扩展仍受信任，请完成一次兼容升级，无需重新配对。');
    await this.keyring.lock();
    await this.clearSensitiveClipboard();
    if (!this.model.state.device?.webUnlock) return false;
    try {
      await this.tryTrustedUnlock();
      return this.model.state.phase === 'ready';
    } catch {
      return false;
    }
  }

  private async withSessionRetry<T>(
    operation: (session: ExtSession) => Promise<T>,
    initialSession: ExtSession | null = this.model.state.session,
  ): Promise<T> {
    let session = initialSession;
    if (!session) throw new SessionUnavailableError();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const result = await operation(session);
        return result;
      } catch (error) {
        if (!(error instanceof PanelApiError) || error.status !== 401) throw error;
        const failedGeneration = error.sessionGeneration ?? session.generation ?? -1;
        this.sessionInvalidationInFlight += 1;
        let replacement: ExtSession | null;
        try {
          replacement = await this.browser.invalidateSession(failedGeneration);
        } finally {
          this.sessionInvalidationInFlight -= 1;
        }
        if (
          replacement
          && (!this.model.state.device?.userId
            || replacement.user.id === this.model.state.device.userId)
          && attempt === 0
        ) {
          session = replacement;
          this.adoptModelSession(replacement);
          continue;
        }
        if ((this.model.state.session?.generation ?? -1) <= failedGeneration) {
          this.model.state.session = null;
        }
        throw new SessionUnavailableError();
      }
    }
    throw new SessionUnavailableError();
  }

  private adoptModelSession(session: ExtSession): void {
    const deviceUserId = this.model.state.device?.userId;
    if (deviceUserId && session.user.id !== deviceUserId) return;
    const currentGeneration = this.model.state.session?.generation ?? -1;
    if ((session.generation ?? 0) >= currentGeneration) this.model.state.session = session;
  }

  private canContinueUnlock(
    generation: number,
    phase: 'unlocking' | 'ready' = 'unlocking',
  ): boolean {
    return this.model.isSecurityGenerationCurrent(generation)
      && this.model.state.phase === phase;
  }

  private async unlockLocalCache(device: LocalDeviceRecord, unlockFactor: string): Promise<void> {
    const cache = await this.storage.loadCiphertextCache();
    if (!cache) throw new Error('本机没有可用数据，请打开并解锁工作台恢复连接');
    this.model.setUnlocking();
    const generation = this.model.captureSecurityGeneration();
    try {
      await this.keyring.unlock(device, unlockFactor);
      if (!this.canContinueUnlock(generation)) return;
      const items = await this.keyring.loadBootstrap(cache.bootstrap);
      if (!this.canContinueUnlock(generation)) return;
      const activeTab = await this.browser.readActiveTab();
      if (!this.canContinueUnlock(generation)) return;
      this.applyActiveTab(activeTab);
      this.model.setReady(items, true);
    } catch (error) {
      if (!this.model.isSecurityGenerationCurrent(generation)) return;
      await this.keyring.lock();
      this.model.setLocked(errorMessage(error, '本机数据解锁失败'), true);
      throw error;
    }
  }

  private async clearSensitiveClipboard(): Promise<void> {
    if (!this.clipboardPending) return;
    this.clipboardPending = false;
    this.clipboardGeneration += 1;
    await this.browser.writeClipboard('').catch(() => undefined);
  }

  private applyActiveTab(activeTab: ActiveTabContext): void {
    this.model.state.tabId = activeTab.tabId;
    this.model.state.tabOrigin = activeTab.origin;
    this.model.state.tabUrl = activeTab.url;
  }

  private schedulePendingPairingLock(pending: { enrollmentId: string; expiresAt: string }): void {
    const delayMs = Math.max(0, Date.parse(pending.expiresAt) - Date.now());
    this.browser.schedule(() => {
      const current = this.model.state.pendingEnrollment;
      if (
        current?.enrollmentId === pending.enrollmentId &&
        current.expiresAt === pending.expiresAt &&
        Date.parse(current.expiresAt) <= Date.now()
      ) {
        void this.keyring.lock();
      }
    }, delayMs);
  }

  private canUseDecrypted(generation: number): boolean {
    return (
      this.model.isSecurityGenerationCurrent(generation) &&
      this.model.state.phase === 'ready' &&
      this.keyring.unlocked
    );
  }
}

const UNLOCK_ATTEMPT_TIMEOUT_MS = 20_000;
const TRUSTED_UNLOCK_ATTEMPT_TIMEOUT_MS = 30_000;

class SessionUnavailableError extends Error {
  constructor() {
    super('扩展在线连接需要恢复');
    this.name = 'SessionUnavailableError';
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(
      '解锁等待超时。请确认同一账号的工作台已解锁，然后重试。',
    )), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function isConfirmedDeviceRevocation(error: unknown): boolean {
  return error instanceof DeviceRevokedError
    || (error instanceof PanelApiError && error.code === 'extension_device_revoked');
}

function accountBundleFromProfile(profile: UserCryptoProfile): AccountBundle {
  return {
    accountId: profile.userId,
    profileVersion: 1,
    keyVersion: profile.keyVersion,
    suite: profile.suite,
    kdf: profile.kdf,
    encryptedAccountBundle: profile.encryptedAccountBundle,
    encryptionPublicKey: profile.encryptionPublicKey,
    signingPublicKey: profile.signingPublicKey,
  };
}

function currentBootstrapContents(
  bootstrap: ExtensionBootstrap,
  bootstrapContents: ExtensionBootstrap['contents'],
): Record<string, CiphertextCache['contents'][string]> {
  const live = new Set(
    bootstrap.items
      .filter((item) => !item.deleted)
      .map((item) => `${item.itemId}:${item.version}:${item.secretVersion}`),
  );
  const retained: Record<string, CiphertextCache['contents'][string]> = {};
  for (const content of bootstrapContents ?? []) {
    const key = `${content.metadata.itemId}:${content.metadata.version}:${content.metadata.secretVersion}`;
    if (live.has(key)) retained[key] = content;
  }
  return retained;
}

function contentCacheKey(item: DecryptedExtensionItem): string {
  return `${item.id}:${item.version}:${item.secretVersion}`;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
