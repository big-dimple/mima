import { SECRET_LEASE_TTL_MS } from '@mima/contracts';

export interface SecretLease {
  itemId: string;
  secretVersion: number;
  expiresAt: number;
}

type LeaseListener = (itemId: string) => void;

/**
 * 敏感内容展示租约：只保存 itemId、版本和到期时间，不保存解密后的正文。
 * 密码、Token 和备注正文仅作为函数局部值短暂经过主线程并直接写入 DOM，
 * 不进入 Zustand、React props/state、Context 可达对象、日志或任何持久化缓存。
 * 默认 60 秒过期；锁屏、网络边界变化、退出、会话失效、权限撤销、角色降级、
 * 条目切换和版本更新时立即销毁。
 *
 * 安全代际（epoch）：revokeAll 推进全局代际，revoke(itemId) 推进该条目代际。
 * 发起 Reveal 前捕获 epoch(itemId)，响应返回后用 grantIfCurrent 写入——
 * 锁定/离线/退出/401/撤权/降级/条目切换之后才到达的"晚到响应"会因代际
 * 不匹配而被丢弃，不可能恢复已被销毁的敏感内容。
 */
export class SecretLeaseStore {
  private leases = new Map<string, SecretLease & { timer: ReturnType<typeof setTimeout> }>();
  private listeners = new Set<LeaseListener>();
  private clockListeners = new Set<() => void>();
  private clockTimer: ReturnType<typeof setInterval> | null = null;
  private globalGen = 0;
  private itemGens = new Map<string, number>();

  private key(itemId: string, secretVersion: number): string {
    return `${itemId}#${secretVersion}`;
  }

  /** 当前安全代际标记。在发起 Reveal 请求前捕获，响应到达后比对。 */
  epoch(itemId: string): string {
    return `${this.globalGen}:${this.itemGens.get(itemId) ?? 0}`;
  }

  isEpochCurrent(itemId: string, epoch: string): boolean {
    return this.epoch(itemId) === epoch;
  }

  grant(itemId: string, secretVersion: number, ttlMs = SECRET_LEASE_TTL_MS): void {
    this.revokeVersion(itemId, secretVersion);
    const timer = setTimeout(() => this.revokeVersion(itemId, secretVersion), ttlMs);
    this.leases.set(this.key(itemId, secretVersion), {
      itemId,
      secretVersion,
      expiresAt: Date.now() + ttlMs,
      timer,
    });
    this.notify(itemId);
  }

  /**
   * 代际守卫写入：epoch 与当前不一致（期间发生过锁定/离线/退出/撤权/条目切换等
   * 任一销毁事件）时拒绝写入并返回 false，晚到的查看响应不得恢复已清除的内容。
   */
  grantIfCurrent(itemId: string, secretVersion: number, epoch: string, ttlMs = SECRET_LEASE_TTL_MS): boolean {
    if (!this.isEpochCurrent(itemId, epoch)) return false;
    this.grant(itemId, secretVersion, ttlMs);
    return true;
  }

  /** 读取指定版本的租约；已过期立即销毁并返回 null。 */
  get(itemId: string, secretVersion: number): SecretLease | null {
    const lease = this.leases.get(this.key(itemId, secretVersion));
    if (!lease) return null;
    if (lease.expiresAt <= Date.now()) {
      this.revokeVersion(itemId, secretVersion);
      return null;
    }
    const { timer: _timer, ...rest } = lease;
    return rest;
  }

  has(itemId: string, secretVersion: number): boolean {
    return this.get(itemId, secretVersion) !== null;
  }

  /** 销毁该条目的全部租约（含历史版本）并推进条目代际。
   * 条目切换/删除/版本变更/撤权时调用——即使当前没有租约，也会使
   * 该条目在途的 Reveal 响应失效。 */
  revoke(itemId: string): void {
    this.itemGens.set(itemId, (this.itemGens.get(itemId) ?? 0) + 1);
    let touched = false;
    for (const [key, lease] of [...this.leases]) {
      if (lease.itemId !== itemId) continue;
      clearTimeout(lease.timer);
      this.leases.delete(key);
      touched = true;
    }
    if (touched) this.notify(itemId);
  }

  revokeVersion(itemId: string, secretVersion: number): void {
    const key = this.key(itemId, secretVersion);
    const lease = this.leases.get(key);
    if (!lease) return;
    clearTimeout(lease.timer);
    this.leases.delete(key);
    this.notify(itemId);
  }

  /** 版本更新时销毁旧租约（其他客户端修改了该条目）。 */
  revokeIfStale(itemId: string, currentSecretVersion: number): void {
    for (const lease of [...this.leases.values()]) {
      if (lease.itemId === itemId && lease.secretVersion !== currentSecretVersion) {
        this.revokeVersion(itemId, lease.secretVersion);
      }
    }
  }

  /** 销毁全部租约并推进全局代际：锁定/网络切换/退出/401 之后，任何在途响应全部失效。 */
  revokeAll(): void {
    this.globalGen += 1;
    const itemIds = new Set([...this.leases.values()].map((l) => l.itemId));
    for (const lease of [...this.leases.values()]) clearTimeout(lease.timer);
    this.leases.clear();
    for (const itemId of itemIds) this.notify(itemId);
  }

  /** 订阅租约变化（授予/销毁），回调只携带 itemId，不携带值。 */
  subscribe(listener: LeaseListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * 订阅统一秒级时钟。用于倒计时 UI：无论多少组件使用，
   * SecretLeaseStore 内部只维护一个 setInterval。
   */
  subscribeToClock(listener: () => void): () => void {
    this.clockListeners.add(listener);
    if (this.clockListeners.size === 1) {
      this.clockTimer = setInterval(() => {
        for (const l of this.clockListeners) l();
      }, 1000);
    }
    return () => {
      this.clockListeners.delete(listener);
      if (this.clockListeners.size === 0 && this.clockTimer) {
        clearInterval(this.clockTimer);
        this.clockTimer = null;
      }
    };
  }

  private notify(itemId: string): void {
    for (const l of this.listeners) l(itemId);
  }
}
