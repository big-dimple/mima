import { useState } from 'react';
import { Copy, Eye, EyeOff } from 'lucide-react';
import { StaleRevealError } from '@mima/client-core';
import type { ItemKind } from '@mima/contracts';
import { getItemPresentation } from '@mima/domain';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { useLease } from '../hooks/useLease.ts';
import { useTransientText } from '../hooks/useTransientText.ts';
import { clearSecretClipboard, copyWithTimedClear } from '../utils/clipboard.ts';
import { ActionButton } from './ActionButton.tsx';
import styles from './SecretField.module.css';

/**
 * 敏感内容展示区：默认遮罩；Reveal 后进入 60 秒 Lease 倒计时；
 * 展示租约只保存到期时间；正文通过 ref 直接写入 DOM，不进入 React/Context 状态。
 * 复制走独立的 revealForCopy 通道，不在界面上顺带显示敏感内容；
 * 在线时服务端只能记录密文投递，离线时使用本地密文缓存。晚到响应按安全代际丢弃。
 */
export function SecretField({ itemId, kind, secretVersion }: { itemId: string; kind: ItemKind; secretVersion: number }) {
  const { actions, leases } = useApp();
  const toast = useUi((s) => s.toast);
  const { lease, remainingSec } = useLease(itemId, secretVersion);
  const [busy, setBusy] = useState(false);

  const revealed = lease !== null;
  const transient = useTransientText(`${itemId}:${secretVersion}`, revealed);

  const doReveal = async () => {
    setBusy(true);
    try {
      const epoch = leases.epoch(itemId);
      const result = await actions.reveal(itemId, 'view');
      if (!leases.isEpochCurrent(itemId, epoch) || !transient.show(result.value)) {
        transient.clear();
        leases.revokeVersion(itemId, result.secretVersion);
        throw new StaleRevealError();
      }
    } catch (err) {
      if (!(err instanceof StaleRevealError)) {
        toast('error', err instanceof Error ? err.message : '查看失败');
      }
    } finally {
      setBusy(false);
    }
  };

  const doCopy = async () => {
    const epoch = leases.epoch(itemId);
    try {
      // 在线时先取得服务端投递的密文，离线时读取本地密文缓存；
      // 期间发生锁定/离线/退出/撤权/条目切换 → StaleRevealError，什么都不写
      const value = await actions.revealForCopy(itemId);
      await copyWithTimedClear(value);
      // 写剪贴板期间状态又变了（如恰好锁定）：立即清掉刚写入的内容
      if (!leases.isEpochCurrent(itemId, epoch)) {
        await clearSecretClipboard();
        return;
      }
      toast('info', '已复制，30 秒后将尽力清理剪贴板');
    } catch (err) {
      if (!(err instanceof StaleRevealError)) {
        toast('error', err instanceof Error ? err.message : '复制失败');
      }
    }
  };

  const label = getItemPresentation(kind).secretLabel;
  const isNote = kind === 'secure_note';

  return (
    <div className={styles.wrap} data-tour="secret-field">
      <div className={styles.labelRow}>
        <span className={styles.label}>{label}</span>
        {revealed && (
          <span className={styles.countdown} role="timer">
            {remainingSec}s 后自动遮罩
          </span>
        )}
      </div>
      <div className={styles.valueRow}>
        {isNote ? (
          <pre ref={transient.bind} className={styles.noteValue} hidden={!revealed} />
        ) : (
          <code ref={transient.bind} className={styles.value} hidden={!revealed} />
        )}
        {!revealed && (
          <span className={styles.masked} aria-label={`${label}已遮罩`}>
            ••••••••••••
          </span>
        )}
      </div>
      <div className={styles.actionRow}>
        {revealed ? (
          <ActionButton
            label="立即遮罩"
            icon={<EyeOff size={16} />}
            variant="secondary"
            onClick={() => {
              transient.clear();
              leases.revoke(itemId);
            }}
          />
        ) : (
          <ActionButton
            label={`查看${label}`}
            icon={<Eye size={16} />}
            onClick={() => void doReveal()}
            disabled={busy}
            title={`查看${label}，60 秒后自动遮罩`}
          />
        )}
        <ActionButton
          label="复制"
          icon={<Copy size={16} />}
          variant={revealed ? 'secondary' : 'primary'}
          onClick={() => void doCopy()}
          title="复制到剪贴板（不在屏幕显示，30 秒后尽力清理）"
        />
      </div>
    </div>
  );
}
