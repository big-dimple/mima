import type { ReactNode } from 'react';
import styles from './ActionButton.module.css';

/**
 * 高频主操作按钮（新建、查看、复制、保存等）：图标 + 文字，
 * 点击区域至少 44×44px。低频操作请继续使用 IconButton（紧凑图标 + tooltip）。
 */
export function ActionButton({
  label,
  icon,
  onClick,
  disabled,
  variant = 'primary',
  type = 'button',
  title,
  tour,
  size = 'standard',
}: {
  label: string;
  icon?: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: 'primary' | 'secondary' | 'danger';
  type?: 'button' | 'submit';
  /** 覆盖悬停提示（如禁用原因）。 */
  title?: string;
  /** 新手引导定位锚点（data-tour）。 */
  tour?: string;
  size?: 'standard' | 'compact';
}) {
  return (
    <button
      type={type}
      className={[
        styles.btn,
        size === 'compact' ? styles.compact : '',
        variant === 'primary' ? styles.primary : variant === 'danger' ? styles.danger : styles.secondary,
      ].join(' ')}
      onClick={onClick}
      disabled={disabled}
      title={title ?? label}
      data-tour={tour}
    >
      {icon && <span className={styles.icon} aria-hidden>{icon}</span>}
      <span>{label}</span>
    </button>
  );
}
