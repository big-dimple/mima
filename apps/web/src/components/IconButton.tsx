import * as Tooltip from '@radix-ui/react-tooltip';
import type { ReactNode } from 'react';
import styles from './IconButton.module.css';

export function IconButton({
  label,
  onClick,
  children,
  danger,
  disabled,
  active,
  tour,
  ariaExpanded,
  ariaHaspopup,
}: {
  label: string;
  onClick?: () => void;
  children: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  active?: boolean;
  /** 新手引导定位锚点（data-tour）。 */
  tour?: string;
  ariaExpanded?: boolean;
  ariaHaspopup?: 'menu' | 'dialog';
}) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <button
          type="button"
          aria-label={label}
          className={[
            styles.btn,
            danger ? styles.danger : '',
            active ? styles.active : '',
          ].join(' ')}
          onClick={onClick}
          disabled={disabled}
          data-tour={tour}
          aria-expanded={ariaExpanded}
          aria-haspopup={ariaHaspopup}
        >
          {children}
        </button>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className={styles.tooltip} sideOffset={6}>
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

export function IconLink({
  label,
  href,
  children,
}: {
  label: string;
  href: string;
  children: ReactNode;
}) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <a
          aria-label={label}
          className={styles.btn}
          href={href}
          target="_blank"
          rel="noopener noreferrer"
        >
          {children}
        </a>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className={styles.tooltip} sideOffset={6}>
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}
