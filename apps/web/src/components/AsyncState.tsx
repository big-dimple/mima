import { AlertCircle, Inbox, LoaderCircle, RefreshCw } from 'lucide-react';
import styles from './AsyncState.module.css';

type StateVariant = 'compact' | 'page' | 'overlay';

export function LoadingState({
  label = '加载中…',
  variant = 'compact',
}: {
  label?: string;
  variant?: StateVariant;
}) {
  return (
    <div className={[styles.state, styles[variant]].join(' ')} role="status" aria-live="polite">
      <LoaderCircle className={styles.spin} size={18} aria-hidden />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({
  title = '加载失败',
  message,
  onRetry,
  variant = 'compact',
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
  variant?: StateVariant;
}) {
  return (
    <div className={[styles.state, styles[variant]].join(' ')} role="alert">
      <AlertCircle className={styles.errorIcon} size={variant === 'compact' ? 18 : 24} aria-hidden />
      <strong className={styles.title}>{title}</strong>
      <span className={styles.message}>{message}</span>
      {onRetry && (
        <button className={styles.retry} type="button" onClick={onRetry}>
          <RefreshCw size={15} aria-hidden />
          <span>重试</span>
        </button>
      )}
    </div>
  );
}

export function EmptyState({ label }: { label: string }) {
  return (
    <div className={[styles.state, styles.compact].join(' ')} role="status">
      <Inbox size={18} aria-hidden />
      <span>{label}</span>
    </div>
  );
}
