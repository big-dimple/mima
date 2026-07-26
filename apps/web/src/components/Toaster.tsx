import { X } from 'lucide-react';
import { useUi } from '../state/ui-store.ts';
import styles from './Toaster.module.css';

export function Toaster() {
  const toasts = useUi((s) => s.toasts);
  const dismiss = useUi((s) => s.dismissToast);
  if (toasts.length === 0) return null;
  return (
    <div className={styles.wrap} role="region" aria-label="通知">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={[styles.toast, styles[t.kind]].join(' ')}
          role={t.kind === 'error' ? 'alert' : 'status'}
          aria-live={t.kind === 'error' ? 'assertive' : 'polite'}
        >
          <span className={styles.text}>{t.text}</span>
          <button
            className={styles.close}
            onClick={() => dismiss(t.id)}
            aria-label="关闭通知"
            type="button"
          >
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}
