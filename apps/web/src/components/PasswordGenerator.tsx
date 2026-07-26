import { useLayoutEffect, useRef, useState } from 'react';
import { Copy, RefreshCw } from 'lucide-react';
import { DEFAULT_PASSWORD_OPTIONS, generatePassword, type PasswordOptions } from '@mima/domain';
import { copyWithTimedClear } from '../utils/clipboard.ts';
import { useUi } from '../state/ui-store.ts';
import styles from './PasswordGenerator.module.css';

export function PasswordGenerator({ onUse }: { onUse: (value: string) => void }) {
  const [opts, setOpts] = useState<PasswordOptions>(DEFAULT_PASSWORD_OPTIONS);
  const [seq, setSeq] = useState(0);
  const [available, setAvailable] = useState(true);
  const previewRef = useRef<HTMLElement>(null);
  const toast = useUi((s) => s.toast);

  useLayoutEffect(() => {
    const preview = previewRef.current;
    if (!preview) return;
    let generated = '';
    try {
      void seq;
      generated = generatePassword(opts);
    } catch {
      generated = '';
    }
    preview.textContent = generated || '（请至少选择一类字符）';
    setAvailable(Boolean(generated));
    return () => preview.replaceChildren();
  }, [opts, seq]);

  const toggle = (key: keyof Omit<PasswordOptions, 'length'>) =>
    setOpts((o) => ({ ...o, [key]: !o[key] }));

  const handleCopy = () => {
    const candidate = available ? previewRef.current?.textContent ?? '' : '';
    if (!candidate) return;
    void copyWithTimedClear(candidate);
    toast('info', '已复制生成的密码');
  };

  const handleUse = () => {
    const candidate = available ? previewRef.current?.textContent ?? '' : '';
    if (candidate) onUse(candidate);
  };

  return (
    <div className={styles.wrap}>
      <div className={styles.row}>
        <code
          ref={previewRef}
          id="pg-preview"
          className={styles.preview}
          aria-live="polite"
          aria-atomic="true"
        />
        <button
          type="button"
          className={styles.regen}
          onClick={() => setSeq((s) => s + 1)}
          aria-label="重新生成"
          disabled={!available}
        >
          <RefreshCw size={13} aria-hidden />
        </button>
        <button
          type="button"
          className={styles.regen}
          onClick={handleCopy}
          aria-label="复制生成的密码"
          disabled={!available}
        >
          <Copy size={13} aria-hidden />
        </button>
      </div>
      <div className={styles.controls}>
        <label htmlFor="pg-length" className={styles.len}>
          长度 {opts.length}
          <input
            id="pg-length"
            type="range"
            min={8}
            max={64}
            value={opts.length}
            onChange={(e) => setOpts((o) => ({ ...o, length: Number(e.target.value) }))}
          />
        </label>
        {(
          [
            ['upper', 'A-Z'],
            ['lower', 'a-z'],
            ['digits', '0-9'],
            ['symbols', '!@#'],
          ] as const
        ).map(([key, label]) => (
          <label key={key} htmlFor={`pg-${key}`} className={styles.check}>
            <input id={`pg-${key}`} type="checkbox" checked={opts[key]} onChange={() => toggle(key)} />
            {label}
          </label>
        ))}
        <button
          type="button"
          className={styles.use}
          disabled={!available}
          onClick={handleUse}
        >
          使用
        </button>
      </div>
    </div>
  );
}
