import { useEffect, useRef, useState } from 'react';
import { Lock, ShieldCheck } from 'lucide-react';
import type { AuthConfig } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import styles from './LockOverlay.module.css';

export function LockOverlay() {
  const { actions, api } = useApp();
  const user = useMeta((state) => state.user);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.authConfig().then(setConfig).catch(() => setError('认证服务暂时不可用'));
  }, [api]);

  const submitPassword = async (event: React.FormEvent) => {
    event.preventDefault();
    const password = passwordRef.current?.value ?? '';
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      await actions.unlock(password);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '解锁失败');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      setBusy(false);
    }
  };

  const beginOidcReauthentication = async () => {
    setBusy(true);
    setError(null);
    try {
      const { redirectUrl } = await api.beginOidcReauthentication();
      window.location.assign(redirectUrl);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '统一认证解锁失败');
      setBusy(false);
    }
  };

  return (
    <div className={styles.overlay} role="dialog" aria-modal="true" aria-label="密码库已锁定">
      <div className={styles.card}>
        <Lock size={22} className={styles.icon} aria-hidden />
        <h2 className={styles.title}>密码库已锁定</h2>
        <p className={styles.hint}>
          刚才查看过的密码和敏感内容已隐藏，并已尝试清理由本应用复制的内容。已保存的数据没有删除。
        </p>
        {user && <div className={styles.account}>{user.displayName} · {user.username}</div>}

        {config?.reauthMethod === 'oidc' ? (
          <button
            className={styles.submit}
            type="button"
            disabled={busy}
            onClick={() => void beginOidcReauthentication()}
          >
            <ShieldCheck size={18} aria-hidden />
            <span>{busy ? '正在前往账号登录…' : '重新完成账号登录'}</span>
          </button>
        ) : config?.reauthMethod === 'password' ? (
          <form className={styles.form} onSubmit={submitPassword}>
            <label className={styles.fieldLabel} htmlFor="unlock-password">
              {config.reauthProvider === 'ldap' ? '域密码' : '登录密码'}
            </label>
            <input
              id="unlock-password"
              ref={passwordRef}
              className={styles.input}
              type="password"
              placeholder={config.reauthProvider === 'ldap' ? '输入域密码' : '输入登录密码'}
              autoFocus
              autoComplete="current-password"
              required
            />
            <button className={styles.submit} type="submit" disabled={busy}>
              解锁
            </button>
          </form>
        ) : (
          <p className={styles.hint}>正在连接认证服务…</p>
        )}
        {error && <div className={styles.error} role="alert">{error}</div>}
      </div>
    </div>
  );
}
