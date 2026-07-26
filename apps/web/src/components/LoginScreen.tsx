import { useCallback, useEffect, useRef, useState } from 'react';
import { KeyRound, ShieldCheck, Sparkles } from 'lucide-react';
import type { AuthConfig, SessionInfo } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import { GuideDialog } from './GuideDialog.tsx';
import styles from './LoginScreen.module.css';

export function LoginScreen({ onLoggedIn }: { onLoggedIn: (session: SessionInfo) => Promise<void> }) {
  const { api } = useApp();
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [users, setUsers] = useState<{ username: string; displayName: string }[]>([]);
  const [username, setUsername] = useState('');
  const passwordRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);

  const loadConfig = useCallback(async () => {
    setConfig(null);
    setConfigError(null);
    try {
      const value = await api.authConfig();
      setConfig(value);
      if (value.mode === 'dev') {
        void api.devUsers().then((result) => setUsers(result.users)).catch(() => setUsers([]));
      }
    } catch {
      setConfigError('认证服务暂时不可用，请检查网络后重试。');
    }
  }, [api]);

  useEffect(() => {
    const errorCode = new URLSearchParams(window.location.search).get('auth_error');
    if (errorCode) {
      setError(errorCode.startsWith('feishu_') ? '飞书登录未完成，请重新登录' : '账号登录未完成，请重新登录');
      window.history.replaceState({}, '', window.location.pathname);
    }
    void loadConfig();
  }, [loadConfig]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const password = passwordRef.current?.value ?? '';
      if (!password) throw new Error('请输入登录密码');
      const info = await api.login({ username, password });
      api.setCsrfToken(info.csrfToken);
      if (passwordRef.current) passwordRef.current.value = '';
      await onLoggedIn(info);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '登录失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={styles.wrap}>
      <div className={styles.card}>
        <div className={styles.logo}>
          <KeyRound size={20} aria-hidden />
          <span>Mima</span>
        </div>

        {config?.loginProvider === 'oidc' || config?.loginProvider === 'feishu' ? (
          <>
            <p className={styles.hint}>使用公司飞书账号登录</p>
            {error && <div className={styles.error} role="alert">{error}</div>}
            <a
              className={styles.primaryLink}
              href={config.loginProvider === 'feishu' ? '/api/auth/feishu/start' : '/api/auth/oidc/start'}
            >
              <ShieldCheck size={19} aria-hidden />
              <span>{config.providerLabel}</span>
            </a>
          </>
        ) : config?.loginMethod === 'password' ? (
          <form className={styles.devForm} onSubmit={submit}>
            <p className={styles.hint}>{config.loginProvider === 'ldap' ? '使用公司域账号登录' : '本地开发身份'}</p>
            <label className={styles.label} htmlFor="login-username">
              {config.loginProvider === 'ldap' ? '域账号' : '用户名'}
            </label>
            <input
              id="login-username"
              className={styles.input}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              autoFocus
            />
            <label className={styles.label} htmlFor="login-password">
              {config.loginProvider === 'ldap' ? '域密码' : '开发密码'}
            </label>
            <input
              id="login-password"
              ref={passwordRef}
              className={styles.input}
              type="password"
              autoComplete="current-password"
            />
            {error && <div className={styles.error} role="alert">{error}</div>}
            <button className={styles.submit} type="submit" disabled={busy || !username}>
              {busy ? '登录中…' : '登录'}
            </button>
            {config.loginProvider === 'dev' && users.length > 0 && (
              <div className={styles.devUsers}>
                <span className={styles.devTitle}>测试身份（密码 dev）：</span>
                {users.map((user) => (
                  <button
                    key={user.username}
                    type="button"
                    className={styles.devUser}
                    onClick={() => {
                      setUsername(user.username);
                      if (passwordRef.current) passwordRef.current.value = 'dev';
                    }}
                  >
                    {user.username}
                  </button>
                ))}
              </div>
            )}
          </form>
        ) : (
          <>
            {configError ? (
              <ErrorState message={configError} onRetry={() => void loadConfig()} />
            ) : (
              <LoadingState label="正在连接认证服务…" />
            )}
            {error && <div className={styles.error} role="alert">{error}</div>}
          </>
        )}

        <button type="button" className={styles.guideEntry} onClick={() => setGuideOpen(true)}>
          <Sparkles size={16} aria-hidden />
          <span>为什么使用Mima / 3 分钟入门</span>
        </button>
      </div>
      <GuideDialog open={guideOpen} onClose={() => setGuideOpen(false)} />
    </div>
  );
}
