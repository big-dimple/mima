import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiRequestError } from '@mima/client-core';
import type { SessionInfo } from '@mima/contracts';
import { useApp, useMeta } from './state/app-context.ts';
import { LoginScreen } from './components/LoginScreen.tsx';
import { Workspace } from './components/Workspace.tsx';
import { SecurityGate } from './components/SecurityGate.tsx';
import { Toaster } from './components/Toaster.tsx';
import { ErrorState, LoadingState } from './components/AsyncState.tsx';
import { useUi } from './state/ui-store.ts';
import './global.css';

type StartupState = 'loading' | 'ready' | 'error';

export function describeStartupFailure(error: unknown): string {
  if (error instanceof ApiRequestError && error.status === 0) {
    return '无法连接Mima服务，并且此浏览器没有可用的离线数据。请检查网络后重试。';
  }
  return '工作台初始化失败。服务器没有收到你的主密码、密码或敏感内容。';
}

export function App() {
  const { api, zeroKnowledge, leases } = useApp();
  const securityPhase = useMeta((state) => state.securityPhase);
  const user = useMeta((state) => state.user);
  const [startup, setStartup] = useState<StartupState>('loading');
  const [startupError, setStartupError] = useState<string | null>(null);
  const initializationStarted = useRef(false);

  useEffect(
    () =>
      useUi.subscribe((state, previous) => {
        if (previous.selectedItemId && previous.selectedItemId !== state.selectedItemId) {
          leases.revoke(previous.selectedItemId);
        }
      }),
    [leases],
  );

  const initialize = useCallback(async () => {
    setStartup('loading');
    setStartupError(null);
    try {
      const session = await api.session();
      await zeroKnowledge.prepare(session);
      setStartup('ready');
    } catch (error) {
      if (error instanceof ApiRequestError && (error.status === 401 || error.status === 0)) {
        api.setCsrfToken(null);
        const offlineReady = await zeroKnowledge.prepareOffline().catch(() => false);
        if (offlineReady) {
          setStartup('ready');
          return;
        }
        if (error.status === 401) {
          setStartup('ready');
          return;
        }
      }
      setStartupError(describeStartupFailure(error));
      setStartup('error');
    }
  }, [api, zeroKnowledge]);

  useEffect(() => {
    if (!initializationStarted.current) {
      initializationStarted.current = true;
      void initialize();
    }
  }, [initialize]);

  useEffect(() => {
    const onOffline = () => zeroKnowledge.setOnline(false);
    const onOnline = () => zeroKnowledge.setOnline(true);
    window.addEventListener('offline', onOffline);
    window.addEventListener('online', onOnline);
    return () => {
      window.removeEventListener('offline', onOffline);
      window.removeEventListener('online', onOnline);
    };
  }, [zeroKnowledge]);

  const handleLoggedIn = useCallback(async (session: SessionInfo) => {
    setStartup('loading');
    setStartupError(null);
    try {
      await zeroKnowledge.prepare(session);
      setStartup('ready');
    } catch (error) {
      setStartupError(describeStartupFailure(error));
      setStartup('error');
    }
  }, [zeroKnowledge]);

  const handleLoggedOut = useCallback(() => {
    setStartup('ready');
  }, []);

  return (
    <>
      {(securityPhase === 'unlocked-online' || securityPhase === 'unlocked-offline') && (
        <a href="#main-content" className="skipLink">跳转到主内容</a>
      )}
      {startup === 'loading' && <LoadingState variant="page" label="正在准备密码库…" />}
      {startup === 'error' && (
        <ErrorState
          variant="page"
          title="暂时无法进入工作台"
          message={startupError ?? '工作台初始化失败。'}
          onRetry={() => void initialize()}
        />
      )}
      {startup === 'ready' && securityPhase === 'unauthenticated' && (
        <LoginScreen onLoggedIn={handleLoggedIn} />
      )}
      {startup === 'ready' && (
        securityPhase === 'authenticated-locked' ||
        securityPhase === 'setup-required' ||
        securityPhase === 'unlocking' ||
        securityPhase === 'rotating-identity' ||
        securityPhase === 'account-reset' ||
        securityPhase === 'migration-required' ||
        securityPhase === 'rekey-blocked'
      ) && (
        <SecurityGate phase={securityPhase} user={user} onLoggedOut={handleLoggedOut} />
      )}
      {startup === 'ready' && user && (
        securityPhase === 'unlocked-online' || securityPhase === 'unlocked-offline'
      ) && <Workspace onLoggedOut={handleLoggedOut} />}
      <Toaster />
    </>
  );
}
