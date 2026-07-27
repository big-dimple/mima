import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiRequestError, createMetaStore } from '@mima/client-core';
import { App, describeStartupFailure } from '../src/App.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';

describe('App startup', () => {
  it('shows a retryable service error instead of treating network failure as logout', async () => {
    const session = vi.fn().mockRejectedValue(new ApiRequestError(0, { message: 'Failed to fetch' }));
    const services = {
      api: { session, setCsrfToken: vi.fn() },
      store: createMetaStore(),
      zeroKnowledge: {
        prepareOffline: vi.fn().mockResolvedValue(false),
        setOnline: vi.fn(),
      },
      leases: { revoke: vi.fn() },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <App />
      </AppContext.Provider>,
    );

    expect(await screen.findByRole('alert')).toHaveTextContent('无法连接Mima服务');
    await userEvent.click(screen.getByRole('button', { name: '重试' }));
    await waitFor(() => expect(session).toHaveBeenCalledTimes(2));
  });

  it('uses a safe generic message for non-network bootstrap failures', () => {
    expect(describeStartupFailure(new ApiRequestError(500, { message: 'internal detail' }))).toBe(
      '工作台初始化失败。服务器没有收到你的主密码、密码或敏感内容。',
    );
  });

  it('treats an expired account session as reauthentication instead of a network outage', async () => {
    const store = createMetaStore();
    const lock = vi.fn(async () => undefined);
    const prepareOffline = vi.fn(async () => {
      store.getState().setConnection('offline');
      store.getState().setSecurityPhase('authenticated-locked');
      return true;
    });
    const services = {
      api: {
        session: vi.fn().mockRejectedValue(new ApiRequestError(401, { message: '未登录' })),
        authConfig: vi.fn().mockResolvedValue({
          mode: 'oidc',
          loginProvider: 'oidc',
          reauthProvider: 'oidc',
          directoryProvider: 'authentik',
          loginMethod: 'oidc',
          reauthMethod: 'oidc',
          providerLabel: 'OIDC 登录',
        }),
        setCsrfToken: vi.fn(),
      },
      store,
      zeroKnowledge: {
        prepareOffline,
        setOnline: vi.fn(),
        lock,
      },
      leases: { revoke: vi.fn() },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <App />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('账号登录已过期')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '重新登录' })).toHaveAttribute('href', '/api/auth/oidc/start');
    expect(screen.queryByText('当前离线')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '暂时使用本机数据' }));
    expect(await screen.findByLabelText('主密码（本机解密）')).toBeInTheDocument();
    expect(screen.getByText(/账号登录已过期，当前只使用这台设备保存的数据/)).toBeInTheDocument();
    expect(screen.queryByText(/网络暂时不可用/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '重新登录' }));
    await waitFor(() => expect(lock).toHaveBeenCalledWith(false));
    expect(await screen.findByText('账号登录已过期')).toBeInTheDocument();
  });

  it('shows the normal login on a first visit with no cached vault data', async () => {
    const services = {
      api: {
        session: vi.fn().mockRejectedValue(new ApiRequestError(401, { message: '未登录' })),
        authConfig: vi.fn().mockResolvedValue({
          mode: 'oidc',
          loginProvider: 'oidc',
          reauthProvider: 'oidc',
          directoryProvider: 'authentik',
          loginMethod: 'oidc',
          reauthMethod: 'oidc',
          providerLabel: 'OIDC 登录',
        }),
        setCsrfToken: vi.fn(),
      },
      store: createMetaStore(),
      zeroKnowledge: {
        prepareOffline: vi.fn().mockResolvedValue(false),
        setOnline: vi.fn(),
      },
      leases: { revoke: vi.fn() },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <App />
      </AppContext.Provider>,
    );

    expect(await screen.findByRole('link', { name: 'OIDC 登录' })).toBeInTheDocument();
    expect(screen.queryByText('账号登录已过期')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '暂时使用本机数据' })).not.toBeInTheDocument();
  });

  it('uses offline wording only when the network is unavailable', async () => {
    const store = createMetaStore();
    const prepareOffline = vi.fn(async () => {
      store.getState().setConnection('offline');
      store.getState().setSecurityPhase('authenticated-locked');
      return true;
    });
    const services = {
      api: {
        session: vi.fn().mockRejectedValue(new ApiRequestError(0, { message: 'Failed to fetch' })),
        setCsrfToken: vi.fn(),
      },
      store,
      zeroKnowledge: {
        prepareOffline,
        setOnline: vi.fn(),
      },
      leases: { revoke: vi.fn() },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <App />
      </AppContext.Provider>,
    );

    expect(await screen.findByLabelText('主密码（本机解密）')).toBeInTheDocument();
    expect(screen.getByText('网络暂时不可用，将使用这台设备保存的数据。')).toBeInTheDocument();
    expect(screen.queryByText(/账号登录已过期/)).not.toBeInTheDocument();
  });
});
