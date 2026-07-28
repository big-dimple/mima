import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { LoginScreen } from '../src/components/LoginScreen.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';

describe('LoginScreen', () => {
  it('retries authentication configuration without remaining on a loading message', async () => {
    const authConfig = vi.fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({
        mode: 'dev',
        loginProvider: 'dev',
        reauthProvider: 'dev',
        directoryProvider: 'dev',
        loginMethod: 'password',
        reauthMethod: 'password',
        providerLabel: 'Development',
      });
    const services = {
      api: {
        authConfig,
        devUsers: vi.fn().mockResolvedValue({ users: [] }),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <LoginScreen onLoggedIn={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(await screen.findByRole('alert')).toHaveTextContent('认证服务暂时不可用');
    await userEvent.click(screen.getByRole('button', { name: '重试' }));
    expect(await screen.findByLabelText('用户名')).toBeVisible();
    expect(authConfig).toHaveBeenCalledTimes(2);
  });

  it('offers direct Feishu login without showing a password form', async () => {
    const services = {
      api: {
        authConfig: vi.fn().mockResolvedValue({
          mode: 'feishu',
          loginProvider: 'feishu',
          reauthProvider: 'ldap',
          directoryProvider: 'ldap',
          loginMethod: 'feishu',
          reauthMethod: 'password',
          providerLabel: '使用飞书登录',
        }),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <LoginScreen onLoggedIn={vi.fn()} />
      </AppContext.Provider>,
    );

    const link = await screen.findByRole('link', { name: '使用飞书登录' });
    expect(link).toHaveAttribute('href', '/api/auth/feishu/start');
    expect(screen.queryByLabelText('域密码')).not.toBeInTheDocument();
  });

  it('describes a generic OIDC provider as company unified authentication', async () => {
    const services = {
      api: {
        authConfig: vi.fn().mockResolvedValue({
          mode: 'oidc',
          loginProvider: 'oidc',
          reauthProvider: 'oidc',
          directoryProvider: 'oidc',
          loginMethod: 'oidc',
          reauthMethod: 'oidc',
          providerLabel: '组织统一认证',
        }),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <LoginScreen onLoggedIn={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('使用组织统一认证登录')).toBeVisible();
    expect(screen.queryByText(/飞书账号/)).not.toBeInTheDocument();
  });

  it('logs in with a domain account when LDAP is the login provider', async () => {
    const onLoggedIn = vi.fn().mockResolvedValue(undefined);
    const login = vi.fn().mockResolvedValue({ csrfToken: 'csrf-1', locked: false });
    const setCsrfToken = vi.fn();
    const services = {
      api: {
        authConfig: vi.fn().mockResolvedValue({
          mode: 'ldap',
          loginProvider: 'ldap',
          reauthProvider: 'ldap',
          directoryProvider: 'ldap',
          loginMethod: 'password',
          reauthMethod: 'password',
          providerLabel: '公司域账号',
        }),
        login,
        setCsrfToken,
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <LoginScreen onLoggedIn={onLoggedIn} />
      </AppContext.Provider>,
    );

    await userEvent.type(await screen.findByLabelText('域账号'), 'alice');
    await userEvent.type(screen.getByLabelText('域密码'), 'correct-horse');
    await userEvent.click(screen.getByRole('button', { name: '登录' }));

    expect(login).toHaveBeenCalledWith({ username: 'alice', password: 'correct-horse' });
    expect(setCsrfToken).toHaveBeenCalledWith('csrf-1');
    expect(onLoggedIn).toHaveBeenCalledWith({ csrfToken: 'csrf-1', locked: false });
  });
});
