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
});
