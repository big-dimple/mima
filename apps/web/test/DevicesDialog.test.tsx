import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CryptoDevice } from '@mima/contracts';
import { DevicesDialog } from '../src/components/DevicesDialog.tsx';
import { Toaster } from '../src/components/Toaster.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const device: CryptoDevice = {
  id: '10000000-0000-4000-8000-000000000001',
  userId: 'user-1',
  deviceType: 'web',
  encryptedLabel: null,
  encryptionPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  signingPublicKey: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  certificate: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
  certificateSignature: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
  keyVersion: 1,
  trustedAt: '2026-07-18T00:00:00.000Z',
  lastSeenAt: '2026-07-18T01:00:00.000Z',
  revokedAt: null,
};

describe('DevicesDialog main password change', () => {
  beforeEach(() => useUi.setState({ devicesOpen: true, toasts: [] }));
  afterEach(() => useUi.setState({ devicesOpen: false, toasts: [] }));

  it('keeps passwords out of React state and blocks concurrent security mutations', async () => {
    let finishChange!: (value: { localCachePersisted: boolean }) => void;
    const changeMainPassword = vi.fn(() => new Promise<{ localCachePersisted: boolean }>((resolve) => {
      finishChange = resolve;
    }));
    const services = {
      zeroKnowledge: {
        currentDeviceId: device.id,
        listDevices: vi.fn().mockResolvedValue([device]),
        changeMainPassword,
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <DevicesDialog />
          <Toaster />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(await screen.findByText(/旧主密码仍可能打开其本地旧数据/)).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '修改主密码' }));
    await userEvent.type(screen.getByLabelText('当前主密码'), 'old-main-password-value');
    await userEvent.type(screen.getByLabelText('新主密码'), 'new-main-password-value');
    await userEvent.type(screen.getByLabelText('再次输入新主密码'), 'new-main-password-value');
    await userEvent.click(screen.getByRole('button', { name: '验证并更新' }));

    expect(changeMainPassword).toHaveBeenCalledWith(
      'old-main-password-value',
      'new-main-password-value',
      'new-main-password-value',
    );
    expect(screen.getByRole('button', { name: '正在更新…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '取消' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '关闭' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '撤销当前工作台' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '轮换身份密钥' })).toBeDisabled();
    expect(JSON.stringify(useUi.getState())).not.toContain('main-password-value');

    finishChange({ localCachePersisted: true });
    await waitFor(() => expect(screen.queryByLabelText('当前主密码')).not.toBeInTheDocument());
    expect(screen.getByText(/其他已联网设备会立即锁定/)).toBeVisible();
  });

  it('distinguishes the current workbench from a separately authorized extension', async () => {
    const extension = {
      ...device,
      id: '10000000-0000-4000-8000-000000000002',
      deviceType: 'extension' as const,
    };
    const services = {
      zeroKnowledge: {
        currentDeviceId: device.id,
        listDevices: vi.fn().mockResolvedValue([device, extension]),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <DevicesDialog />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(await screen.findByText('工作台浏览器')).toBeVisible();
    expect(screen.getByText('当前工作台')).toBeVisible();
    expect(screen.getByText('浏览器扩展（独立授权）')).toBeVisible();
    expect(screen.getByText(/正常升级或重启不会要求重新配对/)).toBeVisible();
    expect(screen.getByRole('button', { name: '撤销浏览器扩展' })).toBeEnabled();
  });
});
