import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
} from '@mima/contracts';
import { createMetaStore } from '@mima/client-core';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import {
  RecoveryKeyManager,
  parseEnterpriseRecoveryManifest,
} from '../src/components/RecoveryKeyManager.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

beforeEach(() => {
  useUi.setState({ confirm: null, toasts: [] });
});

describe('enterprise recovery key manager', () => {
  it('accepts only the public manifest and maps its evidence digest to registration', async () => {
    const pending = recoveryKey('pending');
    const api = {
      recoveryKeys: vi.fn()
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([pending]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
      registerRecoveryKey: vi.fn().mockResolvedValue(pending),
    };
    renderManager(api);

    expect(await screen.findByText(/企业可选的兜底能力/)).toBeVisible();
    expect(screen.getByText(/三份恢复材料不得上传、截图/)).toHaveTextContent('同一保管位置');
    const textarea = screen.getByLabelText('公开清单 manifest.json');

    fireEvent.change(textarea, { target: { value: 'share-1-private-canary.mimashare' } });
    await userEvent.click(screen.getByRole('button', { name: '登记公开清单' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('不要粘贴 .mimashare');
    expect(api.registerRecoveryKey).not.toHaveBeenCalled();

    fireEvent.change(textarea, { target: { value: JSON.stringify(publicManifest()) } });
    await userEvent.click(screen.getByRole('button', { name: '登记公开清单' }));
    await waitFor(() => expect(api.registerRecoveryKey).toHaveBeenCalledWith({
      ceremonyId: pending.ceremonyId,
      publicEncryptionKey: pending.publicEncryptionKey,
      keyFingerprint: pending.keyFingerprint,
      threshold: 2,
      shareCount: 3,
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    }));
    expect(textarea).toHaveValue('');
    expect(await screen.findByText('1/2')).toBeVisible();
    expect(screen.getByText('恢复材料摘要')).toBeVisible();
  });

  it('binds approval and activation to the digest after readiness and coverage are complete', async () => {
    const pending = recoveryKey('pending');
    const staged = recoveryKey('staged');
    const active = recoveryKey('active');
    const api = {
      recoveryKeys: vi.fn()
        .mockResolvedValueOnce([pending])
        .mockResolvedValueOnce([staged])
        .mockResolvedValueOnce([active]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
      recoveryCoverage: vi.fn().mockResolvedValue(coverage(2)),
      approveRecoveryKey: vi.fn().mockResolvedValue(staged),
      activateRecoveryKey: vi.fn().mockResolvedValue(active),
    };
    renderManager(api, true);

    await userEvent.click(await screen.findByRole('button', { name: '核对公开清单并批准' }));
    await waitFor(() => expect(api.approveRecoveryKey).toHaveBeenCalledWith(pending.id, {
      idempotencyKey: expect.any(String),
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    }));

    await userEvent.click(await screen.findByRole('button', { name: '正式启用企业恢复' }));
    expect(screen.getByText(/三份恢复材料已经交给三个独立保管人/)).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '确认保管并启用' }));
    await waitFor(() => expect(api.activateRecoveryKey).toHaveBeenCalledWith(pending.id, {
      idempotencyKey: expect.any(String),
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    }));
    expect(await screen.findByText('企业恢复当前已启用。')).toBeVisible();
  });

  it('keeps activation unavailable while any existing vault is uncovered', async () => {
    const staged = recoveryKey('staged');
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([staged]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
      recoveryCoverage: vi.fn().mockResolvedValue(coverage(1)),
      activateRecoveryKey: vi.fn(),
    };
    renderManager(api);

    const activate = await screen.findByRole('button', { name: '正式启用企业恢复' });
    expect(activate).toBeDisabled();
    expect(screen.getByText('密码库覆盖尚未完成，启用操作不可用。')).toBeVisible();
    expect(screen.getByText(/还有 1 个密码库待处理/)).toBeVisible();
    expect(api.activateRecoveryKey).not.toHaveBeenCalled();
  });

  it('does not offer a duplicate approval to the administrator who already approved', async () => {
    const pending = recoveryKey('pending');
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([pending]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
    };
    renderManager(api, false, 'admin-1');

    expect(await screen.findByText(/你已批准，等待另一名管理员/)).toBeVisible();
    expect(screen.queryByRole('button', { name: '核对公开清单并批准' })).not.toBeInTheDocument();
  });

  it('rejects manifests with any non-public field', () => {
    expect(() => parseEnterpriseRecoveryManifest(JSON.stringify({
      ...publicManifest(),
      share: 'private-share-canary',
    }))).toThrow('已拒绝导入');
  });
});

function renderManager(api: Record<string, unknown>, withConfirmation = false, currentUserId = 'admin-3') {
  const store = createMetaStore();
  store.getState().setUser({
    id: currentUserId,
    username: currentUserId,
    displayName: currentUserId,
    email: `${currentUserId}@example.test`,
    groups: [],
    isPlatformAdmin: true,
    isLocalPlatformAdmin: true,
  });
  render(
    <AppContext.Provider value={{ api, store } as unknown as AppServices}>
      <RecoveryKeyManager />
      {withConfirmation && <ConfirmDialog />}
    </AppContext.Provider>,
  );
}

function publicManifest() {
  const key = recoveryKey('pending');
  return {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-manifest',
    ceremonyId: key.ceremonyId,
    ceremonyDigest: key.ceremonyEvidenceDigest,
    publicEncryptionKey: key.publicEncryptionKey,
    keyFingerprint: key.keyFingerprint,
    threshold: 2,
    shareCount: 3,
  };
}

function recoveryKey(status: EnterpriseRecoveryKey['status']): EnterpriseRecoveryKey {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    ceremonyId: 'production-recovery-2026',
    keyFingerprint: 'A'.repeat(43),
    publicEncryptionKey: 'B'.repeat(43),
    threshold: 2,
    shareCount: 3,
    status,
    ceremonyEvidenceDigest: 'C'.repeat(43),
    approvalUserIds: status === 'pending' ? ['admin-1'] : ['admin-1', 'admin-2'],
    createdAt: '2026-07-19T00:00:00.000Z',
    retiredAt: null,
  };
}

function readyAdministrators(): EnterpriseRecoveryReadiness {
  return {
    requiredAdministratorCount: 3,
    administratorCount: 3,
    readyAdministratorCount: 3,
    ready: true,
    administrators: ['alice', 'bob', 'carol'].map((username, index) => ({
      userId: `admin-${index + 1}`,
      username,
      displayName: username[0]!.toUpperCase() + username.slice(1),
      identitySource: 'oidc' as const,
      active: true,
      hasCryptoProfile: true,
      activeDeviceCount: 1,
      ready: true,
    })),
  };
}

function coverage(coveredVaultCount: number): EnterpriseRecoveryCoverage {
  return {
    keyId: '10000000-0000-4000-8000-000000000001',
    totalVaultCount: 2,
    coveredVaultCount,
    complete: coveredVaultCount === 2,
    vaults: [
      {
        vaultId: '20000000-0000-4000-8000-000000000001',
        epoch: 1,
        covered: true,
        canManage: false,
        ownerUserIds: ['owner-1'],
      },
      {
        vaultId: '20000000-0000-4000-8000-000000000002',
        epoch: 1,
        covered: coveredVaultCount === 2,
        canManage: false,
        ownerUserIds: ['owner-2'],
      },
    ],
  };
}
