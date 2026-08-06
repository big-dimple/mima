import { render, screen, waitFor } from '@testing-library/react';
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
    const pending = { ...recoveryKey('pending'), approvalUserIds: ['admin-3'] };
    const api = {
      recoveryKeys: vi.fn()
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([pending]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
      registerRecoveryKey: vi.fn().mockResolvedValue(pending),
      approveRecoveryKey: vi.fn().mockResolvedValue(pending),
    };
    renderManager(api);

    expect(await screen.findByText(/只需准备一次/)).toBeVisible();
    expect(screen.getByText(/生成和使用恢复材料时，它们始终不会接触服务器或网络/)).toBeVisible();
    expect(screen.getByText(/每次帮助普通用户恢复只需要其中两位/)).toBeVisible();
    for (const name of ['Alice', 'Bob', 'Carol']) expect(screen.getByText(name)).toBeVisible();
    expect(screen.getByText(/恢复材料绝不能上传/)).toBeVisible();
    const input = screen.getByLabelText('选择企业恢复公开清单');

    await userEvent.upload(input, new File(
      ['share-1-private-canary.mimashare'],
      'not-a-manifest.json',
      { type: 'application/json' },
    ));
    expect(await screen.findByRole('alert')).toHaveTextContent('不是有效的公开清单');
    expect(screen.getByRole('button', { name: '登记并完成第一次确认' })).toBeDisabled();
    expect(api.registerRecoveryKey).not.toHaveBeenCalled();

    await userEvent.upload(input, new File(
      [JSON.stringify(publicManifest())],
      'manifest.json',
      { type: 'application/json' },
    ));
    expect(await screen.findByText(/manifest.json 文件检查通过/)).toBeVisible();
    await userEvent.click(screen.getByRole('checkbox'));
    await userEvent.click(screen.getByRole('button', { name: '登记并完成第一次确认' }));
    await waitFor(() => expect(api.registerRecoveryKey).toHaveBeenCalledWith({
      ceremonyId: pending.ceremonyId,
      publicEncryptionKey: pending.publicEncryptionKey,
      keyFingerprint: pending.keyFingerprint,
      threshold: 2,
      shareCount: 3,
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    }));
    expect(api.approveRecoveryKey).toHaveBeenCalledWith(pending.id, {
      idempotencyKey: expect.any(String),
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    });
    expect(input).toHaveValue('');
    expect(await screen.findByText(/你的确认已经完成/)).toBeVisible();
  });

  it('automatically activates after the second approval and background coverage complete', async () => {
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

    await userEvent.click(await screen.findByRole('button', { name: '核对并确认' }));
    await userEvent.click(screen.getByRole('button', { name: '已经核对，确认' }));
    await waitFor(() => expect(api.approveRecoveryKey).toHaveBeenCalledWith(pending.id, {
      idempotencyKey: expect.any(String),
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    }));
    await waitFor(() => expect(api.activateRecoveryKey).toHaveBeenCalledWith(pending.id, {
      idempotencyKey: `activate-${pending.id}`,
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
    }));
    expect(await screen.findByText('企业恢复已经准备完成。')).toBeVisible();
  });

  it('waits in the background while any existing vault is uncovered', async () => {
    const staged = recoveryKey('staged');
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([staged]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
      recoveryCoverage: vi.fn().mockResolvedValue(coverage(1)),
      activateRecoveryKey: vi.fn(),
    };
    renderManager(api);

    expect(await screen.findByText('系统正在后台保护现有密码库：1/2')).toBeVisible();
    expect(screen.queryByRole('button', { name: /启用企业恢复/ })).not.toBeInTheDocument();
    expect(api.activateRecoveryKey).not.toHaveBeenCalled();
  });

  it('does not offer a duplicate approval to the administrator who already approved', async () => {
    const pending = recoveryKey('pending');
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([pending]),
      recoveryReadiness: vi.fn().mockResolvedValue(readyAdministrators()),
    };
    renderManager(api, false, 'admin-1');

    expect(await screen.findByText(/你的确认已经完成/)).toBeVisible();
    expect(screen.queryByRole('button', { name: '核对并确认' })).not.toBeInTheDocument();
  });

  it('rejects manifests with any non-public field', () => {
    expect(() => parseEnterpriseRecoveryManifest(JSON.stringify({
      ...publicManifest(),
      share: 'private-share-canary',
    }))).toThrow('不要选择恢复材料');
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
