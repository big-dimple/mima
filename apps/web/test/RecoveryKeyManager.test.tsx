import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
  EnterpriseRecoveryWorkspace,
} from '@mima/contracts';
import { createMetaStore } from '@mima/client-core';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import { RecoveryKeyManager } from '../src/components/RecoveryKeyManager.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

beforeEach(() => {
  useUi.setState({ confirm: null, toasts: [] });
});

describe('enterprise recovery key manager', () => {
  it('creates encrypted administrator custody without asking for files', async () => {
    const pending = recoveryKey('pending', ['admin-1']);
    const api = workspaceApi([
      workspace([], null),
      workspace([pending], null),
    ]);
    const prepareManagedEnterpriseRecoveryKey = vi.fn().mockResolvedValue({
      idempotencyKey: 'managed-recovery-setup',
      actorDeviceId: '90000000-0000-4000-8000-000000000001',
      key: {},
      shares: [],
      signature: 'S'.repeat(86),
    });
    api.registerManagedRecoveryKey = vi.fn().mockResolvedValue(pending);

    renderManager(api, { prepareManagedEnterpriseRecoveryKey });

    expect(await screen.findByText(/管理员账号就绪后，还需两位不同管理员/)).toBeVisible();
    expect(screen.getByText(/最少两位，最多六位/)).toBeVisible();
    expect(screen.queryByLabelText(/文件/)).not.toBeInTheDocument();
    expect(screen.queryByText(/下载|上传|离线向导/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '启用企业恢复' }));
    await userEvent.click(screen.getByRole('button', { name: '确认启用' }));

    await waitFor(() => expect(prepareManagedEnterpriseRecoveryKey)
      .toHaveBeenCalledWith(readyAdministrators().administrators));
    expect(api.registerManagedRecoveryKey).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/你的设置确认已记录/)).toBeVisible();
    expect(screen.getAllByText('账号已就绪')).toHaveLength(3);
    expect(screen.getByRole('heading', { name: /2\. 两位管理员确认设置/ }).closest('section'))
      .toHaveAttribute('data-complete', 'false');
  });

  it('lets a different administrator complete the second confirmation', async () => {
    const pending = recoveryKey('pending', ['admin-1']);
    const staged = recoveryKey('staged', ['admin-1', 'admin-2']);
    const api = workspaceApi([
      workspace([pending], null),
      workspace([staged], coverage(1)),
    ]);
    api.recoveryCustodyShare = vi.fn().mockResolvedValue({
      recoveryKeyId: pending.id,
      administratorUserId: 'admin-2',
      administratorKeyVersion: 1,
      shareIndex: 2,
      sealedShare: 'D'.repeat(86),
      sealedShareDigest: 'E'.repeat(43),
    });
    api.approveRecoveryKey = vi.fn().mockResolvedValue(staged);
    api.activateRecoveryKey = vi.fn().mockResolvedValue(staged);
    const preparedApproval = {
      idempotencyKey: 'managed-approval',
      ceremonyEvidenceDigest: pending.ceremonyEvidenceDigest,
      actorDeviceId: '90000000-0000-4000-8000-000000000002',
      sealedShareDigest: 'E'.repeat(43),
      signature: 'F'.repeat(86),
    };
    const prepareManagedEnterpriseRecoveryKeyApproval = vi.fn().mockResolvedValue(preparedApproval);

    renderManager(api, { prepareManagedEnterpriseRecoveryKeyApproval }, 'admin-2');

    await userEvent.click(await screen.findByRole('button', { name: '完成第二位管理员确认' }));
    await userEvent.click(screen.getByRole('button', { name: '核对并确认' }));

    await waitFor(() => expect(api.approveRecoveryKey).toHaveBeenCalledWith(pending.id, preparedApproval));
    expect(prepareManagedEnterpriseRecoveryKeyApproval).toHaveBeenCalledWith(
      pending,
      expect.objectContaining({ administratorUserId: 'admin-2' }),
    );
    await waitFor(() => expect(api.activateRecoveryKey).toHaveBeenCalled());
    expect(await screen.findByText(/历史密码库正在后台更新保护/)).toBeVisible();
    expect(screen.getByRole('heading', { name: /2\. 两位管理员确认设置/ }).closest('section'))
      .toHaveAttribute('data-complete', 'true');
    expect(screen.queryByText(/1\/2/)).not.toBeInTheDocument();
  });

  it('does not offer duplicate confirmation to the first administrator', async () => {
    const pending = recoveryKey('pending', ['admin-1']);
    const api = workspaceApi([workspace([pending], null)]);

    renderManager(api, {}, 'admin-1');

    expect(await screen.findByText(/你的设置确认已记录/)).toBeVisible();
    expect(screen.queryByRole('button', { name: /第二次确认/ })).not.toBeInTheDocument();
  });

  it('waits for complete coverage before replacing an active recovery key', async () => {
    const staged = recoveryKey('staged', ['admin-1', 'admin-2']);
    const active = {
      ...recoveryKey('active', ['admin-1', 'admin-2']),
      id: '10000000-0000-4000-8000-000000000099',
      custodyMode: 'legacy_offline' as const,
      custodyUserIds: [],
    };
    const api = workspaceApi([workspace([staged, active], coverage(1))]);
    api.activateRecoveryKey = vi.fn();

    renderManager(api);

    expect(await screen.findByText(/历史密码库正在后台更新保护/)).toBeVisible();
    expect(api.activateRecoveryKey).not.toHaveBeenCalled();
  });

  it('automatically activates a fully covered replacement', async () => {
    const staged = recoveryKey('staged', ['admin-1', 'admin-2']);
    const active = {
      ...recoveryKey('active', ['admin-1', 'admin-2']),
      id: '10000000-0000-4000-8000-000000000099',
      custodyMode: 'legacy_offline' as const,
      custodyUserIds: [],
    };
    const activated = recoveryKey('active', ['admin-1', 'admin-2']);
    const api = workspaceApi([
      workspace([staged, active], coverage(2)),
      workspace([activated], coverage(2)),
    ]);
    api.activateRecoveryKey = vi.fn().mockResolvedValue(activated);

    renderManager(api);

    await waitFor(() => expect(api.activateRecoveryKey).toHaveBeenCalledWith(staged.id, {
      idempotencyKey: `activate-${staged.id}`,
      ceremonyEvidenceDigest: staged.ceremonyEvidenceDigest,
    }));
    expect(await screen.findByText(/现有密码库均已保护/)).toBeVisible();
  });
});

function renderManager(
  api: Record<string, ReturnType<typeof vi.fn>>,
  zeroKnowledgeOverrides: Record<string, unknown> = {},
  currentUserId = 'admin-1',
) {
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
    <AppContext.Provider value={{
      api,
      store,
      zeroKnowledge: {
        refresh: vi.fn().mockResolvedValue(undefined),
        ...zeroKnowledgeOverrides,
      },
    } as unknown as AppServices}>
      <RecoveryKeyManager />
      <ConfirmDialog />
    </AppContext.Provider>,
  );
}

function workspaceApi(values: EnterpriseRecoveryWorkspace[]) {
  const fallback = values.at(-1)!;
  const queue = [...values];
  return {
    recoveryWorkspace: vi.fn(async () => queue.shift() ?? fallback),
  } as Record<string, ReturnType<typeof vi.fn>>;
}

function workspace(
  keys: EnterpriseRecoveryKey[],
  recoveryCoverage: EnterpriseRecoveryCoverage | null,
): EnterpriseRecoveryWorkspace {
  return {
    refreshedAt: '2026-08-07T00:00:00.000Z',
    keys,
    readiness: readyAdministrators(),
    coverage: recoveryCoverage,
    requests: [],
    candidates: [],
    cases: [],
  };
}

function recoveryKey(
  status: EnterpriseRecoveryKey['status'],
  approvalUserIds: string[],
): EnterpriseRecoveryKey {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    ceremonyId: 'managed-recovery-2026',
    keyFingerprint: 'A'.repeat(43),
    publicEncryptionKey: 'B'.repeat(43),
    threshold: 2,
    shareCount: 3,
    custodyMode: 'administrator_accounts',
    custodyUserIds: ['admin-1', 'admin-2', 'admin-3'],
    status,
    ceremonyEvidenceDigest: 'C'.repeat(43),
    approvalUserIds,
    createdAt: '2026-08-07T00:00:00.000Z',
    retiredAt: null,
    cancelledAt: null,
  };
}

function readyAdministrators(): EnterpriseRecoveryReadiness {
  return {
    requiredAdministratorCount: 2,
    maximumAdministratorCount: 6,
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
      cryptoGeneration: 1,
      encryptionPublicKey: String.fromCharCode(68 + index).repeat(43),
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
    vaults: [1, 2].map((index) => ({
      vaultId: `20000000-0000-4000-8000-00000000000${index}`,
      epoch: 1,
      covered: index <= coveredVaultCount,
      canManage: false,
      ownerUserIds: [`owner-${index}`],
    })),
  };
}
