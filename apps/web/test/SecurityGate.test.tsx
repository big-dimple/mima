import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore, type LegacyMigrationStatusResponse } from '@mima/client-core';
import { AdminAccountResetApprovals, SecurityGate } from '../src/components/SecurityGate.tsx';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const vaultId = '20000000-0000-4000-8000-000000000001';
const jobId = '30000000-0000-4000-8000-000000000001';
const user = {
  id: 'u-owner',
  username: 'owner',
  displayName: 'Owner',
  email: 'owner@example.test',
  groups: [],
  isPlatformAdmin: false,
};

afterEach(() => useUi.getState().resetWorkspaceUi());

describe('master password browser form contract', () => {
  it('exposes the authenticated account and current password to password managers', async () => {
    const unlock = vi.fn(async () => undefined);
    const store = createMetaStore();
    store.getState().setConnection('online');
    const services = {
      store,
      zeroKnowledge: { unlock },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="authenticated-locked" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    const username = screen.getByLabelText('账号');
    expect(username).toHaveAttribute('name', 'username');
    expect(username).toHaveAttribute('autocomplete', 'username');
    expect(username).toHaveValue(user.username);
    expect(username).toHaveAttribute('readonly');

    const password = screen.getByLabelText('主密码（本机解密）');
    expect(password).toHaveAttribute('name', 'password');
    expect(password).toHaveAttribute('autocomplete', 'current-password');
    await userEvent.type(password, 'saved-main-password');
    await userEvent.click(screen.getByRole('button', { name: '解锁密码库' }));
    await waitFor(() => expect(unlock).toHaveBeenCalledWith('saved-main-password'));
  });

  it('uses the same account identity when creating a saved main password', () => {
    const store = createMetaStore();
    const services = {
      store,
      zeroKnowledge: { setup: vi.fn() },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="setup-required" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(screen.getByLabelText('账号')).toHaveValue(user.username);
    expect(screen.getByLabelText('主密码（本机解密）')).toHaveAttribute('autocomplete', 'new-password');
    expect(screen.getByLabelText('再次输入主密码（本机解密）')).toHaveAttribute('name', 'password-confirmation');
    expect(screen.getByText(/包括平台管理员也绝对无法查看受保护库/)).toBeVisible();
  });

  it('does not bind an approved recovery case to the browser that set the new password', async () => {
    const caseId = '70000000-0000-4000-8000-000000000009';
    const activatePreparedAccountCryptoReset = vi.fn();
    const store = createMetaStore();
    const services = {
      store,
      api: {
        recoveryCases: vi.fn(async () => [{ id: caseId }]),
      },
      zeroKnowledge: {
        accountCryptoResetRequests: vi.fn(async () => [{
          id: '73000000-0000-4000-8000-000000000009',
          caseId,
          targetUserId: user.id,
          status: 'approved',
          approvalUserIds: ['u-admin-1', 'u-admin-2'],
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }]),
        activatePreparedAccountCryptoReset,
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="account-reset" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(await screen.findByText(/之后可在任意浏览器重新登录/)).toBeVisible();
    await waitFor(() => expect(services.zeroKnowledge.accountCryptoResetRequests).toHaveBeenCalled());
    expect(activatePreparedAccountCryptoReset).not.toHaveBeenCalled();
  });
});

describe('legacy migration security gate', () => {
  it('exposes the frozen, local conversion, verification, cutover and rollback stages', async () => {
    let prepared = false;
    let status = migrationStatus('frozen');
    const legacyMigrationStatus = vi.fn(async () => status);
    const convertLegacyMigration = vi.fn(async () => {
      prepared = true;
      status = migrationStatus('encrypting');
      return status;
    });
    const verifyLegacyMigration = vi.fn(async () => {
      status = migrationStatus('verifying');
      return status;
    });
    const cutoverLegacyMigration = vi.fn(async () => undefined);
    const rollbackLegacyMigration = vi.fn(async () => undefined);
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user,
      vaults: [{
        id: vaultId,
        kind: 'team',
        name: '等待迁移',
        ownerUserId: user.id,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }],
      memberships: [],
      items: [],
      cursor: 0,
      vaultCrypto: {
        [vaultId]: {
          vaultId,
          status: 'frozen',
          activeEpoch: 0,
          pendingEpoch: null,
          rekeyTaskId: null,
          encryptedHeader: null,
          migrationJobId: jobId,
          updatedAt: new Date().toISOString(),
        },
      },
      encryptedItems: {},
      vaultDirectories: {},
    });
    const services = {
      store,
      zeroKnowledge: {
        legacyMigrationStatus,
        hasPreparedLegacyMigration: vi.fn(() => prepared),
        convertLegacyMigration,
        verifyLegacyMigration,
        cutoverLegacyMigration,
        rollbackLegacyMigration,
        refresh: vi.fn(),
        logout: vi.fn(),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="migration-required" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('等待隔离迁移程序')).toBeInTheDocument();
    expect(screen.getByText(jobId)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '回滚本次迁移' })).toBeInTheDocument();

    status = migrationStatus('encrypting');
    await userEvent.click(screen.getByTitle('刷新状态'));
    await userEvent.click(await screen.findByRole('button', { name: '领取并本地转换' }));
    await waitFor(() => expect(convertLegacyMigration).toHaveBeenCalledWith(vaultId));
    expect(await screen.findByRole('button', { name: '核对记录与接收人' })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '核对记录与接收人' }));
    expect(await screen.findByRole('button', { name: '切换到零知识密文' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '切换到零知识密文' }));
    await waitFor(() => expect(cutoverLegacyMigration).toHaveBeenCalledWith(vaultId));
  });

  it('only shows empty-vault initialization after the server confirms eligibility', async () => {
    let status = migrationStatus('pending', false);
    const legacyMigrationStatus = vi.fn(async () => status);
    const initializePendingVault = vi.fn(async () => undefined);
    useUi.setState({ selectedVaultId: 'all' });
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user,
      vaults: [{
        id: vaultId,
        kind: 'team',
        name: '待判断旧库',
        ownerUserId: user.id,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }],
      memberships: [],
      items: [],
      cursor: 0,
      vaultCrypto: {
        [vaultId]: {
          vaultId,
          status: 'legacy',
          activeEpoch: 0,
          pendingEpoch: null,
          rekeyTaskId: null,
          encryptedHeader: null,
          migrationJobId: null,
          updatedAt: new Date().toISOString(),
        },
      },
      encryptedItems: {},
      vaultDirectories: {},
    });
    const services = {
      store,
      zeroKnowledge: {
        legacyMigrationStatus,
        hasPreparedLegacyMigration: vi.fn(() => false),
        initializePendingVault,
        startLegacyMigration: vi.fn(),
        refresh: vi.fn(),
        logout: vi.fn(),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="migration-required" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    await screen.findByText('尚未开始');
    expect(screen.queryByText('这是没有条目和旧审计内容的空密码库')).not.toBeInTheDocument();

    status = { ...migrationStatus('pending', true), materials: null };
    await userEvent.click(screen.getByTitle('刷新状态'));
    expect(await screen.findByText('创建密码库')).toBeInTheDocument();
    expect(screen.getByText(/本地密钥材料尚未准备完成/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '等待本地密钥准备完成' })).toBeDisabled();

    status = migrationStatus('pending', true, false);
    await userEvent.click(screen.getByRole('button', { name: '重新检查' }));
    expect(await screen.findByText(/企业恢复可稍后配置，不影响现在创建和使用密码库/)).toBeInTheDocument();
    const initialize = await screen.findByRole('button', { name: '创建并进入工作台' });
    expect(initialize).toBeDisabled();
    await userEvent.type(screen.getByLabelText('密码库名称'), '我的密码');
    expect(initialize).toBeEnabled();
    await userEvent.click(initialize);
    await waitFor(() => expect(initializePendingVault).toHaveBeenCalledWith(vaultId, '我的密码'));
    expect(useUi.getState().selectedVaultId).toBe(vaultId);
  });

  it('never asks for a name when an empty personal vault is being prepared', async () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user,
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '个人库',
        ownerUserId: user.id,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }],
      memberships: [],
      items: [],
      cursor: 0,
      vaultCrypto: {
        [vaultId]: {
          vaultId,
          status: 'legacy',
          activeEpoch: 0,
          pendingEpoch: null,
          rekeyTaskId: null,
          encryptedHeader: null,
          migrationJobId: null,
          updatedAt: new Date().toISOString(),
        },
      },
      encryptedItems: {},
      vaultDirectories: {},
    });
    const services = {
      store,
      zeroKnowledge: {
        legacyMigrationStatus: vi.fn().mockResolvedValue(migrationStatus('pending', true, false)),
        hasPreparedLegacyMigration: vi.fn(() => false),
        refresh: vi.fn(),
        logout: vi.fn(),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="migration-required" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('正在自动准备“我的密码库”')).toBeVisible();
    expect(screen.queryByLabelText('密码库名称')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '创建并进入工作台' })).not.toBeInTheDocument();
  });

  it('shows an honest enterprise-recovery path without a doomed rekey action', async () => {
    const store = createMetaStore();
    const completeVaultRekey = vi.fn();
    store.getState().applyDecryptedBootstrap({
      user,
      vaults: [{
        id: vaultId,
        kind: 'personal',
        name: '需要企业恢复',
        ownerUserId: user.id,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }],
      memberships: [],
      items: [],
      cursor: 0,
      vaultCrypto: {
        [vaultId]: {
          vaultId,
          status: 'rekey_required',
          activeEpoch: 1,
          pendingEpoch: 2,
          rekeyTaskId: null,
          encryptedHeader: null,
          migrationJobId: null,
          recoveryRequired: true,
          recoveryReason: 'missing_current_full_envelope',
          updatedAt: new Date().toISOString(),
        },
      },
      encryptedItems: {},
      vaultDirectories: {},
    });
    const services = {
      store,
      api: { recoveryCases: vi.fn(async () => []) },
      zeroKnowledge: {
        completeVaultRekey,
        rekeyTaskId: vi.fn(() => null),
        refresh: vi.fn(),
        logout: vi.fn(),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="rekey-blocked" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(await screen.findByRole('heading', { name: '部分密码库需要企业恢复' })).toBeInTheDocument();
    expect(screen.getByText(/系统不会返回对应条目/)).toBeInTheDocument();
    expect(screen.getByText(/两位管理员确认后/)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: '刷新状态' }).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: '完成安全更新' })).not.toBeInTheDocument();
    expect(completeVaultRekey).not.toHaveBeenCalled();
  });

  it('explains routine access protection without exposing rekey internals', async () => {
    const store = createMetaStore();
    const completeVaultRekey = vi.fn(async () => undefined);
    store.getState().applyDecryptedBootstrap({
      user,
      vaults: [{
        id: vaultId,
        kind: 'team',
        name: '运维密码库',
        ownerUserId: user.id,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }],
      memberships: [],
      items: [],
      cursor: 0,
      vaultCrypto: {
        [vaultId]: {
          vaultId,
          status: 'rekey_required',
          activeEpoch: 1,
          pendingEpoch: 2,
          rekeyTaskId: jobId,
          encryptedHeader: null,
          migrationJobId: null,
          recoveryRequired: false,
          recoveryReason: null,
          updatedAt: new Date().toISOString(),
        },
      },
      encryptedItems: {},
      vaultDirectories: {},
    });
    const services = {
      store,
      zeroKnowledge: {
        completeVaultRekey,
        rekeyTaskId: vi.fn(() => jobId),
        refresh: vi.fn(),
        logout: vi.fn(),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <SecurityGate phase="rekey-blocked" user={user} onLoggedOut={vi.fn()} />
      </AppContext.Provider>,
    );

    expect(screen.getByRole('heading', { name: '密码库正在安全更新' })).toBeVisible();
    expect(screen.getByText(/避免旧权限继续获得新内容/)).toBeVisible();
    expect(screen.getByText('运维密码库 · 等待安全更新')).toBeVisible();
    expect(screen.queryByText(/新密钥版本|重新分发密钥/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '完成安全更新' }));
    await waitFor(() => expect(completeVaultRekey).toHaveBeenCalledWith(vaultId));
  });

  it('lets a platform admin start one recovery case for a colleague', async () => {
    const adminUser = {
      ...user,
      id: 'u-admin',
      username: 'admin',
      isPlatformAdmin: true,
      isLocalPlatformAdmin: true,
    };
    const store = createMetaStore();
    store.getState().setUser(adminUser);
    const createRecoveryCase = vi.fn(async () => ({}));
    const searchUsers = vi.fn(async (query: string) => ({
      syncedAt: '2026-08-06T00:00:00.000Z',
      users: query ? [user] : [],
    }));
    const services = {
      store,
      api: {
        recoveryCases: vi.fn(async () => []),
        searchUsers,
        createRecoveryCase,
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <AdminAccountResetApprovals />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const createButton = await screen.findByRole('button', { name: '发起恢复协助' });
    expect(createButton).toBeDisabled();
    const picker = screen.getByRole('combobox', { name: '需要帮助的同事' });
    expect(picker).toHaveAttribute('placeholder', '搜索姓名、拼音或域账号');
    await userEvent.type(picker, 'owner');
    await userEvent.click(await screen.findByRole('option', { name: /Owner.*owner/i }));
    expect(searchUsers).toHaveBeenCalledWith('owner', []);
    await userEvent.click(createButton);
    await waitFor(() => expect(createRecoveryCase).toHaveBeenCalledWith({
      idempotencyKey: expect.any(String),
      kind: 'forgot_password',
      targetUserId: user.id,
    }));
  });

  it('requires a second administrator to confirm the colleague identity', async () => {
    const adminUser = {
      ...user,
      id: 'u-admin',
      username: 'admin',
      isPlatformAdmin: true,
      isLocalPlatformAdmin: true,
    };
    const recoveryCase = {
      id: '70000000-0000-4000-8000-000000000001',
      kind: 'forgot_password',
      targetUserId: 'u-applicant',
      targetUsername: 'applicant',
      targetDisplayName: 'Applicant',
      recoveryKeyId: '71000000-0000-4000-8000-000000000001',
      status: 'pending_approval',
      caseDigest: 'FULL_CASE_DIGEST_IS_BOUND_BUT_NOT_SHOWN',
      targetDeviceId: '72000000-0000-4000-8000-000000000001',
      targetKeyVersion: 2,
      accountResetRequestId: '73000000-0000-4000-8000-000000000001',
      approvalUserIds: [],
      items: [{ id: '74000000-0000-4000-8000-000000000001' }],
      resolvedItemCount: 0,
      skippedItemCount: 0,
      hasOfflineResult: false,
      createdByUserId: 'u-first-admin',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      finalizedAt: new Date().toISOString(),
      approvedAt: null,
      processingAt: null,
      completedAt: null,
      cancelledAt: null,
      expiredAt: null,
      lastErrorCode: null,
    };
    const approveRecoveryCase = vi.fn().mockResolvedValue(undefined);
    const store = createMetaStore();
    store.getState().setUser(adminUser);
    const services = {
      store,
      api: {
        recoveryCases: vi.fn().mockResolvedValue([recoveryCase]),
        approveRecoveryCase,
      },
    } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <AdminAccountResetApprovals />
        <ConfirmDialog />
      </AppContext.Provider>,
    );

    await userEvent.click(await screen.findByRole('button', { name: '确认身份并同意协助' }));
    expect(screen.getByText(/请先通过公司沟通渠道确认本人身份/)).toBeVisible();
    expect(screen.queryByText(/FULL_CASE_DIGEST_IS_BOUND_BUT_NOT_SHOWN/)).not.toBeInTheDocument();
    const confirmButtons = screen.getAllByRole('button', { name: '身份已确认，同意协助' });
    await userEvent.click(confirmButtons.at(-1)!);
    await waitFor(() => expect(approveRecoveryCase).toHaveBeenCalledWith(recoveryCase.id, {
      idempotencyKey: expect.any(String),
      caseDigest: recoveryCase.caseDigest,
    }));
  });
});

function migrationStatus(
  status: LegacyMigrationStatusResponse['status'],
  emptyVaultInitializationAllowed = false,
  recoveryEnabled = true,
): LegacyMigrationStatusResponse {
  return {
    status,
    emptyVaultInitializationAllowed,
    job: {
      id: jobId,
      vaultId,
      attempt: 1,
      status,
      targetEpoch: 1,
      expectedItemCount: 2,
      expectedMetadataVersionCount: 2,
      expectedSecretVersionCount: 4,
      expectedRecipientCount: 3,
      verifiedItemCount: status === 'verifying' ? 2 : 0,
      verifiedMetadataVersionCount: status === 'verifying' ? 2 : 0,
      verifiedSecretVersionCount: status === 'verifying' ? 4 : 0,
      verifiedRecipientCount: status === 'verifying' ? 3 : 0,
      sourceDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      lastErrorCode: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      completedAt: null,
      rolledBackAt: null,
    },
    materials: {
      recipients: [],
      devices: [],
      recoveryKey: recoveryEnabled ? {
        id: '60000000-0000-4000-8000-000000000001',
        ceremonyId: 'test',
        keyFingerprint: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        publicEncryptionKey: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
        threshold: 2,
        shareCount: 3,
        status: 'active',
        ceremonyEvidenceDigest: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
        createdAt: new Date().toISOString(),
        retiredAt: null,
      } : null,
    },
  };
}
