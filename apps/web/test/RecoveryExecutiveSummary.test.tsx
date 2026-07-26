import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
} from '@mima/contracts';
import { RecoveryExecutiveSummary } from '../src/components/RecoveryExecutiveSummary.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';

describe('RecoveryExecutiveSummary', () => {
  it('explains readiness, recovery scenarios, and the boundary in executive language', async () => {
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([activeKey()]),
      recoveryReadiness: vi.fn().mockResolvedValue(readiness()),
      recoveryCoverage: vi.fn().mockResolvedValue(coverage()),
    };
    render(
      <AppContext.Provider value={{ api, store: createMetaStore() } as unknown as AppServices}>
        <RecoveryExecutiveSummary />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('可以恢复')).toBeVisible();
    expect(screen.getByText('任何一个人都不能单独恢复')).toBeVisible();
    expect(screen.getByText('只恢复已纳入保护的密码库')).toBeVisible();
    expect(screen.getByText('个人库不能转交给别人')).toBeVisible();
    expect(screen.getByText(/忘记主密码且没有可用设备/)).toBeVisible();
    expect(screen.getByText(/离职未完成交接/)).toBeVisible();
    expect(screen.getByText(/恢复的是指定访问能力，不会找回员工旧主密码/)).toBeVisible();
  });

  it('does not claim recovery is available when the current administrator roster is incomplete', async () => {
    const incompleteReadiness = {
      ...readiness(),
      readyAdministratorCount: 0,
      ready: false,
    };
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([activeKey()]),
      recoveryReadiness: vi.fn().mockResolvedValue(incompleteReadiness),
      recoveryCoverage: vi.fn().mockResolvedValue(coverage()),
    };
    render(
      <AppContext.Provider value={{ api, store: createMetaStore() } as unknown as AppServices}>
        <RecoveryExecutiveSummary />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('待完善')).toBeVisible();
    expect(screen.getByText('先补齐三位管理员，目前已准备 0/3。')).toBeVisible();
    expect(screen.queryByText('可以恢复')).not.toBeInTheDocument();
  });

  it('does not claim recovery is available while any vault still lacks coverage', async () => {
    const incompleteCoverage = { ...coverage(), coveredVaultCount: 1, complete: false };
    const api = {
      recoveryKeys: vi.fn().mockResolvedValue([activeKey()]),
      recoveryReadiness: vi.fn().mockResolvedValue(readiness()),
      recoveryCoverage: vi.fn().mockResolvedValue(incompleteCoverage),
    };
    render(
      <AppContext.Provider value={{ api, store: createMetaStore() } as unknown as AppServices}>
        <RecoveryExecutiveSummary />
      </AppContext.Provider>,
    );

    expect(await screen.findByText('待完善')).toBeVisible();
    expect(screen.getByText('下一步由密码库所有者为尚未覆盖的密码库添加恢复保护。')).toBeVisible();
    expect(screen.queryByText('可以恢复')).not.toBeInTheDocument();
  });
});

function activeKey(): EnterpriseRecoveryKey {
  return {
    id: 'recovery-key-1',
    ceremonyId: 'executive-summary-test',
    keyFingerprint: 'A'.repeat(43),
    publicEncryptionKey: 'B'.repeat(43),
    threshold: 2,
    shareCount: 3,
    status: 'active',
    ceremonyEvidenceDigest: 'C'.repeat(43),
    approvalUserIds: ['admin-1', 'admin-2'],
    createdAt: '2026-07-21T00:00:00.000Z',
    retiredAt: null,
  };
}

function readiness(): EnterpriseRecoveryReadiness {
  return {
    requiredAdministratorCount: 3,
    administratorCount: 3,
    readyAdministratorCount: 3,
    ready: true,
    administrators: [],
  };
}

function coverage(): EnterpriseRecoveryCoverage {
  return {
    keyId: activeKey().id,
    totalVaultCount: 2,
    coveredVaultCount: 2,
    complete: true,
    vaults: [],
  };
}
