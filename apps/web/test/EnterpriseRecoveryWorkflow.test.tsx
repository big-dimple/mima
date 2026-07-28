import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createMetaStore,
  type OfflineRecoveryResult,
} from '@mima/client-core';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
} from '@mima/contracts';
import { EnterpriseRecoveryRequestPanel } from '../src/components/EnterpriseRecoveryRequestPanel.tsx';
import { RecoveryCoverageTasks } from '../src/components/RecoveryCoverageTasks.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const owner = {
  id: 'u-owner',
  username: 'owner',
  displayName: 'Owner',
  email: 'owner@example.test',
  groups: [],
  isPlatformAdmin: false,
};
const vaultOne = '20000000-0000-4000-8000-000000000001';
const vaultTwo = '20000000-0000-4000-8000-000000000002';

beforeEach(() => {
  useUi.setState({ selectedVaultId: 'all', toasts: [] });
});

afterEach(() => {
  vi.restoreAllMocks();
  Reflect.deleteProperty(URL, 'createObjectURL');
  Reflect.deleteProperty(URL, 'revokeObjectURL');
});

describe('enterprise recovery owner coverage', () => {
  it('processes every owned vault independently and keeps per-vault outcomes', async () => {
    const distribute = vi.fn(async (_key: EnterpriseRecoveryKey, vault: { vaultId: string }) => {
      if (vault.vaultId === vaultTwo) throw new Error('当前设备没有这个密码库的密钥');
      return { alreadyCovered: false };
    });
    renderCoverage(distribute);

    await userEvent.click(await screen.findByRole('button', { name: '处理全部 2 个' }));
    await waitFor(() => expect(distribute).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('恢复保护已添加')).toBeVisible();
    expect(screen.getByText('当前设备没有这个密码库的密钥')).toBeVisible();
  });

  it('aborts an in-flight envelope task when the selected vault changes', async () => {
    let signal: AbortSignal | undefined;
    const distribute = vi.fn((_key, _vault, currentSignal?: AbortSignal) => {
      signal = currentSignal;
      return new Promise<{ alreadyCovered: boolean }>((_resolve, reject) => {
        currentSignal?.addEventListener('abort', () => reject(currentSignal.reason));
      });
    });
    const view = renderCoverage(distribute);

    await userEvent.click((await screen.findAllByRole('button', { name: '添加保护' }))[0]!);
    await waitFor(() => expect(signal).toBeDefined());
    act(() => useUi.getState().selectVault(vaultTwo));
    expect(signal?.aborted).toBe(true);

    act(() => useUi.getState().selectVault('all'));
    await userEvent.click((await screen.findAllByRole('button', { name: '添加保护' }))[0]!);
    await waitFor(() => expect(distribute).toHaveBeenCalledTimes(2));
    const secondSignal = distribute.mock.calls[1]?.[2] as AbortSignal;
    view.unmount();
    expect(secondSignal.aborted).toBe(true);
  });
});

describe('enterprise recovery target request', () => {
  it('downloads the approved package and imports the current tool result without field renaming', async () => {
    const request = recoveryRequest();
    const recoveryRequests = vi.fn()
      .mockResolvedValueOnce([request])
      .mockResolvedValueOnce([]);
    const recoveryPackage = vi.fn().mockResolvedValue({ protocol: 'lm-e2ee-v1', request: request.id });
    const completeRecovery = vi.fn().mockResolvedValue(undefined);
    const store = createMetaStore();
    store.getState().setUser(owner);
    const createObjectURL = vi.fn().mockReturnValue('blob:test-recovery');
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    render(
      <AppContext.Provider value={{
        store,
        api: { recoveryRequests, recoveryPackage },
        zeroKnowledge: { completeRecovery },
      } as unknown as AppServices}>
        <EnterpriseRecoveryRequestPanel />
      </AppContext.Provider>,
    );

    expect(await screen.findByText(/两位管理员已经确认/)).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '下载本次恢复包' }));
    expect(recoveryPackage).toHaveBeenCalledWith(request.id);
    expect(createObjectURL).toHaveBeenCalled();

    await userEvent.upload(
      screen.getByLabelText('离线恢复结果 JSON'),
      new File([JSON.stringify(currentToolResult(request))], 'recovery-result.json', {
        type: 'application/json',
      }),
    );
    expect(await screen.findByText('recovery-result.json')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '验证并导入恢复结果' }));
    await waitFor(() => expect(completeRecovery).toHaveBeenCalledWith(
      request,
      expect.objectContaining({
        formatVersion: 1,
        evidenceFormat: 'recovered-envelope-v1',
        recoveredEnvelope: expect.objectContaining({ recipientId: owner.id }),
      } satisfies Partial<OfflineRecoveryResult>),
    ));
    expect(await screen.findByText(/当前没有需要你处理的恢复请求/)).toBeVisible();
  });
});

function renderCoverage(
  distributeEnterpriseRecoveryEnvelope: (
    key: EnterpriseRecoveryKey,
    vault: EnterpriseRecoveryCoverage['vaults'][number],
    signal?: AbortSignal,
  ) => Promise<{ alreadyCovered: boolean }>,
) {
  const store = createMetaStore();
  store.getState().setUser(owner);
  const api = {
    recoveryKeys: vi.fn().mockResolvedValue([stagedRecoveryKey()]),
    recoveryCoverage: vi.fn().mockResolvedValue(ownerCoverage()),
  };
  return render(
    <AppContext.Provider value={{
      store,
      api,
      zeroKnowledge: { distributeEnterpriseRecoveryEnvelope },
    } as unknown as AppServices}>
      <RecoveryCoverageTasks />
    </AppContext.Provider>,
  );
}

function stagedRecoveryKey(): EnterpriseRecoveryKey {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    ceremonyId: 'recovery-coverage-test',
    keyFingerprint: 'A'.repeat(43),
    publicEncryptionKey: 'B'.repeat(43),
    threshold: 2,
    shareCount: 3,
    status: 'staged',
    ceremonyEvidenceDigest: 'C'.repeat(43),
    approvalUserIds: ['u-admin-one', 'u-admin-two'],
    createdAt: '2026-07-20T00:00:00.000Z',
    retiredAt: null,
  };
}

function ownerCoverage(): EnterpriseRecoveryCoverage {
  return {
    keyId: stagedRecoveryKey().id,
    totalVaultCount: 2,
    coveredVaultCount: 0,
    complete: false,
    vaults: [vaultOne, vaultTwo].map((vaultId) => ({
      vaultId,
      epoch: 1,
      covered: false,
      canManage: true,
      ownerUserIds: [owner.id],
    })),
  };
}

function recoveryRequest(): EnterpriseRecoveryRequest {
  return {
    id: '30000000-0000-4000-8000-000000000001',
    vaultId: vaultOne,
    recoveryKeyId: stagedRecoveryKey().id,
    keyEpoch: 1,
    targetUserId: owner.id,
    targetDeviceId: '40000000-0000-4000-8000-000000000001',
    targetEncryptionPublicKey: 'D'.repeat(43),
    targetKeyVersion: 1,
    targetCapability: 'full',
    accountResetRequestId: null,
    requestDigest: 'E'.repeat(43),
    status: 'approved',
    approvalUserIds: ['u-admin-one', 'u-admin-two'],
    createdAt: '2026-07-20T00:00:00.000Z',
    expiresAt: '2099-07-20T01:00:00.000Z',
    completedAt: null,
  };
}

function currentToolResult(request: EnterpriseRecoveryRequest) {
  return {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-transfer',
    formatVersion: 1,
    requestId: request.id,
    requestDigest: request.requestDigest,
    vaultId: request.vaultId,
    epoch: 1,
    recoveryKeyId: request.recoveryKeyId,
    ceremonyId: stagedRecoveryKey().ceremonyId,
    recoveryCeremonyDigest: stagedRecoveryKey().ceremonyEvidenceDigest,
    targetUserId: request.targetUserId,
    targetCapability: request.targetCapability,
    toolEvidenceDigest: 'F'.repeat(43),
    recoveredEnvelope: {
      vaultId: request.vaultId,
      epoch: 1,
      recipientKind: 'user',
      recipientId: request.targetUserId,
      recipientKeyVersion: request.targetKeyVersion,
      capability: request.targetCapability,
      sealedKeyBundle: 'G'.repeat(80),
      signerUserId: request.targetUserId,
      signerKeyVersion: request.targetKeyVersion,
    },
  };
}
