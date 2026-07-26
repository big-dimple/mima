import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { LegacyKeyRetirementResponse } from '@mima/contracts';
import { createMetaStore } from '@mima/client-core';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { LegacyKeyRetirementDialog } from '../src/components/LegacyKeyRetirementDialog.tsx';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import { useUi } from '../src/state/ui-store.ts';

const currentUser = {
  id: 'u-dave',
  username: 'dave',
  displayName: 'Dave',
  email: 'dave@example.test',
  groups: [],
  isPlatformAdmin: true,
};

beforeEach(() => {
  useUi.setState({ retirementOpen: true, confirm: null });
});

describe('legacy key retirement admin dialog', () => {
  it('creates a fresh-install plan using only non-sensitive digests', async () => {
    const createLegacyKeyRetirement = vi.fn().mockResolvedValue(status({
      status: 'planned',
      reasonCode: 'fresh_install',
      retireBy: null,
      kekFingerprintDigest: null,
      legacyKeyState: 'unknown',
    }));
    const services = appServices({
      legacyKeyRetirementStatus: vi.fn().mockResolvedValue(status({ status: 'unplanned' })),
      createLegacyKeyRetirement,
    });
    renderDialog(services);

    await userEvent.selectOptions(await screen.findByLabelText('保留原因'), 'fresh_install');
    expect(screen.queryByLabelText('旧 KEK 指纹 SHA-256（base64url）')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('最晚退役时间')).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('副本清点 SHA-256（base64url）'), 'A'.repeat(43));
    await userEvent.type(screen.getByLabelText('清单 manifest SHA-256（base64url）'), 'B'.repeat(43));
    await userEvent.click(screen.getByRole('button', { name: '签名并登记计划' }));

    await waitFor(() => expect(createLegacyKeyRetirement).toHaveBeenCalledWith({
      reasonCode: 'fresh_install',
      retireBy: null,
      copyInventoryDigest: 'A'.repeat(43),
      copyManifestDigest: 'B'.repeat(43),
      kekFingerprintDigest: null,
    }));
    expect(screen.getByText('等待双人审批')).toBeInTheDocument();
  });

  it('reuses the first approval evidence digest for the second approval and completion', async () => {
    const sharedEvidenceDigest = 'E'.repeat(43);
    const planned = status({
      status: 'planned',
      approvalCount: 1,
      approvalUserIds: ['u-alice'],
      approvalEvidenceDigest: sharedEvidenceDigest,
      legacyKeyState: 'retained',
    });
    const approved = status({
      status: 'approved',
      approvalCount: 2,
      approvalUserIds: ['u-alice', currentUser.id],
      approvalEvidenceDigest: sharedEvidenceDigest,
      approvedAt: '2026-07-18T01:00:00.000Z',
      legacyKeyState: 'retained',
    });
    const approveLegacyKeyRetirement = vi.fn().mockResolvedValue(approved);
    const completeLegacyKeyRetirement = vi.fn().mockResolvedValue(status({
      ...approved,
      status: 'completed',
      legacyKeyState: 'retired',
      evidenceJobCount: 1,
      completedAt: '2026-07-18T02:00:00.000Z',
    }));
    const services = appServices({
      legacyKeyRetirementStatus: vi.fn().mockResolvedValue(planned),
      approveLegacyKeyRetirement,
      completeLegacyKeyRetirement,
    });
    renderDialog(services);

    const evidenceInput = await screen.findByLabelText('销毁与副本清点证据 SHA-256（base64url）');
    expect(evidenceInput).toHaveValue(sharedEvidenceDigest);
    expect(evidenceInput).toHaveAttribute('readonly');
    await userEvent.click(screen.getByRole('button', { name: '核对后签名批准' }));
    await waitFor(() => expect(approveLegacyKeyRetirement)
      .toHaveBeenCalledWith(planned.planDigest, sharedEvidenceDigest));

    await userEvent.click(await screen.findByRole('button', { name: '确认旧 KEK 已按清单退役' }));
    await userEvent.click(await screen.findByRole('button', { name: '确认已经退役' }));
    await waitFor(() => expect(completeLegacyKeyRetirement)
      .toHaveBeenCalledWith(planned.planDigest, sharedEvidenceDigest));
    expect(await screen.findByText(/旧密钥退役证据已完成/)).toBeInTheDocument();
  });
});

function appServices(zeroKnowledge: Record<string, unknown>): AppServices {
  const store = createMetaStore();
  store.getState().applyBootstrap({
    user: currentUser,
    vaults: [],
    memberships: [],
    items: [],
    cursor: 0,
  });
  return { store, zeroKnowledge } as unknown as AppServices;
}

function renderDialog(services: AppServices) {
  render(
    <AppContext.Provider value={services}>
      <LegacyKeyRetirementDialog />
      <ConfirmDialog />
    </AppContext.Provider>,
  );
}

function status(overrides: Partial<LegacyKeyRetirementResponse>): LegacyKeyRetirementResponse {
  return {
    deploymentId: 'primary',
    status: 'planned',
    reasonCode: 'rollback_window',
    retireBy: '2026-08-01T00:00:00.000Z',
    copyInventoryDigest: 'A'.repeat(43),
    copyManifestDigest: 'B'.repeat(43),
    kekFingerprintDigest: 'C'.repeat(43),
    planDigest: 'D'.repeat(43),
    approvalCount: 0,
    approvalUserIds: [],
    approvalEvidenceDigest: null,
    migratedJobCount: 1,
    evidenceJobCount: 0,
    legacyKeyState: 'retained',
    overdue: false,
    createdAt: '2026-07-18T00:00:00.000Z',
    approvedAt: null,
    completedAt: null,
    ...overrides,
  };
}
