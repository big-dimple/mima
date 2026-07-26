import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { LegacyKeyRetirementResponse } from '@mima/contracts';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import {
  LegacyKeyRetirementBanner,
  describeRetirement,
} from '../src/components/LegacyKeyRetirementBanner.tsx';

describe('legacy key retirement disclosure', () => {
  it('warns every user while migrated data still has a retained legacy KEK', async () => {
    const legacyKeyRetirementStatus = vi.fn().mockResolvedValue(status({
      status: 'approved',
      legacyKeyState: 'retained',
      retireBy: '2026-08-01T00:00:00.000Z',
    }));
    const services = { api: { legacyKeyRetirementStatus } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <LegacyKeyRetirementBanner />
      </AppContext.Provider>,
    );
    expect(await screen.findByRole('status')).toHaveTextContent('旧托管密钥仍在受控保留期');
    expect(screen.getByRole('status')).toHaveTextContent('部署方仍可能解密迁移前的旧副本');
  });

  it('uses an alert for overdue, unplanned, or unverifiable retirement state', async () => {
    expect(describeRetirement(status({ status: 'unplanned', legacyKeyState: 'unknown' })))
      .toMatchObject({ danger: true });
    expect(describeRetirement(status({ status: 'approved', legacyKeyState: 'retained', overdue: true })))
      .toMatchObject({ danger: true });
    const services = {
      api: { legacyKeyRetirementStatus: vi.fn().mockRejectedValue(new Error('offline')) },
    } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <LegacyKeyRetirementBanner />
      </AppContext.Provider>,
    );
    expect(await screen.findByRole('alert')).toHaveTextContent('无法确认旧托管密钥是否已经退役');
  });

  it('stays hidden after retirement evidence is complete or on a fresh install', () => {
    expect(describeRetirement(status({ status: 'completed', legacyKeyState: 'retired' }))).toBeNull();
    expect(describeRetirement(status({ status: 'not_applicable', legacyKeyState: 'not_applicable' }))).toBeNull();
  });
});

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
    approvalCount: 1,
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
