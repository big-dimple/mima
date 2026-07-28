import { describe, expect, it } from 'vitest';
import { EnterpriseRecoveryRequestSchema } from '@mima/contracts';
import { recoveryCapabilityStillAuthorized } from '../../src/routes/e2ee-recovery.ts';

describe('enterprise recovery capability boundary', () => {
  it('never authorizes a broader recovery scope than the current membership', () => {
    expect(recoveryCapabilityStillAuthorized('metadata', 'metadata')).toBe(true);
    expect(recoveryCapabilityStillAuthorized('metadata', 'full')).toBe(true);
    expect(recoveryCapabilityStillAuthorized('metadata', null)).toBe(false);
    expect(recoveryCapabilityStillAuthorized('full', 'full')).toBe(true);
    expect(recoveryCapabilityStillAuthorized('full', 'metadata')).toBe(false);
    expect(recoveryCapabilityStillAuthorized('full', null)).toBe(false);
  });

  it('requires the immutable target capability in recovery DTOs', () => {
    const base = {
      id: '10000000-0000-4000-8000-000000000001',
      vaultId: '20000000-0000-4000-8000-000000000001',
      recoveryKeyId: '30000000-0000-4000-8000-000000000001',
      keyEpoch: 1,
      targetUserId: 'u-auditor',
      targetDeviceId: '40000000-0000-4000-8000-000000000001',
      targetEncryptionPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      targetKeyVersion: 1,
      accountResetRequestId: null,
      requestDigest: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      status: 'pending',
      approvalUserIds: [],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      completedAt: null,
    };
    expect(EnterpriseRecoveryRequestSchema.safeParse(base).success).toBe(false);
    expect(EnterpriseRecoveryRequestSchema.safeParse({ ...base, targetCapability: 'metadata' }).success).toBe(true);
  });
});
