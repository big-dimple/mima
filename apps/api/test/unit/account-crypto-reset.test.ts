import { describe, expect, it } from 'vitest';
import { CreateEnterpriseRecoveryRequestSchema } from '@mima/contracts';
import { mergeAccountResetAffectedVaultIds } from '../../src/routes/e2ee-account-reset.ts';

describe('account crypto reset affected vault coverage', () => {
  it('includes authorized vaults even when their user/device envelope is missing', () => {
    const authorizedWithoutEnvelope = 'd3b66a48-4bbb-47bb-a8b5-668e36ff3e3d';
    const envelopeOnly = '4f9029aa-2bc5-4fda-88cf-cb35129d3700';
    const duplicated = '5a3b356b-b5e5-4587-9c88-90245553d7a4';

    expect(mergeAccountResetAffectedVaultIds(
      [{ vaultId: envelopeOnly }, { vaultId: duplicated }],
      [{ vaultId: duplicated }],
      [{ vaultId: authorizedWithoutEnvelope }, { vaultId: duplicated }],
    )).toEqual([envelopeOnly, duplicated, authorizedWithoutEnvelope]);
  });

  it('requires explicit account-reset provenance for each vault recovery request', () => {
    const base = {
      idempotencyKey: 'recovery-test-0001',
      vaultId: 'd3b66a48-4bbb-47bb-a8b5-668e36ff3e3d',
      targetUserId: 'u-target',
      targetDeviceId: '4f9029aa-2bc5-4fda-88cf-cb35129d3700',
      targetEncryptionPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      targetKeyVersion: 2,
      reason: 'account_reset' as const,
    };
    expect(CreateEnterpriseRecoveryRequestSchema.safeParse(base).success).toBe(false);
    expect(CreateEnterpriseRecoveryRequestSchema.safeParse({
      ...base,
      accountResetRequestId: '5a3b356b-b5e5-4587-9c88-90245553d7a4',
    }).success).toBe(true);
  });
});
