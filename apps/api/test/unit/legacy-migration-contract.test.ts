import { describe, expect, it } from 'vitest';
import { LegacyMigrationStatusResponseSchema } from '@mima/contracts';

describe('legacy migration status contract', () => {
  const pendingStatus = {
    status: 'pending',
    job: null,
    materials: null,
    emptyVaultInitializationAllowed: false,
  };

  it('requires an explicit server decision for empty-vault initialization', () => {
    expect(LegacyMigrationStatusResponseSchema.safeParse(pendingStatus).success).toBe(true);
    const { emptyVaultInitializationAllowed: _decision, ...missingDecision } = pendingStatus;
    expect(LegacyMigrationStatusResponseSchema.safeParse(missingDecision).success).toBe(false);
  });
});
