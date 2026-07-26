import { describe, expect, it } from 'vitest';
import { mergeSecurityMutationVaultIds } from '../../src/routes/e2ee-crypto.ts';

describe('device revocation vault coverage', () => {
  it('includes user-accessible vaults even when a Web device has no device envelope', () => {
    expect(mergeSecurityMutationVaultIds(
      [],
      [{ vaultId: 'personal-vault' }, { vaultId: 'shared-vault' }],
    )).toEqual(['personal-vault', 'shared-vault']);
  });

  it('deduplicates user and device envelope coverage', () => {
    expect(mergeSecurityMutationVaultIds(
      [{ vaultId: 'extension-vault' }],
      [{ vaultId: 'extension-vault' }, { vaultId: 'shared-vault' }],
      [{ vaultId: 'shared-vault' }],
    )).toEqual(['extension-vault', 'shared-vault']);
  });
});
