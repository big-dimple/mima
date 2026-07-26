import { describe, expect, it } from 'vitest';
import { parseOfflineRecoveryResult } from '../src/e2ee-keyring.ts';

describe('offline enterprise recovery result compatibility', () => {
  it('accepts the versioned recoveredEnvelope format', () => {
    const parsed = parseOfflineRecoveryResult(currentResult());
    expect(parsed).toMatchObject({
      formatVersion: 1,
      evidenceFormat: 'recovered-envelope-v1',
      recoveredEnvelope: { recipientId: 'u-target' },
    });
  });

  it('normalizes the legacy unsignedEnvelope format inside the compatibility window', () => {
    const current = currentResult();
    const { formatVersion: _version, recoveredEnvelope, ...common } = current;
    const parsed = parseOfflineRecoveryResult({ ...common, unsignedEnvelope: recoveredEnvelope });
    expect(parsed).toMatchObject({
      formatVersion: 1,
      evidenceFormat: 'unsigned-envelope-v0',
      recoveredEnvelope: { recipientId: 'u-target' },
    });
  });

  it('rejects ambiguous or unversioned current results', () => {
    const current = currentResult();
    expect(() => parseOfflineRecoveryResult({
      ...current,
      unsignedEnvelope: current.recoveredEnvelope,
    })).toThrow('必须且只能包含一个恢复 envelope');
    const { formatVersion: _version, ...unversioned } = current;
    expect(() => parseOfflineRecoveryResult(unversioned)).toThrow('版本不受支持');
  });
});

function currentResult() {
  return {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-transfer',
    formatVersion: 1,
    requestId: '30000000-0000-4000-8000-000000000001',
    requestDigest: 'A'.repeat(43),
    vaultId: '20000000-0000-4000-8000-000000000001',
    epoch: 1,
    recoveryKeyId: '10000000-0000-4000-8000-000000000001',
    ceremonyId: 'compatibility-test',
    recoveryCeremonyDigest: 'B'.repeat(43),
    targetUserId: 'u-target',
    targetCapability: 'full',
    toolEvidenceDigest: 'C'.repeat(43),
    recoveredEnvelope: {
      vaultId: '20000000-0000-4000-8000-000000000001',
      epoch: 1,
      recipientKind: 'user',
      recipientId: 'u-target',
      recipientKeyVersion: 1,
      capability: 'full',
      sealedKeyBundle: 'D'.repeat(80),
      signerUserId: 'u-target',
      signerKeyVersion: 1,
    },
  } as const;
}
