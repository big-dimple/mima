import { describe, expect, it } from 'vitest';
import { parseRecoveryInput } from '../src/protocol.ts';

describe('recovery tool package protocol', () => {
  it('preserves the server-derived metadata-only target capability', () => {
    const parsed = parseRecoveryInput(JSON.stringify({
      protocol: 'lm-e2ee-v1',
      kind: 'enterprise-recovery-request-package',
      request: {
        id: '10000000-0000-4000-8000-000000000001',
        requestDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        vaultId: '20000000-0000-4000-8000-000000000001',
        targetCapability: 'metadata',
      },
      activeEpoch: 4,
      recoveryKey: {
        id: '30000000-0000-4000-8000-000000000001',
        ceremonyId: 'ceremony-1',
        ceremonyEvidenceDigest: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        publicEncryptionKey: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      },
      recoveryEnvelope: { vaultId: 'placeholder' },
      trustedSigner: { signingPublicKey: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' },
      targetProfile: {
        userId: 'u-auditor',
        keyVersion: 2,
        encryptionPublicKey: 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
      },
    }));
    expect(parsed.targetCapability).toBe('metadata');
    expect(parsed.target.userId).toBe('u-auditor');
  });

  it('rejects packages that omit the authorized target capability', () => {
    expect(() => parseRecoveryInput(JSON.stringify({
      protocol: 'lm-e2ee-v1',
      kind: 'enterprise-recovery-request-package',
      requestId: 'request-1',
      requestDigest: 'digest',
      vaultId: 'vault-1',
      epoch: 1,
      recovery: { keyId: 'key-1', ceremonyId: 'c', ceremonyDigest: 'd', publicKey: 'p' },
      recoveryEnvelope: {},
      trustedOwnerSigningPublicKey: 's',
      target: { userId: 'u', encryptionPublicKey: 'p', keyVersion: 1 },
    }))).toThrow('invalid enterprise recovery request package');
  });
});
