import type { VaultKeyEnvelopeInput } from '@mima/e2ee';

export interface RecoveryInput {
  protocol: 'lm-e2ee-v1';
  kind: 'enterprise-recovery-request-package';
  requestId: string;
  requestDigest: string;
  vaultId: string;
  epoch: number;
  targetCapability: 'metadata' | 'full';
  recovery: {
    keyId: string;
    ceremonyId: string;
    ceremonyDigest: string;
    publicKey: string;
  };
  recoveryEnvelope: VaultKeyEnvelopeInput;
  trustedOwnerSigningPublicKey: string;
  target: {
    userId: string;
    encryptionPublicKey: string;
    keyVersion: number;
  };
}

export interface RecoveryCaseInput {
  protocol: 'mima-e2ee-v2';
  kind: 'enterprise-recovery-case-package';
  caseId: string;
  caseDigest: string;
  recovery: RecoveryInput['recovery'];
  items: RecoveryInput[];
}

export function parseRecoveryInput(value: string): RecoveryInput {
  const parsed = JSON.parse(value) as unknown;
  const normalized = normalizeApiPackage(parsed) ?? parsed;
  if (!isRecord(normalized)) throw new Error('invalid enterprise recovery request package');
  if (
    normalized.protocol !== 'lm-e2ee-v1' ||
    normalized.kind !== 'enterprise-recovery-request-package' ||
    typeof normalized.requestId !== 'string' ||
    typeof normalized.requestDigest !== 'string' ||
    typeof normalized.vaultId !== 'string' ||
    !Number.isSafeInteger(normalized.epoch) ||
    (normalized.targetCapability !== 'metadata' && normalized.targetCapability !== 'full') ||
    !isRecord(normalized.recovery) ||
    typeof normalized.recovery.keyId !== 'string' ||
    typeof normalized.recovery.ceremonyId !== 'string' ||
    typeof normalized.recovery.ceremonyDigest !== 'string' ||
    typeof normalized.recovery.publicKey !== 'string' ||
    !isRecord(normalized.recoveryEnvelope) ||
    typeof normalized.trustedOwnerSigningPublicKey !== 'string' ||
    !isRecord(normalized.target) ||
    typeof normalized.target.userId !== 'string' ||
    typeof normalized.target.encryptionPublicKey !== 'string' ||
    !Number.isSafeInteger(normalized.target.keyVersion)
  ) {
    throw new Error('invalid enterprise recovery request package');
  }
  return normalized as unknown as RecoveryInput;
}

export function parseRecoveryCaseInput(value: string): RecoveryCaseInput {
  const parsed = JSON.parse(value) as unknown;
  if (isRecord(parsed) && parsed.kind === 'enterprise-recovery-manifest') {
    throw new Error('你选择的是首次准备时的“企业恢复公开清单”。这里需要从平台中的具体恢复案件点击“下载案件文件”得到的 JSON 文件。');
  }
  if (!isRecord(parsed)
    || parsed.protocol !== 'mima-e2ee-v2'
    || parsed.kind !== 'enterprise-recovery-case-package'
    || typeof parsed.caseId !== 'string'
    || typeof parsed.caseDigest !== 'string'
    || !isRecord(parsed.recoveryKey)
    || typeof parsed.recoveryKey.id !== 'string'
    || typeof parsed.recoveryKey.ceremonyId !== 'string'
    || typeof parsed.recoveryKey.ceremonyEvidenceDigest !== 'string'
    || typeof parsed.recoveryKey.publicEncryptionKey !== 'string'
    || !Array.isArray(parsed.items)
    || parsed.items.length === 0
  ) throw new Error('这不是有效的企业恢复处理包');
  const recovery = {
    keyId: parsed.recoveryKey.id,
    ceremonyId: parsed.recoveryKey.ceremonyId,
    ceremonyDigest: parsed.recoveryKey.ceremonyEvidenceDigest,
    publicKey: parsed.recoveryKey.publicEncryptionKey,
  };
  const items = parsed.items.map((item) => parseRecoveryInput(JSON.stringify({
    ...(isRecord(item) ? item : {}),
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-request-package',
    recoveryKey: parsed.recoveryKey,
  })));
  const uniqueRequestIds = new Set(items.map((item) => item.requestId));
  if (uniqueRequestIds.size !== items.length) throw new Error('恢复处理包包含重复内容');
  return {
    protocol: 'mima-e2ee-v2',
    kind: 'enterprise-recovery-case-package',
    caseId: parsed.caseId,
    caseDigest: parsed.caseDigest,
    recovery,
    items,
  };
}

function normalizeApiPackage(value: unknown): RecoveryInput | null {
  if (!isRecord(value) || !isRecord(value.request) || !isRecord(value.recoveryKey) ||
    !isRecord(value.trustedSigner) || !isRecord(value.targetProfile) || !isRecord(value.recoveryEnvelope)) {
    return null;
  }
  const request = value.request;
  return {
    protocol: value.protocol as RecoveryInput['protocol'],
    kind: value.kind as RecoveryInput['kind'],
    requestId: request.id as string,
    requestDigest: request.requestDigest as string,
    vaultId: request.vaultId as string,
    epoch: value.activeEpoch as number,
    targetCapability: request.targetCapability as RecoveryInput['targetCapability'],
    recovery: {
      keyId: value.recoveryKey.id as string,
      ceremonyId: value.recoveryKey.ceremonyId as string,
      ceremonyDigest: value.recoveryKey.ceremonyEvidenceDigest as string,
      publicKey: value.recoveryKey.publicEncryptionKey as string,
    },
    recoveryEnvelope: value.recoveryEnvelope as unknown as VaultKeyEnvelopeInput,
    trustedOwnerSigningPublicKey: value.trustedSigner.signingPublicKey as string,
    target: {
      userId: value.targetProfile.userId as string,
      encryptionPublicKey: value.targetProfile.encryptionPublicKey as string,
      keyVersion: value.targetProfile.keyVersion as number,
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
