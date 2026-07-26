import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type {
  EnterpriseRecoveryKey,
  EnterpriseRecoveryRequest,
  UserCryptoProfile,
} from '@mima/contracts';
import {
  createVaultKeyGrant,
  createVaultKeys,
  destroyKeyPair,
  destroyVaultKeys,
  encryptVaultMetadata,
  generateSigningKeyPair,
} from '@mima/e2ee';
import {
  E2eeKeyring,
  parseOfflineRecoveryResult,
} from '../../../packages/client-core/src/e2ee-keyring.ts';

const root = resolve(import.meta.dirname, '../../..');
const temporaryDirectories: string[] = [];

afterEach(() => {
  temporaryDirectories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

describe('recovery tool CLI contract', () => {
  it('generates private files and completes recovery from the untouched CLI result', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'mima-recovery-cli-'));
    temporaryDirectories.push(parent);
    const outputDirectory = join(parent, 'ceremony');
    runCli([
      'generate',
      '--ceremony-id', 'cli-contract-test',
      '--output-dir', outputDirectory,
    ]);
    expect(statSync(outputDirectory).mode & 0o777).toBe(0o700);
    for (const filename of ['manifest.json', 'share-1.mimashare', 'share-2.mimashare', 'share-3.mimashare']) {
      expect(statSync(join(outputDirectory, filename)).mode & 0o777).toBe(0o600);
    }

    const manifest = JSON.parse(readFileSync(join(outputDirectory, 'manifest.json'), 'utf8')) as {
      ceremonyId: string;
      ceremonyDigest: string;
      publicEncryptionKey: string;
      keyFingerprint: string;
    };
    const targetUserId = 'user:cli-recovery-target';
    const targetDeviceId = '40000000-0000-4000-8000-000000000001';
    const vaultId = '20000000-0000-4000-8000-000000000001';
    const recoveryKeyId = '10000000-0000-4000-8000-000000000001';
    const targetKeyring = new E2eeKeyring();
    const setup = await targetKeyring.setup('cli recovery target password', {
      accountId: targetUserId,
      deviceId: targetDeviceId,
      deviceName: 'CLI recovery target',
      platform: 'test',
    });
    const now = new Date().toISOString();
    const profile: UserCryptoProfile = {
      userId: targetUserId,
      profileVersion: 1,
      keyVersion: 1,
      suite: setup.request.suite,
      kdf: setup.request.kdf,
      encryptedAccountBundle: setup.request.encryptedAccountBundle,
      encryptionPublicKey: setup.request.encryptionPublicKey,
      signingPublicKey: setup.request.signingPublicKey,
      recoveryEnabled: true,
      createdAt: now,
      updatedAt: now,
    };
    const recoveryKey: EnterpriseRecoveryKey = {
      id: recoveryKeyId,
      ceremonyId: manifest.ceremonyId,
      keyFingerprint: manifest.keyFingerprint,
      publicEncryptionKey: manifest.publicEncryptionKey,
      threshold: 2,
      shareCount: 3,
      status: 'active',
      ceremonyEvidenceDigest: manifest.ceremonyDigest,
      approvalUserIds: ['admin-one', 'admin-two'],
      createdAt: now,
      retiredAt: null,
    };
    const request: EnterpriseRecoveryRequest = {
      id: '30000000-0000-4000-8000-000000000001',
      vaultId,
      recoveryKeyId,
      targetUserId,
      targetDeviceId,
      targetEncryptionPublicKey: profile.encryptionPublicKey,
      targetKeyVersion: 1,
      targetCapability: 'full',
      accountResetRequestId: null,
      requestDigest: 'A'.repeat(43),
      status: 'approved',
      approvalUserIds: ['admin-one', 'admin-two'],
      createdAt: now,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      completedAt: null,
    };
    const vaultKeys = await createVaultKeys(1);
    const ownerSigning = await generateSigningKeyPair();
    try {
      const recoveryEnvelope = await createVaultKeyGrant(
        vaultKeys,
        manifest.publicEncryptionKey,
        ownerSigning.privateKey,
        {
          vaultId,
          recipientKind: 'recovery',
          recipientId: recoveryKeyId,
          recipientKeyVersion: 1,
          capability: 'recovery',
          signerUserId: 'user:cli-owner',
          signerKeyVersion: 1,
        },
      );
      const encryptedHeader = await encryptVaultMetadata(
        vaultKeys.metadataKey,
        { vaultId, version: 1, keyEpoch: 1 },
        { name: 'CLI recovered vault' },
      );
      const requestPath = join(parent, 'request.json');
      const resultPath = join(parent, 'result.json');
      writeFileSync(requestPath, JSON.stringify({
        protocol: 'lm-e2ee-v1',
        kind: 'enterprise-recovery-request-package',
        requestId: request.id,
        requestDigest: request.requestDigest,
        vaultId,
        epoch: 1,
        targetCapability: 'full',
        recovery: {
          keyId: recoveryKeyId,
          ceremonyId: manifest.ceremonyId,
          ceremonyDigest: manifest.ceremonyDigest,
          publicKey: manifest.publicEncryptionKey,
        },
        recoveryEnvelope,
        trustedOwnerSigningPublicKey: ownerSigning.publicKey,
        target: {
          userId: targetUserId,
          encryptionPublicKey: profile.encryptionPublicKey,
          keyVersion: 1,
        },
      }), { mode: 0o600 });
      runCli([
        'recover',
        '--input', requestPath,
        '--share', join(outputDirectory, 'share-1.mimashare'),
        '--share', join(outputDirectory, 'share-3.mimashare'),
        '--output', resultPath,
      ]);
      expect(statSync(resultPath).mode & 0o777).toBe(0o600);
      const rawResult = JSON.parse(readFileSync(resultPath, 'utf8')) as Record<string, unknown>;
      expect(rawResult).toHaveProperty('recoveredEnvelope');
      expect(rawResult).not.toHaveProperty('unsignedEnvelope');
      const parsed = parseOfflineRecoveryResult(rawResult);
      const completion = await targetKeyring.completeRecovery(
        targetUserId,
        request,
        recoveryKey,
        {
          vaultId,
          version: 1,
          keyEpoch: 1,
          blob: encryptedHeader.blob,
          updatedAt: now,
          updatedBy: 'user:cli-owner',
        },
        parsed,
      );
      expect(completion.recoveredEnvelope.recipientId).toBe(targetUserId);
      await expect(targetKeyring.encryptCreate(targetUserId, vaultId, {
        kind: 'secure_note',
        title: 'Recovered through CLI',
        username: null,
        origin: null,
        tags: [],
        favorite: false,
        sensitivity: 'medium',
        secretValue: 'content key recovered',
      })).resolves.toMatchObject({ keyEpoch: 1 });
    } finally {
      await targetKeyring.lock();
      await destroyVaultKeys(vaultKeys);
      await destroyKeyPair(ownerSigning);
    }
  }, 20_000);
});

function runCli(arguments_: string[]): void {
  const result = spawnSync(process.execPath, [
    resolve(root, 'apps/recovery-tool/node_modules/tsx/dist/cli.mjs'),
    resolve(root, 'apps/recovery-tool/src/cli.ts'),
    ...arguments_,
  ], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
  });
  expect(result.status, result.stderr || result.stdout).toBe(0);
}
