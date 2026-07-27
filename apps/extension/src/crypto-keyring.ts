import type {
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  EncryptedItemMetadata,
} from '@mima/contracts';
import {
  CryptoDeviceSchema,
  EncryptedBootstrapResponseSchema,
  EncryptedContentResponseSchema,
  SessionUserSchema,
} from '@mima/contracts';
import {
  canonicalJson,
  createKdfProfile,
  decodeJson,
  decryptBytes,
  decryptItemContent,
  deriveMasterKey,
  deriveExtensionDeviceUnlockKey,
  destroyUnlockedAccount,
  destroyKeyPair,
  destroyVaultKeys,
  encodeJson,
  encryptBytes,
  fromBase64Url,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  openSealedBytes,
  openVaultKeyGrant,
  signBytes,
  sodiumReady,
  EXTENSION_TRUSTED_UNLOCK_PROTOCOL,
  EXTENSION_TRUSTED_UNLOCK_TTL_MS,
  assertExtensionTrustedUnlockRequest,
  trustedUnlockBindingMatches,
  toBase64Url,
  unlockAccountBundle,
  utf8,
  type EncryptionKeyPair,
  type AccountBundle,
  type ExtensionTrustedUnlockRequest,
  type ExtensionTrustedUnlockResponse,
  type JsonValue,
  type SigningKeyPair,
  type VaultKeys,
} from '@mima/e2ee';
import { ITEM_DESCRIPTION_MAX_LENGTH, normalizeLoginUrls, normalizeOrigin } from '@mima/domain';
import { DeviceRevokedError } from './crypto-errors.ts';
import { assertServerDeviceMatches, verifyApprovedDevice } from './device-verification.ts';
import type {
  DecryptedExtensionItem,
  LocalDeviceRecord,
  PairingApproval,
  PairingClaimRequest,
} from './protocol.ts';

interface UnlockedDevice {
  encryptionKeyPair: EncryptionKeyPair;
  signingKeyPair: SigningKeyPair;
}

interface PrivateDevicePayload {
  version: 1;
  encryptionPrivateKey: string;
  signingPrivateKey: string;
}

export class ExtensionKeyring {
  private device: UnlockedDevice | null = null;
  private deviceRecord: LocalDeviceRecord | null = null;
  private readonly vaultKeys = new Map<string, VaultKeys>();
  private pendingTrustedUnlock: {
    request: ExtensionTrustedUnlockRequest;
    keyPair: EncryptionKeyPair;
  } | null = null;

  get unlocked(): boolean {
    return this.device !== null;
  }

  get deviceId(): string | null {
    return this.deviceRecord?.deviceId ?? null;
  }

  async createLocalDevice(
    unlockFactor: string,
    input: { deviceId: string; name: string; platform: string },
  ): Promise<LocalDeviceRecord> {
    const [encryptionKeyPair, signingKeyPair] = await Promise.all([
      generateEncryptionKeyPair(),
      generateSigningKeyPair(),
    ]);
    const crypto = await sodiumReady();
    let wrappingKey: Uint8Array | undefined;
    let plaintext: Uint8Array | undefined;
    try {
      const kdf = await createKdfProfile();
      wrappingKey = await deriveMasterKey(unlockFactor, kdf);
      plaintext = encodeJson({
        version: 1,
        encryptionPrivateKey: await toBase64Url(encryptionKeyPair.privateKey),
        signingPrivateKey: await toBase64Url(signingKeyPair.privateKey),
      });
      const fingerprint = await deviceFingerprint({
        deviceId: input.deviceId,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        signingPublicKey: signingKeyPair.publicKey,
      });
      return {
        version: 1,
        unlockFactorKind: 'web-main-password',
        ...input,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        signingPublicKey: signingKeyPair.publicKey,
        fingerprint,
        kdf,
        encryptedPrivateBundle: await encryptBytes(wrappingKey, plaintext, {
          blobType: 'device-private-key-bundle',
          deviceId: input.deviceId,
        }),
        userId: null,
        certificate: null,
        certificateSignature: null,
      };
    } finally {
      if (wrappingKey) crypto.memzero(wrappingKey);
      if (plaintext) crypto.memzero(plaintext);
      await destroyKeyPair(encryptionKeyPair);
      await destroyKeyPair(signingKeyPair);
    }
  }

  async createPairingDevice(
    input: { deviceId: string; name: string; platform: string },
  ): Promise<LocalDeviceRecord> {
    await this.lock();
    const [encryptionKeyPair, signingKeyPair] = await Promise.all([
      generateEncryptionKeyPair(),
      generateSigningKeyPair(),
    ]);
    const crypto = await sodiumReady();
    const temporaryKey = crypto.randombytes_buf(32);
    let plaintext: Uint8Array | undefined;
    try {
      plaintext = encodeJson({
        version: 1,
        encryptionPrivateKey: await toBase64Url(encryptionKeyPair.privateKey),
        signingPrivateKey: await toBase64Url(signingKeyPair.privateKey),
      });
      const record: LocalDeviceRecord = {
        version: 1,
        pairingOnly: true,
        unlockFactorKind: 'web-main-password',
        ...input,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        signingPublicKey: signingKeyPair.publicKey,
        fingerprint: await deviceFingerprint({
          deviceId: input.deviceId,
          encryptionPublicKey: encryptionKeyPair.publicKey,
          signingPublicKey: signingKeyPair.publicKey,
        }),
        kdf: await createKdfProfile(),
        encryptedPrivateBundle: await encryptBytes(temporaryKey, plaintext, {
          blobType: 'device-private-key-bundle',
          deviceId: input.deviceId,
        }),
        userId: null,
        certificate: null,
        certificateSignature: null,
      };
      this.device = { encryptionKeyPair, signingKeyPair };
      this.deviceRecord = record;
      return record;
    } catch (error) {
      await destroyKeyPair(encryptionKeyPair);
      await destroyKeyPair(signingKeyPair);
      throw error;
    } finally {
      crypto.memzero(temporaryKey);
      if (plaintext) crypto.memzero(plaintext);
    }
  }

  async unlock(record: LocalDeviceRecord, unlockFactor: string): Promise<void> {
    await this.lock();
    if (record.webUnlock) {
      await this.unlockTrustedRecord(record, unlockFactor);
      return;
    }
    if (record.pairingOnly) throw new Error('配对尚未完成，请重新生成配对码');
    const crypto = await sodiumReady();
    const wrappingKey = await deriveMasterKey(unlockFactor, record.kdf);
    let plaintext: Uint8Array | undefined;
    let encryptionPrivateKey: Uint8Array | undefined;
    let signingPrivateKey: Uint8Array | undefined;
    try {
      plaintext = await decryptBytes(wrappingKey, record.encryptedPrivateBundle, {
        blobType: 'device-private-key-bundle',
        deviceId: record.deviceId,
      });
      const parsed = parsePrivateDevicePayload(decodeJson(plaintext));
      encryptionPrivateKey = await fromBase64Url(parsed.encryptionPrivateKey, 32);
      signingPrivateKey = await fromBase64Url(parsed.signingPrivateKey, 64);
      this.device = {
        encryptionKeyPair: {
          publicKey: record.encryptionPublicKey,
          privateKey: encryptionPrivateKey,
        },
        signingKeyPair: {
          publicKey: record.signingPublicKey,
          privateKey: signingPrivateKey,
        },
      };
      this.deviceRecord = record;
      encryptionPrivateKey = undefined;
      signingPrivateKey = undefined;
    } catch {
      throw new Error(record.unlockFactorKind === 'web-main-password'
        ? '主密码不正确'
        : '旧版扩展解锁密码不正确');
    } finally {
      crypto.memzero(wrappingKey);
      if (plaintext) crypto.memzero(plaintext);
      if (encryptionPrivateKey) crypto.memzero(encryptionPrivateKey);
      if (signingPrivateKey) crypto.memzero(signingPrivateKey);
    }
  }

  async lock(): Promise<void> {
    const pendingTrustedUnlock = this.pendingTrustedUnlock;
    this.pendingTrustedUnlock = null;
    if (pendingTrustedUnlock) await destroyKeyPair(pendingTrustedUnlock.keyPair);
    const device = this.device;
    this.device = null;
    this.deviceRecord = null;
    if (device) {
      await Promise.all([
        destroyKeyPair(device.encryptionKeyPair),
        destroyKeyPair(device.signingKeyPair),
      ]);
    }
    const keys = [...this.vaultKeys.values()];
    this.vaultKeys.clear();
    await Promise.all(keys.map((entry) => destroyVaultKeys(entry)));
  }

  async createTrustedUnlockRequest(
    record: LocalDeviceRecord,
    accountBundle?: AccountBundle,
  ): Promise<ExtensionTrustedUnlockRequest> {
    const account = record.webUnlock?.accountBundle
      ?? accountBundle
      ?? await trustedUnlockBindingFromDeviceCertificate(record);
    if (!record.userId || account.accountId !== record.userId) {
      throw new Error('此扩展的可信连接信息不完整，请重新配对');
    }
    if (this.pendingTrustedUnlock) {
      await destroyKeyPair(this.pendingTrustedUnlock.keyPair);
      this.pendingTrustedUnlock = null;
    }
    const keyPair = await generateEncryptionKeyPair();
    const issuedAt = new Date();
    const request: ExtensionTrustedUnlockRequest = {
      protocol: EXTENSION_TRUSTED_UNLOCK_PROTOCOL,
      requestId: crypto.randomUUID(),
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + EXTENSION_TRUSTED_UNLOCK_TTL_MS).toISOString(),
      accountId: account.accountId,
      accountKeyVersion: account.keyVersion,
      deviceId: record.deviceId,
      deviceEncryptionPublicKey: record.encryptionPublicKey,
      deviceSigningPublicKey: record.signingPublicKey,
      fingerprint: record.fingerprint,
      recordDigest: await trustedRecordDigest(record, account),
      ephemeralEncryptionPublicKey: keyPair.publicKey,
    };
    this.pendingTrustedUnlock = { request, keyPair };
    return request;
  }

  async completeTrustedUnlock(
    record: LocalDeviceRecord,
    response: ExtensionTrustedUnlockResponse,
  ): Promise<LocalDeviceRecord> {
    const pending = this.pendingTrustedUnlock;
    this.pendingTrustedUnlock = null;
    if (!pending) throw new Error('扩展可信解锁请求不存在或已经使用');
    const crypto = await sodiumReady();
    let deviceUnlockKey: Uint8Array | undefined;
    try {
      assertExtensionTrustedUnlockRequest(pending.request);
      if (!trustedUnlockBindingMatches(pending.request, response)) {
        throw new Error('扩展可信解锁响应与本机请求不一致');
      }
      if (
        response.accountBundle.accountId !== response.accountId ||
        response.accountBundle.keyVersion !== response.accountKeyVersion ||
        response.accountBundle.encryptionPublicKey.length < 16 ||
        response.accountBundle.signingPublicKey.length < 16
      ) {
        throw new Error('此扩展连接的账号与当前工作台不一致，请切换到同一账号后重试');
      }
      deviceUnlockKey = await openSealedBytes(
        response.sealedDeviceUnlockKey,
        pending.keyPair,
      );
      if (deviceUnlockKey.byteLength !== 32) throw new Error('扩展可信解锁钥匙长度无效');
      const upgraded = record.webUnlock
        ? await this.restoreTrustedRecord(record, response.accountBundle, deviceUnlockKey)
        : await this.encryptTrustedRecord(record, response.accountBundle, deviceUnlockKey);
      this.deviceRecord = upgraded;
      return upgraded;
    } finally {
      if (deviceUnlockKey) crypto.memzero(deviceUnlockKey);
      await destroyKeyPair(pending.keyPair);
    }
  }

  async upgradeTrustedUnlock(
    record: LocalDeviceRecord,
    unlockFactor: string,
    accountBundle: AccountBundle,
  ): Promise<LocalDeviceRecord> {
    const account = await unlockAccountBundle(unlockFactor, accountBundle);
    const crypto = await sodiumReady();
    let deviceUnlockKey: Uint8Array | undefined;
    try {
      if (account.accountId !== record.userId) throw new Error('扩展账号与主密码不匹配');
      deviceUnlockKey = await deriveExtensionDeviceUnlockKey(account.accountKey, {
        accountId: account.accountId,
        accountKeyVersion: accountBundle.keyVersion,
        deviceId: record.deviceId,
      });
      const upgraded = await this.encryptTrustedRecord(record, accountBundle, deviceUnlockKey);
      this.deviceRecord = upgraded;
      return upgraded;
    } finally {
      if (deviceUnlockKey) crypto.memzero(deviceUnlockKey);
      await destroyUnlockedAccount(account);
    }
  }

  async pairingProof(code: string, record: LocalDeviceRecord): Promise<string> {
    const device = this.requireDevice(record.deviceId);
    const message = pairingClaimBytes(code, record);
    try {
      return await signBytes(message, device.signingKeyPair.privateKey);
    } finally {
      message.fill(0);
    }
  }

  pairingRequest(code: string, record: LocalDeviceRecord, proof?: string): PairingClaimRequest {
    return {
      code,
      device: {
        id: record.deviceId,
        deviceType: 'extension',
        encryptionPublicKey: record.encryptionPublicKey,
        signingPublicKey: record.signingPublicKey,
        joinChannelPublicKey: record.encryptionPublicKey,
        fingerprint: record.fingerprint,
      },
      ...(proof ? { existingDeviceProof: proof } : {}),
    };
  }

  async signChallenge(challenge: string): Promise<string> {
    const device = this.requireDevice();
    const bytes = await fromBase64Url(challenge);
    try {
      return await signBytes(bytes, device.signingKeyPair.privateKey);
    } finally {
      bytes.fill(0);
    }
  }

  async openPairingApproval(sealedApproval: string): Promise<PairingApproval> {
    const device = this.requireDevice();
    const plaintext = await openSealedBytes(sealedApproval, device.encryptionKeyPair);
    try {
      return parsePairingApproval(decodeJson(plaintext));
    } finally {
      plaintext.fill(0);
    }
  }

  async verifyApprovedDevice(
    record: LocalDeviceRecord,
    device: CryptoDevice,
    profileSigningPublicKey: string,
  ): Promise<LocalDeviceRecord> {
    this.requireDevice(record.deviceId);
    const approved = await verifyApprovedDevice(record, device, profileSigningPublicKey);
    this.deviceRecord = approved;
    return approved;
  }

  async signContentIntent(input: {
    itemId: string;
    purpose: 'copy' | 'fill';
    secretVersion: number;
  }): Promise<string> {
    const device = this.requireDevice();
    const message = utf8(canonicalJson({
      deviceId: this.deviceRecord!.deviceId,
      itemId: input.itemId,
      kind: 'encrypted-content-intent',
      protocol: 'lm-e2ee-v1',
      purpose: input.purpose,
      secretVersion: input.secretVersion,
    }));
    try {
      return await signBytes(message, device.signingKeyPair.privateKey);
    } finally {
      message.fill(0);
    }
  }

  async loadBootstrap(bootstrap: EncryptedBootstrapResponse): Promise<DecryptedExtensionItem[]> {
    const record = this.deviceRecord;
    const device = this.requireDevice();
    if (
      !record ||
      bootstrap.user.id !== record.userId ||
      bootstrap.profile?.userId !== bootstrap.user.id
    ) {
      throw new Error('本次配对与当前扩展不一致，已拒绝继续；请重新生成配对码');
    }
    const serverDevice = bootstrap.devices.find((entry) => entry.id === record.deviceId);
    if (!serverDevice || serverDevice.revokedAt) {
      throw new DeviceRevokedError();
    }
    assertServerDeviceMatches(record, serverDevice);
    if (!bootstrap.profile) throw new Error('当前账号尚未设置主密码，请先在工作台完成设置');

    const signerProfiles = new Map(
      [
        ...(bootstrap.profile ? [{
          userId: bootstrap.profile.userId,
          keyVersion: bootstrap.profile.keyVersion,
          signingPublicKey: bootstrap.profile.signingPublicKey,
        }] : []),
        ...((bootstrap as EncryptedBootstrapResponse & {
          signerProfiles?: Array<{ userId: string; keyVersion: number; signingPublicKey: string }>;
        }).signerProfiles ?? []),
      ].map((profile) => [profile.userId, profile] as const),
    );
    const nextKeys = new Map<string, VaultKeys>();
    try {
      for (const envelope of bootstrap.envelopes) {
        if (envelope.recipientKind !== 'device' || envelope.recipientId !== record.deviceId) continue;
        const signer = signerProfiles.get(envelope.signerUserId);
        if (!signer || envelope.signerKeyVersion !== signer.keyVersion) {
          throw new Error('密码库安全信息校验失败，已拒绝解锁；请刷新后重试');
        }
        const opened = await openVaultKeyGrant(
          envelope,
          device.encryptionKeyPair,
          signer.signingPublicKey,
          {
            vaultId: envelope.vaultId,
            recipientId: record.deviceId,
            epoch: envelope.epoch,
            recipientKeyVersion: 1,
          },
        );
        const keyId = vaultKeyId(envelope.vaultId, envelope.epoch);
        if (nextKeys.has(keyId)) {
          await destroyVaultKeys(opened);
          throw new Error('密码库安全信息重复，已拒绝解锁；请刷新后重试');
        }
        nextKeys.set(keyId, opened);
      }

      const items: DecryptedExtensionItem[] = [];
      for (const encrypted of bootstrap.items) {
        if (encrypted.deleted) continue;
        const keys = nextKeys.get(vaultKeyId(encrypted.vaultId, encrypted.keyEpoch));
        if (!keys) continue;
        const metadata = await decryptMetadata(keys, encrypted);
        items.push(parseItemMetadata(metadata, encrypted));
      }
      const previousKeys = [...this.vaultKeys.values()];
      this.vaultKeys.clear();
      for (const [id, keys] of nextKeys) this.vaultKeys.set(id, keys);
      nextKeys.clear();
      await Promise.all(previousKeys.map((entry) => destroyVaultKeys(entry)));
      return items;
    } finally {
      await Promise.all([...nextKeys.values()].map((entry) => destroyVaultKeys(entry)));
    }
  }

  async decryptContent(
    item: DecryptedExtensionItem,
    response: EncryptedContentResponse,
  ): Promise<string> {
    if (
      response.metadata.itemId !== item.id ||
      response.metadata.vaultId !== item.vaultId ||
      response.metadata.version !== item.version ||
      response.metadata.secretVersion !== item.secretVersion ||
      response.metadata.keyEpoch !== item.keyEpoch ||
      response.secret.itemId !== item.id ||
      response.secret.vaultId !== item.vaultId ||
      response.secret.recordVersion !== response.secret.secretVersion ||
      response.secret.secretVersion !== item.secretVersion ||
      response.keyWrap.itemId !== item.id ||
      response.keyWrap.vaultId !== item.vaultId ||
      response.keyWrap.secretVersion !== item.secretVersion ||
      response.keyWrap.keyEpoch !== item.keyEpoch
    ) {
      throw new Error('返回内容与所选条目不一致，已拒绝显示');
    }
    const keys = this.vaultKeys.get(vaultKeyId(item.vaultId, response.keyWrap.keyEpoch));
    if (!keys?.contentKey) throw new Error('当前设备没有查看该敏感内容的权限');
    const content = await decryptItemContent(keys.contentKey, {
      vaultId: item.vaultId,
      itemId: item.id,
      itemKind: item.kind,
      version: response.secret.recordVersion,
      secretVersion: item.secretVersion,
      keyEpoch: response.keyWrap.keyEpoch,
      metadata: response.metadata.blob,
      wrappedDek: response.keyWrap.wrappedDek,
      encryptedValue: response.secret.encryptedValue,
    });
    if (
      !isRecord(content) ||
      typeof content.value !== 'string' ||
      (content.itemKind !== undefined && content.itemKind !== item.kind) ||
      (content.itemId !== undefined && content.itemId !== item.id) ||
      (content.secretVersion !== undefined && content.secretVersion !== item.secretVersion)
    ) {
      throw new Error('敏感内容校验失败，已拒绝显示');
    }
    return content.value;
  }

  private async unlockTrustedRecord(record: LocalDeviceRecord, mainPassword: string): Promise<void> {
    const webUnlock = record.webUnlock;
    if (!webUnlock) throw new Error('此扩展尚未完成长期连接设置，请保持工作台已解锁后重试');
    const crypto = await sodiumReady();
    let account: Awaited<ReturnType<typeof unlockAccountBundle>> | undefined;
    let deviceUnlockKey: Uint8Array | undefined;
    try {
      account = await unlockAccountBundle(mainPassword, webUnlock.accountBundle);
      if (account.accountId !== record.userId) throw new Error('主密码与扩展账号不匹配');
      deviceUnlockKey = await deriveExtensionDeviceUnlockKey(account.accountKey, {
        accountId: account.accountId,
        accountKeyVersion: webUnlock.accountBundle.keyVersion,
        deviceId: record.deviceId,
      });
      await this.loadTrustedDevice(record, deviceUnlockKey);
    } catch {
      throw new Error('主密码不正确');
    } finally {
      if (deviceUnlockKey) crypto.memzero(deviceUnlockKey);
      if (account) await destroyUnlockedAccount(account);
    }
  }

  private async loadTrustedDevice(record: LocalDeviceRecord, deviceUnlockKey: Uint8Array): Promise<void> {
    const webUnlock = record.webUnlock;
    if (!webUnlock) throw new Error('此扩展尚未完成长期连接设置，请保持工作台已解锁后重试');
    const crypto = await sodiumReady();
    let plaintext: Uint8Array | undefined;
    let encryptionPrivateKey: Uint8Array | undefined;
    let signingPrivateKey: Uint8Array | undefined;
    try {
      plaintext = await decryptBytes(deviceUnlockKey, webUnlock.encryptedPrivateBundle, {
        blobType: 'extension-trusted-device-private-key-bundle',
        accountId: webUnlock.accountBundle.accountId,
        deviceId: record.deviceId,
        recordVersion: webUnlock.accountBundle.keyVersion,
      });
      const parsed = parsePrivateDevicePayload(decodeJson(plaintext));
      encryptionPrivateKey = await fromBase64Url(parsed.encryptionPrivateKey, 32);
      signingPrivateKey = await fromBase64Url(parsed.signingPrivateKey, 64);
      this.device = {
        encryptionKeyPair: {
          publicKey: record.encryptionPublicKey,
          privateKey: encryptionPrivateKey,
        },
        signingKeyPair: {
          publicKey: record.signingPublicKey,
          privateKey: signingPrivateKey,
        },
      };
      this.deviceRecord = record;
      encryptionPrivateKey = undefined;
      signingPrivateKey = undefined;
    } finally {
      if (plaintext) crypto.memzero(plaintext);
      if (encryptionPrivateKey) crypto.memzero(encryptionPrivateKey);
      if (signingPrivateKey) crypto.memzero(signingPrivateKey);
    }
  }

  private async restoreTrustedRecord(
    record: LocalDeviceRecord,
    accountBundle: AccountBundle,
    deviceUnlockKey: Uint8Array,
  ): Promise<LocalDeviceRecord> {
    await this.loadTrustedDevice(record, deviceUnlockKey);
    return {
      ...record,
      webUnlock: {
        ...record.webUnlock!,
        accountBundle,
      },
    };
  }

  private async encryptTrustedRecord(
    record: LocalDeviceRecord,
    accountBundle: AccountBundle,
    deviceUnlockKey: Uint8Array,
  ): Promise<LocalDeviceRecord> {
    const device = this.requireDevice(record.deviceId);
    const crypto = await sodiumReady();
    const plaintext = encodeJson({
      version: 1,
      encryptionPrivateKey: await toBase64Url(device.encryptionKeyPair.privateKey),
      signingPrivateKey: await toBase64Url(device.signingKeyPair.privateKey),
    });
    try {
      const { pairingOnly: _pairingOnly, ...stableRecord } = record;
      return {
        ...stableRecord,
        kdf: accountBundle.kdf,
        webUnlock: {
          version: 1,
          accountBundle,
          encryptedPrivateBundle: await encryptBytes(deviceUnlockKey, plaintext, {
            blobType: 'extension-trusted-device-private-key-bundle',
            accountId: accountBundle.accountId,
            deviceId: record.deviceId,
            recordVersion: accountBundle.keyVersion,
          }),
        },
      };
    } finally {
      crypto.memzero(plaintext);
    }
  }

  private requireDevice(expectedDeviceId?: string): UnlockedDevice {
    if (!this.device || !this.deviceRecord) throw new Error('扩展已锁定，请先用主密码解锁');
    if (expectedDeviceId && this.deviceRecord.deviceId !== expectedDeviceId) {
      throw new Error('此扩展的本机授权与当前设备不一致，请重新配对');
    }
    return this.device;
  }
}

async function trustedUnlockBindingFromDeviceCertificate(
  record: LocalDeviceRecord,
): Promise<Pick<AccountBundle, 'accountId' | 'keyVersion'>> {
  if (!record.certificate) throw new Error('此扩展的可信连接信息不完整，请重新配对');
  const bytes = await fromBase64Url(record.certificate);
  try {
    const certificate = decodeJson(bytes);
    if (
      !isRecord(certificate)
      || certificate.protocol !== 'lm-e2ee-v1'
      || certificate.kind !== 'device-certificate'
      || certificate.deviceType !== 'extension'
      || certificate.accountId !== record.userId
      || certificate.deviceId !== record.deviceId
      || certificate.encryptionPublicKey !== record.encryptionPublicKey
      || certificate.signingPublicKey !== record.signingPublicKey
      || !Number.isSafeInteger(certificate.keyVersion)
      || Number(certificate.keyVersion) < 1
    ) {
      throw new Error('此扩展的本机授权不完整，请重新配对');
    }
    return {
      accountId: certificate.accountId as string,
      keyVersion: Number(certificate.keyVersion),
    };
  } finally {
    bytes.fill(0);
  }
}

async function trustedRecordDigest(
  record: LocalDeviceRecord,
  account: Pick<AccountBundle, 'accountId' | 'keyVersion'>,
): Promise<string> {
  const crypto = await sodiumReady();
  const bytes = utf8(canonicalJson({
    accountId: account.accountId,
    accountKeyVersion: account.keyVersion,
    deviceId: record.deviceId,
    encryptionPublicKey: record.encryptionPublicKey,
    fingerprint: record.fingerprint,
    kind: 'extension-trusted-unlock-record',
    protocol: EXTENSION_TRUSTED_UNLOCK_PROTOCOL,
    signingPublicKey: record.signingPublicKey,
    webUnlockCiphertext: record.webUnlock?.encryptedPrivateBundle.ciphertext ?? null,
    webUnlockNonce: record.webUnlock?.encryptedPrivateBundle.nonce ?? null,
  }));
  try {
    const digest = crypto.crypto_hash_sha256(bytes);
    try {
      return await toBase64Url(digest);
    } finally {
      crypto.memzero(digest);
    }
  } finally {
    crypto.memzero(bytes);
  }
}

export async function deviceFingerprint(input: {
  deviceId: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
}): Promise<string> {
  const crypto = await sodiumReady();
  const encoded = utf8(canonicalJson({
    deviceId: input.deviceId,
    encryptionPublicKey: input.encryptionPublicKey,
    kind: 'extension-device-fingerprint',
    protocol: 'lm-e2ee-v1',
    signingPublicKey: input.signingPublicKey,
  }));
  try {
    const digest = crypto.crypto_hash_sha256(encoded);
    try {
      return Array.from(digest.subarray(0, 16), (byte) => byte.toString(16).padStart(2, '0').toUpperCase())
        .join('')
        .match(/.{1,4}/g)!
        .join(' ');
    } finally {
      crypto.memzero(digest);
    }
  } finally {
    crypto.memzero(encoded);
  }
}

function pairingClaimBytes(code: string, record: LocalDeviceRecord): Uint8Array {
  return utf8(canonicalJson({
    code,
    deviceId: record.deviceId,
    deviceType: 'extension',
    encryptionPublicKey: record.encryptionPublicKey,
    fingerprint: record.fingerprint,
    kind: 'extension-pairing-claim',
    protocol: 'lm-e2ee-v1',
    signingPublicKey: record.signingPublicKey,
    joinChannelPublicKey: record.encryptionPublicKey,
  }));
}

async function decryptMetadata(keys: VaultKeys, encrypted: EncryptedItemMetadata): Promise<JsonValue> {
  const plaintext = await decryptBytes(keys.metadataKey, encrypted.blob, {
    blobType: 'item-metadata',
    vaultId: encrypted.vaultId,
    itemId: encrypted.itemId,
    recordVersion: encrypted.version,
    secretVersion: encrypted.secretVersion,
    keyEpoch: encrypted.keyEpoch,
  });
  try {
    return decodeJson(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

function parsePrivateDevicePayload(value: JsonValue): PrivateDevicePayload {
  if (
    !isRecord(value) ||
    value.version !== 1 ||
    typeof value.encryptionPrivateKey !== 'string' ||
    typeof value.signingPrivateKey !== 'string'
  ) {
    throw new Error('此扩展的本机授权已损坏，请重新配对');
  }
  return value as unknown as PrivateDevicePayload;
}

function parsePairingApproval(value: JsonValue): PairingApproval {
  if (!isRecord(value) || !isRecord(value.session)) {
    throw new Error('本次配对授权校验失败，请重新配对');
  }
  const token = value.session.token;
  const expiresAt = value.session.expiresAt;
  if (
    typeof token !== 'string' ||
    token.length < 16 ||
    typeof expiresAt !== 'string' ||
    !Number.isFinite(Date.parse(expiresAt)) ||
    typeof value.profileSigningPublicKey !== 'string'
  ) {
    throw new Error('本次配对授权校验失败，请重新配对');
  }
  const user = SessionUserSchema.parse(value.session.user);
  const device = CryptoDeviceSchema.parse(value.device);
  let bootstrap: PairingApproval['bootstrap'];
  if (value.bootstrap !== undefined) {
    const base = EncryptedBootstrapResponseSchema.parse(value.bootstrap);
    const rawContents = isRecord(value.bootstrap) ? value.bootstrap.contents : undefined;
    const signerProfiles = isRecord(value.bootstrap) ? value.bootstrap.signerProfiles : undefined;
    bootstrap = {
      ...base,
      ...(Array.isArray(signerProfiles)
        ? { signerProfiles: signerProfiles.map(parseSignerProfile) }
        : {}),
      ...(Array.isArray(rawContents)
        ? { contents: rawContents.map((entry) => EncryptedContentResponseSchema.parse(entry)) }
        : {}),
    };
  }
  return {
    session: { token, expiresAt, user },
    device,
    profileSigningPublicKey: value.profileSigningPublicKey,
    ...(bootstrap ? { bootstrap } : {}),
  };
}

function parseSignerProfile(value: unknown) {
  if (
    !isRecord(value) ||
    typeof value.userId !== 'string' ||
    !Number.isSafeInteger(value.keyVersion) ||
    Number(value.keyVersion) <= 0 ||
    typeof value.encryptionPublicKey !== 'string' ||
    typeof value.signingPublicKey !== 'string'
  ) {
    throw new Error('密码库安全信息校验失败，已拒绝解锁；请刷新后重试');
  }
  return {
    userId: value.userId,
    keyVersion: Number(value.keyVersion),
    encryptionPublicKey: value.encryptionPublicKey,
    signingPublicKey: value.signingPublicKey,
  };
}

function parseItemMetadata(
  value: JsonValue,
  encrypted: EncryptedItemMetadata,
): DecryptedExtensionItem {
  if (!isRecord(value)) throw new Error('条目信息校验失败，已拒绝显示');
  const kind = value.kind;
  const title = value.title;
  const username = value.username;
  const origin = value.origin;
  const loginUrl = value.loginUrl;
  const loginUrls = value.loginUrls;
  const description = value.description;
  const linkedLoginItemId = value.linkedLoginItemId;
  const tags = value.tags;
  const favorite = value.favorite;
  const sensitivity = value.sensitivity;
  const secretState = value.secretState ?? 'present';
  if (
    !['login', 'api_token', 'secure_note'].includes(String(kind)) ||
    typeof title !== 'string' ||
    !(username === null || typeof username === 'string') ||
    !(origin === null || typeof origin === 'string') ||
    !(loginUrl === undefined || loginUrl === null || typeof loginUrl === 'string') ||
    !(loginUrls === undefined || (Array.isArray(loginUrls) && loginUrls.every((entry) => typeof entry === 'string'))) ||
    !(
      description === undefined ||
      description === null ||
      (typeof description === 'string' && description.length <= ITEM_DESCRIPTION_MAX_LENGTH)
    ) ||
    !(
      linkedLoginItemId === undefined ||
      linkedLoginItemId === null ||
      (typeof linkedLoginItemId === 'string' && isUuid(linkedLoginItemId))
    ) ||
    !Array.isArray(tags) ||
    !tags.every((entry) => typeof entry === 'string') ||
    typeof favorite !== 'boolean' ||
    !['low', 'medium', 'high'].includes(String(sensitivity)) ||
    !['present', 'absent'].includes(String(secretState)) ||
    (secretState === 'absent' && kind !== 'login')
  ) {
    throw new Error('条目信息校验失败，已拒绝显示');
  }
  const legacyLoginUrl = typeof loginUrl === 'string' ? loginUrl : typeof origin === 'string' ? origin : null;
  const normalizedLoginUrls = loginUrls === undefined
    ? normalizeLoginUrls(legacyLoginUrl ? [legacyLoginUrl] : [])
    : normalizeLoginUrls(loginUrls as string[]);
  if (normalizedLoginUrls === null || (kind !== 'login' && normalizedLoginUrls.length > 0)) {
    throw new Error('条目网址校验失败，已拒绝打开');
  }
  const normalizedLoginUrl = normalizedLoginUrls[0] ?? null;
  return {
    id: encrypted.itemId,
    vaultId: encrypted.vaultId,
    kind: kind as DecryptedExtensionItem['kind'],
    title,
    username,
    origin: normalizedLoginUrl ? normalizeOrigin(normalizedLoginUrl) : null,
    loginUrl: normalizedLoginUrl,
    loginUrls: normalizedLoginUrls,
    description: kind === 'secure_note' ? null : (description ?? null),
    linkedLoginItemId: kind === 'api_token' ? (linkedLoginItemId ?? null) : null,
    tags,
    favorite,
    sensitivity: sensitivity as DecryptedExtensionItem['sensitivity'],
    secretState: secretState as DecryptedExtensionItem['secretState'],
    version: encrypted.version,
    secretVersion: encrypted.secretVersion,
    keyEpoch: encrypted.keyEpoch,
  };
}

function vaultKeyId(vaultId: string, epoch: number): string {
  return `${vaultId}:${epoch}`;
}

function isRecord(value: unknown): value is Record<string, JsonValue | undefined> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
