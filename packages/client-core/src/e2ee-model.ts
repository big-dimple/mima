import type {
  CipherBlob,
  ActivateAccountCryptoResetRequest,
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedItemMetadata,
  ItemKind,
  ItemMeta,
  ItemMetaPatch,
  Membership,
  Sensitivity,
  SessionUser,
  UserCryptoProfile,
  Vault,
  VaultCryptoState,
} from '@mima/contracts';
import type { AccountBundle, DeviceKeyBundle } from '@mima/e2ee';
import type { AccountCryptoResetRequest } from '@mima/contracts';
import {
  ITEM_DESCRIPTION_MAX_LENGTH,
  normalizeFolderPath,
  normalizeLoginUrl,
  normalizeLoginUrls,
  normalizeOrigin,
  normalizeVaultGroupName,
  normalizeVaultDirectories,
  type VaultDirectoryEntry,
} from '@mima/domain';

export type SecurityPhase =
  | 'unauthenticated'
  | 'authenticated-locked'
  | 'setup-required'
  | 'migration-required'
  | 'unlocking'
  | 'rotating-identity'
  | 'account-reset'
  | 'unlocked-online'
  | 'unlocked-offline'
  | 'rekey-blocked';

export type SecretState = 'present' | 'absent';

export interface ItemMetadataPayload {
  kind: ItemKind;
  secretState: SecretState;
  title: string;
  username: string | null;
  origin: string | null;
  loginUrl?: string | null;
  loginUrls?: string[];
  folderPath?: string | null;
  description?: string | null;
  linkedLoginItemId?: string | null;
  tags: string[];
  favorite: boolean;
  sensitivity: Sensitivity;
}

export type DecryptedItemMeta = ItemMeta & {
  secretState: SecretState;
  loginUrl?: string | null;
  loginUrls?: string[];
  folderPath?: string | null;
  description?: string | null;
  linkedLoginItemId?: string | null;
};
export type DecryptedItemMetaPatch = ItemMetaPatch & {
  loginUrl?: string | null;
  loginUrls?: string[];
  folderPath?: string | null;
  description?: string | null;
  linkedLoginItemId?: string | null;
};

export type CreateItemInput = Omit<ItemMetadataPayload, 'secretState'> & {
  secretValue: string | null;
};

export interface VaultHeaderPayload {
  name: string;
  directories: VaultDirectoryEntry[];
  vaultGroupName: string | null;
}

export interface DecryptedBootstrapProjection {
  user: SessionUser;
  vaults: Vault[];
  memberships: Membership[];
  items: DecryptedItemMeta[];
  cursor: number;
  vaultCrypto: Record<string, VaultCryptoState>;
  pendingVaultAccessIds?: Record<string, true>;
  vaultDirectories: Record<string, VaultDirectoryEntry[]>;
  encryptedItems: Record<string, EncryptedItemMetadata>;
}

export interface CachedAccountLocator {
  accountId: string;
  profile: UserCryptoProfile;
  device: CryptoDevice;
  deviceBundle: DeviceKeyBundle;
  encryptedBootstrap: CipherBlob | null;
  cachedAt: string;
}

export interface PendingAccountCryptoResetLocator {
  accountId: string;
  request: AccountCryptoResetRequest;
  recoveryCaseId?: string | null;
  activationRequest?: ActivateAccountCryptoResetRequest;
  accountBundle: AccountBundle;
  deviceBundle: DeviceKeyBundle;
  cachedAt: string;
}

export interface PreparedEncryptedSession {
  bootstrap: EncryptedBootstrapResponse;
  profile: UserCryptoProfile;
  device: CryptoDevice;
}

export function itemPayload(item: ItemMetadataPayload): ItemMetadataPayload {
  const loginUrls = normalizeItemLoginUrls(item);
  const primaryLoginUrl = loginUrls[0] ?? null;
  return {
    kind: item.kind,
    secretState: item.kind === 'login' ? item.secretState : 'present',
    title: item.title,
    username: item.username,
    origin: primaryLoginUrl === null ? null : normalizeOrigin(primaryLoginUrl),
    loginUrl: primaryLoginUrl,
    loginUrls,
    folderPath: normalizeFolderPath(item.folderPath),
    description: item.kind === 'secure_note' ? null : (item.description ?? null),
    linkedLoginItemId: item.kind === 'api_token' ? (item.linkedLoginItemId ?? null) : null,
    tags: [...item.tags],
    favorite: item.favorite,
    sensitivity: item.sensitivity,
  };
}

export function parseItemMetadataPayload(value: unknown): ItemMetadataPayload {
  if (!isRecord(value)) throw new Error('条目信息格式不正确');
  const kind = value.kind;
  const secretState = value.secretState ?? 'present';
  const sensitivity = value.sensitivity;
  if (kind !== 'login' && kind !== 'api_token' && kind !== 'secure_note') {
    throw new Error('条目类型不受支持');
  }
  if (sensitivity !== 'low' && sensitivity !== 'medium' && sensitivity !== 'high') {
    throw new Error('敏感级别不受支持');
  }
  if (secretState !== 'present' && secretState !== 'absent') {
    throw new Error('敏感内容状态不受支持');
  }
  if (kind !== 'login' && secretState === 'absent') {
    throw new Error('只有账号密码可以不保存密码');
  }
  if (typeof value.title !== 'string' || value.title.length === 0 || value.title.length > 200) {
    throw new Error('条目标题格式不正确');
  }
  if (!nullableString(value.username, 200) || !nullableString(value.origin, 300)) {
    throw new Error('条目信息格式不正确');
  }
  const loginUrl = value.loginUrl;
  const normalizedLoginUrl = typeof loginUrl === 'string' ? normalizeLoginUrl(loginUrl) : loginUrl;
  if (
    loginUrl !== undefined &&
    loginUrl !== null &&
    (typeof loginUrl !== 'string' || normalizedLoginUrl === null)
  ) {
    throw new Error('网址格式不正确');
  }
  const loginUrls = value.loginUrls;
  if (
    loginUrls !== undefined &&
    (!Array.isArray(loginUrls) || loginUrls.some((url) => typeof url !== 'string'))
  ) {
    throw new Error('网址格式不正确');
  }
  const normalizedLoginUrls = loginUrls === undefined
    ? normalizeLegacyLoginUrls(normalizedLoginUrl as string | null | undefined, value.origin as string | null)
    : normalizeLoginUrls(loginUrls as string[]);
  if (normalizedLoginUrls === null) throw new Error('网址格式不正确');
  if (kind !== 'login' && normalizedLoginUrls.length > 0) {
    throw new Error('只有账号密码可以保存网址');
  }
  const primaryLoginUrl = normalizedLoginUrls[0] ?? null;
  const folderPath = value.folderPath;
  const normalizedFolderPath = typeof folderPath === 'string' ? normalizeFolderPath(folderPath) : folderPath;
  if (
    folderPath !== undefined &&
    folderPath !== null &&
    (typeof folderPath !== 'string' || (folderPath.trim() !== '' && normalizedFolderPath === null))
  ) {
    throw new Error('条目目录格式不正确');
  }
  const description = value.description;
  if (description !== undefined && !nullableString(description, ITEM_DESCRIPTION_MAX_LENGTH)) {
    throw new Error('条目说明格式不正确');
  }
  const linkedLoginItemId = value.linkedLoginItemId;
  if (
    linkedLoginItemId !== undefined &&
    linkedLoginItemId !== null &&
    (typeof linkedLoginItemId !== 'string' || !isUuid(linkedLoginItemId))
  ) {
    throw new Error('关联账号密码格式不正确');
  }
  if (!Array.isArray(value.tags) || value.tags.length > 20 || value.tags.some((tag) => typeof tag !== 'string')) {
    throw new Error('条目标签格式不正确');
  }
  if (typeof value.favorite !== 'boolean') throw new Error('收藏状态格式不正确');
  return {
    kind,
    secretState,
    title: value.title,
    username: value.username as string | null,
    origin: primaryLoginUrl === null ? null : normalizeOrigin(primaryLoginUrl),
    loginUrl: primaryLoginUrl,
    loginUrls: normalizedLoginUrls,
    folderPath: (normalizedFolderPath as string | null | undefined) ?? null,
    description: kind === 'secure_note' ? null : ((description as string | null | undefined) ?? null),
    linkedLoginItemId: kind === 'api_token'
      ? ((linkedLoginItemId as string | null | undefined) ?? null)
      : null,
    tags: [...value.tags] as string[],
    favorite: value.favorite,
    sensitivity,
  };
}

function normalizeItemLoginUrls(item: ItemMetadataPayload): string[] {
  if (item.kind !== 'login') return [];
  const normalized = item.loginUrls === undefined
    ? normalizeLegacyLoginUrls(item.loginUrl, item.origin)
    : normalizeLoginUrls(item.loginUrls);
  if (normalized === null) throw new Error('网址格式不正确');
  return normalized;
}

function normalizeLegacyLoginUrls(loginUrl: string | null | undefined, origin: string | null): string[] | null {
  const legacyUrl = loginUrl ?? origin;
  return legacyUrl ? normalizeLoginUrls([legacyUrl]) : [];
}

export function parseVaultHeaderPayload(value: unknown): VaultHeaderPayload {
  if (!isRecord(value) || typeof value.name !== 'string' || value.name.length === 0 || value.name.length > 120) {
    throw new Error('密码库名称格式不正确');
  }
  const directoriesValue = value.directories ?? [];
  if (!Array.isArray(directoriesValue)) throw new Error('密码库目录清单格式不正确');
  const directories = normalizeVaultDirectories(directoriesValue.map((entry) => {
    if (!isRecord(entry) || typeof entry.path !== 'string' || !Array.isArray(entry.aliases)) {
      return { path: '', aliases: [] };
    }
    return {
      path: entry.path,
      aliases: entry.aliases.filter((alias): alias is string => typeof alias === 'string'),
    };
  }));
  if (!directories || directoriesValue.some((entry) =>
    !isRecord(entry) ||
    typeof entry.path !== 'string' ||
    !Array.isArray(entry.aliases) ||
    entry.aliases.some((alias) => typeof alias !== 'string')
  )) throw new Error('密码库目录清单格式不正确');
  const rawVaultGroupName = value.vaultGroupName;
  if (rawVaultGroupName !== undefined && rawVaultGroupName !== null && typeof rawVaultGroupName !== 'string') {
    throw new Error('密码库旧版设置格式不正确');
  }
  const vaultGroupName = normalizeVaultGroupName(rawVaultGroupName as string | null | undefined);
  if (typeof rawVaultGroupName === 'string' && rawVaultGroupName.trim() && vaultGroupName === null) {
    throw new Error('密码库旧版设置格式不正确');
  }
  return { name: value.name, directories, vaultGroupName };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nullableString(value: unknown, max: number): boolean {
  return value === null || (typeof value === 'string' && value.length <= max);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
