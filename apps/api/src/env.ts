import os from 'node:os';
import { join } from 'node:path';
import { lstatSync, readFileSync } from 'node:fs';

function str(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.length > 0 ? v : fallback;
}

function optional(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value || undefined;
}

function bool(name: string, fallback: boolean): boolean {
  const value = optional(name);
  if (!value) return fallback;
  if (/^(1|true|yes|on)$/i.test(value)) return true;
  if (/^(0|false|no|off)$/i.test(value)) return false;
  throw new Error(`${name} must be true or false`);
}

function positiveInt(name: string, fallback: number): number {
  const value = Number(optional(name) ?? fallback);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function enumValue<const T extends readonly string[]>(
  name: string,
  values: T,
  fallback: T[number],
): T[number] {
  const value = optional(name) ?? fallback;
  if (!values.includes(value)) throw new Error(`${name} must be one of ${values.join(', ')}`);
  return value as T[number];
}

function valueOrFile(name: string, fallback: string): string {
  const file = optional(`${name}_FILE`);
  if (!file) return str(name, fallback);
  const metadata = lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error(`${name}_FILE must be a private regular file`);
  }
  const value = readFileSync(file, 'utf8').trim();
  if (!value) throw new Error(`${name}_FILE points to an empty file`);
  return value;
}

const authMode = optional('AUTH_MODE') ?? 'dev';
if (authMode !== 'dev' && authMode !== 'oidc') {
  throw new Error('AUTH_MODE must be dev or oidc');
}
const legacyLoginProvider = authMode === 'oidc' ? 'oidc' : 'dev';
const loginProvider = enumValue(
  'MIMA_LOGIN_PROVIDER',
  ['dev', 'feishu', 'ldap', 'oidc'] as const,
  legacyLoginProvider,
);
const reauthProvider = enumValue(
  'MIMA_REAUTH_PROVIDER',
  ['none', 'dev', 'ldap', 'oidc'] as const,
  loginProvider === 'dev' ? 'dev' : 'none',
);
const directoryProvider = enumValue(
  'MIMA_DIRECTORY_PROVIDER',
  ['dev', 'ldap', 'authentik'] as const,
  authMode === 'oidc' ? 'authentik' : loginProvider === 'dev' ? 'dev' : 'ldap',
);
const demoMode = bool('MIMA_DEMO_MODE', false);
const host = str('MIMA_API_HOST', '127.0.0.1');
const webOrigins = str('MIMA_WEB_ORIGINS', 'http://localhost:4173,http://127.0.0.1:4173')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const publicBaseUrl = str('MIMA_PUBLIC_BASE_URL', 'http://localhost:4173').replace(/\/$/, '');

function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

if ([loginProvider, reauthProvider, directoryProvider].includes('dev')) {
  if (!demoMode) throw new Error('dev authentication requires MIMA_DEMO_MODE=true');
  const origins = [...webOrigins, publicBaseUrl].map((value) => new URL(value));
  if (!isLoopbackHostname(host) || origins.some((origin) => !isLoopbackHostname(origin.hostname))) {
    throw new Error('dev authentication is restricted to loopback hosts');
  }
}

const defaultKeyRoot = join(os.homedir(), '.local', 'share', 'mima');

export const env = {
  deploymentId: str('MIMA_DEPLOYMENT_ID', 'primary'),
  port: Number(str('MIMA_API_PORT', '4174')),
  host,
  databaseUrl: valueOrFile(
    'MIMA_DATABASE_URL',
    'postgres://mima:mima_dev_pw@127.0.0.1:55432/mima',
  ),
  authMode,
  demoMode,
  loginProvider,
  reauthProvider,
  directoryProvider,
  runtimeKeyDir: str('MIMA_RUNTIME_KEY_DIR', join(defaultKeyRoot, 'runtime-keys')),
  auditKeyDir: str('MIMA_AUDIT_KEY_DIR', join(defaultKeyRoot, 'audit-keys')),
  e2eeRequired: bool('MIMA_E2EE_REQUIRED', true),
  /** 允许携带 Cookie 的浏览器 Origin（Web 前端）。 */
  webOrigins,
  /** 允许访问 API 的浏览器扩展 ID（manifest key 固定，见 apps/extension/public/manifest.json）。 */
  extensionIds: str('MIMA_EXTENSION_IDS', 'gkhbkfdgghiaoohpldbjkpmopaojjhhp')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0),
  publicBaseUrl,
  sessionCookieSecure: bool('MIMA_SESSION_COOKIE_SECURE', loginProvider !== 'dev'),
  trustProxy: bool('MIMA_TRUST_PROXY', false),
  sessionTtlMs: positiveInt('MIMA_SESSION_TTL_MS', 12 * 60 * 60 * 1000),
  oidc: {
    issuer: optional('MIMA_OIDC_ISSUER'),
    clientId: optional('MIMA_OIDC_CLIENT_ID'),
    clientSecretFile: optional('MIMA_OIDC_CLIENT_SECRET_FILE'),
    redirectUri: optional('MIMA_OIDC_REDIRECT_URI'),
  },
  feishu: {
    appId: optional('MIMA_FEISHU_APP_ID'),
    appSecretFile: optional('MIMA_FEISHU_APP_SECRET_FILE'),
    redirectUri: optional('MIMA_FEISHU_REDIRECT_URI'),
    tenantKey: optional('MIMA_FEISHU_TENANT_KEY'),
    authorizeUrl: str(
      'MIMA_FEISHU_AUTHORIZE_URL',
      'https://accounts.feishu.cn/open-apis/authen/v1/authorize',
    ),
    tokenUrl: str(
      'MIMA_FEISHU_TOKEN_URL',
      'https://open.feishu.cn/open-apis/authen/v2/oauth/token',
    ),
    userInfoUrl: str(
      'MIMA_FEISHU_USER_INFO_URL',
      'https://open.feishu.cn/open-apis/authen/v1/user_info',
    ),
    requestTimeoutMs: positiveInt('MIMA_FEISHU_REQUEST_TIMEOUT_MS', 10_000),
  },
  ldap: {
    directoryId: str('MIMA_LDAP_DIRECTORY_ID', 'primary-ad'),
    urls: str('MIMA_LDAP_URLS', '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
    bindDn: optional('MIMA_LDAP_BIND_DN'),
    bindPasswordFile: optional('MIMA_LDAP_BIND_PASSWORD_FILE'),
    baseDn: optional('MIMA_LDAP_BASE_DN'),
    userFilter: str(
      'MIMA_LDAP_USER_FILTER',
      '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    ),
    loginAttribute: str('MIMA_LDAP_LOGIN_ATTRIBUTE', 'sAMAccountName'),
    stableIdAttribute: str('MIMA_LDAP_STABLE_ID_ATTRIBUTE', 'objectGUID'),
    displayNameAttribute: str('MIMA_LDAP_DISPLAY_NAME_ATTRIBUTE', 'displayName'),
    emailAttribute: str('MIMA_LDAP_EMAIL_ATTRIBUTE', 'mail'),
    caFile: optional('MIMA_LDAP_CA_FILE'),
    connectTimeoutMs: positiveInt('MIMA_LDAP_CONNECT_TIMEOUT_MS', 5_000),
    operationTimeoutMs: positiveInt('MIMA_LDAP_OPERATION_TIMEOUT_MS', 15_000),
    syncIntervalMs: positiveInt('MIMA_LDAP_SYNC_INTERVAL_MS', 5 * 60 * 1000),
    maxStaleMs: positiveInt('MIMA_LDAP_MAX_STALE_MS', 30 * 60 * 1000),
    pageSize: positiveInt('MIMA_LDAP_PAGE_SIZE', 500),
    maxDropPercent: positiveInt('MIMA_LDAP_MAX_DROP_PERCENT', 50),
  },
  directory: {
    baseUrl: optional('MIMA_DIRECTORY_BASE_URL'),
    tokenFile: optional('MIMA_DIRECTORY_TOKEN_FILE'),
    serviceUsername: str('MIMA_DIRECTORY_SERVICE_USERNAME', 'mima-directory-sync'),
    groupMapJson: str('MIMA_DIRECTORY_GROUP_MAP', '{}'),
    syncIntervalMs: positiveInt('MIMA_DIRECTORY_SYNC_INTERVAL_MS', 5 * 60 * 1000),
    maxStaleMs: positiveInt('MIMA_DIRECTORY_MAX_STALE_MS', 30 * 60 * 1000),
    requestTimeoutMs: positiveInt('MIMA_DIRECTORY_REQUEST_TIMEOUT_MS', 15_000),
  },
  logLevel: str('MIMA_LOG_LEVEL', 'info'),
};
