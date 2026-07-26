import type { SessionUser } from '@mima/contracts';

export type LoginProvider = 'dev' | 'feishu' | 'ldap' | 'oidc';
export type ReauthProvider = 'none' | 'dev' | 'ldap' | 'oidc';
export type DirectoryProvider = 'dev' | 'ldap' | 'authentik';
export type LoginMethod = 'password' | 'oidc' | 'feishu';

export interface AuthUserRecord {
  id: string;
  username: string;
  displayName: string;
  email: string;
  groups: string[];
  source: 'dev' | 'oidc' | 'ldap' | 'feishu';
  active: boolean;
}

export interface DirectorySnapshot {
  users: Array<Pick<AuthUserRecord, 'id' | 'username' | 'displayName'>>;
  groups: string[];
  syncedAt: Date | null;
}

export interface DirectoryService {
  readonly source: 'dev' | 'oidc' | 'ldap';
  listDirectory(): Promise<DirectorySnapshot>;
  findActiveUser(userId: string): Promise<AuthUserRecord | null>;
  findActiveOidcUser(issuer: string, subject: string): Promise<AuthUserRecord | null>;
  findActiveUsername(username: string): Promise<AuthUserRecord | null>;
  resolveExternalIdentity(
    provider: 'feishu',
    namespace: string,
    subject: string,
  ): Promise<AuthUserRecord | null>;
  start(): void;
  stop(): void;
}

export interface PasswordLoginAuthenticator {
  readonly method: 'password';
  authenticatePassword(username: string, password: string): Promise<AuthUserRecord | null>;
}

export interface PasswordReauthenticator {
  readonly method: 'password';
  reauthenticatePassword(username: string, password: string): Promise<boolean>;
}

export interface OidcIdentity {
  issuer: string;
  subject: string;
  preferredUsername: string;
  displayName: string;
  email: string;
  sid: string | null;
  authTime: Date;
}

export interface ReauthenticationBinding {
  sessionId: string;
  userId: string;
  authenticatedAt: Date;
}

export interface OidcCallbackResult {
  purpose: 'login' | 'reauth';
  identity: OidcIdentity;
  sessionId: string | null;
  userId: string | null;
  previousAuthenticatedAt: Date | null;
  startedAt: Date;
}

export interface OidcLogoutIdentity {
  issuer: string;
  subject: string | null;
  sid: string | null;
  jti: string;
  expiresAt: Date;
}

export interface OidcLoginAuthenticator {
  readonly method: 'oidc';
  beginLogin(): Promise<OidcAuthorizationStart>;
  completeCallback(callbackUrl: URL, browserBindingToken: string | undefined): Promise<OidcCallbackResult>;
  validateLogoutToken(token: string): Promise<OidcLogoutIdentity>;
}

export interface OidcReauthenticator {
  readonly method: 'oidc';
  beginReauthentication(binding: ReauthenticationBinding): Promise<OidcAuthorizationStart>;
}

export interface OidcAuthorizationStart {
  url: URL;
  browserBindingToken: string;
}

export interface FeishuAuthorizationStart {
  url: URL;
  browserBindingToken: string;
}

export interface FeishuIdentity {
  tenantKey: string;
  userId: string;
  displayName: string;
  email: string;
}

export interface FeishuCallbackResult {
  identity: FeishuIdentity;
  startedAt: Date;
}

export interface FeishuLoginAuthenticator {
  readonly method: 'feishu';
  beginLogin(): Promise<FeishuAuthorizationStart>;
  completeCallback(
    callbackUrl: URL,
    browserBindingToken: string | undefined,
  ): Promise<FeishuCallbackResult>;
}

export type LoginAuthenticator =
  | PasswordLoginAuthenticator
  | OidcLoginAuthenticator
  | FeishuLoginAuthenticator;
export type Reauthenticator = PasswordReauthenticator | OidcReauthenticator;

export function toSessionUser(user: AuthUserRecord, isLocalPlatformAdmin = false): SessionUser {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    groups: user.groups,
    isPlatformAdmin: isLocalPlatformAdmin,
    isLocalPlatformAdmin,
  };
}
