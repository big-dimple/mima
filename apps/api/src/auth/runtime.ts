import type { MasterKeyProvider } from '@mima/crypto';
import type { Db } from '../db/client.ts';
import { env } from '../env.ts';
import type {
  DirectoryProvider,
  DirectoryService,
  LoginAuthenticator,
  LoginProvider,
  Reauthenticator,
  ReauthProvider,
} from './contracts.ts';
import { DevCredentialStore } from './provider.ts';
import { AuthentikDirectoryService } from './directory.ts';
import { AuthentikOidcAuthenticator } from './oidc.ts';
import { OidcTransactionStore } from './transaction-store.ts';
import { FeishuTransactionStore } from './feishu-transaction-store.ts';
import { FeishuAuthenticator } from './feishu.ts';
import { LdapConnector, LdapDirectoryService, LdapPasswordAuthenticator } from './ldap.ts';
import { ldapOptionsFromEnv } from './ldap-config.ts';
import { DbSessionService, type SessionService } from '../services/session-service.ts';
import type { SyncBus } from '../services/bus.ts';

export interface AuthRuntime {
  loginProvider: LoginProvider;
  reauthProvider: ReauthProvider;
  directoryProvider: DirectoryProvider;
  login: LoginAuthenticator;
  reauth: Reauthenticator | null;
  directory: DirectoryService;
  sessions: SessionService;
}

export function createAuthRuntime(db: Db, keys: MasterKeyProvider, bus?: SyncBus): AuthRuntime {
  const sessionService = new DbSessionService(db, env.sessionTtlMs, bus);
  if (env.reauthProvider === 'dev' && env.loginProvider !== 'dev') {
    throw new Error('dev reauthentication is only allowed with dev login');
  }
  if (env.directoryProvider === 'dev' && env.loginProvider !== 'dev') {
    throw new Error('dev directory is only allowed with dev login');
  }

  const dev = new DevCredentialStore();
  let ldapConnector: LdapConnector | null = null;
  const ldap = () => {
    ldapConnector ??= new LdapConnector(ldapOptionsFromEnv());
    return ldapConnector;
  };

  const oidcNeeded = env.loginProvider === 'oidc' || env.reauthProvider === 'oidc';
  const issuer = oidcNeeded || env.directoryProvider === 'authentik'
    ? required(env.oidc.issuer, 'MIMA_OIDC_ISSUER')
    : undefined;
  const oidc = oidcNeeded
    ? new AuthentikOidcAuthenticator(new OidcTransactionStore(db, keys), {
        issuer: issuer!,
        clientId: required(env.oidc.clientId, 'MIMA_OIDC_CLIENT_ID'),
        clientSecretFile: required(
          env.oidc.clientSecretFile,
          'MIMA_OIDC_CLIENT_SECRET_FILE',
        ),
        redirectUri: required(env.oidc.redirectUri, 'MIMA_OIDC_REDIRECT_URI'),
      })
    : null;

  const directory: DirectoryService = env.directoryProvider === 'dev'
    ? dev
    : env.directoryProvider === 'authentik'
      ? new AuthentikDirectoryService(db, {
          baseUrl: required(env.directory.baseUrl, 'MIMA_DIRECTORY_BASE_URL'),
          issuer: new URL(issuer!).href,
          tokenFile: required(env.directory.tokenFile, 'MIMA_DIRECTORY_TOKEN_FILE'),
          serviceUsername: env.directory.serviceUsername,
          groupMapJson: env.directory.groupMapJson,
          syncIntervalMs: env.directory.syncIntervalMs,
          maxStaleMs: env.directory.maxStaleMs,
          requestTimeoutMs: env.directory.requestTimeoutMs,
        }, bus)
      : new LdapDirectoryService(db, ldap()!, bus);

  const ldapCredentials = env.loginProvider === 'ldap' || env.reauthProvider === 'ldap'
    ? new LdapPasswordAuthenticator(ldap()!, directory)
    : null;
  const login: LoginAuthenticator = env.loginProvider === 'dev'
    ? dev
    : env.loginProvider === 'ldap'
      ? ldapCredentials!
      : env.loginProvider === 'oidc'
        ? oidc!
        : new FeishuAuthenticator(new FeishuTransactionStore(db, keys), {
            appId: required(env.feishu.appId, 'MIMA_FEISHU_APP_ID'),
            appSecretFile: required(
              env.feishu.appSecretFile,
              'MIMA_FEISHU_APP_SECRET_FILE',
            ),
            redirectUri: required(env.feishu.redirectUri, 'MIMA_FEISHU_REDIRECT_URI'),
            tenantKey: required(env.feishu.tenantKey, 'MIMA_FEISHU_TENANT_KEY'),
            authorizeUrl: env.feishu.authorizeUrl,
            tokenUrl: env.feishu.tokenUrl,
            userInfoUrl: env.feishu.userInfoUrl,
            requestTimeoutMs: env.feishu.requestTimeoutMs,
          });
  const reauth: Reauthenticator | null = env.reauthProvider === 'none'
    ? null
    : env.reauthProvider === 'dev'
      ? dev
      : env.reauthProvider === 'ldap'
        ? ldapCredentials!
        : oidc!;

  return {
    loginProvider: env.loginProvider,
    reauthProvider: env.reauthProvider,
    directoryProvider: env.directoryProvider,
    login,
    reauth,
    directory,
    sessions: sessionService,
  };
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is required by the configured authentication providers`);
  return value;
}
