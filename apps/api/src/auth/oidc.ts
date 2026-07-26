import { createHash, timingSafeEqual } from 'node:crypto';
import * as oidc from 'openid-client';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type {
  OidcCallbackResult,
  OidcAuthorizationStart,
  OidcLoginAuthenticator,
  OidcLogoutIdentity,
  OidcReauthenticator,
  ReauthenticationBinding,
} from './contracts.ts';
import { OidcTransactionStore } from './transaction-store.ts';
import { readPrivateFile } from './secrets.ts';

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

export interface OidcAuthenticatorOptions {
  issuer: string;
  clientId: string;
  clientSecretFile: string;
  redirectUri: string;
}

interface LogoutClaims extends JWTPayload {
  events?: Record<string, unknown>;
  sid?: string;
}

export class AuthentikOidcAuthenticator
  implements OidcLoginAuthenticator, OidcReauthenticator
{
  readonly method = 'oidc';
  private readonly issuer: string;
  private readonly clientSecret: string;
  private configurationPromise: Promise<oidc.Configuration> | null = null;
  private jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

  constructor(
    private readonly transactions: OidcTransactionStore,
    private readonly options: OidcAuthenticatorOptions,
  ) {
    this.issuer = new URL(options.issuer).href;
    const redirect = new URL(options.redirectUri);
    if (new URL(this.issuer).protocol !== 'https:' || redirect.protocol !== 'https:') {
      throw new Error('OIDC issuer and redirect URI must use HTTPS');
    }
    this.clientSecret = readPrivateFile(options.clientSecretFile, 'OIDC client secret file');
  }

  async beginLogin(): Promise<OidcAuthorizationStart> {
    return this.begin('login', null);
  }

  async beginReauthentication(binding: ReauthenticationBinding): Promise<OidcAuthorizationStart> {
    return this.begin('reauth', binding);
  }

  async completeCallback(
    callbackUrl: URL,
    browserBindingToken: string | undefined,
  ): Promise<OidcCallbackResult> {
    const state = callbackUrl.searchParams.get('state');
    if (!state) throw new Error('OIDC callback is missing state');
    const transaction = await this.transactions.consume(state);
    if (!transaction) throw new Error('OIDC transaction is missing, expired, or already consumed');
    if (!browserBindingToken || !safeEqualHash(browserBindingToken, transaction.browserBindingHash)) {
      throw new Error('OIDC browser transaction binding is invalid');
    }
    const config = await this.configuration();
    const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: transaction.codeVerifier,
      expectedState: state,
      expectedNonce: transaction.nonce,
      idTokenExpected: true,
      maxAge: transaction.purpose === 'reauth' ? 0 : undefined,
    });
    const claims = tokens.claims();
    if (!claims || typeof claims.sub !== 'string') throw new Error('OIDC ID token is missing subject');
    if (typeof claims.preferred_username !== 'string' || !claims.preferred_username.trim()) {
      throw new Error('OIDC ID token is missing preferred_username');
    }
    if (transaction.purpose === 'reauth' && typeof claims.auth_time !== 'number') {
      throw new Error('OIDC reauthentication is missing auth_time');
    }
    const authTime = typeof claims.auth_time === 'number' ? new Date(claims.auth_time * 1000) : new Date();
    if (transaction.purpose === 'reauth') {
      assertFreshReauthentication(
        authTime,
        transaction.startedAt,
        transaction.previousAuthenticatedAt ? new Date(transaction.previousAuthenticatedAt) : null,
      );
    }
    return {
      purpose: transaction.purpose,
      identity: {
        issuer: this.issuer,
        subject: claims.sub,
        preferredUsername: claims.preferred_username,
        displayName: typeof claims.name === 'string' && claims.name.trim()
          ? claims.name
          : claims.preferred_username,
        email: typeof claims.email === 'string' ? claims.email : '',
        sid: typeof claims.sid === 'string' ? claims.sid : null,
        authTime,
      },
      sessionId: transaction.sessionId,
      userId: transaction.userId,
      previousAuthenticatedAt: transaction.previousAuthenticatedAt
        ? new Date(transaction.previousAuthenticatedAt)
        : null,
      startedAt: transaction.startedAt,
    };
  }

  async validateLogoutToken(token: string): Promise<OidcLogoutIdentity> {
    const config = await this.configuration();
    const metadata = config.serverMetadata();
    if (!metadata.jwks_uri) throw new Error('OIDC discovery metadata is missing jwks_uri');
    this.jwks ??= createRemoteJWKSet(new URL(metadata.jwks_uri));
    const supported = (metadata.id_token_signing_alg_values_supported ?? [])
      .filter((algorithm) => !algorithm.startsWith('HS'));
    const { payload } = await jwtVerify<LogoutClaims>(token, this.jwks, {
      issuer: this.issuer,
      audience: this.options.clientId,
      algorithms: supported.length > 0 ? supported : ['RS256'],
      requiredClaims: ['iat', 'jti', 'events'],
      maxTokenAge: '5 minutes',
    });
    if (payload.nonce !== undefined) throw new Error('logout token must not contain nonce');
    if (!payload.events || !(LOGOUT_EVENT in payload.events)) {
      throw new Error('logout token is missing the back-channel logout event');
    }
    const subject = typeof payload.sub === 'string' ? payload.sub : null;
    const sid = typeof payload.sid === 'string' ? payload.sid : null;
    if (!subject && !sid) throw new Error('logout token must contain sub or sid');
    return {
      issuer: this.issuer,
      subject,
      sid,
      jti: payload.jti!,
      expiresAt: typeof payload.exp === 'number'
        ? new Date(payload.exp * 1000)
        : new Date(Date.now() + 5 * 60 * 1000),
    };
  }

  private async begin(
    purpose: 'login' | 'reauth',
    binding: ReauthenticationBinding | null,
  ): Promise<OidcAuthorizationStart> {
    const config = await this.configuration();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const browserBindingToken = oidc.randomState();
    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
    await this.transactions.create(state, {
      purpose,
      codeVerifier,
      nonce,
      sessionId: binding?.sessionId ?? null,
      userId: binding?.userId ?? null,
      previousAuthenticatedAt: binding?.authenticatedAt.toISOString() ?? null,
      browserBindingHash: hashValue(browserBindingToken),
    });
    const parameters: Record<string, string> = {
      redirect_uri: this.options.redirectUri,
      response_type: 'code',
      response_mode: 'form_post',
      scope: 'openid profile email',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      nonce,
    };
    if (purpose === 'reauth') {
      parameters.prompt = 'login';
      parameters.max_age = '0';
    }
    return {
      url: oidc.buildAuthorizationUrl(config, parameters),
      browserBindingToken,
    };
  }

  private configuration(): Promise<oidc.Configuration> {
    if (!this.configurationPromise) {
      const pending = oidc.discovery(
        new URL(this.issuer),
        this.options.clientId,
        this.clientSecret,
        undefined,
        { timeout: 10 },
      );
      this.configurationPromise = pending;
      void pending.catch(() => {
        if (this.configurationPromise === pending) this.configurationPromise = null;
      });
    }
    return this.configurationPromise;
  }
}

function hashValue(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function safeEqualHash(value: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashValue(value), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function assertFreshReauthentication(
  authTime: Date,
  startedAt: Date,
  previousAuthenticatedAt: Date | null,
): void {
  if (authTime.getTime() < startedAt.getTime() - 5_000) {
    throw new Error('OIDC reauthentication did not produce a fresh auth_time');
  }
  if (
    previousAuthenticatedAt &&
    Math.floor(startedAt.getTime() / 1000) > Math.floor(previousAuthenticatedAt.getTime() / 1000) &&
    authTime.getTime() <= previousAuthenticatedAt.getTime()
  ) {
    throw new Error('OIDC reauthentication reused the previous authentication event');
  }
}
