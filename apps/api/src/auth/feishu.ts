import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import type { FeishuCallbackResult, FeishuLoginAuthenticator } from './contracts.ts';
import { FeishuTransactionStore } from './feishu-transaction-store.ts';
import { readPrivateFile } from './secrets.ts';

export interface FeishuAuthenticatorOptions {
  appId: string;
  appSecretFile: string;
  redirectUri: string;
  tenantKey: string;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  requestTimeoutMs: number;
}

const TokenResponseSchema = z.object({
  code: z.number().optional(),
  message: z.string().optional(),
  access_token: z.string().min(1),
});

const UserInfoResponseSchema = z.object({
  code: z.number().optional(),
  message: z.string().optional(),
  data: z.object({
    tenant_key: z.string().min(1),
    user_id: z.string().min(1),
    name: z.string().optional().default(''),
    email: z.string().optional().default(''),
    enterprise_email: z.string().optional().default(''),
  }),
});

export class FeishuAuthenticator implements FeishuLoginAuthenticator {
  readonly method = 'feishu';
  private readonly appSecret: string;

  constructor(
    private readonly transactions: FeishuTransactionStore,
    private readonly options: FeishuAuthenticatorOptions,
  ) {
    const redirect = new URL(options.redirectUri);
    const authorize = new URL(options.authorizeUrl);
    const token = new URL(options.tokenUrl);
    const userInfo = new URL(options.userInfoUrl);
    if ([redirect, authorize, token, userInfo].some((url) => url.protocol !== 'https:')) {
      throw new Error('Feishu OAuth URLs must use HTTPS');
    }
    this.appSecret = readPrivateFile(options.appSecretFile, 'Feishu app secret file');
  }

  async beginLogin() {
    const state = randomBytes(32).toString('base64url');
    const browserBindingToken = randomBytes(32).toString('base64url');
    await this.transactions.create(state, { browserBindingHash: hashValue(browserBindingToken) });
    const url = new URL(this.options.authorizeUrl);
    url.searchParams.set('app_id', this.options.appId);
    url.searchParams.set('redirect_uri', this.options.redirectUri);
    url.searchParams.set('state', state);
    return { url, browserBindingToken };
  }

  async completeCallback(
    callbackUrl: URL,
    browserBindingToken: string | undefined,
  ): Promise<FeishuCallbackResult> {
    const state = callbackUrl.searchParams.get('state');
    const code = callbackUrl.searchParams.get('code');
    if (!state || !code) throw new Error('Feishu callback is missing code or state');
    const transaction = await this.transactions.consume(state);
    if (!transaction) throw new Error('Feishu transaction is missing, expired, or already consumed');
    if (!browserBindingToken || !safeEqualHash(browserBindingToken, transaction.browserBindingHash)) {
      throw new Error('Feishu browser transaction binding is invalid');
    }

    const tokenResponse = await fetch(this.options.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: this.options.appId,
        client_secret: this.appSecret,
        code,
        redirect_uri: this.options.redirectUri,
      }),
      signal: AbortSignal.timeout(this.options.requestTimeoutMs),
    });
    if (!tokenResponse.ok) throw new Error(`Feishu token request failed with HTTP ${tokenResponse.status}`);
    const token = TokenResponseSchema.parse(await tokenResponse.json());
    if (token.code !== undefined && token.code !== 0) throw new Error('Feishu token request was rejected');

    const userResponse = await fetch(this.options.userInfoUrl, {
      headers: { authorization: `Bearer ${token.access_token}` },
      signal: AbortSignal.timeout(this.options.requestTimeoutMs),
    });
    if (!userResponse.ok) throw new Error(`Feishu user request failed with HTTP ${userResponse.status}`);
    const user = UserInfoResponseSchema.parse(await userResponse.json());
    if (user.code !== undefined && user.code !== 0) throw new Error('Feishu user request was rejected');
    if (user.data.tenant_key !== this.options.tenantKey) throw new Error('Feishu tenant does not match');

    return {
      identity: {
        tenantKey: user.data.tenant_key,
        userId: user.data.user_id,
        displayName: user.data.name || user.data.user_id,
        email: user.data.enterprise_email || user.data.email,
      },
      startedAt: transaction.startedAt,
    };
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
