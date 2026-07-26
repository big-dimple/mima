import type {
  AuthUserRecord,
  DirectoryService,
  PasswordLoginAuthenticator,
  PasswordReauthenticator,
} from './contracts.ts';

export type { AuthUserRecord } from './contracts.ts';
export { toSessionUser } from './contracts.ts';

/** 固定虚构测试身份，全部使用 example.test 假数据。 */
export const DEV_USERS: AuthUserRecord[] = [
  {
    id: 'u-alice',
    username: 'alice',
    displayName: 'Alice Zhang（平台管理员）',
    email: 'alice@example.test',
    groups: ['group:demo/operations'],
    source: 'dev',
    active: true,
  },
  {
    id: 'u-bob',
    username: 'bob',
    displayName: 'Bob Li（Ops）',
    email: 'bob@example.test',
    groups: ['group:default/ops'],
    source: 'dev',
    active: true,
  },
  {
    id: 'u-carol',
    username: 'carol',
    displayName: 'Carol Wu（QA）',
    email: 'carol@example.test',
    groups: ['group:default/qa'],
    source: 'dev',
    active: true,
  },
  {
    id: 'u-dave',
    username: 'dave',
    displayName: 'Dave Chen（RD）',
    email: 'dave@example.test',
    groups: ['group:default/rd'],
    source: 'dev',
    active: true,
  },
  {
    id: 'u-erin',
    username: 'erin',
    displayName: 'Erin Guo（QA / 审计）',
    email: 'erin@example.test',
    groups: ['group:default/qa'],
    source: 'dev',
    active: true,
  },
];

/** dev 模式固定开发密码，仅用于本地测试。 */
export const DEV_PASSWORD = 'dev';

export class DevCredentialStore
  implements PasswordLoginAuthenticator, PasswordReauthenticator, DirectoryService
{
  readonly method = 'password';
  readonly source = 'dev';

  async authenticatePassword(username: string, password: string): Promise<AuthUserRecord | null> {
    const user = DEV_USERS.find((u) => u.username === username);
    if (!user || password !== DEV_PASSWORD) return null;
    return user;
  }

  async reauthenticatePassword(username: string, password: string): Promise<boolean> {
    return (await this.authenticatePassword(username, password)) !== null;
  }

  async listDirectory() {
    return {
      users: DEV_USERS.map(({ id, username, displayName }) => ({ id, username, displayName })),
      groups: [
        'group:demo/operations',
        'group:default/ops',
        'group:default/qa',
        'group:default/rd',
      ],
      syncedAt: null,
    };
  }

  async findActiveUser(userId: string): Promise<AuthUserRecord | null> {
    return DEV_USERS.find((user) => user.id === userId) ?? null;
  }

  async findActiveOidcUser(): Promise<null> {
    return null;
  }

  async findActiveUsername(username: string): Promise<AuthUserRecord | null> {
    return DEV_USERS.find((user) => user.username === username) ?? null;
  }

  async resolveExternalIdentity(
    _provider: 'feishu',
    _namespace: string,
    subject: string,
  ): Promise<AuthUserRecord | null> {
    return this.findActiveUsername(subject);
  }

  start(): void {}

  stop(): void {}
}
