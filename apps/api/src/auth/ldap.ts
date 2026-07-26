import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { and, eq, sql } from 'drizzle-orm';
import { Client, InvalidCredentialsError, escapeFilter, type Entry } from 'ldapts';
import type {
  AuthUserRecord,
  DirectoryService,
  DirectorySnapshot,
  PasswordLoginAuthenticator,
  PasswordReauthenticator,
} from './contracts.ts';
import type { Db } from '../db/client.ts';
import {
  directorySyncState,
  customGroups,
  extensionPairingCodes,
  extensionSessions,
  sessions,
  userIdentities,
  users,
} from '../db/schema.ts';
import { DirectoryUnavailableError, findActiveUsername, resolveExternalIdentity } from './directory.ts';
import { readPrivateFile } from './secrets.ts';
import { reconcileDirectoryMembershipChange } from '../services/vault-envelope-tasks.ts';
import type { SyncBus, SyncEventRow } from '../services/bus.ts';

export interface LdapOptions {
  directoryId: string;
  urls: string[];
  bindDn: string;
  bindPasswordFile: string;
  baseDn: string;
  userFilter: string;
  loginAttribute: string;
  stableIdAttribute: string;
  displayNameAttribute: string;
  emailAttribute: string;
  caFile?: string;
  connectTimeoutMs: number;
  operationTimeoutMs: number;
  syncIntervalMs: number;
  maxStaleMs: number;
  pageSize: number;
  maxDropPercent: number;
}

interface LdapUser {
  dn: string;
  username: string;
  displayName: string;
  email: string;
  stableId: string;
}

export interface LdapSyncReport {
  remoteUsers: number;
  currentUsers: number;
  newUsers: number;
  matchedUsers: number;
  missingUsers: number;
  conflicts: string[];
  applied: boolean;
}

export class LdapConnector {
  private readonly bindPassword: string;
  private readonly ca: Buffer[] | undefined;

  constructor(readonly options: LdapOptions) {
    if (options.urls.length === 0) throw new Error('MIMA_LDAP_URLS is required');
    for (const url of options.urls) {
      const parsed = new URL(url);
      if (parsed.protocol !== 'ldaps:') throw new Error('LDAP URLs must use ldaps://');
    }
    this.bindPassword = readPrivateFile(options.bindPasswordFile, 'LDAP bind password file');
    this.ca = options.caFile ? [readFileSync(options.caFile)] : undefined;
  }

  async listUsers(): Promise<LdapUser[]> {
    return this.withServiceClient(async (client) => {
      const { searchEntries } = await client.search(this.options.baseDn, {
        scope: 'sub',
        filter: this.options.userFilter,
        attributes: [
          this.options.loginAttribute,
          this.options.stableIdAttribute,
          this.options.displayNameAttribute,
          this.options.emailAttribute,
        ],
        explicitBufferAttributes: [this.options.stableIdAttribute],
        paged: { pageSize: this.options.pageSize },
        timeLimit: Math.max(1, Math.ceil(this.options.operationTimeoutMs / 1000)),
      });
      return searchEntries.map((entry) => this.toUser(entry)).filter((entry): entry is LdapUser => entry !== null);
    });
  }

  async verifyPassword(username: string, password: string): Promise<boolean> {
    if (!username.trim() || !password) return false;
    let lastError: unknown;
    for (const url of this.options.urls) {
      const service = this.client(url);
      try {
        await service.bind(this.options.bindDn, this.bindPassword);
        const { searchEntries } = await service.search(this.options.baseDn, {
          scope: 'sub',
          filter: `(&${this.options.userFilter}(${this.options.loginAttribute}=${escapeFilter`${username.trim()}`}))`,
          attributes: [this.options.loginAttribute],
          sizeLimit: 2,
          timeLimit: Math.max(1, Math.ceil(this.options.operationTimeoutMs / 1000)),
        });
        if (searchEntries.length !== 1) return false;
        const login = stringValue(searchEntries[0]!, this.options.loginAttribute);
        if (!login || login.localeCompare(username.trim(), undefined, { sensitivity: 'accent' }) !== 0) return false;
        const userClient = this.client(url);
        try {
          await userClient.bind(searchEntries[0]!.dn, password);
          return true;
        } catch (error) {
          if (error instanceof InvalidCredentialsError) return false;
          throw error;
        } finally {
          await userClient.unbind().catch(() => undefined);
        }
      } catch (error) {
        if (error instanceof InvalidCredentialsError) return false;
        lastError = error;
      } finally {
        await service.unbind().catch(() => undefined);
      }
    }
    throw lastError instanceof Error ? lastError : new Error('LDAP servers are unavailable');
  }

  async probe(): Promise<{ url: string; usersVisible: number }> {
    return this.withServiceClient(async (client, url) => {
      const { searchEntries } = await client.search(this.options.baseDn, {
        scope: 'sub',
        filter: this.options.userFilter,
        attributes: ['1.1'],
        sizeLimit: 2,
        timeLimit: Math.max(1, Math.ceil(this.options.operationTimeoutMs / 1000)),
      });
      return { url, usersVisible: searchEntries.length };
    });
  }

  private client(url: string): Client {
    return new Client({
      url,
      connectTimeout: this.options.connectTimeoutMs,
      timeout: this.options.operationTimeoutMs,
      tlsOptions: { ca: this.ca, rejectUnauthorized: true, servername: new URL(url).hostname },
    });
  }

  private async withServiceClient<T>(run: (client: Client, url: string) => Promise<T>): Promise<T> {
    let lastError: unknown;
    for (const url of this.options.urls) {
      const client = this.client(url);
      try {
        await client.bind(this.options.bindDn, this.bindPassword);
        return await run(client, url);
      } catch (error) {
        lastError = error;
      } finally {
        await client.unbind().catch(() => undefined);
      }
    }
    throw lastError instanceof Error ? lastError : new Error('LDAP servers are unavailable');
  }

  private toUser(entry: Entry): LdapUser | null {
    const username = stringValue(entry, this.options.loginAttribute)?.trim();
    const stableValue = attributeValue(entry, this.options.stableIdAttribute);
    if (!username || !stableValue) return null;
    const stableId = Buffer.isBuffer(stableValue)
      ? adGuidToString(stableValue)
      : String(stableValue).trim().toLowerCase();
    if (!stableId) return null;
    return {
      dn: entry.dn,
      username,
      stableId,
      displayName: stringValue(entry, this.options.displayNameAttribute)?.trim() || username,
      email: stringValue(entry, this.options.emailAttribute)?.trim() || '',
    };
  }
}

export class LdapPasswordAuthenticator
  implements PasswordLoginAuthenticator, PasswordReauthenticator
{
  readonly method = 'password';

  constructor(
    private readonly connector: LdapConnector,
    private readonly directory: DirectoryService,
  ) {}

  async authenticatePassword(username: string, password: string): Promise<AuthUserRecord | null> {
    const record = await this.directory.findActiveUsername(username);
    if (!record) return null;
    return (await this.connector.verifyPassword(record.username, password)) ? record : null;
  }

  async reauthenticatePassword(username: string, password: string): Promise<boolean> {
    return (await this.authenticatePassword(username, password)) !== null;
  }
}

export class LdapDirectoryService implements DirectoryService {
  readonly source = 'ldap';
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<LdapSyncReport> | null = null;

  constructor(
    private readonly db: Db,
    private readonly connector: LdapConnector,
    private readonly bus?: SyncBus,
  ) {}

  start(): void {
    if (this.timer) return;
    void this.syncInitializedDirectory().catch(() => undefined);
    this.timer = setInterval(
      () => void this.syncInitializedDirectory().catch(() => undefined),
      this.connector.options.syncIntervalMs,
    );
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async listDirectory(): Promise<DirectorySnapshot> {
    const syncedAt = await this.requireFreshDirectory();
    const rows = await this.db
      .select()
      .from(users)
      .where(and(
        eq(users.directoryProvider, this.connector.options.directoryId),
        eq(users.active, true),
      ));
    return {
      users: rows
        .map(({ id, username, displayName }) => ({ id, username, displayName }))
        .sort((left, right) => left.displayName.localeCompare(right.displayName, 'zh-Hans-CN')),
      groups: [],
      syncedAt,
    };
  }

  async findActiveUser(userId: string): Promise<AuthUserRecord | null> {
    await this.requireFreshDirectory();
    const row = (
      await this.db.select().from(users).where(and(eq(users.id, userId), eq(users.active, true))).limit(1)
    )[0];
    return row ? recordFromRow(row) : null;
  }

  async findActiveOidcUser(issuer: string, subject: string): Promise<AuthUserRecord | null> {
    await this.requireFreshDirectory();
    const row = (
      await this.db
        .select({ user: users })
        .from(userIdentities)
        .innerJoin(users, eq(users.id, userIdentities.userId))
        .where(and(
          eq(userIdentities.provider, 'oidc'),
          eq(userIdentities.issuer, issuer),
          eq(userIdentities.subject, subject),
          eq(users.active, true),
        ))
        .limit(1)
    )[0];
    return row ? recordFromRow(row.user) : null;
  }

  async findActiveUsername(username: string): Promise<AuthUserRecord | null> {
    await this.requireFreshDirectory();
    return findActiveUsername(this.db, username);
  }

  async resolveExternalIdentity(
    provider: 'feishu',
    namespace: string,
    subject: string,
  ): Promise<AuthUserRecord | null> {
    await this.requireFreshDirectory();
    return resolveExternalIdentity(this.db, provider, namespace, subject);
  }

  async sync(force: boolean, dryRun: boolean): Promise<LdapSyncReport> {
    if (this.running && !dryRun) return this.running;
    const pending = this.performSync(force, dryRun);
    if (!dryRun) this.running = pending;
    try {
      return await pending;
    } finally {
      if (this.running === pending) this.running = null;
    }
  }

  private async performSync(force: boolean, dryRun: boolean): Promise<LdapSyncReport> {
    const now = new Date();
    const provider = this.connector.options.directoryId;
    const state = (
      await this.db.select().from(directorySyncState).where(eq(directorySyncState.provider, provider)).limit(1)
    )[0];
    if (!force && state?.lastSuccessAt && now.getTime() - state.lastSuccessAt.getTime() < this.connector.options.syncIntervalMs) {
      return {
        remoteUsers: state.userCount,
        currentUsers: state.userCount,
        newUsers: 0,
        matchedUsers: state.userCount,
        missingUsers: 0,
        conflicts: [],
        applied: false,
      };
    }

    try {
      const remote = await this.connector.listUsers();
      if (remote.length === 0) throw new Error('LDAP sync returned zero active users');
      if (
        state?.userCount &&
        remote.length * 100 < state.userCount * (100 - this.connector.options.maxDropPercent)
      ) {
        throw new Error('LDAP sync refused an unsafe mass deactivation');
      }
      const existingRows = await this.db.select().from(users);
      const byUsername = new Map(existingRows.map((row) => [row.username.toLocaleLowerCase(), row]));
      const identities = await this.db
        .select()
        .from(userIdentities)
        .where(and(eq(userIdentities.provider, 'ldap'), eq(userIdentities.issuer, provider)));
      const byStableId = new Map(identities.map((identity) => [identity.subject, identity.userId]));
      const seen = new Set<string>();
      const conflicts: string[] = [];
      const resolved = remote.map((entry) => {
        const identityUserId = byStableId.get(entry.stableId);
        const usernameUser = byUsername.get(entry.username.toLocaleLowerCase());
        if (identityUserId && usernameUser && identityUserId !== usernameUser.id) {
          conflicts.push(entry.username);
          return null;
        }
        const userId = identityUserId ?? usernameUser?.id ?? ldapUserId(provider, entry.stableId);
        seen.add(userId);
        return { entry, userId, existing: existingRows.find((row) => row.id === userId) };
      });
      const managed = existingRows.filter((row) => row.directoryProvider === provider);
      const report: LdapSyncReport = {
        remoteUsers: remote.length,
        currentUsers: managed.length,
        newUsers: resolved.filter((item) => item && !item.existing).length,
        matchedUsers: resolved.filter(Boolean).length,
        missingUsers: managed.filter((row) => !seen.has(row.id)).length,
        conflicts,
        applied: false,
      };
      if (conflicts.length > 0) throw new Error(`LDAP identity conflicts: ${conflicts.join(', ')}`);
      if (dryRun) return report;

      const securityChanged = new Set<string>();
      const events = await this.db.transaction(async (tx) => {
        const pendingEvents: SyncEventRow[] = [];
        await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${'mima:ldap-sync:' + provider}))`);
        for (const item of resolved) {
          if (!item) continue;
          const { entry, userId, existing } = item;
          if (existing && (!existing.active || existing.groups.length > 0)) securityChanged.add(userId);
          await tx
            .insert(users)
            .values({
              id: userId,
              username: entry.username,
              displayName: entry.displayName,
              email: entry.email,
              groups: [],
              source: 'ldap',
              active: true,
              directoryProvider: provider,
              directoryDn: entry.dn,
              directoryStableId: entry.stableId,
              directorySyncedAt: now,
              updatedAt: now,
            })
            .onConflictDoUpdate({
              target: users.id,
              set: {
                username: entry.username,
                displayName: entry.displayName,
                email: entry.email,
                groups: [],
                source: 'ldap',
                active: true,
                directoryProvider: provider,
                directoryDn: entry.dn,
                directoryStableId: entry.stableId,
                directorySyncedAt: now,
                updatedAt: now,
              },
            });
          await tx
            .insert(userIdentities)
            .values({ provider: 'ldap', issuer: provider, subject: entry.stableId, userId, updatedAt: now })
            .onConflictDoUpdate({
              target: [userIdentities.provider, userIdentities.issuer, userIdentities.subject],
              set: { userId, updatedAt: now },
            });
          const change = await reconcileDirectoryMembershipChange(
            tx,
            userId,
            existing?.groups ?? [],
            [],
            now,
            true,
            existing?.active ?? false,
          );
          pendingEvents.push(...change.events);
        }
        for (const row of managed) {
          if (seen.has(row.id)) continue;
          securityChanged.add(row.id);
          await tx
            .update(users)
            .set({ active: false, groups: [], directorySyncedAt: now, updatedAt: now })
            .where(eq(users.id, row.id));
          const change = await reconcileDirectoryMembershipChange(
            tx,
            row.id,
            row.groups,
            [],
            now,
            false,
            row.active,
          );
          pendingEvents.push(...change.events);
          await tx
            .update(customGroups)
            .set({ frozen: true, updatedAt: now })
            .where(eq(customGroups.ownerUserId, row.id));
        }
        for (const userId of securityChanged) {
          await tx.delete(sessions).where(eq(sessions.userId, userId));
          await tx.delete(extensionSessions).where(eq(extensionSessions.userId, userId));
          await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, userId));
        }
        await tx
          .insert(directorySyncState)
          .values({
            provider,
            lastAttemptAt: now,
            lastSuccessAt: now,
            lastError: null,
            userCount: seen.size,
            groupCount: 0,
          })
          .onConflictDoUpdate({
            target: directorySyncState.provider,
            set: {
              lastAttemptAt: now,
              lastSuccessAt: now,
              lastError: null,
              userCount: seen.size,
              groupCount: 0,
            },
          });
        return pendingEvents;
      });
      this.bus?.publish(events);
      return { ...report, applied: true };
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 300) : 'LDAP directory sync failed';
      if (!dryRun) {
        await this.db
          .insert(directorySyncState)
          .values({ provider, lastAttemptAt: now, lastError: message })
          .onConflictDoUpdate({
            target: directorySyncState.provider,
            set: { lastAttemptAt: now, lastError: message },
          });
      }
      throw error;
    }
  }

  private async requireFreshDirectory(): Promise<Date> {
    const provider = this.connector.options.directoryId;
    let state = (
      await this.db.select().from(directorySyncState).where(eq(directorySyncState.provider, provider)).limit(1)
    )[0];
    if (!state?.lastSuccessAt) throw new DirectoryUnavailableError();
    if (Date.now() - state.lastSuccessAt.getTime() > this.connector.options.maxStaleMs) {
      try {
        await this.sync(true, false);
      } catch {
        throw new DirectoryUnavailableError();
      }
      state = (
        await this.db.select().from(directorySyncState).where(eq(directorySyncState.provider, provider)).limit(1)
      )[0];
    }
    if (!state?.lastSuccessAt || Date.now() - state.lastSuccessAt.getTime() > this.connector.options.maxStaleMs) {
      throw new DirectoryUnavailableError();
    }
    return state.lastSuccessAt;
  }

  private async syncInitializedDirectory(): Promise<void> {
    const state = (
      await this.db
        .select({ lastSuccessAt: directorySyncState.lastSuccessAt })
        .from(directorySyncState)
        .where(eq(directorySyncState.provider, this.connector.options.directoryId))
        .limit(1)
    )[0];
    if (state?.lastSuccessAt) await this.sync(false, false);
  }
}

export function ldapUserId(directoryId: string, stableId: string): string {
  const digest = createHash('sha256').update(`${directoryId}\0${stableId}`).digest('base64url');
  return `ldap:${digest}`;
}

export function adGuidToString(value: Buffer): string {
  if (value.length !== 16) throw new Error('AD objectGUID must be 16 bytes');
  const hex = (index: number) => value[index]!.toString(16).padStart(2, '0');
  return [
    [3, 2, 1, 0].map(hex).join(''),
    [5, 4].map(hex).join(''),
    [7, 6].map(hex).join(''),
    [8, 9].map(hex).join(''),
    [10, 11, 12, 13, 14, 15].map(hex).join(''),
  ].join('-');
}

function attributeValue(entry: Entry, attribute: string): Buffer | string | undefined {
  const key = Object.keys(entry).find((candidate) => candidate.toLocaleLowerCase() === attribute.toLocaleLowerCase());
  if (!key) return undefined;
  const value = entry[key];
  return Array.isArray(value) ? value[0] : value;
}

function stringValue(entry: Entry, attribute: string): string | undefined {
  const value = attributeValue(entry, attribute);
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  return typeof value === 'string' ? value : undefined;
}

function recordFromRow(row: typeof users.$inferSelect): AuthUserRecord {
  return {
    id: row.id,
    username: row.username,
    displayName: row.displayName,
    email: row.email,
    groups: row.groups,
    source: row.source,
    active: row.active,
  };
}
