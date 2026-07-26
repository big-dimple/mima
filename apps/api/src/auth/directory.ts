import { createHash } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import type { AuthUserRecord, DirectoryService, DirectorySnapshot } from './contracts.ts';
import type { Db } from '../db/client.ts';
import {
  directoryGroups,
  directorySyncState,
  extensionPairingCodes,
  extensionSessions,
  sessions,
  userIdentities,
  users,
} from '../db/schema.ts';
import { readPrivateFile } from './secrets.ts';
import { reconcileDirectoryMembershipChange } from '../services/vault-envelope-tasks.ts';
import type { SyncBus, SyncEventRow } from '../services/bus.ts';

const PROVIDER = 'authentik';

interface AuthentikGroup {
  pk: string;
  name: string;
}

interface AuthentikUser {
  uuid: string;
  username: string;
  name: string;
  email: string;
  is_active: boolean;
  type: string;
  groups_obj: AuthentikGroup[] | null;
}

interface PaginatedResponse<T> {
  results: T[];
  pagination?: { next?: number | string | null };
  next?: string | null;
}

export interface AuthentikDirectoryOptions {
  baseUrl: string;
  issuer: string;
  tokenFile: string;
  serviceUsername: string;
  groupMapJson: string;
  syncIntervalMs: number;
  maxStaleMs: number;
  requestTimeoutMs: number;
}

export class DirectoryUnavailableError extends Error {
  constructor() {
    super('公司成员目录暂时不可用，请稍后重试');
  }
}

export function oidcUserId(issuer: string, subject: string): string {
  const digest = createHash('sha256').update(`${issuer}\0${subject}`).digest('base64url');
  return `oidc:${digest}`;
}

export class AuthentikDirectoryService implements DirectoryService {
  readonly source = 'oidc';
  private readonly token: string;
  private readonly groupMap: ReadonlyMap<string, string>;
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<void> | null = null;

  constructor(
    private readonly db: Db,
    private readonly options: AuthentikDirectoryOptions,
    private readonly bus?: SyncBus,
  ) {
    this.token = readPrivateFile(options.tokenFile, 'Authentik directory token file');
    this.groupMap = parseGroupMap(options.groupMapJson);
  }

  start(): void {
    if (this.timer) return;
    void this.sync(false).catch(() => undefined);
    this.timer = setInterval(() => void this.sync(false).catch(() => undefined), this.options.syncIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async listDirectory(): Promise<DirectorySnapshot> {
    const syncedAt = await this.requireFreshDirectory();
    const [userRows, groupRows] = await Promise.all([
      this.db.select().from(users).where(and(eq(users.source, 'oidc'), eq(users.active, true))),
      this.db
        .select()
        .from(directoryGroups)
        .where(and(eq(directoryGroups.provider, PROVIDER), eq(directoryGroups.active, true))),
    ]);
    return {
      users: userRows
        .map(({ id, username, displayName }) => ({ id, username, displayName }))
        .sort((left, right) => left.displayName.localeCompare(right.displayName, 'zh-Hans-CN')),
      groups: groupRows.map((row) => row.id).sort(),
      syncedAt,
    };
  }

  async findActiveUser(userId: string): Promise<AuthUserRecord | null> {
    await this.requireFreshDirectory();
    const row = (
      await this.db
        .select()
        .from(users)
        .where(and(eq(users.id, userId), eq(users.source, 'oidc'), eq(users.active, true)))
        .limit(1)
    )[0];
    return row ? recordFromRow(row) : null;
  }

  async findActiveOidcUser(issuer: string, subject: string): Promise<AuthUserRecord | null> {
    await this.requireFreshDirectory();
    let record = await this.lookupIdentity(issuer, subject);
    if (record) return record;
    await this.sync(true);
    record = await this.lookupIdentity(issuer, subject);
    return record;
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

  async sync(force: boolean): Promise<void> {
    if (this.running) return this.running;
    this.running = this.performSync(force).finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async performSync(force: boolean): Promise<void> {
    const now = new Date();
    const currentState = (
      await this.db
        .select()
        .from(directorySyncState)
        .where(eq(directorySyncState.provider, PROVIDER))
        .limit(1)
    )[0];
    if (
      !force &&
      currentState?.lastSuccessAt &&
      now.getTime() - currentState.lastSuccessAt.getTime() < this.options.syncIntervalMs
    ) {
      return;
    }

    try {
      const remoteUsers = await this.fetchAll<AuthentikUser>('/api/v3/core/users/', {
        include_groups: 'true',
      });
      const activeUsers = remoteUsers.filter(
        (user) =>
          user.is_active &&
          user.username !== this.options.serviceUsername &&
          user.type !== 'service_account' &&
          user.type !== 'internal_service_account',
      );
      const providerGroups = new Map<string, AuthentikGroup>();
      for (const user of activeUsers) {
        for (const group of user.groups_obj ?? []) providerGroups.set(group.pk, group);
      }
      const mappedGroups = [...providerGroups.values()]
        .map((group) => ({ group, internalId: this.groupMap.get(group.pk) ?? this.groupMap.get(group.name) }))
        .filter((item): item is { group: AuthentikGroup; internalId: string } => Boolean(item.internalId));

      const previousRows = await this.db.select().from(users).where(eq(users.source, 'oidc'));
      const previous = new Map(previousRows.map((row) => [row.id, row]));
      const seenUserIds = new Set<string>();
      const securityChanged = new Set<string>();

      const events = await this.db.transaction(async (tx) => {
        const pendingEvents: SyncEventRow[] = [];
        await tx
          .update(directoryGroups)
          .set({ active: false, syncedAt: now })
          .where(eq(directoryGroups.provider, PROVIDER));
        for (const { group, internalId } of mappedGroups) {
          await tx
            .insert(directoryGroups)
            .values({
              id: internalId,
              provider: PROVIDER,
              providerGroupId: group.pk,
              displayName: group.name,
              active: true,
              syncedAt: now,
            })
            .onConflictDoUpdate({
              target: directoryGroups.id,
              set: {
                providerGroupId: group.pk,
                displayName: group.name,
                active: true,
                syncedAt: now,
              },
            });
        }

        for (const remote of activeUsers) {
          if (!remote.uuid || !remote.username) continue;
          const id = oidcUserId(this.options.issuer, remote.uuid);
          const groups = (remote.groups_obj ?? [])
            .map((group) => this.groupMap.get(group.pk) ?? this.groupMap.get(group.name))
            .filter((group): group is string => Boolean(group))
            .sort();
          const prior = previous.get(id);
          if (prior && (!prior.active || JSON.stringify([...prior.groups].sort()) !== JSON.stringify(groups))) {
            securityChanged.add(id);
          }
          seenUserIds.add(id);
          await tx
            .insert(users)
            .values({
              id,
              username: remote.username,
              displayName: remote.name || remote.username,
              email: remote.email || '',
              groups,
              source: 'oidc',
              active: true,
              directorySyncedAt: now,
              updatedAt: now,
            })
            .onConflictDoUpdate({
              target: users.id,
              set: {
                username: remote.username,
                displayName: remote.name || remote.username,
                email: remote.email || '',
                groups,
                source: 'oidc',
                active: true,
                directorySyncedAt: now,
                updatedAt: now,
              },
            });
          await tx
            .insert(userIdentities)
            .values({
              provider: PROVIDER,
              issuer: this.options.issuer,
              subject: remote.uuid,
              userId: id,
              updatedAt: now,
            })
            .onConflictDoUpdate({
              target: [userIdentities.provider, userIdentities.issuer, userIdentities.subject],
              set: { provider: PROVIDER, userId: id, updatedAt: now },
            });
          const change = await reconcileDirectoryMembershipChange(
            tx,
            id,
            prior?.groups ?? [],
            groups,
            now,
            true,
            prior?.active ?? false,
          );
          pendingEvents.push(...change.events);
        }

        for (const prior of previousRows) {
          if (seenUserIds.has(prior.id)) continue;
          securityChanged.add(prior.id);
          await tx
            .update(users)
            .set({ active: false, groups: [], directorySyncedAt: now, updatedAt: now })
            .where(eq(users.id, prior.id));
          const change = await reconcileDirectoryMembershipChange(
            tx,
            prior.id,
            prior.groups,
            [],
            now,
            false,
            prior.active,
          );
          pendingEvents.push(...change.events);
        }

        for (const userId of securityChanged) {
          await tx.delete(sessions).where(eq(sessions.userId, userId));
          await tx.delete(extensionSessions).where(eq(extensionSessions.userId, userId));
          await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, userId));
        }

        await tx
          .insert(directorySyncState)
          .values({
            provider: PROVIDER,
            lastAttemptAt: now,
            lastSuccessAt: now,
            lastError: null,
            userCount: seenUserIds.size,
            groupCount: mappedGroups.length,
          })
          .onConflictDoUpdate({
            target: directorySyncState.provider,
            set: {
              lastAttemptAt: now,
              lastSuccessAt: now,
              lastError: null,
              userCount: seenUserIds.size,
              groupCount: mappedGroups.length,
            },
          });
        return pendingEvents;
      });
      this.bus?.publish(events);
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 300) : 'directory sync failed';
      await this.db
        .insert(directorySyncState)
        .values({ provider: PROVIDER, lastAttemptAt: now, lastError: message })
        .onConflictDoUpdate({
          target: directorySyncState.provider,
          set: { lastAttemptAt: now, lastError: message },
        });
      throw error;
    }
  }

  private async requireFreshDirectory(): Promise<Date> {
    let state = (
      await this.db
        .select()
        .from(directorySyncState)
        .where(eq(directorySyncState.provider, PROVIDER))
        .limit(1)
    )[0];
    if (!state?.lastSuccessAt || Date.now() - state.lastSuccessAt.getTime() > this.options.maxStaleMs) {
      try {
        await this.sync(true);
      } catch {
        throw new DirectoryUnavailableError();
      }
      state = (
        await this.db
          .select()
          .from(directorySyncState)
          .where(eq(directorySyncState.provider, PROVIDER))
          .limit(1)
      )[0];
    }
    if (!state?.lastSuccessAt || Date.now() - state.lastSuccessAt.getTime() > this.options.maxStaleMs) {
      throw new DirectoryUnavailableError();
    }
    return state.lastSuccessAt;
  }

  private async lookupIdentity(issuer: string, subject: string): Promise<AuthUserRecord | null> {
    const rows = await this.db
      .select({ user: users })
      .from(userIdentities)
      .innerJoin(users, eq(users.id, userIdentities.userId))
      .where(
        and(
          eq(userIdentities.provider, PROVIDER),
          eq(userIdentities.issuer, issuer),
          eq(userIdentities.subject, subject),
          eq(users.active, true),
        ),
      )
      .limit(1);
    return rows[0] ? recordFromRow(rows[0].user) : null;
  }

  private async fetchAll<T>(path: string, params: Record<string, string>): Promise<T[]> {
    const result: T[] = [];
    let page = 1;
    let nextUrl: URL | null = new URL(path, ensureTrailingSlash(this.options.baseUrl));
    for (const [key, value] of Object.entries(params)) nextUrl.searchParams.set(key, value);
    nextUrl.searchParams.set('page_size', '100');

    while (nextUrl) {
      nextUrl.searchParams.set('page', String(page));
      const response = await fetch(nextUrl, {
        headers: { authorization: `Bearer ${this.token}`, accept: 'application/json' },
        signal: AbortSignal.timeout(this.options.requestTimeoutMs),
      });
      if (!response.ok) throw new Error(`Authentik directory request failed with HTTP ${response.status}`);
      const payload = (await response.json()) as PaginatedResponse<T> | T[];
      if (Array.isArray(payload)) {
        result.push(...payload);
        break;
      }
      result.push(...payload.results);
      const next = payload.pagination?.next ?? payload.next;
      if (!next) break;
      if (typeof next === 'number') {
        page = next;
      } else if (/^\d+$/.test(next)) {
        page = Number(next);
      } else {
        nextUrl = new URL(next, ensureTrailingSlash(this.options.baseUrl));
        page = Number(nextUrl.searchParams.get('page') ?? page + 1);
      }
    }
    return result;
  }
}

export function parseGroupMap(json: string): ReadonlyMap<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('MIMA_DIRECTORY_GROUP_MAP must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('MIMA_DIRECTORY_GROUP_MAP must be a JSON object');
  }
  const entries = Object.entries(parsed);
  const values = new Set<string>();
  for (const [key, value] of entries) {
    if (!key.trim() || typeof value !== 'string' || !/^group:default\/[a-z0-9._-]+$/.test(value)) {
      throw new Error('directory group mappings must use group:default/<name> values');
    }
    if (values.has(value)) throw new Error(`directory group mapping is ambiguous for ${value}`);
    values.add(value);
  }
  return new Map(entries as Array<[string, string]>);
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith('/') ? value : `${value}/`;
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

export async function findActiveUsername(db: Db, username: string): Promise<AuthUserRecord | null> {
  const row = (
    await db
      .select()
      .from(users)
      .where(and(sql`lower(${users.username}) = lower(${username.trim()})`, eq(users.active, true)))
      .limit(1)
  )[0];
  return row ? recordFromRow(row) : null;
}

export async function resolveExternalIdentity(
  db: Db,
  provider: 'feishu',
  namespace: string,
  subject: string,
): Promise<AuthUserRecord | null> {
  const existing = (
    await db
      .select({ user: users })
      .from(userIdentities)
      .innerJoin(users, eq(users.id, userIdentities.userId))
      .where(and(
        eq(userIdentities.provider, provider),
        eq(userIdentities.issuer, namespace),
        eq(userIdentities.subject, subject),
        eq(users.active, true),
      ))
      .limit(1)
  )[0];
  if (existing) return recordFromRow(existing.user);
  return null;
}
