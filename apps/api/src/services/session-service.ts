import { and, eq, lt } from 'drizzle-orm';
import type { SessionInfo } from '@mima/contracts';
import type { AuthUserRecord, OidcLogoutIdentity } from '../auth/contracts.ts';
import { toSessionUser } from '../auth/contracts.ts';
import type { Db } from '../db/client.ts';
import {
  extensionPairingCodes,
  extensionSessions,
  oidcLogoutTokens,
  sessions,
  userCryptoProfiles,
  users,
  vaults,
} from '../db/schema.ts';
import { hashToken, newToken, pruneExpired } from '../plugins/auth.ts';
import { reconcileDirectoryMembershipChange } from './vault-envelope-tasks.ts';
import type { SyncBus } from './bus.ts';
import { hasLocalPlatformAdminRole } from './system-roles.ts';

export interface SessionAuthContext {
  method: 'password' | 'oidc' | 'feishu';
  provider: 'dev' | 'ldap' | 'oidc' | 'feishu';
  authenticatedAt: Date;
  issuer?: string;
  subject?: string;
  sid?: string | null;
}

export interface CreatedSession {
  token: string;
  info: SessionInfo;
}

export interface SessionService {
  create(user: AuthUserRecord, auth: SessionAuthContext): Promise<CreatedSession>;
  completeReauthentication(sessionId: string, userId: string, authenticatedAt: Date): Promise<boolean>;
  consumeOidcLogout(
    identity: OidcLogoutIdentity,
    jtiHash: string,
  ): Promise<{ replayed: boolean; sessionsRevoked: number; userIds: string[] }>;
}

export class DbSessionService implements SessionService {
  constructor(
    private readonly db: Db,
    private readonly ttlMs: number,
    private readonly bus?: SyncBus,
  ) {}

  async create(user: AuthUserRecord, auth: SessionAuthContext): Promise<CreatedSession> {
    await pruneExpired(this.db);
    const token = newToken();
    const csrfToken = newToken();
    const now = new Date();
    const state = await this.db.transaction(async (tx) => {
      const previous = (await tx.select().from(users).where(eq(users.id, user.id)).for('update').limit(1))[0];
      await tx
        .insert(users)
        .values({
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          email: user.email,
          groups: user.groups,
          source: user.source,
          active: user.active,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: users.id,
          set: {
            username: user.username,
            displayName: user.displayName,
            email: user.email,
            groups: user.groups,
            source: user.source,
            active: user.active,
            updatedAt: now,
          },
        });
      const directoryChange = await reconcileDirectoryMembershipChange(
        tx,
        user.id,
        previous?.groups ?? [],
        user.groups,
        now,
        user.active,
        previous?.active ?? false,
      );
      if (previous && (
        previous.active !== user.active ||
        !sameGroups(previous.groups, user.groups)
      )) {
        await tx.delete(sessions).where(eq(sessions.userId, user.id));
        await tx.delete(extensionSessions).where(eq(extensionSessions.userId, user.id));
        await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, user.id));
      }
      await tx
        .insert(vaults)
        .values({ kind: 'personal', name: '个人库', ownerUserId: user.id })
        .onConflictDoNothing();

      const cryptoProfile = (
        await tx
        .select({ userId: userCryptoProfiles.userId })
        .from(userCryptoProfiles)
        .where(eq(userCryptoProfiles.userId, user.id))
        .limit(1)
      )[0];
      const locked = Boolean(cryptoProfile);
      await tx.insert(sessions).values({
        tokenHash: hashToken(token),
        userId: user.id,
        csrfToken,
        authMethod: auth.method,
        authProvider: auth.provider,
        authenticatedAt: auth.authenticatedAt,
        locked,
        externalNamespace: auth.issuer ?? null,
        externalSubject: auth.subject ?? null,
        externalSessionId: auth.sid ?? null,
        oidcIssuer: auth.issuer ?? null,
        oidcSubject: auth.subject ?? null,
        oidcSid: auth.sid ?? null,
        expiresAt: new Date(Date.now() + this.ttlMs),
      });
      const isLocalPlatformAdmin = await hasLocalPlatformAdminRole(tx, user.id);
      return { locked, isLocalPlatformAdmin, events: directoryChange.events };
    });
    this.bus?.publish(state.events);
    return {
      token,
      info: {
        user: toSessionUser(user, state.isLocalPlatformAdmin),
        csrfToken,
        locked: state.locked,
        cryptoProfileInitialized: state.locked,
        cryptoDeviceId: null,
      },
    };
  }

  async completeReauthentication(
    sessionId: string,
    userId: string,
    authenticatedAt: Date,
  ): Promise<boolean> {
    const rows = await this.db
      .update(sessions)
      .set({ locked: false, authenticatedAt })
      .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), eq(sessions.locked, true)))
      .returning({ id: sessions.id });
    return rows.length === 1;
  }

  async consumeOidcLogout(
    identity: OidcLogoutIdentity,
    jtiHash: string,
  ): Promise<{ replayed: boolean; sessionsRevoked: number; userIds: string[] }> {
    return this.db.transaction(async (tx) => {
      await tx.delete(oidcLogoutTokens).where(lt(oidcLogoutTokens.expiresAt, new Date()));
      const inserted = await tx
        .insert(oidcLogoutTokens)
        .values({ jtiHash, expiresAt: identity.expiresAt })
        .onConflictDoNothing()
        .returning({ jtiHash: oidcLogoutTokens.jtiHash });
      if (inserted.length === 0) {
        return { replayed: true, sessionsRevoked: 0, userIds: [] };
      }

      let revoked = identity.sid
        ? await tx
            .delete(sessions)
            .where(and(eq(sessions.oidcIssuer, identity.issuer), eq(sessions.oidcSid, identity.sid)))
            .returning({ userId: sessions.userId })
        : [];
      if (revoked.length === 0 && identity.subject) {
        revoked = await tx
          .delete(sessions)
          .where(
            and(
              eq(sessions.oidcIssuer, identity.issuer),
              eq(sessions.oidcSubject, identity.subject),
            ),
          )
          .returning({ userId: sessions.userId });
      }
      const userIds = [...new Set(revoked.map((row) => row.userId))];
      for (const userId of userIds) {
        await tx.delete(extensionSessions).where(eq(extensionSessions.userId, userId));
        await tx.delete(extensionPairingCodes).where(eq(extensionPairingCodes.userId, userId));
      }
      return { replayed: false, sessionsRevoked: revoked.length, userIds };
    });
  }
}

function sameGroups(left: string[], right: string[]): boolean {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return leftSet.size === rightSet.size && [...leftSet].every((group) => rightSet.has(group));
}
