import { desc, eq, inArray } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { extensionSessions } from '../db/schema.ts';

export const EXTENSION_SESSION_HANDOFF_LIMIT = 2;

type ExtensionSessionStore = Pick<Db, 'select' | 'delete'>;

export async function retainExtensionSessionHandoff(
  db: ExtensionSessionStore,
  deviceId: string,
  currentSessionId: string,
  limit = EXTENSION_SESSION_HANDOFF_LIMIT,
): Promise<string[]> {
  const sessions = await db.select({ id: extensionSessions.id })
    .from(extensionSessions)
    .where(eq(extensionSessions.deviceId, deviceId))
    .orderBy(desc(extensionSessions.createdAt), desc(extensionSessions.id));
  if (!sessions.some((session) => session.id === currentSessionId)) {
    throw new Error('Current extension session is missing during handoff');
  }
  const retainedIds = [
    currentSessionId,
    ...sessions
      .filter((session) => session.id !== currentSessionId)
      .slice(0, Math.max(1, limit) - 1)
      .map((session) => session.id),
  ];
  const retained = new Set(retainedIds);
  const staleIds = sessions
    .filter((session) => !retained.has(session.id))
    .map((session) => session.id);
  if (staleIds.length) {
    await db.delete(extensionSessions).where(inArray(extensionSessions.id, staleIds));
  }
  return retainedIds;
}
