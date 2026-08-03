import { and, asc, eq, gt, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { EncryptedSyncEvent } from '@mima/contracts';
import {
  encryptedVaultHeaders,
  sessions,
  syncEvents,
  vaultCryptoStates,
  vaultRekeyJobs,
} from '../db/schema.ts';
import {
  getVaultAccess,
  getVaultAuthorization,
  listAccessibleVaults,
  listAuthorizedVaults,
  listPersonalVaultRecoveryCandidates,
} from '../services/access.ts';
import type { SyncEventRow } from '../services/bus.ts';
import { encodeCipherBlob } from '../services/e2ee.ts';

export function registerEncryptedEventRoutes(app: FastifyInstance): void {
  const { db, bus } = app.ctx;
  app.get('/api/v2/events', { preHandler: [app.requireSession] }, async (req, reply) => {
    const cursor = Number((req.query as { cursor?: string }).cursor ?? '0') || 0;
    const user = req.user;
    const sessionId = req.sessionRow.id;
    for (const [name, value] of Object.entries(reply.getHeaders())) {
      if (value !== undefined) reply.raw.setHeader(name, value);
    }
    reply.raw.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    reply.hijack();
    reply.raw.write(':connected\n\n');
    let closed = false;
    let lastSent = cursor;
    const [initialAccessible, initialAuthorized, initialRecoveryCandidates] = await Promise.all([
      listAccessibleVaults(db, user),
      listAuthorizedVaults(db, user),
      listPersonalVaultRecoveryCandidates(db, user.id),
    ]);
    const known = new Set([
      ...initialAccessible.map((access) => access.vault.id),
      ...initialAuthorized
        .filter((access) => access.vault.kind === 'team')
        .map((access) => access.vault.id),
      ...initialRecoveryCandidates.map((candidate) => candidate.vault.id),
    ]);
    const send = (event: EncryptedSyncEvent) => {
      if (!closed) reply.raw.write(`id: ${event.cursor}\ndata: ${JSON.stringify(event)}\n\n`);
    };
    const sessionValid = async () => {
      const row = (await db.select({ locked: sessions.locked, expiresAt: sessions.expiresAt })
        .from(sessions).where(eq(sessions.id, sessionId)).limit(1))[0];
      return Boolean(row && !row.locked && row.expiresAt.getTime() > Date.now());
    };
    const buffer: SyncEventRow[] = [];
    let ready = false;
    let chain = Promise.resolve();
    const close = () => {
      if (closed) return;
      closed = true;
      clearInterval(ping);
      unsubscribe();
      reply.raw.end();
    };
    const deliver = async (row: SyncEventRow) => {
      if (closed || row.id <= cursor) return;
      if (!await sessionValid()) return close();
      if (row.type === 'device.revoked') {
        if (row.payload.userId === user.id) {
          send({ type: 'device.revoked', cursor: row.id, deviceId: String(row.payload.deviceId) });
        } else send({ type: 'sync.cursor', cursor: row.id });
        lastSent = Math.max(lastSent, row.id);
        return;
      }
      if (row.type === 'crypto.profile_rewrapped') {
        if (row.payload.userId === user.id) {
          send({
            type: 'crypto.profile_rewrapped',
            cursor: row.id,
            actorDeviceId: String(row.payload.actorDeviceId),
            profileVersion: Number(row.payload.profileVersion),
          });
        } else send({ type: 'sync.cursor', cursor: row.id });
        lastSent = Math.max(lastSent, row.id);
        return;
      }
      const [access, authorization] = await Promise.all([
        getVaultAccess(db, user, row.vaultId),
        getVaultAuthorization(db, user, row.vaultId),
      ]);
      const hasAccess = Boolean(access?.role);
      const waitingForEnvelope = !hasAccess && authorization?.vault.kind === 'team' && Boolean(authorization.role);
      const recoveryRequired = !hasAccess && known.has(row.vaultId) &&
        (await listPersonalVaultRecoveryCandidates(db, user.id))
        .some((candidate) => candidate.vault.id === row.vaultId);
      if (!hasAccess && !waitingForEnvelope && !recoveryRequired) {
        if (known.delete(row.vaultId)) send({ type: 'vault.revoked', cursor: row.id, vaultId: row.vaultId });
        else send({ type: 'sync.cursor', cursor: row.id });
        lastSent = Math.max(lastSent, row.id);
        return;
      }
      known.add(row.vaultId);
      if (row.type === 'item.encrypted_upserted') {
        if (hasAccess) send({ type: 'item.encrypted_upserted', cursor: row.id, item: row.payload.item as never });
        else send({ type: 'sync.cursor', cursor: row.id });
      } else if (row.type === 'item.deleted') {
        if (hasAccess) send({ type: 'item.deleted', cursor: row.id, vaultId: row.vaultId, itemId: row.itemId! });
        else send({ type: 'sync.cursor', cursor: row.id });
      } else if (row.type === 'vault.rekey_required' || row.payload.rekeyRequired === true) {
        if (!hasAccess) {
          send({ type: 'sync.cursor', cursor: row.id });
          lastSent = Math.max(lastSent, row.id);
          return;
        }
        const task = await db.select().from(vaultRekeyJobs).where(and(
          eq(vaultRekeyJobs.vaultId, row.vaultId),
          inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
        )).limit(1);
        if (!task[0]) {
          send({ type: 'sync.cursor', cursor: row.id });
          lastSent = Math.max(lastSent, row.id);
          return;
        }
        send({
          type: 'vault.rekey_required',
          cursor: row.id,
          vaultId: row.vaultId,
          pendingEpoch: task[0].toEpoch,
          taskId: task[0].id,
        });
      } else if (row.type === 'vault.crypto_changed') {
        const state = (await db.select().from(vaultCryptoStates)
          .where(eq(vaultCryptoStates.vaultId, row.vaultId)).limit(1))[0];
        const header = state?.activeEpoch
          ? (await db.select().from(encryptedVaultHeaders).where(and(
              eq(encryptedVaultHeaders.vaultId, row.vaultId),
              eq(encryptedVaultHeaders.keyEpoch, state.activeEpoch),
              eq(encryptedVaultHeaders.headerVersion, state.activeHeaderVersion),
            )).limit(1))[0]
          : null;
        const rekey = state?.writeState === 'rekeying'
          ? (await db.select().from(vaultRekeyJobs).where(and(
              eq(vaultRekeyJobs.vaultId, row.vaultId),
              inArray(vaultRekeyJobs.status, ['pending', 'distributing', 'rewrapping', 'verifying', 'ready']),
            )).limit(1))[0]
          : null;
        const canReceiveHeader = hasAccess || recoveryRequired;
        if (!state) send({ type: 'sync.cursor', cursor: row.id });
        else send({
          type: 'vault.crypto_changed',
          cursor: row.id,
          state: {
            vaultId: state.vaultId,
            status: state.storageMode === 'e2ee'
              ? (state.writeState === 'rekeying' ? 'rekey_required' : 'e2ee')
              : (state.writeState === 'frozen' ? 'frozen' : 'legacy'),
            activeEpoch: state.activeEpoch ?? 0,
            pendingEpoch: rekey?.toEpoch ?? null,
            rekeyTaskId: hasAccess && !recoveryRequired ? rekey?.id ?? null : null,
            encryptedHeader: canReceiveHeader && header ? encodeCipherBlob(header.nonce, header.ciphertext) : null,
            migrationJobId: null,
            recoveryRequired,
            recoveryReason: recoveryRequired ? 'missing_current_full_envelope' : null,
            updatedAt: state.updatedAt.toISOString(),
          },
          header: canReceiveHeader && header ? {
            vaultId: header.vaultId,
            version: header.headerVersion,
            keyEpoch: header.keyEpoch,
            blob: encodeCipherBlob(header.nonce, header.ciphertext),
            updatedAt: header.createdAt.toISOString(),
            updatedBy: header.createdByDeviceId,
          } : null,
        });
      } else {
        send({ type: 'sync.cursor', cursor: row.id });
      }
      lastSent = Math.max(lastSent, row.id);
    };
    const unsubscribe = bus.subscribe((row) => {
      if (!ready) buffer.push(row);
      else chain = chain.then(() => deliver(row)).catch(close);
    });
    const ping = setInterval(() => {
      void sessionValid().then((valid) => {
        if (!valid) close();
        else if (!closed) reply.raw.write(':ping\n\n');
      }).catch(close);
    }, 15_000);
    req.raw.on('close', close);
    const backlog = await db.select().from(syncEvents)
      .where(gt(syncEvents.id, cursor)).orderBy(asc(syncEvents.id));
    for (const row of backlog) await deliver(row as SyncEventRow);
    while (buffer.length > 0) await deliver(buffer.shift()!);
    if (closed) return;
    ready = true;
    const [authoritative, authoritativeAuthorizations, authoritativeRecoveryCandidates] = await Promise.all([
      listAccessibleVaults(db, user),
      listAuthorizedVaults(db, user),
      listPersonalVaultRecoveryCandidates(db, user.id),
    ]);
    const authoritativeVaultIds = new Set([
      ...authoritative.map((access) => access.vault.id),
      ...authoritativeAuthorizations
        .filter((access) => access.vault.kind === 'team')
        .map((access) => access.vault.id),
      ...authoritativeRecoveryCandidates.map((candidate) => candidate.vault.id),
    ]);
    send({
      type: 'sync.ready',
      cursor: lastSent,
      vaultIds: [...authoritativeVaultIds],
    });
  });
}
