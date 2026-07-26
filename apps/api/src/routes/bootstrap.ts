import { desc, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { ApiErrorSchema, BootstrapResponseSchema, type ItemMeta, type Membership } from '@mima/contracts';
import { syncEvents, vaultCryptoStates } from '../db/schema.ts';
import { listAccessibleVaults, listVaultItems, listVaultMemberships } from '../services/access.ts';
import { toItemMeta, toMembershipDto, toVaultDto } from '../services/mappers.ts';

export function registerBootstrapRoutes(app: FastifyInstance): void {
  const { db } = app.ctx;
  const r = app.withTypeProvider<ZodTypeProvider>();

  r.get('/api/bootstrap', {
    preHandler: [app.requireSession],
    schema: { tags: ['sync'], response: { 200: BootstrapResponseSchema, '4xx': ApiErrorSchema } },
  }, async (req, reply) => {
    reply.header('cache-control', 'no-store');
    if (app.ctx.e2eeRequired) {
      return reply.code(410).send({
        statusCode: 410,
        error: 'Gone',
        message: '旧版同步接口已停用，请刷新页面',
      } as never);
    }
    // REPEATABLE READ：快照与 cursor 出自同一数据库快照，
    // 避免"cursor 领先快照"导致事件丢失或"快照领先 cursor"导致重复回放歧义。
    return db.transaction(async (tx) => {
      const last = await tx
        .select({ id: syncEvents.id })
        .from(syncEvents)
        .orderBy(desc(syncEvents.id))
        .limit(1);
      const allAccesses = await listAccessibleVaults(tx, req.user);
      const states = allAccesses.length
        ? await tx.select().from(vaultCryptoStates).where(inArray(
            vaultCryptoStates.vaultId,
            allAccesses.map((access) => access.vault.id),
          ))
        : [];
      const legacyIds = new Set(states.filter((state) => state.storageMode === 'legacy').map((state) => state.vaultId));
      const accesses = allAccesses.filter((access) => legacyIds.has(access.vault.id));
      const items: ItemMeta[] = [];
      const memberships: Membership[] = [];
      for (const a of accesses) {
        const rows = await listVaultItems(tx, a.vault.id);
        items.push(...rows.map(toItemMeta));
        if (a.vault.kind === 'team') {
          memberships.push(...(await listVaultMemberships(tx, a.vault.id)).map(toMembershipDto));
        }
      }
      return {
        user: req.user,
        vaults: accesses.map((a) => toVaultDto(a.vault)),
        memberships,
        items,
        cursor: last[0]?.id ?? 0,
      };
    }, { isolationLevel: 'repeatable read', accessMode: 'read only' });
  });
}
