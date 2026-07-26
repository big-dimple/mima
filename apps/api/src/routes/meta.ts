import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';

export function registerMetaRoutes(app: FastifyInstance): void {
  app.get('/api/healthz', { schema: { tags: ['meta'] } }, async () => ({ ok: true }));

  app.get('/api/readyz', { schema: { tags: ['meta'] } }, async (_req, reply) => {
    try {
      await app.ctx.db.execute(sql`SELECT 1`);
      const migrations = await app.ctx.db.execute<{ count: string }>(
        sql`SELECT count(*)::text AS count FROM schema_migrations`,
      );
      return {
        ok: true,
        database: true,
        migrations: Number(migrations.rows[0]?.count ?? 0),
        e2eeRequired: app.ctx.e2eeRequired,
      };
    } catch {
      return reply.code(503).send({
        ok: false,
        message: '服务尚未准备好',
      });
    }
  });
}
