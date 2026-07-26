import type { FastifyInstance } from 'fastify';
import { buildBaseApp, type BuildBaseAppOptions } from './app-base.ts';
import { env } from './env.ts';
import { registerEncryptedEventRoutes } from './routes/e2ee-events.ts';
import { registerE2eeAuditRoutes } from './routes/e2ee-audit.ts';
import { registerE2eeCryptoRoutes } from './routes/e2ee-crypto.ts';
import { registerE2eeVaultRoutes } from './routes/e2ee-vaults.ts';
import { registerE2eeRecoveryRoutes } from './routes/e2ee-recovery.ts';
import { registerE2eeExtensionRoutes } from './routes/e2ee-extension.ts';
import { registerE2eeEnvelopeTaskRoutes } from './routes/e2ee-envelope-tasks.ts';
import { registerE2eeAccountResetRoutes } from './routes/e2ee-account-reset.ts';
import { registerE2eeLegacyKeyRetirementRoutes } from './routes/e2ee-legacy-key-retirement.ts';
import { buildOpenApiDocument } from './openapi-contract.ts';

export type BuildStrictAppOptions = Omit<BuildBaseAppOptions, 'e2eeRequired'>;

export async function buildStrictApp(opts: BuildStrictAppOptions = {}): Promise<FastifyInstance> {
  const app = await buildBaseApp({ ...opts, e2eeRequired: true });

  registerEncryptedEventRoutes(app);
  registerE2eeAuditRoutes(app);
  registerE2eeCryptoRoutes(app);
  registerE2eeAccountResetRoutes(app);
  registerE2eeLegacyKeyRetirementRoutes(app);
  registerE2eeVaultRoutes(app);
  registerE2eeRecoveryRoutes(app);
  registerE2eeExtensionRoutes(app);
  registerE2eeEnvelopeTaskRoutes(app);

  app.get('/api/openapi.json', async () => buildOpenApiDocument(app.swagger(), env.publicBaseUrl));
  return app;
}
