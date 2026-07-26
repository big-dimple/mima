import { buildStrictApp } from './strict-app.ts';
import { env } from './env.ts';

let app: Awaited<ReturnType<typeof buildStrictApp>> | null = null;
try {
  app = await buildStrictApp();
  await app.listen({ port: env.port, host: env.host });
  console.log(`mima API listening on http://${env.host}:${env.port}`);
} catch (error) {
  const errorName = error instanceof Error ? error.name : 'Error';
  if (app) {
    app.log.error({ errorName }, 'API startup failed');
    await app.close().catch(() => undefined);
  } else {
    console.error(`mima API startup failed (${errorName})`);
  }
  process.exitCode = 1;
}
