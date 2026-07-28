import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { commandDedup } from '../../src/db/schema.ts';
import { IdempotencyConflictError, runCommand } from '../../src/services/commands.ts';
import { freshTestApp, login, type TestSession } from './helpers.ts';

let app: FastifyInstance;
let session: TestSession;

beforeAll(async () => {
  app = await freshTestApp('mima_test_command_idempotency');
  session = await login(app, 'bob');
});

afterAll(async () => {
  await app.close();
});

describe('command idempotency identity', () => {
  it('binds strict commands to their name and request digest', async () => {
    const idempotencyKey = 'strict-command-idempotency';
    const requestDigest = randomBytes(32);
    let executions = 0;
    const execute = () => runCommand(
      app.ctx.db,
      app.ctx.bus,
      app.ctx.audit,
      session.userId,
      idempotencyKey,
      async () => {
        executions += 1;
        return { statusCode: 201, response: { value: 'created' } };
      },
      { commandName: 'recovery.test.create', requestDigest },
    );

    await expect(execute()).resolves.toEqual({ statusCode: 201, response: { value: 'created' } });
    await expect(execute()).resolves.toEqual({ statusCode: 201, response: { value: 'created' } });
    expect(executions).toBe(1);

    await expect(runCommand(
      app.ctx.db,
      app.ctx.bus,
      app.ctx.audit,
      session.userId,
      idempotencyKey,
      async () => ({ statusCode: 201, response: { value: 'must-not-run' } }),
      { commandName: 'recovery.test.create', requestDigest: randomBytes(32) },
    )).rejects.toBeInstanceOf(IdempotencyConflictError);

    await expect(runCommand(
      app.ctx.db,
      app.ctx.bus,
      app.ctx.audit,
      session.userId,
      idempotencyKey,
      async () => ({ statusCode: 200, response: { value: 'separate-command' } }),
      { commandName: 'recovery.test.cancel', requestDigest: randomBytes(32) },
    )).resolves.toEqual({ statusCode: 200, response: { value: 'separate-command' } });
  });

  it('keeps pre-upgrade legacy command responses replayable', async () => {
    const idempotencyKey = 'legacy-command-idempotency';
    await app.ctx.db.insert(commandDedup).values({
      idempotencyKey,
      userId: session.userId,
      commandName: 'legacy',
      requestDigest: null,
      statusCode: 200,
      response: { value: 'legacy-response' },
    });

    let executed = false;
    await expect(runCommand(
      app.ctx.db,
      app.ctx.bus,
      app.ctx.audit,
      session.userId,
      idempotencyKey,
      async () => {
        executed = true;
        return { statusCode: 200, response: { value: 'new-response' } };
      },
    )).resolves.toEqual({ statusCode: 200, response: { value: 'legacy-response' } });
    expect(executed).toBe(false);
  });
});
