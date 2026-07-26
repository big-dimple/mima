import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../../..');

describe('production log redaction', () => {
  it('keeps credentials, callback parameters, and sensitive bodies out of API logs', () => {
    const result = spawnSync('pnpm', [
      '--filter',
      '@mima/api',
      'exec',
      'tsx',
      'test/fixtures/log-redaction-runner.ts',
    ], {
      cwd: root,
      encoding: 'utf8',
      env: process.env,
      timeout: 30_000,
    });
    const output = `${result.stdout}\n${result.stderr}`;
    expect(result.status, output).toBe(0);
    expect(output).toContain('request failed');
    expect(output).toContain('LOG_REDACTION_RUNNER_COMPLETE');
    for (const forbidden of [
      'LOG_AUTHORIZATION_CANARY',
      'LOG_COOKIE_CANARY',
      'LOG_ERROR_MESSAGE_CANARY',
      'LOG_NOTE_CANARY',
      'LOG_OIDC_CODE_CANARY',
      'LOG_OIDC_STATE_CANARY',
      'LOG_PASSWORD_CANARY',
      'LOG_TOKEN_CANARY',
    ]) {
      expect(output).not.toContain(forbidden);
    }
  });
});
