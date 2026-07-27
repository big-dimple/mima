#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';

const REQUIRED_NODE_MAJOR = 24;
const PUBLICATION_POSTGRES_CONTAINER = process.env.MIMA_POSTGRES_CONTAINER
  ?? 'mima-github-publish-postgres';
const PUBLICATION_POSTGRES_PORT = process.env.MIMA_POSTGRES_PORT ?? '55433';
const COMMANDS = [
  ['pnpm', ['install', '--frozen-lockfile']],
  ['pnpm', ['db:up']],
  ['pnpm', ['api:specs:check']],
  ['pnpm', ['db:migrations:check']],
  ['pnpm', ['public:audit']],
  ['pnpm', ['typecheck']],
  ['pnpm', ['lint']],
  ['pnpm', ['test']],
  ['pnpm', ['test:integration']],
  ['pnpm', ['test:e2e']],
  ['pnpm', ['build']],
  ['pnpm', ['runtime:scan']],
  ['git', ['diff', '--check']],
];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function run(command, args, environment = process.env) {
  process.stdout.write(`+ ${[command, ...args].join(' ')}\n`);
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: environment,
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) fail(`${command} exited with ${result.status}`);
}

function output(command, args) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
  });
  if (result.error || result.status !== 0) return '';
  return result.stdout.trim();
}

function isIpv4(value) {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(octet)) return false;
    const number = Number(octet);
    return number >= 0 && number <= 255;
  });
}

function firstIpv4(value) {
  return value.split(/\s+/).map((token) => token.trim()).find(isIpv4);
}

function isWsl() {
  if (process.platform !== 'linux') return false;
  if (process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP) return true;
  try {
    return /microsoft/i.test(readFileSync('/proc/sys/kernel/osrelease', 'utf8'));
  } catch {
    return false;
  }
}

function testEnvironment(baseEnvironment) {
  if (!isWsl()) {
    return {
      ...baseEnvironment,
      MIMA_INTEGRATION_DATABASE_URL: process.env.MIMA_INTEGRATION_DATABASE_URL
        ?? `postgres://mima:mima_dev_pw@127.0.0.1:${PUBLICATION_POSTGRES_PORT}/mima`,
      MIMA_E2E_DATABASE_URL: process.env.MIMA_E2E_DATABASE_URL
        ?? `postgres://mima:mima_dev_pw@127.0.0.1:${PUBLICATION_POSTGRES_PORT}/mima_test_e2e`,
    };
  }
  const containerAddress = firstIpv4(output('docker', [
    'inspect',
    '--format',
    '{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{end}}',
    PUBLICATION_POSTGRES_CONTAINER,
  ]));
  if (!containerAddress) fail('Cannot resolve the mima-postgres container address on WSL');
  process.stdout.write('[gate] WSL-stable PostgreSQL and IPv6 loopback test networking enabled\n');
  return {
    ...baseEnvironment,
    MIMA_E2E_API_HOST: process.env.MIMA_E2E_API_HOST ?? '::1',
    MIMA_INTEGRATION_DATABASE_URL: process.env.MIMA_INTEGRATION_DATABASE_URL
      ?? `postgres://mima:mima_dev_pw@${containerAddress}:5432/mima`,
    MIMA_E2E_DATABASE_URL: process.env.MIMA_E2E_DATABASE_URL
      ?? `postgres://mima:mima_dev_pw@${containerAddress}:5432/mima_test_e2e`,
  };
}

const nodeMajor = Number(process.versions.node.split('.')[0]);
if (nodeMajor < REQUIRED_NODE_MAJOR) {
  fail(`Node >= ${REQUIRED_NODE_MAJOR} is required; current Node is ${process.versions.node}`);
}

const baseEnvironment = {
  ...process.env,
  MIMA_POSTGRES_CONTAINER: PUBLICATION_POSTGRES_CONTAINER,
  MIMA_POSTGRES_PORT: PUBLICATION_POSTGRES_PORT,
};
run(...COMMANDS[0]);
run(COMMANDS[1][0], COMMANDS[1][1], baseEnvironment);
const environment = testEnvironment(baseEnvironment);
for (const [command, args] of COMMANDS.slice(2)) {
  run(command, args, environment);
}
