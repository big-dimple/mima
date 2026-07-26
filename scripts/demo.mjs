import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtimeRoot = join(root, '.mima', 'demo');
const command = process.argv[2] ?? 'up';
const container = process.env.MIMA_DEMO_POSTGRES_CONTAINER?.trim() || 'mima-demo-postgres';
const webPort = readPort('MIMA_DEMO_WEB_PORT', 4173);
const apiPort = readPort('MIMA_DEMO_API_PORT', 4174);
const postgresPort = readPort('MIMA_DEMO_POSTGRES_PORT', 55432);
const databaseUrl = `postgres://mima:mima_demo_pw@127.0.0.1:${postgresPort}/mima`;
const extensionId = 'gkhbkfdgghiaoohpldbjkpmopaojjhhp';
const runtimeKeyDir = join(runtimeRoot, 'keys', 'runtime');
const auditKeyDir = join(runtimeRoot, 'keys', 'audit');
const postgresDir = join(runtimeRoot, 'postgres');

if (command === 'down') {
  run('docker', ['stop', container], { allowFailure: true });
  console.log('Mima Demo 已停止，数据仍保留在 .mima/demo。');
  process.exit(0);
}
if (command !== 'up') throw new Error('usage: node scripts/demo.mjs [up|down]');
if (Number(process.versions.node.split('.')[0]) < 24) throw new Error('Mima requires Node.js 24 or newer');
if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(container)) {
  throw new Error('MIMA_DEMO_POSTGRES_CONTAINER is not a valid Docker container name');
}

for (const directory of [runtimeRoot, runtimeKeyDir, auditKeyDir, postgresDir]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
}
writeFileSync(join(runtimeRoot, 'README.txt'), [
  'Mima 本地 Demo 运行目录，请勿提交到 Git。',
  'keys/ 保存本地运行与审计密钥；postgres/ 保存 Demo 数据库。',
  '执行 pnpm demo:down 只停止服务，不删除这里的数据。',
  '',
].join('\n'), { mode: 0o600 });

await assertPortAvailable(webPort);
await assertPortAvailable(apiPort);
startPostgres();

const webOrigin = `http://127.0.0.1:${webPort}`;
const apiOrigin = `http://127.0.0.1:${apiPort}`;

const env = {
  ...process.env,
  AUTH_MODE: 'dev',
  MIMA_DEMO_MODE: 'true',
  MIMA_DEPLOYMENT_ID: 'mima-local-demo',
  MIMA_LOGIN_PROVIDER: 'dev',
  MIMA_REAUTH_PROVIDER: 'dev',
  MIMA_DIRECTORY_PROVIDER: 'dev',
  MIMA_DATABASE_URL: databaseUrl,
  MIMA_API_HOST: '127.0.0.1',
  MIMA_API_PORT: String(apiPort),
  MIMA_PUBLIC_BASE_URL: webOrigin,
  MIMA_WEB_ORIGINS: `${webOrigin},http://localhost:${webPort}`,
  MIMA_RUNTIME_KEY_DIR: runtimeKeyDir,
  MIMA_AUDIT_KEY_DIR: auditKeyDir,
  MIMA_EXTENSION_IDS: extensionId,
  MIMA_SESSION_COOKIE_SECURE: 'false',
  VITE_MIMA_API_BASE: apiOrigin,
  VITE_MIMA_EXTENSION_ID: extensionId,
};

run('node', ['scripts/init-server-keys.mjs'], { env });
run('pnpm', ['db:migrate'], { env });
run('pnpm', ['--filter', '@mima/api', 'run', 'demo:seed'], { env });
run('pnpm', ['system-role', 'grant', 'alice'], { env });
run('pnpm', ['--filter', '@mima/extension', 'build'], { env });

console.log('\nMima 本地 Demo（禁止用于生产）');
console.log(`工作台: ${webOrigin}`);
console.log('账号: alice  密码: dev');
console.log(`扩展目录: ${join(root, 'apps', 'extension', 'dist')}`);
console.log('按 Ctrl+C 停止 Web/API；执行 pnpm demo:down 停止 PostgreSQL。\n');

const children = [
  spawn('pnpm', ['--filter', '@mima/api', 'start'], { cwd: root, env, stdio: 'inherit' }),
  spawn('pnpm', ['--filter', '@mima/web', 'exec', 'vite', '--host', '127.0.0.1', '--port', String(webPort)], {
    cwd: root,
    env,
    stdio: 'inherit',
  }),
];
let stopping = false;
const stop = (signal = 'SIGTERM') => {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill(signal);
};
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
for (const child of children) {
  child.on('exit', (code) => {
    if (!stopping && code !== 0) process.exitCode = code ?? 1;
    stop();
  });
}
await Promise.all(children.map((child) => new Promise((resolveChild) => child.on('exit', resolveChild))));

function startPostgres() {
  const running = run('docker', ['ps', '--filter', `name=^/${container}$`, '--format', '{{.Names}}'], {
    capture: true,
  }).stdout.trim() === container;
  if (!running) {
    const exists = run('docker', ['ps', '-a', '--filter', `name=^/${container}$`, '--format', '{{.Names}}'], {
      capture: true,
    }).stdout.trim() === container;
    if (exists) run('docker', ['start', container]);
    else run('docker', [
      'run', '-d', '--name', container,
      '-e', 'POSTGRES_DB=mima',
      '-e', 'POSTGRES_USER=mima',
      '-e', 'POSTGRES_PASSWORD=mima_demo_pw',
      '-e', 'PGDATA=/var/lib/postgresql/data',
      '-p', `127.0.0.1:${postgresPort}:5432`,
      '-v', `${postgresDir}:/var/lib/postgresql/data`,
      'postgres:18-trixie',
    ]);
  }
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const probe = spawnSync('docker', ['exec', container, 'pg_isready', '-U', 'mima', '-d', 'mima']);
    if (probe.status === 0) return;
    spawnSync('sleep', ['1']);
  }
  throw new Error('PostgreSQL did not become ready');
}

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: root,
    env: options.env ?? process.env,
    encoding: 'utf8',
    stdio: options.capture ? 'pipe' : 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !options.allowFailure) {
    throw new Error(`${executable} ${args.join(' ')} failed with exit code ${result.status}`);
  }
  return result;
}

function assertPortAvailable(port) {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once('error', () => rejectPort(new Error(`127.0.0.1:${port} is already in use`)));
    server.listen(port, '127.0.0.1', () => server.close(resolvePort));
  });
}

function readPort(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`${name} must be an integer between 1 and 65535`);
  }
  return value;
}
