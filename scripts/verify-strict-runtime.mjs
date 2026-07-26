import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const options = parseOptions(process.argv.slice(2));
const apiDirectory = resolve(root, options.get('--api-dir') ?? 'apps/api/dist');
const workerDirectory = options.has('--worker-dir')
  ? resolve(root, options.get('--worker-dir') ?? 'apps/api/dist-migration-worker')
  : null;
const openApiFile = options.has('--openapi')
  ? resolve(root, options.get('--openapi') ?? 'apps/api/openapi/openapi.json')
  : null;
const asyncApiFile = options.has('--asyncapi')
  ? resolve(root, options.get('--asyncapi') ?? 'apps/api/openapi/asyncapi.json')
  : null;
const webDirectory = options.has('--web-dir')
  ? resolve(root, options.get('--web-dir') ?? 'apps/web/dist')
  : null;
const extensionDirectory = options.has('--extension-dir')
  ? resolve(root, options.get('--extension-dir') ?? 'apps/extension/dist')
  : null;
const extensionApiBase = options.get('--extension-api-base') || null;
const runtimeRoot = options.has('--runtime-root')
  ? resolve(options.get('--runtime-root') ?? '/app')
  : null;
const workerRuntimeRoot = options.has('--worker-runtime-root')
  ? resolve(options.get('--worker-runtime-root') ?? '/app')
  : null;
const recoveryToolFile = options.has('--recovery-tool-file')
  ? resolve(options.get('--recovery-tool-file') ?? '/app/cli.mjs')
  : null;

if (options.has('--api-dir') || options.size === 0) verifyApiBundle(apiDirectory);
if (workerDirectory) verifyMigrationWorker(workerDirectory);
if (openApiFile) verifyOpenApi(openApiFile);
if (asyncApiFile) verifyAsyncApi(asyncApiFile);
if (webDirectory) verifyWebBundle(webDirectory);
if (extensionDirectory) verifyExtensionBundle(extensionDirectory, extensionApiBase);
if (runtimeRoot) verifyRuntimeFilesystem(runtimeRoot);
if (workerRuntimeRoot) verifyWorkerRuntimeFilesystem(workerRuntimeRoot);
if (recoveryToolFile) verifyRecoveryTool(recoveryToolFile);

console.log(JSON.stringify({
  ok: true,
  apiDirectory: options.has('--api-dir') ? apiDirectory : null,
  workerDirectory,
  openApiFile,
  asyncApiFile,
  webDirectory,
  extensionDirectory,
  extensionApiBase,
  runtimeRoot,
  workerRuntimeRoot,
  recoveryToolFile,
}, null, 2));

function verifyApiBundle(directory) {
  const files = javascriptFiles(directory);
  assert(files.length > 0, `strict API bundle is missing: ${directory}`);
  const source = files.map(file => readFileSync(file, 'utf8')).join('\n');
  const forbidden = [
    ['/api/bootstrap', 'legacy workspace bootstrap route'],
    ['/api/events', 'legacy workspace event route'],
    ['/api/vaults/:vaultId/items', 'legacy plaintext item create route'],
    ['/api/items/:itemId/reveal', 'legacy plaintext reveal route'],
    ['/api/extension/sessions', 'legacy extension session route'],
    ['/api/extension/items/:itemId/reveal', 'legacy extension decrypt route'],
    ['MIMA_LEGACY_CONTENT_KEY_DIR', 'legacy content KEK environment'],
    ['MIMA_MASTER_KEY_DIR', 'legacy combined key directory environment'],
    ['legacyContentKeys', 'legacy content key provider'],
    ['decryptSecret', 'server-side legacy content decryption'],
    ['encryptSecret', 'server-side legacy content encryption'],
    ['unwrapDek', 'legacy DEK unwrap implementation'],
    ['rewrapDek', 'legacy DEK rewrap implementation'],
    ['src/db/seed', 'legacy seed entry'],
    ['src/scripts/rewrap', 'legacy rewrap entry'],
    ['provisionMigrationDatabaseRole', 'migration database role provisioner'],
    ['MIMA_MIGRATION_DATABASE_PASSWORD_FILE', 'migration database administrator credential'],
  ];
  for (const [canary, label] of forbidden) {
    assert(!source.includes(canary), `${label} found in strict API bundle (${canary})`);
  }
  for (const required of ['/api/v2/bootstrap', '/api/v2/events', '/api/v2/extension/bootstrap']) {
    assert(source.includes(required), `required strict route missing from API bundle: ${required}`);
  }
  assert(!/from\s+["']@mima\//.test(source), 'workspace package import escaped strict bundle');
}

function verifyMigrationWorker(directory) {
  const files = javascriptFiles(directory);
  assert(files.length > 0, `migration worker bundle is missing: ${directory}`);
  const source = files.map(file => readFileSync(file, 'utf8')).join('\n');
  assert(source.includes('MIMA_LEGACY_CONTENT_KEY_DIR'), 'migration worker cannot locate the isolated legacy KEK');
  assert(source.includes('decryptSecret'), 'migration worker does not contain the required legacy decrypt primitive');
  assert(source.includes('provisionMigrationDatabaseRole'), 'migration worker is missing its database role provisioner');
  for (const canary of ['Fastify', '.listen({', 'MIMA_API_PORT', '/api/v2/']) {
    assert(!source.includes(canary), `network API canary found in migration worker: ${canary}`);
  }
  assert(!/from\s+["']@mima\//.test(source), 'workspace package import escaped migration worker bundle');
}

function verifyOpenApi(file) {
  assert(existsSync(file), `OpenAPI document is missing: ${file}`);
  const document = JSON.parse(readFileSync(file, 'utf8'));
  const paths = document.paths ?? {};
  const forbidden = [
    '/api/bootstrap',
    '/api/events',
    '/api/vaults/{vaultId}/items',
    '/api/items/{itemId}',
    '/api/items/{itemId}/secret',
    '/api/items/{itemId}/reveal',
    '/api/extension/sessions',
    '/api/extension/bootstrap',
    '/api/extension/items/{itemId}/reveal',
  ];
  for (const path of forbidden) assert(!(path in paths), `legacy route advertised by strict OpenAPI: ${path}`);
  for (const path of ['/api/v2/bootstrap', '/api/v2/events', '/api/v2/extension/bootstrap']) {
    assert(path in paths, `strict OpenAPI route missing: ${path}`);
  }
  const content = JSON.stringify(document);
  assert(!content.includes('revealItemSecret'), 'legacy reveal operation advertised by strict OpenAPI');
  assert(!content.includes('currentItem'), 'legacy plaintext conflict payload advertised by strict OpenAPI');
}

function verifyAsyncApi(file) {
  assert(existsSync(file), `AsyncAPI document is missing: ${file}`);
  const document = JSON.parse(readFileSync(file, 'utf8'));
  const channels = document.channels ?? {};
  assert('/api/v2/events' in channels, 'strict AsyncAPI channel is missing: /api/v2/events');
  assert(!('/api/events' in channels), 'legacy plaintext event channel advertised by AsyncAPI');
  const content = JSON.stringify(document);
  assert(content.includes('item.encrypted_upserted'), 'encrypted item event is missing from AsyncAPI');
  assert(!content.includes('item.upserted'), 'legacy plaintext item event is advertised by AsyncAPI');
  assert(content.includes('streamEncryptedSyncEvents'), 'strict AsyncAPI operationId is missing');
  const propertyNames = new Set();
  collectSchemaPropertyNames(document.components?.schemas, propertyNames);
  for (const field of ['name', 'title', 'username', 'origin', 'loginUrl', 'folderPath', 'tags', 'favorite', 'sensitivity', 'secretValue']) {
    assert(!propertyNames.has(field), `plaintext metadata field advertised by AsyncAPI schema: ${field}`);
  }
}

function verifyWebBundle(directory) {
  const files = javascriptFiles(directory);
  assert(files.length > 0, `Web bundle is missing: ${directory}`);
  const source = files.map((file) => readFileSync(file, 'utf8')).join('\n');
  for (const canary of [
    '/api/bootstrap',
    '/api/events',
    '/api/items/',
    '/api/extension/sessions',
    '/api/extension/items/',
  ]) {
    assert(!source.includes(canary), `legacy plaintext endpoint found in Web bundle: ${canary}`);
  }
  for (const required of ['/api/v2/bootstrap', '/api/v2/events', '/api/v2/items/']) {
    assert(source.includes(required), `required zero-knowledge endpoint missing from Web bundle: ${required}`);
  }
}

function verifyExtensionBundle(directory, expectedApiBase) {
  const files = javascriptFiles(directory);
  assert(files.length > 0, `extension bundle is missing: ${directory}`);
  const source = files.map((file) => readFileSync(file, 'utf8')).join('\n');
  for (const canary of [
    '/api/extension/sessions',
    '/api/extension/bootstrap',
    '/api/extension/items/',
  ]) {
    assert(!source.includes(canary), `legacy plaintext endpoint found in extension bundle: ${canary}`);
  }
  if (expectedApiBase) {
    assert(source.includes(expectedApiBase), `production API origin missing from extension bundle: ${expectedApiBase}`);
    assert(!source.includes('http://127.0.0.1:4184'), 'development API origin found in production extension bundle');
    const manifestFile = join(directory, 'manifest.json');
    assert(existsSync(manifestFile), 'extension manifest is missing');
    const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
    const expectedPermission = `${new URL(expectedApiBase).origin}/*`;
    assert(manifest.permissions?.includes('tabs'), 'extension must declare tabs permission for persistent active URL matching');
    assert(!manifest.permissions?.includes('history'), 'extension must not request browsing history permission');
    assert(
      JSON.stringify(manifest.optional_host_permissions) === JSON.stringify(['http://*/*', 'https://*/*']),
      'extension optional host permissions must stay user-approved HTTP(S) access',
    );
    assert(
      JSON.stringify(manifest.host_permissions) === JSON.stringify([expectedPermission]),
      `production extension host_permissions must contain only ${expectedPermission}`,
    );
    assert(
      JSON.stringify(manifest.externally_connectable?.matches) === JSON.stringify([expectedPermission]),
      `production extension externally_connectable must contain only ${expectedPermission}`,
    );
    assert(
      !JSON.stringify(manifest).includes('http://127.0.0.1')
        && !JSON.stringify(manifest).includes('http://localhost'),
      'development host permission found in production extension manifest',
    );
  }
  const workerFiles = files.filter((file) => /crypto\.worker-[^/]+\.js$/.test(file));
  assert(workerFiles.length === 1, 'extension must contain exactly one dedicated Crypto Worker bundle');
  const sidePanelFile = join(directory, 'sidepanel.js');
  assert(existsSync(sidePanelFile), 'extension sidepanel bundle is missing');
  const sidePanel = readFileSync(sidePanelFile, 'utf8');
  for (const canary of [
    'encryptionPrivateKey',
    'signingPrivateKey',
    'device-private-key-bundle',
    'ExtensionKeyring',
  ]) {
    assert(!sidePanel.includes(canary), `private-key canary found in extension main thread: ${canary}`);
  }
}

function collectSchemaPropertyNames(value, output) {
  if (Array.isArray(value)) {
    for (const item of value) collectSchemaPropertyNames(item, output);
    return;
  }
  if (!value || typeof value !== 'object') return;
  if (value.properties && typeof value.properties === 'object' && !Array.isArray(value.properties)) {
    for (const key of Object.keys(value.properties)) output.add(key);
  }
  for (const item of Object.values(value)) collectSchemaPropertyNames(item, output);
}

function verifyRuntimeFilesystem(directory) {
  assert(existsSync(join(directory, 'apps/api/dist/server.js')), 'runtime image is missing strict server.js');
  verifyRuntimeUtilityDirectory(directory);
  for (const forbidden of [
    'packages',
    'apps/api/src',
    'apps/api/dist-migration-worker',
    'apps/api/tsup.config.ts',
    'apps/api/tsup.migration.config.ts',
  ]) {
    assert(!existsSync(join(directory, forbidden)), `build/source path leaked into runtime image: ${forbidden}`);
  }
  const runtimePackage = JSON.parse(readFileSync(join(directory, 'apps/api/package.json'), 'utf8'));
  assert(runtimePackage.name === '@mima/api-runtime', 'runtime image did not use the minimal package manifest');
  assert(runtimePackage.scripts === undefined, 'runtime package manifest contains operational source scripts');
  const workspaceLinks = [
    join(directory, 'apps/api/node_modules/@mima'),
    join(directory, 'node_modules/.pnpm/node_modules/@mima'),
  ];
  for (const path of workspaceLinks) assert(!existsSync(path), `workspace source link leaked into runtime image: ${path}`);
  verifyNoEscapingSymlinks(join(directory, 'apps/api/node_modules'), directory);
  verifyApiBundle(join(directory, 'apps/api/dist'));
}

function verifyWorkerRuntimeFilesystem(directory) {
  assert(
    existsSync(join(directory, 'apps/api/dist-migration-worker/legacy-migration-worker.js')),
    'migration worker image is missing its entrypoint',
  );
  assert(
    existsSync(join(directory, 'apps/api/dist-migration-worker/provision-migration-role.js')),
    'migration worker image is missing its role provisioner',
  );
  for (const forbidden of [
    'packages',
    'scripts',
    'apps/api/src',
    'apps/api/dist',
    'apps/api/tsup.config.ts',
    'apps/api/tsup.migration.config.ts',
  ]) {
    assert(!existsSync(join(directory, forbidden)), `build/source path leaked into worker image: ${forbidden}`);
  }
  const runtimePackage = JSON.parse(readFileSync(join(directory, 'apps/api/package.json'), 'utf8'));
  assert(runtimePackage.name === '@mima/api-runtime', 'worker image did not use the minimal package manifest');
  assert(runtimePackage.scripts === undefined, 'worker package manifest contains operational source scripts');
  for (const path of [
    join(directory, 'apps/api/node_modules/@mima'),
    join(directory, 'node_modules/.pnpm/node_modules/@mima'),
  ]) {
    assert(!existsSync(path), `workspace source link leaked into worker image: ${path}`);
  }
  for (const dependency of ['fastify', 'openid-client', 'ldapts', 'jose']) {
    assert(!existsSync(join(directory, 'node_modules', dependency)), `unneeded API dependency leaked into worker image: ${dependency}`);
  }
  verifyNoEscapingSymlinks(join(directory, 'apps/api/node_modules'), directory);
  verifyMigrationWorker(join(directory, 'apps/api/dist-migration-worker'));
}

function verifyRuntimeUtilityDirectory(directory) {
  const utilityDirectory = join(directory, 'scripts');
  assert(existsSync(utilityDirectory), 'runtime image is missing its utility directory');
  const entries = readdirSync(utilityDirectory, { withFileTypes: true });
  assert(
    entries.length === 1 && entries[0]?.isFile() && entries[0].name === 'init-server-keys.mjs',
    'runtime image may contain only scripts/init-server-keys.mjs',
  );
  const source = readFileSync(join(utilityDirectory, 'init-server-keys.mjs'), 'utf8');
  for (const required of ['MIMA_RUNTIME_KEY_DIR', 'MIMA_AUDIT_KEY_DIR']) {
    assert(source.includes(required), `runtime key initializer is missing ${required}`);
  }
  for (const forbidden of ['MIMA_LEGACY_CONTENT_KEY_DIR', 'decryptSecret', 'unwrapDek']) {
    assert(!source.includes(forbidden), `legacy content capability found in runtime key initializer: ${forbidden}`);
  }
}

function verifyRecoveryTool(file) {
  assert(existsSync(file), `recovery tool bundle is missing: ${file}`);
  const source = readFileSync(file, 'utf8');
  for (const required of ['createEnterpriseRecoveryKit', 'recoverEnterpriseRecoveryKey', 'openVaultKeyGrant']) {
    assert(source.includes(required), `recovery tool capability is missing: ${required}`);
  }
  for (const forbidden of [
    'Fastify',
    '.listen({',
    'MIMA_DATABASE_URL',
    'MIMA_LEGACY_CONTENT_KEY_DIR',
    '/api/v2/',
    'legacy-migration-worker',
  ]) {
    assert(!source.includes(forbidden), `server or migration capability found in recovery tool: ${forbidden}`);
  }
  const allowedImports = new Set(['crypto', 'fs', 'path']);
  for (const match of source.matchAll(/from\s+["']([^"']+)["']/g)) {
    const specifier = match[1];
    assert(
      specifier.startsWith('node:') || allowedImports.has(specifier),
      `recovery tool bundle contains a non-Node runtime import: ${specifier}`,
    );
  }
}

function verifyNoEscapingSymlinks(directory, boundary) {
  if (!existsSync(directory)) return;
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) {
        const target = realpathSync(path);
        const offset = relative(boundary, target);
        assert(offset !== '..' && !offset.startsWith(`..${sep}`), `runtime symlink escapes image root: ${path}`);
      } else if (stat.isDirectory()) pending.push(path);
    }
  }
}

function javascriptFiles(directory) {
  if (!existsSync(directory)) return [];
  const files = [];
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && /\.(?:js|mjs)$/.test(entry.name)) files.push(path);
    }
  }
  return files.sort();
}

function parseOptions(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    assert(argument.startsWith('--'), `unexpected argument: ${argument}`);
    const next = args[index + 1];
    if (next && !next.startsWith('--')) {
      values.set(argument, next);
      index += 1;
    } else values.set(argument, '');
  }
  return values;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
