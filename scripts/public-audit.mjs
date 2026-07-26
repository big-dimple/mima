import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(join(fileURLToPath(import.meta.url), '..', '..'));
const ignoredDirectories = new Set([
  '.git', '.mima', 'node_modules', 'dist', 'dist-e2e', 'dist-migration-worker',
  'build', 'coverage', 'playwright-report', 'test-results', '.pnpm-store', '.vite',
]);
const markdownAllowlist = new Set([
  'AGENTS.md', 'CLAUDE.md', 'DEPLOYMENT.md', 'LLMWIKI.md', 'README.md', 'SECURITY.md',
]);
const forbidden = [
  [/lingren|灵刃/giu, 'former product or company name'],
  [/lingrendev|lrgameglobal|lrgame/giu, 'private domain or organization'],
  [/wanghongping|wang hongping|王洪平|chenshiduo/giu, 'personal identity'],
  [/hbregistry-cn/giu, 'private registry'],
  [/(?:118\.89\.92\.181|10\.0\.1\.5|124\.220\.46\.68|192\.168\.15\.(?:240|242))/g, 'private infrastructure address'],
  [/caplpcfaocfodacajnjfjlibcbfcdnin/g, 'former extension id'],
  [/xSews4Lll2RXw56lSlqpbbGwEFokw\+h10L/g, 'former extension manifest key'],
  [/@lingren-mima|LINGREN_MIMA|VITE_LM_|\bLM_|\blm_|\blm-(?!e2ee-v1)|x-lm-|\.lmshare/gu, 'former application namespace'],
  [/100022882018|100020108857/g, 'real account fixture'],
  [/公司统一认证/gu, 'organization-specific UI copy'],
];
const formerIconHashes = new Set([
  '0c5b2aeb829220ea807ddc6653935e1deee0a7e030596a6ff85ee0d90e6d25d9',
  'c932a5144510c279872b045d977a55eb1cafacbfba2ab7a757022baddbfd597a',
  '8e9c8bb07e095ab5a48ff733475b969ac63bbdae8e72e15337f070cc9adb0ebf',
  '222cd6d2fee2719e33ac05419e1689f9d592f2f7e83e547eb540106f8532288e',
  '3bfee1ad8711f5d1e8e6eb32b71410199d311875c80766afc09107dfe7bf4b5f',
]);
const failures = [];
const rootPackage = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

if (rootPackage.license !== 'Apache-2.0') {
  failures.push('package.json: license must be Apache-2.0');
}
if (!readFileSync(join(root, 'LICENSE'), 'utf8').includes('Apache License\n                           Version 2.0')) {
  failures.push('LICENSE: expected the Apache License 2.0 text');
}

for (const path of walk(root)) {
  const file = relative(root, path).replaceAll('\\', '/');
  if (extname(file).toLowerCase() === '.md' && !markdownAllowlist.has(file)) {
    failures.push(`${file}: Markdown file is outside the public allowlist`);
  }
  const bytes = readFileSync(path);
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (formerIconHashes.has(digest)) failures.push(`${file}: former branded icon`);
  if (bytes.includes(0)) continue;
  const content = bytes.toString('utf8');
  if (file !== 'scripts/public-audit.mjs') {
    for (const [pattern, reason] of forbidden) {
      pattern.lastIndex = 0;
      if (pattern.test(content) || pattern.test(file)) failures.push(`${file}: ${reason}`);
    }
  }
}

for (const forbiddenPath of ['.mima', 'deploy/runtime.env', 'deploy/data', 'deploy/secrets', 'deploy/keys']) {
  try {
    lstatSync(join(root, forbiddenPath));
    failures.push(`${forbiddenPath}: runtime data must not be present in the public tree`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

if (failures.length > 0) {
  console.error(`public audit failed with ${failures.length} finding(s):`);
  for (const failure of [...new Set(failures)].sort()) console.error(`- ${failure}`);
  process.exit(1);
}
console.log('public audit passed');

function* walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (entry.isFile()) yield path;
  }
}
