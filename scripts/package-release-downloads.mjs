import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, relative, sep } from 'node:path';
import { parseArgs } from 'node:util';
import { ZipFile } from 'yazl';

const { values } = parseArgs({
  options: {
    prefix: { type: 'string' },
    version: { type: 'string' },
    'extension-dir': { type: 'string' },
    'recovery-tool-file': { type: 'string' },
    'offline-usage-file': { type: 'string' },
    'output-dir': { type: 'string' },
  },
  strict: true,
});

const prefix = requiredOption('prefix');
const version = requiredOption('version');
const extensionDirectory = requiredOption('extension-dir');
const recoveryToolFile = requiredOption('recovery-tool-file');
const offlineUsageFile = requiredOption('offline-usage-file');
const outputDirectory = requiredOption('output-dir');

if (!/^[a-z0-9][a-z0-9-]*$/.test(prefix) || !/^[0-9A-Za-z][0-9A-Za-z.-]*$/.test(version)) {
  throw new Error('prefix or version contains unsupported archive-name characters');
}

await assertRegularFile(recoveryToolFile);
await assertRegularFile(offlineUsageFile);
const extensionFiles = await listRegularFiles(extensionDirectory);
if (extensionFiles.length === 0) throw new Error('extension directory is empty');

await mkdir(outputDirectory, { recursive: true });
const extensionArchive = join(outputDirectory, `${prefix}-extension-${version}.zip`);
const recoveryArchive = join(outputDirectory, `${prefix}-recovery-tool-${version}.zip`);

await writeArchive(extensionArchive, extensionFiles.map((file) => ({
  source: file,
  entry: relative(extensionDirectory, file).split(sep).join('/'),
})));
await writeArchive(recoveryArchive, [
  { source: recoveryToolFile, entry: `${prefix}-recovery-tool.mjs` },
  { source: offlineUsageFile, entry: 'OFFLINE-USAGE.txt' },
]);

const recoveryDigest = await sha256File(recoveryArchive);
await writeFile(`${recoveryArchive}.sha256`, `${recoveryDigest}  ${basename(recoveryArchive)}\n`, {
  encoding: 'utf8',
  mode: 0o644,
});

function requiredOption(name) {
  const value = values[name];
  if (typeof value !== 'string' || value.length === 0) throw new Error(`missing --${name}`);
  return value;
}

async function assertRegularFile(file) {
  const details = await stat(file);
  if (!details.isFile()) throw new Error(`not a regular file: ${file}`);
}

async function listRegularFiles(root) {
  const details = await stat(root);
  if (!details.isDirectory()) throw new Error(`not a directory: ${root}`);
  const files = [];

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`symbolic links are not allowed in release archives: ${path}`);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) files.push(path);
      else throw new Error(`unsupported release archive entry: ${path}`);
    }
  }

  await walk(root);
  return files;
}

async function writeArchive(outputPath, entries) {
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  await mkdir(dirname(outputPath), { recursive: true });
  await rm(temporaryPath, { force: true });
  const archive = new ZipFile();
  const fixedTimestamp = new Date('1980-01-01T00:00:00.000Z');

  for (const entry of entries) {
    archive.addFile(entry.source, entry.entry, {
      mtime: fixedTimestamp,
      mode: 0o100644,
      compressionLevel: 9,
      forceDosTimestamp: true,
    });
  }

  try {
    await new Promise((resolvePromise, rejectPromise) => {
      const output = createWriteStream(temporaryPath, { mode: 0o644 });
      archive.outputStream.once('error', rejectPromise);
      output.once('error', rejectPromise);
      output.once('close', resolvePromise);
      archive.outputStream.pipe(output);
      archive.end();
    });
    await rename(temporaryPath, outputPath);
  } catch (error) {
    await rm(temporaryPath, { force: true });
    throw error;
  }
}

async function sha256File(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
