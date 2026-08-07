import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe('release download packaging', () => {
  it('uses the repository packager and current schema head in the public image build', () => {
    const dockerfile = readFileSync(resolve('deploy/Dockerfile'), 'utf8');
    expect(dockerfile).toContain('node scripts/package-release-downloads.mjs');
    expect(dockerfile).toContain('mima.schema-head="0026_administrator_account_recovery"');
    expect(dockerfile).toContain('打开企业恢复向导.html');
    expect(dockerfile).not.toContain('apt-get install');
    expect(dockerfile).not.toMatch(/\bzip -q/);
  });

  it('creates deterministic extension and recovery archives without an operating-system zip package', () => {
    const root = mkdtempSync(join(tmpdir(), 'mima-release-downloads-'));
    temporaryDirectories.push(root);
    const extensionDirectory = join(root, 'extension');
    const outputDirectory = join(root, 'downloads');
    const recoveryToolFile = join(root, 'tool.mjs');
    const recoveryWizardFile = join(root, 'wizard.html');
    const usageFile = join(root, 'OFFLINE-USAGE.txt');
    mkdirSync(join(extensionDirectory, 'assets'), { recursive: true });
    writeFileSync(join(extensionDirectory, 'manifest.json'), '{"manifest_version":3}\n');
    writeFileSync(join(extensionDirectory, 'assets', 'worker.js'), 'export const ready = true;\n');
    writeFileSync(recoveryToolFile, 'console.log("offline");\n');
    writeFileSync(recoveryWizardFile, '<!doctype html><title>Recovery wizard</title>\n');
    writeFileSync(usageFile, 'Offline use only.\n');

    const first = runPackager(extensionDirectory, recoveryToolFile, recoveryWizardFile, usageFile, outputDirectory);
    expect(first.status, first.stderr).toBe(0);
    const extensionArchive = join(outputDirectory, 'mima-extension-0.2.0.zip');
    const recoveryArchive = join(outputDirectory, 'mima-recovery-tool-0.2.0.zip');
    const firstExtension = readFileSync(extensionArchive);
    const firstRecovery = readFileSync(recoveryArchive);
    expect(firstExtension.subarray(0, 2).toString('ascii')).toBe('PK');
    expect(firstExtension.includes(Buffer.from('manifest.json'))).toBe(true);
    expect(firstExtension.includes(Buffer.from('assets/worker.js'))).toBe(true);
    expect(firstRecovery.includes(Buffer.from('打开企业恢复向导.html'))).toBe(true);
    expect(firstRecovery.includes(Buffer.from('advanced/mima-recovery-tool.mjs'))).toBe(true);
    expect(firstRecovery.includes(Buffer.from('advanced/命令行说明.txt'))).toBe(true);

    const expectedDigest = createHash('sha256').update(firstRecovery).digest('hex');
    expect(readFileSync(`${recoveryArchive}.sha256`, 'utf8'))
      .toBe(`${expectedDigest}  mima-recovery-tool-0.2.0.zip\n`);

    const second = runPackager(extensionDirectory, recoveryToolFile, recoveryWizardFile, usageFile, outputDirectory);
    expect(second.status, second.stderr).toBe(0);
    expect(readFileSync(extensionArchive)).toEqual(firstExtension);
    expect(readFileSync(recoveryArchive)).toEqual(firstRecovery);
  });
});

function runPackager(
  extensionDirectory: string,
  recoveryToolFile: string,
  recoveryWizardFile: string,
  usageFile: string,
  outputDirectory: string,
) {
  return spawnSync(process.execPath, [
    resolve('scripts/package-release-downloads.mjs'),
    '--prefix', 'mima',
    '--version', '0.2.0',
    '--extension-dir', extensionDirectory,
    '--recovery-tool-file', recoveryToolFile,
    '--recovery-wizard-file', recoveryWizardFile,
    '--offline-usage-file', usageFile,
    '--output-dir', outputDirectory,
  ], { encoding: 'utf8' });
}
