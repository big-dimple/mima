import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';
import {
  canonicalJson,
  createEnterpriseRecoveryKit,
  destroyKeyPair,
  destroyVaultKeys,
  inspectRecoveryShare,
  openVaultKeyGrant,
  recoverEnterpriseRecoveryKey,
} from '@mima/e2ee';
import { parseRecoveryCaseInput, parseRecoveryInput } from './protocol.ts';
import { createRecoveryTransfer } from './transfer.ts';
import { createRecoveryCaseTransfer } from './case-transfer.ts';

const cliArguments = process.argv.slice(2);
if (cliArguments[0] === '--') cliArguments.shift();
const [command, ...argv] = cliArguments;

switch (command) {
  case 'generate':
    await generate(argv);
    break;
  case 'inspect':
    await inspect(argv);
    break;
  case 'recover':
    await recover(argv);
    break;
  default:
    throw new Error(
      'usage: recovery-tool <generate|inspect|recover>; run the selected command with --help',
    );
}

async function generate(argv: string[]): Promise<void> {
  if (argv.includes('--help')) {
    console.log('recovery-tool generate --ceremony-id <id> --output-dir <new-directory>');
    return;
  }
  const ceremonyId = requiredOption(argv, '--ceremony-id');
  const outputDirectory = resolve(requiredOption(argv, '--output-dir'));
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  const kit = await createEnterpriseRecoveryKit(ceremonyId);
  const manifest = {
    protocol: 'lm-e2ee-v1',
    kind: 'enterprise-recovery-manifest',
    ceremonyId: kit.ceremonyId,
    ceremonyDigest: kit.ceremonyDigest,
    publicEncryptionKey: kit.publicKey,
    keyFingerprint: kit.publicKeyFingerprint,
    threshold: kit.threshold,
    shareCount: kit.shareCount,
  };
  writeExclusive(`${outputDirectory}/manifest.json`, `${canonicalJson(manifest)}\n`);
  kit.shares.forEach((share, index) => {
    writeExclusive(`${outputDirectory}/share-${index + 1}.mimashare`, `${share}\n`);
  });
  console.log(JSON.stringify({
    outputDirectory,
    ceremonyId: kit.ceremonyId,
    ceremonyDigest: kit.ceremonyDigest,
    keyFingerprint: kit.publicKeyFingerprint,
    shareCount: kit.shareCount,
    threshold: kit.threshold,
  }, null, 2));
}

async function inspect(argv: string[]): Promise<void> {
  if (argv.includes('--help')) {
    console.log('recovery-tool inspect --share <share-file>');
    return;
  }
  const share = readPrivateText(requiredOption(argv, '--share'));
  console.log(JSON.stringify(await inspectRecoveryShare(share), null, 2));
}

async function recover(argv: string[]): Promise<void> {
  if (argv.includes('--help')) {
    console.log(
      'recovery-tool recover --input <request-package.json> --share <one> --share <two> --output <new-file.json>',
    );
    return;
  }
  const inputPath = requiredOption(argv, '--input');
  const outputPath = requiredOption(argv, '--output');
  const sharePaths = repeatedOption(argv, '--share');
  if (sharePaths.length !== 2) throw new Error('recover requires exactly two independently held shares');
  const inputText = readPrivateText(inputPath);
  const parsed = JSON.parse(inputText) as { protocol?: unknown; kind?: unknown };
  if (parsed.protocol === 'mima-e2ee-v2' && parsed.kind === 'enterprise-recovery-case-package') {
    const input = parseRecoveryCaseInput(inputText);
    const result = await createRecoveryCaseTransfer(input, sharePaths.map(readPrivateText));
    writeExclusive(resolve(outputPath), `${canonicalJson(result as never)}\n`);
    console.log(JSON.stringify({
      caseId: input.caseId,
      recoveredVaultCount: result.results.length,
      output: resolve(outputPath),
    }, null, 2));
    return;
  }
  const input = parseRecoveryInput(inputText);
  const recoveryKey = await recoverEnterpriseRecoveryKey(
    sharePaths.map(readPrivateText),
    {
      ceremonyId: input.recovery.ceremonyId,
      ceremonyDigest: input.recovery.ceremonyDigest,
      publicKey: input.recovery.publicKey,
    },
  );
  let vaultKeys: Awaited<ReturnType<typeof openVaultKeyGrant>> | undefined;
  try {
    vaultKeys = await openVaultKeyGrant(
      input.recoveryEnvelope,
      recoveryKey,
      input.trustedOwnerSigningPublicKey,
      {
        vaultId: input.vaultId,
        recipientId: input.recovery.keyId,
        epoch: input.epoch,
      },
    );
    const result = await createRecoveryTransfer(input, vaultKeys);
    writeExclusive(resolve(outputPath), `${canonicalJson(result as never)}\n`);
    console.log(JSON.stringify({
      requestId: input.requestId,
      requestDigest: input.requestDigest,
      vaultId: input.vaultId,
      toolEvidenceDigest: result.toolEvidenceDigest,
      output: resolve(outputPath),
    }, null, 2));
  } finally {
    await destroyKeyPair(recoveryKey);
    if (vaultKeys) await destroyVaultKeys(vaultKeys);
  }
}

function requiredOption(argv: string[], name: string): string {
  const index = argv.indexOf(name);
  const value = index >= 0 ? argv[index + 1] : undefined;
  if (!value || value.startsWith('--')) throw new Error(`${name} is required`);
  return value;
}

function repeatedOption(argv: string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === name && argv[index + 1] && !argv[index + 1]!.startsWith('--')) {
      values.push(argv[index + 1]!);
      index += 1;
    }
  }
  return values;
}

function readPrivateText(path: string): string {
  return readFileSync(resolve(path), 'utf8').trim();
}

function writeExclusive(path: string, value: string): void {
  writeFileSync(path, value, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
}
