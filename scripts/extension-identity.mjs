import { createHash, generateKeyPairSync } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const directory = resolve(process.argv[2] ?? '');
if (!process.argv[2]) throw new Error('usage: node scripts/extension-identity.mjs <directory>');

const publicKeyFile = resolve(directory, 'manifest-public-key');
const extensionIdFile = resolve(directory, 'extension-id');
mkdirSync(directory, { recursive: true, mode: 0o700 });
chmodSync(directory, 0o700);

if (existsSync(publicKeyFile) !== existsSync(extensionIdFile)) {
  throw new Error('extension identity is incomplete; restore both identity files from backup');
}

let manifestKey;
let extensionId;
if (existsSync(publicKeyFile)) {
  manifestKey = readFileSync(publicKeyFile, 'utf8').trim();
  extensionId = readFileSync(extensionIdFile, 'utf8').trim();
  if (deriveExtensionId(manifestKey) !== extensionId) {
    throw new Error('extension identity files do not match');
  }
} else {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const der = publicKey.export({ type: 'spki', format: 'der' });
  manifestKey = der.toString('base64');
  extensionId = deriveExtensionId(manifestKey);
  writeFileSync(publicKeyFile, `${manifestKey}\n`, { mode: 0o600, flag: 'wx' });
  writeFileSync(extensionIdFile, `${extensionId}\n`, { mode: 0o600, flag: 'wx' });
}

chmodSync(publicKeyFile, 0o600);
chmodSync(extensionIdFile, 0o600);
process.stdout.write(`${extensionId}\n`);

function deriveExtensionId(value) {
  const der = Buffer.from(value, 'base64');
  if (der.length < 256 || der[0] !== 0x30) throw new Error('invalid extension manifest public key');
  return createHash('sha256')
    .update(der)
    .digest('hex')
    .slice(0, 32)
    .replace(/[0-9a-f]/g, (digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)));
}
