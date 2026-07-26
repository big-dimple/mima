import { lstatSync, readFileSync } from 'node:fs';

export function readPrivateFile(path: string, label: string): string {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file and not a symlink`);
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must not be group/world accessible`);
  }
  const value = readFileSync(path, 'utf8').trim();
  if (!value) throw new Error(`${label} is empty`);
  return value;
}
