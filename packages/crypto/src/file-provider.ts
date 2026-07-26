import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { MasterKeyProvider } from './envelope.ts';

/**
 * 文件适配器：从目录读取 kek-v<N>.key（64 hex 字符 = 32 字节）。
 * 生产环境可替换为 KMS/HSM 适配器，只需实现 MasterKeyProvider。
 */
export class FileMasterKeyProvider implements MasterKeyProvider {
  private keys = new Map<string, Buffer>();
  private active: string;

  constructor(dir: string) {
    const files = readdirSync(dir)
      .map((f) => /^kek-v(\d+)\.key$/.exec(f))
      .filter((m): m is RegExpExecArray => m !== null)
      .sort((a, b) => Number(a[1]) - Number(b[1]));
    if (files.length === 0) {
      throw new Error(
        `no kek-v*.key found in ${dir}; run \`pnpm keys:init\` to create a development KEK`,
      );
    }
    for (const m of files) {
      const path = join(dir, m[0]);
      const mode = statSync(path).mode & 0o777;
      if ((mode & 0o077) !== 0) {
        console.warn(`[crypto] warning: ${path} is group/world accessible (mode ${mode.toString(8)}); expected 0600`);
      }
      const hex = readFileSync(path, 'utf8').trim();
      if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error(`${path} must contain exactly 64 hex characters`);
      }
      this.keys.set(`v${m[1]}`, Buffer.from(hex, 'hex'));
    }
    this.active = `v${files.at(-1)![1]}`;
  }

  getKey(version: string): Buffer {
    const key = this.keys.get(version);
    if (!key) throw new Error(`unknown KEK version: ${version}`);
    return key;
  }

  activeVersion(): string {
    return this.active;
  }

  listVersions(): string[] {
    return [...this.keys.keys()];
  }
}
