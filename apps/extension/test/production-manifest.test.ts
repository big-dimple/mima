import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  parseProductionApiOrigin,
  parseProductionManifestKey,
  withProductionManifest,
} from '../production-manifest';

const manifestKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9hdb9s7InliiKJLBya8AeYdmLAnkShwAXeCRabJ60uJEDf9Eqb+yfyy/NXORucE1YFb+HUJD2f9ipF1Nm3MyFC0sjRmFrTAzTiVVCeMkK/iVz3K/+x/scVAId0h2J1wtWcYeJNC/06/9HuO2drg/MfKrHxsdGG0yj7/TG5HSeQAkYwk/hH3ygQg8Tpl+fBbPNCNmhJBlvKI2XQoIy2gyKJNbwC/PVQR11nm/S0gCfHhDIl1M6hKuBXDQc6PM1K6tiOloODHKIYHtiGDmHegLenmf/8UnC4p8EmxlArSJNR2MiYmh3eThmWcCra7wWf6IP8gF9K/G/S7nvY9NS8NcgQIDAQAB';

const manifestPath = existsSync('apps/extension/public/manifest.json')
  ? 'apps/extension/public/manifest.json'
  : 'public/manifest.json';

function readManifest() {
  return JSON.parse(readFileSync(manifestPath, 'utf8')) as {
    permissions: string[];
    optional_host_permissions: string[];
    icons: Record<string, string>;
    action: { default_icon: Record<string, string> };
  };
}

describe('production extension manifest', () => {
  it('can continuously read only tab metadata and requests website access on demand', () => {
    const manifest = readManifest();

    expect(manifest.permissions).toContain('tabs');
    expect(manifest.permissions).not.toContain('history');
    expect(manifest.optional_host_permissions).toEqual(['http://*/*', 'https://*/*']);
  });

  it('ships every declared brand icon at its exact manifest size', () => {
    const manifest = readManifest();
    const declaredIcons = { ...manifest.icons, ...manifest.action.default_icon };

    for (const [size, relativePath] of Object.entries(declaredIcons)) {
      const png = readFileSync(resolve(dirname(manifestPath), relativePath));
      expect(png.subarray(0, 8)).toEqual(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
      expect(png.readUInt32BE(16)).toBe(Number(size));
      expect(png.readUInt32BE(20)).toBe(Number(size));
    }
  });

  it('replaces development API permissions with the reviewed production origin', () => {
    const manifest = {
      host_permissions: ['http://127.0.0.1/*', 'http://localhost/*'],
      optional_host_permissions: ['http://*/*', 'https://*/*'],
    };

    expect(withProductionManifest(
      manifest,
      parseProductionApiOrigin('https://mima.example.com'),
      parseProductionManifestKey(manifestKey),
    )).toEqual({
      key: manifestKey,
      host_permissions: ['https://mima.example.com/*'],
      externally_connectable: {
        matches: ['https://mima.example.com/*'],
      },
      optional_host_permissions: ['http://*/*', 'https://*/*'],
    });
    expect(manifest.host_permissions).toEqual(['http://127.0.0.1/*', 'http://localhost/*']);
  });

  it.each([undefined, '', 'not base64', 'TUlNQQ=='])('rejects an unsafe production manifest key: %s', (value) => {
    expect(() => parseProductionManifestKey(value)).toThrow();
  });

  it.each([
    undefined,
    'http://mima.example.com',
    'https://user:password@mima.example.com',
    'https://mima.example.com/api',
    'https://mima.example.com?source=extension',
    'https://mima.example.com#extension',
  ])('rejects an unsafe production API base: %s', (value) => {
    expect(() => parseProductionApiOrigin(value)).toThrow();
  });
});
