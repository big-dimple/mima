import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import {
  parseProductionApiOrigin,
  parseProductionManifestKey,
  withProductionManifest,
} from './production-manifest';

const root = dirname(fileURLToPath(import.meta.url));
const outputDirectory = resolve(root, process.env.MIMA_EXT_OUT_DIR ?? 'dist');
const productionApiOrigin = process.env.MIMA_EXTENSION_PRODUCTION_BUILD === 'true'
  ? parseProductionApiOrigin(process.env.VITE_MIMA_API_BASE)
  : null;
const productionManifestKey = process.env.MIMA_EXTENSION_PRODUCTION_BUILD === 'true'
  ? parseProductionManifestKey(process.env.MIMA_EXTENSION_PUBLIC_KEY)
  : null;

const productionManifestPlugin = {
  name: 'mima-production-manifest',
  closeBundle() {
    if (!productionApiOrigin || !productionManifestKey) return;
    const manifestFile = resolve(outputDirectory, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestFile, 'utf8')) as Record<string, unknown>;
    const productionManifest = withProductionManifest(manifest, productionApiOrigin, productionManifestKey);
    writeFileSync(manifestFile, `${JSON.stringify(productionManifest, null, 2)}\n`, 'utf8');
  },
};

// MV3 多入口构建：侧边栏页面 + Service Worker。文件名不带 hash，供 manifest 静态引用。
// E2E 用 MIMA_EXT_OUT_DIR=dist-e2e + VITE_MIMA_API_BASE 构建指向独立端口的副本。
export default defineConfig({
  base: './',
  plugins: [productionManifestPlugin],
  build: {
    outDir: outputDirectory,
    emptyOutDir: true,
    rollupOptions: {
      input: {
        sidepanel: resolve(root, 'sidepanel.html'),
        background: resolve(root, 'src/background.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
});
