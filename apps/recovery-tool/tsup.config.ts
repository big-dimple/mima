import { defineConfig } from 'tsup';

const bundledDependencies = [
  '@mima/e2ee',
  'libsodium-wrappers-sumo',
  'libsodium-sumo',
  'shamir-secret-sharing',
];

export default defineConfig([
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    platform: 'node',
    target: 'node24',
    outDir: 'dist',
    sourcemap: true,
    clean: false,
    noExternal: bundledDependencies,
  },
  {
    entry: { browser: 'src/browser.ts' },
    format: ['iife'],
    platform: 'browser',
    target: 'es2022',
    outDir: 'dist',
    sourcemap: false,
    clean: false,
    noExternal: bundledDependencies,
  },
]);
