import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'dist',
  sourcemap: true,
  clean: true,
  noExternal: [
    '@mima/e2ee',
    'libsodium-wrappers-sumo',
    'libsodium-sumo',
  ],
});
