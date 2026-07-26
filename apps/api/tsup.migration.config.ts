import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/scripts/legacy-migration-worker.ts',
    'src/scripts/provision-migration-role.ts',
  ],
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'dist-migration-worker',
  sourcemap: false,
  clean: true,
  treeshake: true,
  noExternal: [/^@mima\//],
});
