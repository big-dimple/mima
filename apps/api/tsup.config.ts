import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/server.ts',
    'src/db/migrate.ts',
    'src/scripts/auth-doctor.ts',
    'src/scripts/directory-sync.ts',
    'src/scripts/system-role.ts',
    'src/scripts/rekey-repair.ts',
    'src/scripts/identity-bind.ts',
    'src/scripts/verify-audit.ts',
    'src/scripts/repair-audit-anchor.ts',
  ],
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'dist',
  clean: true,
  sourcemap: false,
  splitting: true,
  treeshake: true,
  noExternal: [/^@mima\//],
});
