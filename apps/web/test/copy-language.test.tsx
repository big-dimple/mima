import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const USER_FACING_FILES = [
  'apps/web/src/components/Header.tsx',
  'apps/web/src/components/GuideDialog.tsx',
  'apps/web/src/components/LoginScreen.tsx',
  'apps/web/src/components/LockOverlay.tsx',
  'apps/web/src/components/PairingDialog.tsx',
  'apps/web/src/components/ItemForm.tsx',
  'apps/web/src/components/ItemDetail.tsx',
  'apps/web/src/components/AuditDialog.tsx',
  'apps/extension/src/panel-view.ts',
  'apps/extension/public/manifest.json',
  'apps/web/public/demo-login.html',
];

describe('plain-language copy', () => {
  it('does not regress to internal jargon in visible product copy', () => {
    const source = USER_FACING_FILES.map((file) => readFileSync(file, 'utf8')).join('\n');
    for (const forbidden of [
      '秘密',
      '揭示',
      '保险库',
      '口令',
      '精确 Origin',
      'storage.session',
      'KEK',
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });
});
