import { beforeEach, describe, expect, it } from 'vitest';
import {
  clampLayout,
  isPreviousAutomaticLayout,
  readLayoutPreference,
} from '../src/components/Workspace.tsx';

describe('workspace layout preferences', () => {
  beforeEach(() => localStorage.clear());

  it('uses the wider desktop defaults', () => {
    expect(readLayoutPreference()).toEqual({ navWidth: 384, listWidth: 420 });
    expect(JSON.parse(localStorage.getItem('mima.layout.v3') ?? '{}'))
      .toEqual({ navWidth: 384, listWidth: 420 });
  });

  it('upgrades old automatic widths but preserves real customization', () => {
    localStorage.setItem('mima.layout.v2', JSON.stringify({ navWidth: 320, listWidth: 360 }));
    expect(readLayoutPreference()).toEqual({ navWidth: 384, listWidth: 420 });

    localStorage.clear();
    localStorage.setItem('mima.layout.v2', JSON.stringify({ navWidth: 280, listWidth: 300 }));
    expect(readLayoutPreference()).toEqual({ navWidth: 384, listWidth: 420 });

    localStorage.clear();
    localStorage.setItem('mima.layout.v2', JSON.stringify({ navWidth: 412, listWidth: 520 }));
    expect(readLayoutPreference()).toEqual({ navWidth: 412, listWidth: 520 });
    expect(isPreviousAutomaticLayout({ navWidth: 412, listWidth: 520 })).toBe(false);
  });

  it('upgrades the legacy narrow navigation without discarding its custom list width', () => {
    localStorage.setItem('mima.layout.v1', JSON.stringify({ navWidth: 200, listWidth: 520 }));
    expect(readLayoutPreference()).toEqual({ navWidth: 384, listWidth: 520 });
  });

  it('clamps only the rendered layout and restores the same preference on a wider viewport', () => {
    const preference = { navWidth: 384, listWidth: 420 };
    expect(clampLayout(preference, 1440)).toEqual(preference);
    expect(clampLayout(preference, 1120)).toEqual({ navWidth: 316, listWidth: 300 });
    expect(clampLayout(preference, 1440)).toEqual(preference);
  });
});
