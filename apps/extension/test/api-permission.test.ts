import { describe, expect, it, vi } from 'vitest';
import { ensureOriginPermission } from '../src/api-permission.ts';

describe('ensureOriginPermission', () => {
  it('reuses an existing production permission without prompting', async () => {
    const contains = vi.fn().mockResolvedValue(true);
    const request = vi.fn();

    await expect(ensureOriginPermission(
      { contains, request },
      'https://mima.example.com/*',
    )).resolves.toBe(true);
    expect(request).not.toHaveBeenCalled();
  });

  it('returns a stable denial when an optional permission cannot be prompted', async () => {
    const contains = vi.fn().mockResolvedValue(false);
    const request = vi.fn().mockRejectedValue(new Error('user gesture required'));

    await expect(ensureOriginPermission(
      { contains, request },
      'https://mima.example.com/*',
    )).resolves.toBe(false);
  });
});
