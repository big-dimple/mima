import { describe, expect, it, vi } from 'vitest';
import { readLastFocusedActiveTab } from '../src/active-tab.ts';

describe('active tab reader', () => {
  it('reads the full URL from the active tab in the last focused browser window', async () => {
    const query = vi.fn().mockResolvedValue([{
      id: 42,
      url: 'https://accounts.example.test/login/tenant/example-b',
    }]);

    await expect(readLastFocusedActiveTab({ query } as never)).resolves.toEqual({
      tabId: 42,
      origin: 'https://accounts.example.test',
      url: 'https://accounts.example.test/login/tenant/example-b',
    });
    expect(query).toHaveBeenCalledWith({ active: true, lastFocusedWindow: true });
  });

  it('keeps restricted browser pages unavailable for matching', async () => {
    const query = vi.fn().mockResolvedValue([{ id: 8, url: 'edge://extensions/' }]);

    await expect(readLastFocusedActiveTab({ query } as never)).resolves.toEqual({
      tabId: 8,
      origin: null,
      url: null,
    });
  });
});
