import { describe, expect, it, vi } from 'vitest';
import { EXTENSION_WORKBENCH_WAKE_EVENT } from '@mima/e2ee';
import {
  createWorkbenchWakeScheduler,
  wakeWorkbenchTabs,
} from '../src/workbench-wake.ts';

describe('wakeWorkbenchTabs', () => {
  it('wakes only live tabs from an allowed workbench origin', async () => {
    const wake = vi.fn().mockResolvedValue(undefined);
    const count = await wakeWorkbenchTabs({
      listTabs: async () => [
        { id: 1, url: 'https://mima.example.com/' },
        { id: 2, url: 'https://mima.example.com/items', discarded: true },
        { id: 3, url: 'https://example.com/' },
        { url: 'https://mima.example.com/' },
      ],
      wake,
    }, new Set(['https://mima.example.com']));

    expect(count).toBe(1);
    expect(wake).toHaveBeenCalledWith(1, EXTENSION_WORKBENCH_WAKE_EVENT);
  });

  it('does not block recovery when tab discovery or injection fails', async () => {
    const wake = vi.fn()
      .mockRejectedValueOnce(new Error('tab closed'))
      .mockResolvedValueOnce(undefined);
    const count = await wakeWorkbenchTabs({
      listTabs: async () => [
        { id: 1, url: 'https://mima.example.com/' },
        { id: 2, url: 'https://mima.example.com/' },
      ],
      wake,
    }, new Set(['https://mima.example.com']));

    expect(count).toBe(1);
    await expect(wakeWorkbenchTabs({
      listTabs: async () => { throw new Error('tabs unavailable'); },
      wake,
    }, new Set(['https://mima.example.com']))).resolves.toBe(0);
  });

  it('coalesces connection-level wake events during an extension restart', async () => {
    let now = 1_000;
    const wake = vi.fn().mockResolvedValue(undefined);
    const adapter = {
      listTabs: vi.fn().mockResolvedValue([
        { id: 1, url: 'https://mima.example.com/' },
      ]),
      wake,
    };
    const schedule = createWorkbenchWakeScheduler(
      adapter,
      new Set(['https://mima.example.com']),
      1_000,
      () => now,
    );

    await expect(schedule()).resolves.toBe(1);
    await expect(schedule()).resolves.toBe(0);
    expect(adapter.listTabs).toHaveBeenCalledOnce();
    expect(wake).toHaveBeenCalledOnce();

    now += 1_001;
    await expect(schedule()).resolves.toBe(1);
    expect(adapter.listTabs).toHaveBeenCalledTimes(2);
  });
});
