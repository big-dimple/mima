import { EXTENSION_WORKBENCH_WAKE_EVENT } from '@mima/e2ee';

export interface WorkbenchTab {
  id?: number;
  url?: string;
  discarded?: boolean;
}

export interface WorkbenchWakeAdapter {
  listTabs(): Promise<readonly WorkbenchTab[]>;
  wake(tabId: number, eventName: string): Promise<void>;
}

export async function wakeWorkbenchTabs(
  adapter: WorkbenchWakeAdapter,
  allowedOrigins: ReadonlySet<string>,
): Promise<number> {
  let tabs: readonly WorkbenchTab[];
  try {
    tabs = await adapter.listTabs();
  } catch {
    return 0;
  }
  const wakeable = tabs.filter((tab): tab is WorkbenchTab & { id: number; url: string } => (
    Number.isSafeInteger(tab.id)
    && typeof tab.url === 'string'
    && !tab.discarded
    && allowedOrigins.has(originOf(tab.url))
  ));
  const results = await Promise.allSettled(wakeable.map((tab) => (
    adapter.wake(tab.id, EXTENSION_WORKBENCH_WAKE_EVENT)
  )));
  return results.filter((result) => result.status === 'fulfilled').length;
}

export function createWorkbenchWakeScheduler(
  adapter: WorkbenchWakeAdapter,
  allowedOrigins: ReadonlySet<string>,
  cooldownMs = 1_000,
  now: () => number = () => Date.now(),
): () => Promise<number> {
  let inFlight: Promise<number> | null = null;
  let lastStartedAt = Number.NEGATIVE_INFINITY;
  return () => {
    if (inFlight) return inFlight;
    if (now() - lastStartedAt < cooldownMs) return Promise.resolve(0);
    lastStartedAt = now();
    const scheduled = wakeWorkbenchTabs(adapter, allowedOrigins).finally(() => {
      if (inFlight === scheduled) inFlight = null;
    });
    inFlight = scheduled;
    return inFlight;
  };
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}
