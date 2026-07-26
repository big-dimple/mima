import { normalizeLoginUrl, normalizeOrigin } from '@mima/domain';

export interface ActiveTabContext {
  tabId: number | null;
  origin: string | null;
  url: string | null;
}

type TabsReader = Pick<typeof chrome.tabs, 'query'>;

export async function readLastFocusedActiveTab(tabs: TabsReader): Promise<ActiveTabContext> {
  const [tab] = await tabs.query({ active: true, lastFocusedWindow: true });
  const rawUrl = tab?.url ?? null;
  return {
    tabId: tab?.id ?? null,
    origin: rawUrl ? normalizeOrigin(rawUrl) : null,
    url: rawUrl ? normalizeLoginUrl(rawUrl) : null,
  };
}
