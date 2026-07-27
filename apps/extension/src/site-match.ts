import { normalizeLoginUrl, normalizeLoginUrls, originsMatchExactly } from '@mima/domain';
import type { DecryptedExtensionItem } from './protocol.ts';

export interface ActiveSiteAddress {
  origin: string | null;
  url: string | null;
}

export function extensionItemMatchScore(
  item: DecryptedExtensionItem,
  site: ActiveSiteAddress,
): 0 | 1 | 2 {
  const activeAddress = site.url ?? site.origin;
  const itemLoginUrls = extensionItemLoginUrls(item);
  const activeLoginUrl = site.url ? normalizeLoginUrl(site.url) : null;
  if (activeLoginUrl && itemLoginUrls.includes(activeLoginUrl)) return 2;
  return itemLoginUrls.some((url) => originsMatchExactly(url, activeAddress)) ? 1 : 0;
}

export function extensionItemLoginUrls(item: DecryptedExtensionItem): string[] {
  const raw = item.loginUrls?.length
    ? item.loginUrls
    : [item.loginUrl ?? item.origin].filter((url): url is string => Boolean(url));
  return normalizeLoginUrls(raw) ?? [];
}

export function extensionItemMatchesSite(
  item: DecryptedExtensionItem,
  site: ActiveSiteAddress,
): boolean {
  return extensionItemMatchScore(item, site) > 0;
}
