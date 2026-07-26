import { normalizeLoginUrl, originsMatchExactly } from '@mima/domain';
import type { DecryptedExtensionItem } from './protocol.ts';

export interface ActiveSiteAddress {
  origin: string | null;
  url: string | null;
}

export function extensionItemMatchScore(
  item: DecryptedExtensionItem,
  site: ActiveSiteAddress,
): 0 | 1 | 2 {
  const itemAddress = item.origin ?? item.loginUrl ?? null;
  const activeAddress = site.url ?? site.origin;
  if (!originsMatchExactly(itemAddress, activeAddress)) return 0;

  const itemLoginUrl = item.loginUrl ? normalizeLoginUrl(item.loginUrl) : null;
  const activeLoginUrl = site.url ? normalizeLoginUrl(site.url) : null;
  return itemLoginUrl && activeLoginUrl && itemLoginUrl === activeLoginUrl ? 2 : 1;
}

export function extensionItemMatchesSite(
  item: DecryptedExtensionItem,
  site: ActiveSiteAddress,
): boolean {
  return extensionItemMatchScore(item, site) > 0;
}
