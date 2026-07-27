/**
 * 网站地址完全匹配：只允许完全相同的 scheme、host、port。
 * 不做子域名、相似域名或 http→https 放宽。
 */
export const LOGIN_URL_MAX_LENGTH = 2048;
export const LOGIN_URLS_MAX_COUNT = 10;

export function normalizeLoginUrl(input: string): string | null {
  if (input.length === 0 || input.length > LOGIN_URL_MAX_LENGTH) return null;
  try {
    const url = new URL(input);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    const normalized = url.href;
    return normalized.length <= LOGIN_URL_MAX_LENGTH ? normalized : null;
  } catch {
    return null;
  }
}

export function normalizeLoginUrls(inputs: readonly string[]): string[] | null {
  if (inputs.length > LOGIN_URLS_MAX_COUNT) return null;
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const input of inputs) {
    const url = normalizeLoginUrl(input.trim());
    if (url === null) return null;
    if (seen.has(url)) continue;
    seen.add(url);
    normalized.push(url);
  }
  return normalized;
}

export function normalizeOrigin(input: string): string | null {
  try {
    const url = new URL(input);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    // URL.origin 已按标准折叠默认端口（https:443 / http:80）
    return url.origin;
  } catch {
    return null;
  }
}

export function originsMatchExactly(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  const na = normalizeOrigin(a);
  const nb = normalizeOrigin(b);
  return na !== null && nb !== null && na === nb;
}
