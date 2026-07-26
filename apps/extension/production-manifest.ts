export function parseProductionApiOrigin(value: string | undefined): string {
  if (!value) throw new Error('production extension build requires VITE_MIMA_API_BASE');
  const url = new URL(value);
  if (
    url.protocol !== 'https:'
    || url.username
    || url.password
    || url.pathname !== '/'
    || url.search
    || url.hash
  ) {
    throw new Error('production extension VITE_MIMA_API_BASE must be an HTTPS origin without credentials, path, query, or hash');
  }
  return url.origin;
}

export function parseProductionManifestKey(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized || !/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
    throw new Error('production extension build requires a base64 manifest public key');
  }
  const decoded = Buffer.from(normalized, 'base64');
  if (decoded.length < 256 || decoded[0] !== 0x30) {
    throw new Error('production extension manifest public key is invalid');
  }
  return normalized;
}

export function withProductionManifest(
  manifest: Record<string, unknown>,
  apiOrigin: string,
  manifestKey: string,
): Record<string, unknown> {
  return {
    ...manifest,
    key: manifestKey,
    host_permissions: [`${apiOrigin}/*`],
    externally_connectable: {
      matches: [`${apiOrigin}/*`],
    },
  };
}
