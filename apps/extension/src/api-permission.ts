interface OriginPermissionApi {
  contains(permissions: { origins: string[] }): Promise<boolean>;
  request(permissions: { origins: string[] }): Promise<boolean>;
}

export async function ensureOriginPermission(
  permissions: OriginPermissionApi,
  originPattern: string,
): Promise<boolean> {
  const request = { origins: [originPattern] };
  if (await permissions.contains(request)) return true;
  try {
    return await permissions.request(request);
  } catch {
    return false;
  }
}
