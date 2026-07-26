export const VAULT_GROUP_NAME_MAX_LENGTH = 60;

export function normalizeVaultGroupName(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const normalized = value.trim();
  if (!normalized) return null;
  if (
    normalized.length > VAULT_GROUP_NAME_MAX_LENGTH ||
    Array.from(normalized).some((character) => {
      const code = character.charCodeAt(0);
      return code <= 31 || code === 127;
    })
  ) return null;
  return normalized;
}
