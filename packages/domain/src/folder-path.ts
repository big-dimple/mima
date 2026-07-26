export const FOLDER_PATH_MAX_DEPTH = 5;
export const FOLDER_PATH_MAX_LENGTH = 200;
export const FOLDER_SEGMENT_MAX_LENGTH = 40;
export const VAULT_DIRECTORY_MAX_COUNT = 500;
export const VAULT_DIRECTORY_MAX_ALIASES = 2_000;

export interface VaultDirectoryEntry {
  path: string;
  aliases: string[];
}

export function normalizeFolderPath(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;

  const segments = trimmed.replaceAll('\\', '/').split('/').map((segment) => segment.trim());
  if (
    segments.length > FOLDER_PATH_MAX_DEPTH ||
    segments.some((segment) =>
      !segment ||
      segment === '.' ||
      segment === '..' ||
      segment.length > FOLDER_SEGMENT_MAX_LENGTH ||
      Array.from(segment).some((character) => {
        const code = character.charCodeAt(0);
        return code <= 31 || code === 127;
      })
    )
  ) return null;

  const path = segments.join('/');
  return path.length <= FOLDER_PATH_MAX_LENGTH ? path : null;
}

export function folderPathAncestors(path: string): string[] {
  const normalized = normalizeFolderPath(path);
  if (!normalized) return [];
  const segments = normalized.split('/');
  return segments.map((_, index) => segments.slice(0, index + 1).join('/'));
}

export function folderContainsPath(folderPath: string, itemFolderPath: string | null | undefined): boolean {
  const normalizedFolder = normalizeFolderPath(folderPath);
  const normalizedItem = normalizeFolderPath(itemFolderPath);
  return Boolean(
    normalizedFolder &&
    normalizedItem &&
    (normalizedItem === normalizedFolder || normalizedItem.startsWith(`${normalizedFolder}/`)),
  );
}

export function normalizeVaultDirectories(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
): VaultDirectoryEntry[] | null {
  if (!entries) return [];
  if (entries.length > VAULT_DIRECTORY_MAX_COUNT) return null;

  const paths = new Map<string, string>();
  const normalized: VaultDirectoryEntry[] = [];
  let aliasCount = 0;
  for (const entry of entries) {
    const path = normalizeFolderPath(entry.path);
    if (!path || !Array.isArray(entry.aliases)) return null;
    const aliases = Array.from(new Set(entry.aliases.map((alias) => normalizeFolderPath(alias))));
    if (aliases.some((alias) => alias === null)) return null;
    const cleanAliases = (aliases as string[]).filter((alias) => alias !== path);
    aliasCount += cleanAliases.length;
    if (aliasCount > VAULT_DIRECTORY_MAX_ALIASES) return null;

    for (const candidate of [path, ...cleanAliases]) {
      const owner = paths.get(candidate);
      if (owner && owner !== path) return null;
      paths.set(candidate, path);
    }
    normalized.push({ path, aliases: cleanAliases.sort(compareFolderPaths) });
  }

  if (new Set(normalized.map((entry) => entry.path)).size !== normalized.length) return null;
  return normalized.sort((left, right) => compareFolderPaths(left.path, right.path));
}

export function materializeVaultDirectories(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  itemFolderPaths: readonly (string | null | undefined)[] = [],
): VaultDirectoryEntry[] {
  const normalized = normalizeVaultDirectories(entries);
  if (!normalized) throw new Error('密码库目录清单格式不正确');
  const byPath = new Map(normalized.map((entry) => [entry.path, entry]));

  for (const rawPath of itemFolderPaths) {
    const resolved = resolveVaultDirectoryPath(normalized, rawPath);
    if (!resolved) continue;
    for (const path of folderPathAncestors(resolved)) {
      if (!byPath.has(path)) byPath.set(path, { path, aliases: [] });
    }
  }
  const result = normalizeVaultDirectories([...byPath.values()]);
  if (!result) throw new Error('密码库目录数量已超过限制');
  return result;
}

export function resolveVaultDirectoryPath(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  folderPath: string | null | undefined,
): string | null {
  const path = normalizeFolderPath(folderPath);
  if (!path) return null;
  const normalized = normalizeVaultDirectories(entries);
  if (!normalized) return path;
  for (const entry of normalized) {
    if (entry.path === path || entry.aliases.includes(path)) return entry.path;
  }
  return path;
}

export function addVaultDirectory(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  folderPath: string,
): VaultDirectoryEntry[] {
  const path = normalizeFolderPath(folderPath);
  if (!path) throw new Error('目录格式不正确');
  const normalized = materializeVaultDirectories(entries);
  const resolved = resolveVaultDirectoryPath(normalized, path);
  if (resolved !== path || normalized.some((entry) => entry.aliases.includes(path))) {
    throw new Error('该路径是目录改名前的历史名称，请直接使用现有目录');
  }
  if (normalized.some((entry) => entry.path === path)) throw new Error('该目录已经存在');
  return materializeVaultDirectories(normalized, [path]);
}

export function renameVaultDirectory(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  sourcePath: string,
  targetPath: string,
): VaultDirectoryEntry[] {
  const source = normalizeFolderPath(sourcePath);
  const target = normalizeFolderPath(targetPath);
  if (!source || !target) throw new Error('目录格式不正确');
  if (source === target) return materializeVaultDirectories(entries);
  if (target.startsWith(`${source}/`)) throw new Error('目录不能移动到自己的子目录');

  const normalized = materializeVaultDirectories(entries);
  if (!normalized.some((entry) => entry.path === source)) throw new Error('要修改的目录不存在');
  const subtree = normalized.filter((entry) => folderContainsPath(source, entry.path));
  const subtreePaths = new Set(subtree.map((entry) => entry.path));
  const outsideNames = new Set(
    normalized
      .filter((entry) => !subtreePaths.has(entry.path))
      .flatMap((entry) => [entry.path, ...entry.aliases]),
  );
  const nextPaths = new Set<string>();
  for (const entry of subtree) {
    const nextPath = `${target}${entry.path.slice(source.length)}`;
    if (!normalizeFolderPath(nextPath)) throw new Error('修改后的目录超过 5 级或长度限制');
    if (outsideNames.has(nextPath) || nextPaths.has(nextPath)) throw new Error('目标目录已经存在');
    nextPaths.add(nextPath);
  }

  const updated = normalized.map((entry) => {
    if (!subtreePaths.has(entry.path)) return entry;
    const path = `${target}${entry.path.slice(source.length)}`;
    return {
      path,
      aliases: Array.from(new Set([...entry.aliases, entry.path])).filter((alias) => alias !== path),
    };
  });
  const result = normalizeVaultDirectories(updated);
  if (!result) throw new Error('目录历史路径发生冲突，请刷新后重试');
  return result;
}

export function removeVaultDirectory(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  sourcePath: string,
  itemFolderPaths: readonly (string | null | undefined)[] = [],
): VaultDirectoryEntry[] {
  const source = normalizeFolderPath(sourcePath);
  if (!source) throw new Error('目录格式不正确');
  const registry = materializeVaultDirectories(entries);
  // 历史别名：用户可能选中改名前的旧路径，先解析到当前节点再删除。
  const target = resolveVaultDirectoryPath(registry, source);
  if (!target) throw new Error('要删除的目录不存在');
  const displayed = materializeVaultDirectories(entries, itemFolderPaths);
  if (!displayed.some((entry) => entry.path === target)) {
    throw new Error('要删除的目录不存在');
  }
  // 非空判定：条目路径同样经别名解析，改名后未回写的旧条目也算占用。
  if (countVaultDirectorySubtreeItems(registry, target, itemFolderPaths) > 0) {
    throw new Error('目录及其子目录中还有条目，请先移动条目后再删除目录');
  }
  // 删除当前节点、全部后代及其 aliases；其他目录及其历史别名保持不变。
  const remaining = registry.filter((entry) => !folderContainsPath(target, entry.path));
  const result = normalizeVaultDirectories(remaining);
  if (!result) throw new Error('目录清单在删除后仍然不合法');
  return result;
}

/**
 * 目标目录整棵子树内的条目数。条目路径经历史别名解析，改名后未回写的旧条目也计入。
 * `removeVaultDirectory` 用它做非空拒绝；UI 用它渲染精确提示与判定二次确认路径。
 */
export function countVaultDirectorySubtreeItems(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  sourcePath: string,
  itemFolderPaths: readonly (string | null | undefined)[] = [],
): number {
  const registry = normalizeVaultDirectories(entries) ?? [];
  const target = resolveVaultDirectoryPath(registry, sourcePath);
  if (!target) return 0;
  return itemFolderPaths.reduce((count, rawPath) => {
    const resolved = resolveVaultDirectoryPath(registry, rawPath);
    return resolved !== null && folderContainsPath(target, resolved) ? count + 1 : count;
  }, 0);
}

/**
 * 目标目录的全部后代目录路径（不含自身），按稳定顺序返回。
 * 用于删除空目录前统计“及其 N 个空子目录”。
 */
export function vaultDirectoryDescendantPaths(
  entries: readonly VaultDirectoryEntry[] | null | undefined,
  sourcePath: string,
  itemFolderPaths: readonly (string | null | undefined)[] = [],
): string[] {
  const target = resolveVaultDirectoryPath(normalizeVaultDirectories(entries) ?? [], sourcePath);
  if (!target) return [];
  return materializeVaultDirectories(entries, itemFolderPaths)
    .map((entry) => entry.path)
    .filter((path) => path !== target && folderContainsPath(target, path));
}

function compareFolderPaths(left: string, right: string): number {
  return left.localeCompare(right, 'zh-CN');
}
