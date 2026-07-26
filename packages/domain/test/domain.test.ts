import { describe, expect, it } from 'vitest';
import {
  resolveEffectiveRole,
  canReveal,
  canReadAudit,
  canManageMembers,
  canManageVault,
  normalizeOrigin,
  normalizeLoginUrl,
  originsMatchExactly,
  generatePassword,
  normalizeFolderPath,
  folderPathAncestors,
  folderContainsPath,
  addVaultDirectory,
  materializeVaultDirectories,
  normalizeVaultDirectories,
  removeVaultDirectory,
  countVaultDirectorySubtreeItems,
  vaultDirectoryDescendantPaths,
  renameVaultDirectory,
  resolveVaultDirectoryPath,
} from '../src/index.ts';

const subject = { userId: 'u-1', groups: ['group:default/qa', 'group:default/ops'] };

describe('resolveEffectiveRole', () => {
  it('直接用户角色无条件覆盖组角色（即使更低）', () => {
    const role = resolveEffectiveRole(
      [
        { subjectKind: 'user', subjectId: 'u-1', role: 'auditor' },
        { subjectKind: 'group', subjectId: 'group:default/qa', role: 'owner' },
      ],
      subject,
    );
    expect(role).toBe('auditor');
  });

  it('无直接角色时取组角色最高权限', () => {
    const role = resolveEffectiveRole(
      [
        { subjectKind: 'group', subjectId: 'group:default/qa', role: 'viewer' },
        { subjectKind: 'group', subjectId: 'group:default/ops', role: 'editor' },
      ],
      subject,
    );
    expect(role).toBe('editor');
  });

  it('auditor 组角色低于 viewer', () => {
    const role = resolveEffectiveRole(
      [
        { subjectKind: 'group', subjectId: 'group:default/qa', role: 'auditor' },
        { subjectKind: 'group', subjectId: 'group:default/ops', role: 'viewer' },
      ],
      subject,
    );
    expect(role).toBe('viewer');
  });

  it('无任何匹配成员时返回 null', () => {
    expect(
      resolveEffectiveRole(
        [{ subjectKind: 'group', subjectId: 'group:default/rd', role: 'owner' }],
        subject,
      ),
    ).toBeNull();
  });
});

describe('capabilities', () => {
  it('auditor 不可 Reveal，可读审计', () => {
    expect(canReveal('auditor')).toBe(false);
    expect(canReadAudit('auditor', false)).toBe(true);
  });
  it('viewer 可 Reveal，不可读审计/管理成员', () => {
    expect(canReveal('viewer')).toBe(true);
    expect(canReadAudit('viewer', false)).toBe(false);
    expect(canManageMembers('viewer')).toBe(false);
  });
  it('platform-admin 可读审计与管库，但不可管理成员、无成员角色时不可 Reveal', () => {
    expect(canManageMembers(null)).toBe(false);
    expect(canManageVault(null, true)).toBe(true);
    expect(canReadAudit(null, true)).toBe(true);
    expect(canReveal(null)).toBe(false);
  });
  it('成员管理仅限该库 owner', () => {
    expect(canManageMembers('owner')).toBe(true);
    expect(canManageMembers('editor')).toBe(false);
    expect(canManageMembers('auditor')).toBe(false);
  });
});

describe('origin 精确匹配', () => {
  it('保留完整登录地址并规范化 URL', () => {
    expect(normalizeLoginUrl('https://accounts.example.test/login/tenant/example-a')).toBe(
      'https://accounts.example.test/login/tenant/example-a',
    );
    expect(normalizeLoginUrl('https://a.example.test/login?tenant=one#account')).toBe(
      'https://a.example.test/login?tenant=one#account',
    );
    expect(normalizeLoginUrl('https://a.example.test')).toBe('https://a.example.test/');
  });
  it('规范化默认端口', () => {
    expect(normalizeOrigin('https://a.example.test:443/path')).toBe('https://a.example.test');
    expect(normalizeOrigin('http://a.example.test:8080')).toBe('http://a.example.test:8080');
  });
  it('拒绝非 http(s) 与非法输入', () => {
    expect(normalizeLoginUrl('ftp://a.example.test')).toBeNull();
    expect(normalizeLoginUrl('javascript:alert(1)')).toBeNull();
    expect(normalizeLoginUrl('not a url')).toBeNull();
    expect(normalizeLoginUrl(`https://a.example.test/${'x'.repeat(2048)}`)).toBeNull();
    expect(normalizeOrigin('ftp://a.example.test')).toBeNull();
    expect(normalizeOrigin('not a url')).toBeNull();
    expect(normalizeOrigin('javascript:alert(1)')).toBeNull();
  });
  it('scheme / host / port 任一不同即不匹配（不放宽子域名）', () => {
    expect(originsMatchExactly('https://a.example.test', 'https://a.example.test/login')).toBe(true);
    expect(originsMatchExactly('https://a.example.test', 'http://a.example.test')).toBe(false);
    expect(originsMatchExactly('https://a.example.test', 'https://b.a.example.test')).toBe(false);
    expect(originsMatchExactly('https://a.example.test', 'https://a.example.test:8443')).toBe(false);
    expect(originsMatchExactly(null, 'https://a.example.test')).toBe(false);
  });
});

describe('generatePassword', () => {
  it('长度正确且每类字符至少一个', () => {
    for (let i = 0; i < 20; i++) {
      const pw = generatePassword({ length: 16, upper: true, lower: true, digits: true, symbols: true });
      expect(pw).toHaveLength(16);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).toMatch(/[^A-Za-z0-9]/);
    }
  });
  it('仅选中的字符类出现', () => {
    const pw = generatePassword({ length: 24, upper: false, lower: true, digits: true, symbols: false });
    expect(pw).toMatch(/^[a-z0-9]+$/);
  });
  it('非法配置抛错', () => {
    expect(() =>
      generatePassword({ length: 2, upper: true, lower: true, digits: true, symbols: true }),
    ).toThrow();
    expect(() =>
      generatePassword({ length: 10, upper: false, lower: false, digits: false, symbols: false }),
    ).toThrow();
  });
});

describe('folder paths', () => {
  it('normalizes nested paths without changing human-readable names', () => {
    expect(normalizeFolderPath(' 工作 \\ 云服务 / 示例云 ')).toBe('工作/云服务/示例云');
    expect(folderPathAncestors('工作/云服务/示例云')).toEqual([
      '工作',
      '工作/云服务',
      '工作/云服务/示例云',
    ]);
  });

  it('rejects ambiguous, over-deep, and overlong paths', () => {
    expect(normalizeFolderPath('工作//云服务')).toBeNull();
    expect(normalizeFolderPath('工作/../云服务')).toBeNull();
    expect(normalizeFolderPath('一/二/三/四/五/六')).toBeNull();
    expect(normalizeFolderPath(`工作/${'云'.repeat(41)}`)).toBeNull();
  });

  it('includes descendants while keeping sibling folders separate', () => {
    expect(folderContainsPath('工作/云服务', '工作/云服务/示例云')).toBe(true);
    expect(folderContainsPath('工作/云服务', '工作/代码托管')).toBe(false);
    expect(folderContainsPath('工作/云服务', null)).toBe(false);
  });

  it('materializes empty directories and all of their ancestors', () => {
    expect(addVaultDirectory([], '工作/云服务/示例云')).toEqual([
      { path: '工作', aliases: [] },
      { path: '工作/云服务', aliases: [] },
      { path: '工作/云服务/示例云', aliases: [] },
    ]);
    expect(materializeVaultDirectories([], ['个人/邮箱'])).toContainEqual({ path: '个人', aliases: [] });
  });

  it('renames a complete subtree without touching every item path', () => {
    const directories = materializeVaultDirectories([], [
      '工作/云服务/示例云',
      '工作/云服务/云平台',
      '工作/代码仓库',
    ]);
    const renamed = renameVaultDirectory(directories, '工作/云服务', '工作/云平台');

    expect(renamed).toContainEqual({ path: '工作/云平台', aliases: ['工作/云服务'] });
    expect(renamed).toContainEqual({
      path: '工作/云平台/示例云',
      aliases: ['工作/云服务/示例云'],
    });
    expect(resolveVaultDirectoryPath(renamed, '工作/云服务/示例云')).toBe('工作/云平台/示例云');
    expect(resolveVaultDirectoryPath(renamed, '工作/代码仓库')).toBe('工作/代码仓库');
  });

  it('rejects ambiguous directory aliases and rename collisions', () => {
    expect(normalizeVaultDirectories([
      { path: '工作', aliases: ['旧目录'] },
      { path: '个人', aliases: ['旧目录'] },
    ])).toBeNull();
    expect(() => renameVaultDirectory(
      materializeVaultDirectories([], ['工作/云服务', '工作/研发']),
      '工作/云服务',
      '工作/研发',
    )).toThrow('目标目录已经存在');
  });
});

describe('removeVaultDirectory', () => {
  it('deletes an empty leaf directory and keeps every sibling intact', () => {
    const directories = materializeVaultDirectories([
      { path: '工作', aliases: [] },
      { path: '工作/云服务', aliases: [] },
      { path: '工作/代码仓库', aliases: [] },
      { path: '个人', aliases: [] },
    ]);
    const result = removeVaultDirectory(directories, '工作/云服务', []);
    expect(result).toEqual([
      { path: '个人', aliases: [] },
      { path: '工作', aliases: [] },
      { path: '工作/代码仓库', aliases: [] },
    ]);
  });

  it('deletes an empty subtree in one call', () => {
    const directories = materializeVaultDirectories([], [
      '工作/云服务/示例云',
      '工作/云服务/云平台',
      '工作/代码仓库',
    ]);
    const result = removeVaultDirectory(directories, '工作/云服务', []);
    expect(result.map((entry) => entry.path)).toEqual(['工作', '工作/代码仓库']);
    expect(result.some((entry) => entry.path.startsWith('工作/云服务'))).toBe(false);
  });

  it('drops the target subtree aliases while preserving unrelated aliases', () => {
    const renamed = renameVaultDirectory(
      materializeVaultDirectories([], ['工作/云服务/示例云', '个人/邮箱']),
      '工作/云服务',
      '工作/云平台',
    );
    // 前置：改名后子树带别名，个人/邮箱 无别名
    expect(renamed).toContainEqual({ path: '工作/云平台', aliases: ['工作/云服务'] });

    const result = removeVaultDirectory(renamed, '工作/云平台', []);
    expect(result.some((entry) => entry.path.startsWith('工作/云平台'))).toBe(false);
    // 被删子树的历史别名一并消失，不残留在其他条目上
    expect(result.every((entry) => !entry.aliases.includes('工作/云服务'))).toBe(true);
    expect(result.every((entry) => !entry.aliases.includes('工作/云服务/示例云'))).toBe(true);
    // 无关目录及其结构保持不变
    expect(result).toContainEqual({ path: '个人', aliases: [] });
    expect(result).toContainEqual({ path: '个人/邮箱', aliases: [] });
  });

  it('refuses to delete a directory whose subtree still holds items', () => {
    const directories = materializeVaultDirectories([], ['工作/云服务/示例云']);
    expect(() => removeVaultDirectory(directories, '工作/云服务', ['工作/云服务/示例云']))
      .toThrow('目录及其子目录中还有条目，请先移动条目后再删除目录');
    // 顶层也一样：后代里有条目就拒绝
    expect(() => removeVaultDirectory(directories, '工作', ['工作/云服务/示例云']))
      .toThrow('还有条目');
  });

  it('counts items even when they still reference a pre-rename alias path', () => {
    const renamed = renameVaultDirectory(
      materializeVaultDirectories([], ['工作/云服务/示例云']),
      '工作/云服务',
      '工作/云平台',
    );
    // 旧条目仍写着改名前的 工作/云服务/示例云；经别名解析后仍算占用，拒绝删除
    expect(() => removeVaultDirectory(renamed, '工作/云平台', ['工作/云服务/示例云']))
      .toThrow('还有条目');
    expect(countVaultDirectorySubtreeItems(renamed, '工作/云平台', ['工作/云服务/示例云'])).toBe(1);
    // 用旧别名选中目标目录也能删除空目录
    const empty = removeVaultDirectory(renamed, '工作/云服务/示例云', []);
    expect(empty.some((entry) => entry.path.includes('示例云'))).toBe(false);
  });

  it('resolves the source through historical aliases before deleting', () => {
    const renamed = renameVaultDirectory(
      materializeVaultDirectories([], ['工作/云服务']),
      '工作/云服务',
      '工作/云平台',
    );
    const result = removeVaultDirectory(renamed, '工作/云服务', []);
    expect(result.map((entry) => entry.path)).toEqual(['工作']);
  });

  it('throws when the target directory does not exist', () => {
    expect(() => removeVaultDirectory([{ path: '工作', aliases: [] }], '不存在', []))
      .toThrow('要删除的目录不存在');
  });

  it('lists descendant paths for the empty-subtree confirmation prompt', () => {
    const directories = materializeVaultDirectories([], [
      '工作/云服务/示例云',
      '工作/云服务/云平台',
      '工作/代码仓库',
    ]);
    expect(vaultDirectoryDescendantPaths(directories, '工作/云服务')).toEqual([
      '工作/云服务/示例云',
      '工作/云服务/云平台',
    ]);
    expect(vaultDirectoryDescendantPaths(directories, '工作/代码仓库')).toEqual([]);
  });
});
